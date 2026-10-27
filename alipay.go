package main

// 支付宝账号：扫码登录 → 保持 Cookie → 轮询收款 → 上报 X-Ypay
//
// 逆向参考程序（PC三网监控重构版V1.0.8）确认的链路：
//   data/alipay_sessions.json 存登录态（qr_url / security_id / cookies）
//   data/account_channels.json 里 "alipay:2088123456789012" -> "5"（通道 ID）
//   records 表：source_key=alipay:{支付宝交易号}，channel_code=alipay_app
//   上报成功回调：{"code":200,...,"pay_type":"alipay"}
//
// 参考程序的 cookie 字段名做了混淆，映射如下：
//   SGIiLheR4HOT -> name      ZZwI0VEe -> value
//   JDgafeLuEw   -> path      EDH1pNu  -> domain
//   O1qzkaN9IGc  -> httpOnly  CkWcBv1l5 -> secure
//
// 登录环节：支付宝登录页挂了 um.js / rds / monitor-sens / security-sdk 四层风控，
// 纯 HTTP 复现会被拦。必须用内嵌浏览器（WebView2）让用户扫码，再从浏览器取 Cookie。

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"time"
)

// AlipayCookie 一条浏览器 Cookie。字段名与参考程序保持一致，便于互换排查。
type AlipayCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	HTTPOnly bool   `json:"httpOnly"`
	Secure   bool   `json:"secure"`
}

// AlipaySession 一个支付宝登录会话
type AlipaySession struct {
	ID       string `json:"id"`
	PID      string `json:"pid"`       // 支付宝 PID，2088 开头
	MaskedID string `json:"masked_id"` // 208****583
	Status   string `json:"status"`    // waiting / confirmed / expired / offline
	Nick     string `json:"nick"`

	ChannelID     string `json:"channel_id"`      // 通用通道 ID（旧字段，兜底）
	ChannelIDXpay string `json:"channel_id_xpay"` // X-Ypay 通道
	ChannelIDV1   string `json:"channel_id_v1"`   // 码支付V1 通道

	QRURL      string `json:"qr_url"`
	SecurityID string `json:"security_id"`
	RdsToken   string `json:"rds_form_token"`
	AlieditUID string `json:"aliedit_uid"`
	LoginURL   string `json:"login_url"` // 内嵌浏览器要打开的登录页

	CreatedAt     string `json:"created_at"`
	OnlineSince   string `json:"online_since"`
	LastCheck     string `json:"last_check"`
	LastHeartbeat string `json:"last_heartbeat"`
	HeartbeatMsg  string `json:"heartbeat_message"`

	Cookies []AlipayCookie `json:"cookies"`

	// 轮询游标：已处理过的支付宝交易号，避免重复
	Reported []string `json:"reported"`

	// BillWatermark 账单基线：本地时间 "2006-01-02 15:04:05"。
	// 只有比它更新的账单才算「新入账」；为空表示还没建立基线。
	// 首次拉账单时只登记基线，不回补页面上的历史账单。
	BillWatermark string `json:"bill_watermark"`

	// 手机端收款记录接口的凭据（每次登录/失效后从 chat.htm 重新取）
	BizToken string `json:"biz_token"`
	SID      string `json:"sid"`

	// UA 登录浏览器的真实 UA。支付宝会把 UA 和登录态绑在一起，
	// 用固定的 Chrome/120 去打 Edge 登录出来的会话容易被风控。
	UA string `json:"ua"`
}

func (s *AlipaySession) cookieHeader() string {
	parts := make([]string, 0, len(s.Cookies))
	for _, c := range s.Cookies {
		if c.Name == "" || c.Value == "" {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// ---------- 登录态与请求 ----------
//
// 参考程序（PC三网监控重构版V1.0.8，Wails+WebView2）的做法已实测复现：
//
//  1. 存下来的 cookie 是「每个域各一份」（87 条 = 17 个名字 × 5 个域：
//     alipay.com / auth / authea178 / my / securitycore），不覆盖、不合并。
//  2. 发请求时把全部 cookie 拼成一条 Cookie 头（不去重、不按域过滤）。
//     这一点很关键：csmobile.alipay.com 上没有自己的 cookie，
//     靠的就是 alipay.com 那几条，按域过滤会直接变成"未登录"。
//  3. 收款记录走 csmobile 的手机端接口（templateId=100），
//     **不碰 consumeprod 的账单页** —— 所以永远不会触发二次扫码。
//
// 之前我们的错：cookie 按 name|domain 去重（Go 的 jar 对 host-only cookie 返回空
// domain，5 个域被压成 1 条），又用 _CHIPS-ALIPAYJSESSIONID 覆盖了 ALIPAYJSESSIONID，
// 再加上用 PC 账单页轮询，10 分钟就被踢回登录页。

// alipayCookieHost 取一条 cookie 属于哪个 host。
// Domain 为空的是老数据（当时没记 host），统一按 .alipay.com 处理。
func alipayCookieHost(c AlipayCookie) (host string, domainCookie bool) {
	d := strings.TrimSpace(c.Domain)
	if d == "" {
		return "alipay.com", true
	}
	if strings.HasPrefix(d, ".") {
		return strings.TrimPrefix(d, "."), true
	}
	return d, false
}

// alipayJarHosts 登录后要挨个访问/采集的域名，和参考程序里出现的 5 个域一致
var alipayJarHosts = []string{
	"https://alipay.com",
	"https://auth.alipay.com",
	"https://my.alipay.com",
	"https://securitycore.alipay.com",
	"https://csmobile.alipay.com",
}

// alipayCollectJar 把 jar 里各域的 cookie 收集成一张表。
//
// 关键：host-only cookie 必须按「从哪个域读到的」区分开（Domain 记成那个 host），
// 只用 name|domain 去重会把 auth / my / csmobile 的 session 压成一条。
func alipayCollectJar(jar http.CookieJar) []AlipayCookie {
	out := make([]AlipayCookie, 0, 64)
	seen := map[string]bool{}
	for _, raw := range alipayJarHosts {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		for _, c := range jar.Cookies(u) {
			if c.Name == "" || c.Value == "" {
				continue
			}
			domain := c.Domain
			if domain == "" {
				domain = u.Hostname() // host-only：记下是哪个域的
			}
			path := orDefault(c.Path, "/")
			key := c.Name + "|" + domain + "|" + path
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, AlipayCookie{
				Name: c.Name, Value: c.Value,
				Domain: domain, Path: path,
				HTTPOnly: c.HttpOnly, Secure: c.Secure,
			})
		}
	}
	return out
}

// alipayUA 统一的浏览器 UA（和参考程序一致）
const alipayUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// alipayUAOf 会话有真实浏览器 UA 就用它，否则用默认的
func alipayUAOf(s *AlipaySession) string {
	if s != nil {
		if ua := strings.TrimSpace(s.UA); ua != "" {
			return ua
		}
	}
	return alipayUA
}

// alipayGet 发一个带「全部 cookie」的 GET。
// cookie 头的拼法就是参考程序的做法：全部 name=value 串起来，
// 同名不同值都保留（支付宝不同域各有一份 session）。
func alipayGet(s *AlipaySession, rawURL, referer string, timeout time.Duration) ([]byte, int, error) {
	if s == nil {
		return nil, 0, fmt.Errorf("会话为空")
	}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	if h := s.cookieHeader(); h != "" {
		req.Header.Set("Cookie", h)
	}
	req.Header.Set("User-Agent", alipayUAOf(s))
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

var (
	aliEncMu    sync.Mutex
	aliEncCache = map[string]string{} // 明文 -> DPAPI 密文

	aliSaveMu     sync.Mutex
	aliLastSaveAt time.Time

	aliMu   sync.Mutex
	aliList []AlipaySession
	aliPath string
	aliStop = make(chan struct{})
	aliRun  bool
)

func aliEncCacheGet(plain string) (string, bool) {
	aliEncMu.Lock()
	defer aliEncMu.Unlock()
	v, ok := aliEncCache[plain]
	return v, ok
}

func aliEncCachePut(plain, enc string) {
	aliEncMu.Lock()
	defer aliEncMu.Unlock()
	if len(aliEncCache) > 5000 { // 换账号/换 session 时自然淘汰，别无限涨
		aliEncCache = map[string]string{}
	}
	aliEncCache[plain] = enc
}

// saveAlipaySessionsThrottled 轮询里用的落盘：正常情况每 20 秒最多写一次。
// 5 秒一轮、每轮都写 48KB JSON（还带 87 次 DPAPI）没必要，参考程序也是隔一段时间写一次。
// force=true 用于状态变化（登录/掉线/新订单）时立刻落盘。
func saveAlipaySessionsThrottled(force bool) {
	aliSaveMu.Lock()
	if !force && time.Since(aliLastSaveAt) < 20*time.Second {
		aliSaveMu.Unlock()
		return
	}
	aliLastSaveAt = time.Now()
	aliSaveMu.Unlock()
	if err := saveAlipaySessions(); err != nil {
		logWarn("alipay", "保存登录态失败：%v", err)
	}
}

// alipayRawFile 最近一次账单响应落盘位置
func alipayRawFile() string {
	exe, err := os.Executable()
	dir := "."
	if err == nil {
		dir = filepath.Dir(exe)
	}
	return filepath.Join(dir, "alipay_bill_raw.html")
}

func alipaySessionsFile() string {
	if aliPath != "" {
		return aliPath
	}
	exe, err := os.Executable()
	dir := "."
	if err == nil {
		dir = filepath.Dir(exe)
	}
	aliPath = filepath.Join(dir, "alipay_sessions.json")
	return aliPath
}

func loadAlipaySessions() {
	b, err := os.ReadFile(alipaySessionsFile())
	if err != nil {
		aliMu.Lock()
		aliList = nil
		aliMu.Unlock()
		return
	}
	var list []AlipaySession
	if err := json.Unmarshal(b, &list); err != nil {
		aliMu.Lock()
		aliList = nil
		aliMu.Unlock()
		return
	}
	// Cookie 是登录态，磁盘上用 DPAPI 加密；内存里保持明文供请求使用。
	for i := range list {
		for j := range list[i].Cookies {
			v := list[i].Cookies[j].Value
			if isEncrypted(v) {
				if plain, err := dpapiDecrypt(v); err == nil {
					list[i].Cookies[j].Value = plain
				}
			}
		}
	}
	aliMu.Lock()
	aliList = list
	aliMu.Unlock()
}

func saveAlipaySessions() error {
	aliMu.Lock()
	// 深拷贝，加密只作用在副本上，内存里的值保持明文
	list := make([]AlipaySession, len(aliList))
	for i := range aliList {
		list[i] = aliList[i]
		if len(aliList[i].Cookies) > 0 {
			cs := make([]AlipayCookie, len(aliList[i].Cookies))
			copy(cs, aliList[i].Cookies)
			list[i].Cookies = cs
		}
	}
	aliMu.Unlock()

	for i := range list {
		for j := range list[i].Cookies {
			v := list[i].Cookies[j].Value
			if v == "" || isEncrypted(v) {
				continue
			}
			// 加密结果缓存：轮询会频繁落盘，同一个 cookie 值反复做 DPAPI
			// （87 条 × 每 5 秒）是白烧 CPU。DPAPI 密文不要求确定性，
			// 缓存下来的密文照样能解开。
			if enc, ok := aliEncCacheGet(v); ok {
				list[i].Cookies[j].Value = enc
				continue
			}
			if enc, err := dpapiEncrypt(v); err == nil {
				aliEncCachePut(v, enc)
				list[i].Cookies[j].Value = enc
			}
		}
	}

	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(alipaySessionsFile(), b, 0600)
}

func alipaySessionsCopy() []AlipaySession {
	aliMu.Lock()
	defer aliMu.Unlock()
	out := make([]AlipaySession, len(aliList))
	copy(out, aliList)
	return out
}

func findAlipaySession(id string) (AlipaySession, bool) {
	aliMu.Lock()
	defer aliMu.Unlock()
	for _, s := range aliList {
		if s.ID == id || s.PID == id {
			return s, true
		}
	}
	return AlipaySession{}, false
}

func upsertAlipaySession(s AlipaySession) {
	aliMu.Lock()
	defer aliMu.Unlock()
	for i := range aliList {
		if aliList[i].ID == s.ID {
			aliList[i] = s
			return
		}
	}
	aliList = append(aliList, s)
}

func removeAlipaySession(id string) {
	aliMu.Lock()
	defer aliMu.Unlock()
	for i := range aliList {
		if aliList[i].ID == id {
			aliList = append(aliList[:i], aliList[i+1:]...)
			return
		}
	}
}

func newAlipaySessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// maskPid 把 2088123456789012 显示成 208****583
func maskPid(pid string) string {
	if len(pid) <= 7 {
		return pid
	}
	return pid[:3] + "****" + pid[len(pid)-3:]
}

// ---------- 账单轮询 ----------

const (
	alipayPollEvery = 5 * time.Second
)

// 手机端收款记录（参考程序实际用的接口，实测可用）。
//
//	chat.htm  : 下发 bizToken + SESSIONID(=接口参数 sid)，并带出登录的 USERID
//	bizData   : templateId=100 的收款记录列表，pageNo=1 是最新一页
const (
	alipayChatURL    = "https://csmobile.alipay.com/mypa/chat.htm?scene=app_mypa_robot"
	alipayBizDataURL = "https://csmobile.alipay.com/guide/getBizData.json"
)

// 旧入口：PC 账单页。会让支付宝跳安全校验（要再扫一次码），
// 现在只在接口拿不到数据时当兜底/校准用，正常轮询不再走它。
var alipayBillURLs = []string{
	"https://consumeprod.alipay.com/record/standard.htm",
	"https://consumeprod.alipay.com/record/advanced.htm",
	"https://my.alipay.com/portal/i.htm",
}

// alipayLooksLikeLoginPage 判断响应体是不是支付宝登录页。
// 支付宝登录页有两个坑：
//  1. 可能直接返回 200（不是 302），所以不能只看状态码
//  2. 页面是 GBK 编码，中文字节对不上 UTF-8 的"登录"，只能靠 ASCII 特征
func alipayLooksLikeLoginPage(body []byte) bool {
	// 安全校验页也有 <input type="password" style="display:none">，
	// 但它不是登录页，不能当成"登录失效"（否则用户永远看不到验证提示）
	if bytes.Contains(body, []byte("securityForm")) || bytes.Contains(body, []byte("checkSecurity")) {
		return false
	}
	if len(body) == 0 {
		return false
	}
	// 只扫前 64KB，登录页特征都在头部
	n := len(body)
	if n > 64<<10 {
		n = 64 << 10
	}
	low := strings.ToLower(string(body[:n]))
	markers := []string{
		`id="loginform"`,
		`class="loginform`,
		`name="password"`,
		`type="password"`,
		`j-loginform`,
		`alipay-login`,
		`login-box`,
		`auth.alipay.com/login`,
	}
	for _, m := range markers {
		if strings.Contains(low, m) {
			return true
		}
	}
	// title 里出现 login 也算
	if i := strings.Index(low, "<title>"); i >= 0 {
		if j := strings.Index(low[i:], "</title>"); j > 0 {
			if strings.Contains(low[i:i+j], "login") {
				return true
			}
		}
	}
	return false
}

// alipayLooksLikeErrorPage 判断响应体是不是支付宝的错误/限流页。
// 这类页面必须当成"本次拉取失败"，不能当成"没有新订单"——
// 否则一次限流就会被误判成零收款，直接漏单。
// 已实测到的：
//
//	<title>服务器繁忙</title>  +  wait-xxxx.css
func alipayLooksLikeErrorPage(body []byte) bool {
	if len(body) == 0 {
		return true // 空响应也算失败
	}
	n := len(body)
	if n > 64<<10 {
		n = 64 << 10
	}
	txt := string(body[:n])
	low := strings.ToLower(txt)

	markers := []string{
		"服务器繁忙",
		"系统繁忙",
		"请稍后重试",
		"网络繁忙",
		"访问过于频繁",
		"service is busy",
		"too many requests",
	}
	for _, m := range markers {
		if strings.Contains(low, strings.ToLower(m)) {
			return true
		}
	}
	// 支付宝的等待/限流页会引 wait-*.css
	if strings.Contains(low, "alipay_site/wait-") || strings.Contains(low, "/wait-") {
		return true
	}
	// 明确的错误标题
	if i := strings.Index(low, "<title>"); i >= 0 {
		if j := strings.Index(low[i:], "</title>"); j > 0 {
			title := low[i : i+j]
			if strings.Contains(title, "error") || strings.Contains(title, "错误") {
				return true
			}
		}
	}
	return false
}

// alipayFetchOne 拉一个 PC 账单页（兜底/校准用）。
// cookie 走 alipayGet 的「全部 cookie」头。
func alipayFetchOne(s *AlipaySession, u string) ([]byte, error) {
	raw, code, err := alipayGet(s, u, "https://my.alipay.com/portal/i.htm", 20*time.Second)
	if err != nil {
		return nil, err
	}
	body := raw
	if code == 302 || code == 301 {
		return nil, fmt.Errorf("登录已失效（被重定向到登录页）")
	}
	if code != 200 {
		return nil, fmt.Errorf("HTTP %d", code)
	}
	// 关键：登录页可能以 200 返回，必须看内容
	if alipayLooksLikeLoginPage(body) {
		return nil, fmt.Errorf("登录已失效（返回的是登录页）")
	}
	// 限流页/错误页也不能当成空账单
	if alipayLooksLikeErrorPage(body) {
		return nil, fmt.Errorf("支付宝返回异常页（可能被限流）")
	}
	// 首次访问账单会被重定向到安全校验页，需要再扫一次码验证身份
	if chk := alipayDetectSecurityCheck(body); chk != nil {
		return nil, &alipaySecurityErr{Check: chk}
	}
	// 账单页是 GBK，统一转成 UTF-8 再交给解析器
	return alipayToUTF8(body), nil
}

// alipaySecurityErr 表示需要用户在支付宝 App 里再扫一次码验证身份
type alipaySecurityErr struct {
	Check *alipaySecurityCheck
}

func (e *alipaySecurityErr) Error() string {
	return "需要安全验证：请用支付宝 App 扫描二维码确认身份"
}

// alipayPendingCheck 记录当前待验证的账单安全校验
var (
	pendingChkMu sync.Mutex
	pendingChk   = map[string]*alipaySecurityCheck{}
)

func setPendingCheck(sessionID string, c *alipaySecurityCheck) {
	pendingChkMu.Lock()
	defer pendingChkMu.Unlock()
	if c == nil {
		delete(pendingChk, sessionID)
		return
	}
	pendingChk[sessionID] = c
}

func getPendingCheck(sessionID string) *alipaySecurityCheck {
	pendingChkMu.Lock()
	defer pendingChkMu.Unlock()
	return pendingChk[sessionID]
}

// alipaySubmitSecurityCheck 扫码通过后把 securityId POST 回 standard.htm
func alipaySubmitSecurityCheck(s *AlipaySession, chk *alipaySecurityCheck) error {
	if s == nil || chk == nil {
		return fmt.Errorf("参数缺失")
	}
	form := url.Values{}
	form.Set("securityId", chk.SecurityID)

	req, err := http.NewRequest("POST", "https://consumeprod.alipay.com/record/standard.htm",
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", alipayUA)
	if h := s.cookieHeader(); h != "" {
		req.Header.Set("Cookie", h)
	}
	req.Header.Set("Referer", "https://consumeprod.alipay.com/record/checkSecurity.htm")

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("提交安全校验返回 HTTP %d", resp.StatusCode)
	}
	if alipayDetectSecurityCheck(body) != nil {
		return fmt.Errorf("安全校验未通过，请重新扫码")
	}
	logInfo("alipay", "账单安全校验已通过（%s）", maskPid(s.PID))
	return nil
}

// alipayToUTF8 把 GBK/GB18030 页面转成 UTF-8。
// 支付宝账单页 <meta charset="GBK">，不转换的话中文说明全是乱码。
func alipayToUTF8(body []byte) []byte {
	if utf8.Valid(body) {
		return body
	}
	dec := simplifiedchinese.GB18030.NewDecoder()
	if out, err := dec.Bytes(body); err == nil {
		return out
	}
	return body
}

// alipayFetchBill 拉账单页。
//
// 每次都用「按域带 cookie 的 jar」发请求，把服务器返回的 Set-Cookie 收下后
// 同步回会话：支付宝的 ALIPAYJSESSIONID / ctoken 是滑动过期的，
// 只拿登录时的快照一直发，十分钟左右就会被踢回登录页。
func alipayFetchBill(s *AlipaySession) ([]byte, error) {
	if s == nil || len(s.Cookies) == 0 {
		return nil, fmt.Errorf("没有 Cookie，需要先扫码登录")
	}
	return alipayFetchBillWith(s)
}

// alipayFetchBillWith 依次尝试各个 PC 账单入口，返回第一个能解析出记录的页面。
func alipayFetchBillWith(s *AlipaySession) ([]byte, error) {
	var lastBody []byte
	var lastErr error
	loginGone := false

	for _, u := range alipayBillURLs {
		body, err := alipayFetchOne(s, u)
		if err != nil {
			// 安全校验是硬性阻断：必须让用户扫码，不能拿别的页面凑数。
			// 否则会退到 my.alipay.com 门户页，表现为"解析到 0 笔"，
			// 用户永远看不到需要验证的提示。
			var se *alipaySecurityErr
			if errors.As(err, &se) {
				return nil, err
			}
			if strings.Contains(err.Error(), "登录已失效") {
				loginGone = true
				lastErr = err
				continue
			}
			lastErr = err
			continue
		}
		lastBody = body
		// 这一页能解析出记录就直接用
		if len(parseAlipayBillHTML(string(body))) > 0 {
			return body, nil
		}
		// 拿到的页面不是账单页（比如门户页），记录下来继续试下一个
		if alipayLooksLikePortal(body) {
			logDebug("alipay", "%s 返回的是门户页，继续试下一个入口", u)
			lastBody = nil
			continue
		}
	}

	if loginGone && lastBody == nil {
		return nil, fmt.Errorf("登录已失效（被重定向到登录页）")
	}
	if lastBody != nil {
		return lastBody, nil // 页面拿到了但没记录，交给上层判断
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("所有账单入口都不可用")
	}
	return nil, lastErr
}

// ---------- 手机端收款记录接口（主力） ----------
//
// 两步，和参考程序完全一致（已用它自己的登录态实测跑通）：
//
//  1. GET chat.htm?scene=app_mypa_robot
//     页面里带 USERID（= 支付宝 PID）、bizToken、SESSIONID（= 接口参数 sid）
//  2. GET guide/getBizData.json?_=<ms>&bizToken=..&pageNo=1&sid=..&templateId=100
//     返回 {"rsp":{"data":{"hasMore":..,"records":[{"month":..,"trans":[
//       {"amount":"0.13","bizType":"TRADE","stateDesc":"交易成功",
//        "time":"今天 18:29","title":"收钱码收款",
//        "transNo":"2026102523001461781454714313","bizTime":1792924199000}]}]}}}
//
// 这条路不碰 consumeprod 账单页，所以不会有"首次读账单要再扫一次码"。

var (
	aliBizRawMu   sync.Mutex
	aliBizRawLast []byte
	aliRawSig     uint64
	reAliUserID   = regexp.MustCompile(`USERID\s*=\s*'([^']*)'`)
	reAliBizTok   = regexp.MustCompile(`bizToken:\s*'([A-Za-z0-9_-]{8,64})'`)
	reAliSessID   = regexp.MustCompile(`SESSIONID\s*=\s*'([A-Za-z0-9_-]{8,64})'`)
)

// alipayChatTokens 打开收款助手页，取回 USERID / bizToken / SESSIONID
func alipayChatTokens(s *AlipaySession) (userID, bizToken, sid string, err error) {
	if s == nil || len(s.Cookies) == 0 {
		return "", "", "", fmt.Errorf("没有 Cookie，需要先扫码登录")
	}
	body, code, err := alipayGet(s, alipayChatURL, "https://my.alipay.com/portal/i.htm", 20*time.Second)
	if err != nil {
		return "", "", "", fmt.Errorf("打开收款页面失败：%w", err)
	}
	if code != 200 {
		return "", "", "", fmt.Errorf("收款页面 HTTP %d", code)
	}
	if alipayLooksLikeLoginPage(body) {
		return "", "", "", fmt.Errorf("登录已失效（返回的是登录页）")
	}
	txt := string(alipayToUTF8(body))
	if m := reAliUserID.FindStringSubmatch(txt); len(m) > 1 {
		userID = strings.TrimSpace(m[1])
	}
	if m := reAliBizTok.FindStringSubmatch(txt); len(m) > 1 {
		bizToken = strings.TrimSpace(m[1])
	}
	if m := reAliSessID.FindStringSubmatch(txt); len(m) > 1 {
		sid = strings.TrimSpace(m[1])
	}
	if bizToken == "" || sid == "" {
		return userID, bizToken, sid, fmt.Errorf("收款页面里没取到 bizToken/sid（页面 %d 字节）", len(body))
	}
	return userID, bizToken, sid, nil
}

// finishBrowserLogin 浏览器扫码成功后的统一收尾：
// 落 cookie（含浏览器真实 UA）→ 用收款接口验收 → 同步上报账号。
// 返回 true 表示收款接口也认这个登录态。
func finishBrowserLogin(sessionID string, cookies []AlipayCookie, ua string) bool {
	s, ok := findAlipaySession(sessionID)
	if !ok {
		return false
	}
	now := time.Now().Format("2006-01-02T15:04:05Z07:00")
	s.Cookies = cookies
	s.UA = ua
	s.Status = "confirmed"
	s.OnlineSince = now
	s.LastCheck = now
	s.HeartbeatMsg = "登录成功"

	// 真正的验收：收款接口把 USERID/bizToken/sid 给我，才算登录成功。
	// 只验证「my.alipay.com 不是登录页」不够 —— 后面每 5 秒拉收款记录靠的是 csmobile 那套。
	var userID, bizToken, csid string
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		userID, bizToken, csid, err = alipayChatTokens(&s)
		if err == nil && userID != "" {
			break
		}
		logWarn("alipay", "登录后验证收款接口第 %d 次失败：%v", attempt, err)
		time.Sleep(time.Duration(attempt) * time.Second)
	}
	verified := err == nil && userID != ""
	if verified {
		s.PID = userID
		s.MaskedID = maskPid(userID)
		s.BizToken, s.SID = bizToken, csid
		s.HeartbeatMsg = "在线"
	} else {
		s.HeartbeatMsg = "登录成功，但收款接口不可用：" + truncate(fmt.Sprint(err), 80)
	}

	upsertAlipaySession(s)
	if err := saveAlipaySessions(); err != nil {
		logWarn("alipay", "保存登录态失败：%v", err)
	}
	if s.PID != "" {
		if err := upsertAccount(Account{
			Type: "alipay", Wxid: s.PID, Nick: s.Nick,
			ChannelID: s.ChannelFor(GetConfig().Mode), ChannelCode: "alipay_app", Enabled: true,
		}); err != nil {
			s.HeartbeatMsg = "账号配置保存失败：" + err.Error()
			upsertAlipaySession(s)
			_ = saveAlipaySessions()
			logWarn("config", "保存支付宝账号 %s 失败：%v", maskPid(s.PID), err)
		}
	}
	logInfo("alipay", "登录完成：Cookie %d 条，PID=%s，%s", len(cookies), maskPid(s.PID), s.HeartbeatMsg)
	return verified
}

// aliRawUnchanged 内容没变就返回 true（用 FNV 指纹比对，省一次写盘）
func aliRawUnchanged(raw []byte) bool {
	var h uint64 = 1469598103934665603
	for _, b := range raw {
		h ^= uint64(b)
		h *= 1099511628211
	}
	aliBizRawMu.Lock()
	defer aliBizRawMu.Unlock()
	if h == aliRawSig {
		return true
	}
	aliRawSig = h
	return false
}

// alipayLastBizRawCopy 取最近一次收款记录接口的原始响应
func alipayLastBizRawCopy() []byte {
	aliBizRawMu.Lock()
	defer aliBizRawMu.Unlock()
	out := make([]byte, len(aliBizRawLast))
	copy(out, aliBizRawLast)
	return out
}

// alipayBizDataResp 收款记录接口的响应
type alipayBizDataResp struct {
	Rsp struct {
		Data struct {
			HasMore bool `json:"hasMore"`
			Records []struct {
				Month int `json:"month"`
				Trans []struct {
					Amount    string `json:"amount"`
					BizType   string `json:"bizType"`
					StateDesc string `json:"stateDesc"`
					Time      string `json:"time"`
					Title     string `json:"title"`
					TransNo   string `json:"transNo"`
					BizTime   int64  `json:"bizTime"` // 毫秒
				} `json:"trans"`
			} `json:"records"`
		} `json:"data"`
	} `json:"rsp"`
	Stat string `json:"stat"`
	Code string `json:"code"`
	Msg  string `json:"msg"`
}

// alipayFetchBillsAPI 拉最新一页收款记录。
// bizToken/sid 失效时（NOT_LOGIN）自动回 chat.htm 换一套再试一次。
func alipayFetchBillsAPI(s *AlipaySession) ([]AlipayBill, error) {
	if s == nil || len(s.Cookies) == 0 {
		return nil, fmt.Errorf("没有 Cookie，需要先扫码登录")
	}
	bills, err := alipayFetchBillsAPIOnce(s)
	if err == nil {
		return bills, nil
	}
	if !strings.Contains(err.Error(), "NOT_LOGIN") && !strings.Contains(err.Error(), "未登陆") {
		return nil, err
	}
	// 换一套 token 再来
	userID, bizToken, sid, terr := alipayChatTokens(s)
	if terr != nil {
		return nil, terr
	}
	if userID != "" && s.PID == "" {
		s.PID, s.MaskedID = userID, maskPid(userID)
	}
	s.BizToken, s.SID = bizToken, sid
	return alipayFetchBillsAPIOnce(s)
}

func alipayFetchBillsAPIOnce(s *AlipaySession) ([]AlipayBill, error) {
	if s.BizToken == "" || s.SID == "" {
		userID, bizToken, sid, err := alipayChatTokens(s)
		if err != nil {
			return nil, err
		}
		if userID != "" && s.PID == "" {
			s.PID, s.MaskedID = userID, maskPid(userID)
		}
		s.BizToken, s.SID = bizToken, sid
	}

	u := fmt.Sprintf("%s?_=%d&bizToken=%s&pageNo=1&sid=%s&templateId=100",
		alipayBizDataURL, time.Now().UnixMilli(),
		url.QueryEscape(s.BizToken), url.QueryEscape(s.SID))
	body, code, err := alipayGet(s, u, alipayChatURL, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("拉收款记录失败：%w", err)
	}
	if code != 200 {
		return nil, fmt.Errorf("收款记录接口 HTTP %d", code)
	}

	aliBizRawMu.Lock()
	aliBizRawLast = body
	aliBizRawMu.Unlock()

	var out alipayBizDataResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("收款记录响应不是预期 JSON（%d 字节）: %v", len(body), err)
	}
	if out.Stat != "" && out.Stat != "success" && out.Stat != "ok" {
		// {"msg":"用户未登陆","stat":"fail","code":"NOT_LOGIN"}
		return nil, fmt.Errorf("%s %s", orDefault(out.Code, "FAIL"), orDefault(out.Msg, out.Stat))
	}

	var bills []AlipayBill
	for _, rec := range out.Rsp.Data.Records {
		for _, t := range rec.Trans {
			amt, err := strconv.ParseFloat(strings.TrimSpace(t.Amount), 64)
			if err != nil || amt <= 0 {
				continue
			}
			// 支出/退款不带正号，这里只认进账
			if t.StateDesc != "" && !strings.Contains(t.StateDesc, "成功") {
				continue
			}
			tm := ""
			if t.BizTime > 0 {
				tm = time.UnixMilli(t.BizTime).Format(alipayBillTimeLayout)
			}
			memo := strings.TrimSpace(t.Title)
			if memo == "" {
				memo = "支付宝收款"
			}
			bills = append(bills, AlipayBill{
				TradeNo: strings.TrimSpace(t.TransNo),
				Amount:  amt,
				Time:    tm,
				Memo:    memo,
			})
		}
	}
	return bills, nil
}

// alipayAccountStats 总览页用：支付宝账号总数与在线数。
// 在线 = 会话 confirmed 且手里有 cookie（登录态可用于拉收款记录）。
func alipayAccountStats() (total, online int) {
	aliMu.Lock()
	defer aliMu.Unlock()
	total = len(aliList)
	for i := range aliList {
		if aliList[i].Status == "confirmed" && len(aliList[i].Cookies) > 0 {
			online++
		}
	}
	return total, online
}

// alipayErrLoginGone 判断这个错误是不是「登录态没了」
func alipayErrLoginGone(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, m := range []string{"登录已失效", "NOT_LOGIN", "未登陆", "未登录"} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// alipaySSORefresh 登录态被踢回登录页时，先用完整 cookie 把单点登录链路走一遍。
//
// 浏览器能「一直不掉线」靠的就是这个：auth.alipay.com 上还有登录态时，
// 访问业务页会被 302 到 auth，再 302 回业务页，一路 Set-Cookie 换出新 session。
// 我们之前遇到"登录已失效"直接标 expired 停止轮询，等于把还能自己续上的会话扔了。
//
// 返回 true 表示链路走通（账号仍是登录态），false 表示真的需要重新扫码。
func alipaySSORefresh(s *AlipaySession) bool {
	if s == nil || len(s.Cookies) == 0 {
		return false
	}
	req, err := http.NewRequest("GET", "https://my.alipay.com/portal/i.htm", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Cookie", s.cookieHeader())
	req.Header.Set("User-Agent", alipayUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")

	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 6 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		logInfo("alipay", "账号 %s SSO 续期失败：HTTP %d 落点 %s",
			maskPid(s.PID), resp.StatusCode, firstN(finalURL, 80))
		return false
	}
	if strings.Contains(finalURL, "auth.alipay.com/login") || alipayLooksLikeLoginPage(body) {
		logInfo("alipay", "账号 %s SSO 续期失败：仍被带到登录页", maskPid(s.PID))
		return false
	}
	logInfo("alipay", "账号 %s 登录态仍然有效（my.alipay.com 可访问）", maskPid(s.PID))
	return true
}

// alipayLooksLikePortal 判断是不是 my.alipay.com 的门户页（不是账单页）
func alipayLooksLikePortal(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	if bytes.Contains(body, []byte("J-item")) || bytes.Contains(body, []byte("amount-pay")) {
		return false
	}
	return bytes.Contains(body, []byte("portal")) &&
		(bytes.Contains(body, []byte("我的支付宝")) || bytes.Contains(body, []byte("mng-index")))
}

// alipayReportMaxAgeMin 只上报这个时间窗口内的账单（分钟）。
// 用于挡住长时间停机后翻出来的老账单：只认「刚刚入账」的收款。
const alipayReportMaxAgeMin = 30

// alipaySeenMax 交易号去重表最多保留多少条（只留最近的，避免 json 无限膨胀）
const alipaySeenMax = 500

// alipayBillTimeLayout 账单时间格式，与 AlipayBill.Time 一致
const alipayBillTimeLayout = "2006-01-02 15:04:05"

// AlipayBill 解析出来的单笔收款
type AlipayBill struct {
	TradeNo string  // 支付宝交易号（source_key 用）
	Amount  float64 // 元
	Time    string  // 2006-01-02 15:04:05
	Memo    string  // 收钱码收款 / Kudi-转账
}

// alipayParseBills 从账单页面解析收款记录。
// 支付宝账单页是服务端渲染的 HTML，结构会变，所以这里做宽松匹配。
func alipayParseBills(body []byte) []AlipayBill {
	return parseAlipayBillHTML(string(body))
}

// ---------- 监控协程 ----------

// startAlipayMonitor 启动支付宝轮询。可重复调用。
func startAlipayMonitor() {
	aliMu.Lock()
	if aliRun {
		aliMu.Unlock()
		return
	}
	aliRun = true
	aliMu.Unlock()

	go func() {
		t := time.NewTicker(alipayPollEvery)
		defer t.Stop()
		for {
			select {
			case <-aliStop:
				return
			case <-t.C:
				alipayPollRound()
			}
		}
	}()
	logInfo("alipay", "支付宝轮询已启动，间隔 %s", alipayPollEvery)
}

func alipayPollRound() {
	// 采集和上报是两件事：模式不对只影响「发不发平台」，
	// 不能因此连账单都不拉 —— 否则用户切个模式就再也看不到收款记录。
	for _, s := range alipaySessionsCopy() {
		if s.Status != "confirmed" || s.PID == "" {
			continue
		}
		// 账号被手动停止时不再拉账单（会话保留，重新启动即可恢复）
		if acc, ok := findAccount(s.PID); ok && !acc.Enabled {
			continue
		}
		alipayPollOne(s)
	}
}

func alipayPollOne(s AlipaySession) {
	// 主力：手机端收款记录接口（不碰 PC 账单页，不会触发二次扫码）
	bills, err := alipayFetchBillsAPI(&s)
	// 被踢回登录页时先让 SSO 自己续一次：浏览器能一直不掉线就是靠这条链路，
	// 只有 auth 也认为没登录（真掉线）才让用户重新扫码。
	if err != nil && alipayErrLoginGone(err) {
		if alipaySSORefresh(&s) {
			s.BizToken, s.SID = "", "" // 换一套 token 再来
			bills, err = alipayFetchBillsAPI(&s)
		}
	}
	now := time.Now().Format("2006-01-02T15:04:05Z07:00")
	if err == nil {
		// 存一份最近一次的接口响应，方便校准解析器（内容没变就不写，5 秒一轮别刷盘）
		if raw := alipayLastBizRawCopy(); len(raw) > 0 && !aliRawUnchanged(raw) {
			_ = os.WriteFile(alipayRawFile(), raw, 0600)
		}
	}
	if err != nil {
		s.LastCheck = now
		var se *alipaySecurityErr
		if errors.As(err, &se) {
			// 首次拉账单需要再扫一次码验证身份，把二维码留给界面显示
			setPendingCheck(s.ID, se.Check)
			s.HeartbeatMsg = "需要安全验证：请用支付宝 App 扫码确认身份"
			logInfo("alipay", "账号 %s 需要安全验证", maskPid(s.PID))
		} else {
			logWarn("alipay", "账号 %s 拉账单失败：%v", maskPid(s.PID), err)
			s.HeartbeatMsg = err.Error()
			if alipayErrLoginGone(err) {
				s.Status = "expired"
			}
		}
		upsertAlipaySession(s)
		saveAlipaySessionsThrottled(true)
		return
	}
	// 拉取成功，清掉待验证状态
	setPendingCheck(s.ID, nil)

	seen := map[string]bool{}
	for _, t := range s.Reported {
		seen[t] = true
	}

	// 只认「新入账」：页面上的历史账单既不进收款记录也不上报。
	// 判据是账单基线（BillWatermark）+ 交易号去重 + 时效窗口，见 alipaySelectNew。
	nowT := time.Now()
	picked, freshSeen, wm, st := alipaySelectNew(bills, seen, s.BillWatermark, nowT,
		time.Duration(alipayReportMaxAgeMin)*time.Minute)
	for _, t := range freshSeen {
		s.Reported = append(s.Reported, t)
	}
	if len(s.Reported) > alipaySeenMax {
		s.Reported = s.Reported[len(s.Reported)-alipaySeenMax:]
	}
	if wm != "" {
		s.BillWatermark = wm
	}

	// 写前落盘：先把「这些交易号见过了 / 基线推进到哪」持久化，再去上报。
	// 否则上报成功后进程崩溃或被杀，重启时这两项还停在旧值，
	// 同一笔收款会被再报一次——平台可能把它匹配到另一张待付单，造成重复确认。
	upsertAlipaySession(s)
	saveAlipaySessionsThrottled(true)

	// 老 → 新逐笔上报，收款记录按时间倒序展示时顺序才对
	reported, failed := 0, 0
	for i := len(picked) - 1; i >= 0; i-- {
		b := picked[i]
		res, m := alipayReportBill(s, b)
		ok := res.Delivered && res.OK
		if res.Delivered && !res.OK && strings.TrimSpace(res.Err) == "" {
			res.Err = fmt.Sprintf("HTTP %d: %s", res.Code, truncate(res.Body, 120))
		}
		// 每笔新入账都落一条收款记录（成功/失败都记），界面上能看到并支持对账
		if eng != nil {
			eng.addHistoryEx(m, ok, res.Err, &res, "支付宝", alipayChannelCode(s.PID))
		}
		markAccountMessage(m.To, m.Content)
		markAccountReport(m.To, ok, res.Err)
		if !ok && reportRetryable(res) {
			enqueueReportRetry(m, res, "alipay")
		}
		switch {
		case ok:
			reported++
			logInfo("alipay", "支付宝订单已上报: %s ¥%.2f", b.TradeNo, b.Amount)
		case res.Delivered:
			failed++
			logWarn("alipay", "支付宝订单上报失败 %s：%s", b.TradeNo, res.Err)
		}
	}

	s.LastCheck = now
	s.LastHeartbeat = now
	switch {
	case st.FirstBaseline > 0:
		s.HeartbeatMsg = fmt.Sprintf("正常，解析到 %d 笔（首次接入只登记基线，不回补历史账单）", st.Total)
		logInfo("alipay", "账号 %s 首次接入：账单基线 %s，跳过 %d 笔历史账单",
			maskPid(s.PID), s.BillWatermark, st.FirstBaseline)
	case st.Picked > 0:
		msg := fmt.Sprintf("正常，解析到 %d 笔，新入账 %d 笔（成功 %d / 失败 %d）",
			st.Total, st.Picked, reported, failed)
		if st.OlderThanWatermark+st.TooOld > 0 {
			msg += fmt.Sprintf("，忽略旧账单 %d 笔", st.OlderThanWatermark+st.TooOld)
		}
		s.HeartbeatMsg = msg
		logInfo("alipay", "账号 %s 新入账 %d 笔（成功 %d / 失败 %d）",
			maskPid(s.PID), st.Picked, reported, failed)
	case st.Total == 0:
		s.HeartbeatMsg = "正常，账单页没有解析到记录"
	default:
		s.HeartbeatMsg = fmt.Sprintf("正常，解析到 %d 笔，无新入账", st.Total)
		if st.OlderThanWatermark+st.TooOld > 0 {
			s.HeartbeatMsg += fmt.Sprintf("（%d 笔旧账单已忽略）", st.OlderThanWatermark+st.TooOld)
		}
	}
	// 上报按当前接口模式分发（xpay / v1 / yjk），这里不再区分平台
	upsertAlipaySession(s)
	saveAlipaySessionsThrottled(st.Picked > 0)
}

// alipaySelectStat 一轮账单筛选的统计，用于日志与心跳文案
type alipaySelectStat struct {
	Total              int // 页面上解析到的总条数
	AlreadyKnown       int // 交易号已处理过
	FirstBaseline      int // 首次接入，只登记基线
	OlderThanWatermark int // 比基线还老（历史账单）
	TooOld             int // 比时效窗口更老（例如长时间停机后翻出来的）
	Picked             int // 真正要计入收款记录并上报的
}

// alipaySelectNew 从账单里挑出「新入账」。
//
// 规则（顺序不能变）：
//  1. 交易号为空 / 已处理过 → 跳过；
//  2. 还没有基线（首次接入）→ 一律不处理，只把基线建立起来。页面上那些都是历史账单，
//     平台的订单早就结束了，回补只会撞 409，也不是用户要的「新入账」；
//  3. 不晚于基线 → 旧账单，跳过；
//  4. 早于 now-maxAge → 停机期间的老账单，跳过；
//  5. 其余才算新入账。
//
// 返回：待处理账单、本轮新见到的交易号、推进后的基线、统计。
// 基线只前进不后退；页面上一笔时间都解析不出来时保持原基线不变。
func alipaySelectNew(bills []AlipayBill, seen map[string]bool, watermark string,
	now time.Time, maxAge time.Duration) (picked []AlipayBill, freshSeen []string,
	newWatermark string, st alipaySelectStat) {

	st.Total = len(bills)
	wm, wmOK := parseAlipayBillTime(watermark)
	firstRun := !wmOK

	// 页面最新一笔时间：用来推进基线（不管是不是新入账，看到就说明到这儿了）
	var newest time.Time
	for _, b := range bills {
		bt, ok := parseAlipayBillTime(b.Time)
		if !ok {
			continue
		}
		if bt.After(newest) {
			newest = bt
		}
	}
	if newest.After(now) {
		newest = now // 防止页面时间超前把基线顶到未来
	}

	freshSeen = make([]string, 0, len(bills))
	for _, b := range bills {
		if b.TradeNo == "" {
			continue
		}
		if seen[b.TradeNo] {
			st.AlreadyKnown++
			continue
		}
		freshSeen = append(freshSeen, b.TradeNo)

		bt, ok := parseAlipayBillTime(b.Time)
		if !ok {
			// 时间缺失时不能直接丢单：按当前时间处理，
			// 最坏情况是平台判定重复（记录里显示回调失败），比漏收款好。
			bt = now
		}
		switch {
		case firstRun:
			st.FirstBaseline++
		case !bt.After(wm):
			st.OlderThanWatermark++
		case now.Sub(bt) > maxAge:
			st.TooOld++
		default:
			picked = append(picked, b)
			st.Picked++
		}
	}

	newWatermark = watermark
	if !newest.IsZero() && (firstRun || newest.After(wm)) {
		newWatermark = newest.Format(alipayBillTimeLayout)
	}
	return
}

// parseAlipayBillTime 解析账单时间；空串或格式不对返回 false
func parseAlipayBillTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation(alipayBillTimeLayout, s, time.Local)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// alipaySessionOnline 这个支付宝账号的登录态是否还能拉账单。
// 心跳要按它决定是否继续上报在线：登录失效后拉不到新入账，
// 通道就不该在平台上显示在线，否则平台会把单派给一个收不到通知的通道。
func alipaySessionOnline(pid string) bool {
	if strings.TrimSpace(pid) == "" {
		return false
	}
	aliMu.Lock()
	defer aliMu.Unlock()
	for i := range aliList {
		if aliList[i].PID == pid {
			return aliList[i].Status == "confirmed" && len(aliList[i].Cookies) > 0
		}
	}
	return false
}

// alipayChannelCode 收款记录里显示的通道编码；优先用账号绑定，否则按类型推断
func alipayChannelCode(pid string) string {
	if a, ok := findAccount(pid); ok {
		if c := strings.TrimSpace(a.ChannelCode); c != "" {
			return c
		}
	}
	return inferChannelCode(pid)
}

// alipayReportBill 把一笔支付宝收款上报到 X-Ypay。
// 返回上报结果和用来落收款记录的 ChatMsg（调用方负责写记录）。
func alipayReportBill(s AlipaySession, b AlipayBill) (ReportResult, *ChatMsg) {
	m := &ChatMsg{
		From:   "支付宝",
		To:     s.PID,
		Amount: b.Amount,
		MsgID:  hashToUint64(b.TradeNo),
	}
	if b.TradeNo != "" {
		m.StableID = fmt.Sprintf("alipay:%016x", m.MsgID)
	}
	if t, ok := parseAlipayBillTime(b.Time); ok {
		m.Time = uint64(t.Unix())
	} else {
		m.Time = uint64(time.Now().Unix())
	}
	m.Content = b.Memo
	m.RawText = b.Memo
	if b.TradeNo != "" {
		m.RawText = b.Memo + "\n交易号 " + b.TradeNo
	}
	// 和微信一样按当前接口模式分发（xpay / v1 / yjk），不做区别对待。
	return Report(m), m
}

func hashToUint64(s string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// ---------- 供界面用的只读视图 ----------

// alipayView 给前端的安全视图（不含 cookie 值）
func alipayView(s AlipaySession) map[string]any {
	// 需要安全验证时把二维码带给界面
	secPending := false
	secQR := ""
	if chk := getPendingCheck(s.ID); chk != nil {
		secPending = true
		secQR = chk.QRURL
	}

	return map[string]any{
		"id":                s.ID,
		"pid":               s.PID,
		"masked_id":         s.MaskedID,
		"nick":              s.Nick,
		"status":            s.Status,
		"channel_id":        s.ChannelFor(GetConfig().Mode),
		"created_at":        s.CreatedAt,
		"online_since":      s.OnlineSince,
		"last_check":        s.LastCheck,
		"last_heartbeat":    s.LastHeartbeat,
		"heartbeat_message": s.HeartbeatMsg,
		"has_cookies":       len(s.Cookies) > 0,
		"cookie_count":      len(s.Cookies),
		"reported_count":    len(s.Reported),
		"bill_watermark":    s.BillWatermark,
		"security_pending":  secPending, "security_qr": secQR,
		"qr_status": getQRState(s.ID).Status,
	}
}

func alipayViews() []map[string]any {
	list := alipaySessionsCopy()
	out := make([]map[string]any, 0, len(list))
	for _, s := range list {
		out = append(out, alipayView(s))
	}
	sort.Slice(out, func(i, j int) bool {
		return fmt.Sprint(out[i]["created_at"]) < fmt.Sprint(out[j]["created_at"])
	})
	return out
}

// ---------- 登录（用内嵌浏览器拿 Cookie） ----------

// alipayLoginURL 返回供内嵌浏览器打开的登录地址
func alipayLoginURL() string {
	u := "https://auth.alipay.com/login/index.htm"
	return u
}

// alipayApplyCookies 把从浏览器拿到的 Cookie 写进会话
func alipayApplyCookies(sessionID string, cookies []AlipayCookie) error {
	s, ok := findAlipaySession(sessionID)
	if !ok {
		return fmt.Errorf("会话不存在")
	}
	s.Cookies = cookies
	s.Status = "confirmed"
	s.OnlineSince = time.Now().Format("2006-01-02T15:04:05Z07:00")
	upsertAlipaySession(s)
	return saveAlipaySessions()
}

// ---------- 账单首次访问的安全校验 ----------
//
// 新登录的支付宝账号第一次访问 consumeprod 账单页时，会被 302 到
//   https://consumeprod.alipay.com/record/checkSecurity.htm?securityId=web|consumeprod_record_list|...GZ00
// 这个页面要求再用手机支付宝扫一次码验证身份（支付宝的风控，绕不过）。
// 页面里内嵌了验证二维码：
//   new alipay.security.riskQRCode({
//     url: "https://securitycore.alipay.com/barcode/barcodeProcessStatus.json",
//     sid: 'web|consumeprod_record_list|...GZ00',
//     text: 'https://qr.alipay.com/_d?_b=PAI_UNSIGN&securityId=web%257Cconsumeprod_record_list%257C...GZ00'
//   })
// 扫码通过后，把 securityId POST 回 standard.htm 才能看到账单。

var (
	reSecCheckSID  = regexp.MustCompile(`sid:\s*'([^']{20,120})'`)
	reSecCheckText = regexp.MustCompile(`text:\s*'([^']{20,300})'`)
)

// alipaySecurityCheck 表示账单页要求二次验证
type alipaySecurityCheck struct {
	SecurityID string
	QRURL      string
}

// alipayDetectSecurityCheck 判断响应是不是安全校验页；是则返回二维码信息
func alipayDetectSecurityCheck(body []byte) *alipaySecurityCheck {
	if !bytes.Contains(body, []byte("checkSecurity")) && !bytes.Contains(body, []byte("securityForm")) {
		return nil
	}
	txt := string(alipayToUTF8(body))

	// 优先从 securityForm 的 hidden input 里取 securityId
	sid := ""
	if m := reHiddenInput.FindAllString(txt, -1); len(m) > 0 {
		for _, tag := range m {
			if strings.Contains(tag, `name="securityId"`) {
				if v := reAttrValue.FindStringSubmatch(tag); len(v) > 1 {
					sid = html.UnescapeString(v[1])
					break
				}
			}
		}
	}
	if sid == "" {
		if v := reSecCheckSID.FindStringSubmatch(txt); len(v) > 1 {
			sid = v[1]
		}
	}
	if sid == "" {
		return nil
	}

	qr := ""
	if v := reSecCheckText.FindStringSubmatch(txt); len(v) > 1 {
		qr = html.UnescapeString(v[1])
	}
	if qr == "" {
		qr = "https://qr.alipay.com/_d?_b=PAI_UNSIGN&securityId=" +
			url.QueryEscape(url.QueryEscape(sid))
	}
	return &alipaySecurityCheck{SecurityID: sid, QRURL: qr}
}

// ChannelFor 按平台取通道 ID，未设置时回落到通用字段
func (s AlipaySession) ChannelFor(mode string) string {
	switch mode {
	case "v1":
		if x := strings.TrimSpace(s.ChannelIDV1); x != "" {
			return x
		}
	case "xpay":
		if x := strings.TrimSpace(s.ChannelIDXpay); x != "" {
			return x
		}
	}
	return strings.TrimSpace(s.ChannelID)
}

// SetChannelFor 按平台写入通道 ID，并同步旧字段
func (s *AlipaySession) SetChannelFor(mode, id string) {
	id = strings.TrimSpace(id)
	s.ChannelID = id
	switch mode {
	case "v1":
		s.ChannelIDV1 = id
	case "xpay":
		s.ChannelIDXpay = id
	}
}
