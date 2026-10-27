package main

// 用 Edge/Chromium 的 DevTools Protocol 完成支付宝扫码登录。
//
// 为什么必须借浏览器：支付宝登录页挂了 um.js(设备指纹)、rds(风险决策)、
// monitor-sens(行为监控)、security-sdk 四层风控，纯 HTTP 复现会被拦，
// 且 ALIPAYJSESSIONID 是 HttpOnly，document.cookie 也取不到。
//
// 流程：
//   1. 起一个独立的 Edge 进程，指定临时 profile，打开支付宝登录页
//   2. 用户在里面用支付宝 App 扫码
//   3. 通过 CDP Storage.getCookies 把 domain 含 alipay.com 的 Cookie 全取出来
//   4. 写入 AlipaySession，关掉浏览器

import (
	"net"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const cdpStartWait = 25 * time.Second

// freePort 找一个空闲端口给调试端口用。
// 固定端口会和上一次没退干净的浏览器/其它程序撞上。
func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 9333
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// findBrowser 找一个可用的 Chromium 内核浏览器
func findBrowser() string {
	cands := []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	}
	for _, p := range cands {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// 兜底：PATH 里找
	for _, name := range []string{"msedge.exe", "chrome.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// cdpBrowserWS 取浏览器级 WebSocket 地址。
// Storage.getCookies / Browser.getVersion 这类 Browser 域的方法
// 必须连浏览器端点，连页面端点会失败（表现就是「cookie 一直是 0 条」）。
func cdpBrowserWS(port int) (string, error) {
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/json/version", port))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var v struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", err
	}
	if v.WebSocketDebuggerURL == "" {
		return "", fmt.Errorf("浏览器端点没有 webSocketDebuggerUrl")
	}
	return v.WebSocketDebuggerURL, nil
}

// cdpTarget /json 返回的一个页面目标
type cdpTarget struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	Title                string `json:"title"`
	URL                  string `json:"url"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

// cdpListTargets 拉目标列表
func cdpListTargets(port int) ([]cdpTarget, error) {
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/json", port))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var list []cdpTarget
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	return list, nil
}

// cdpResult CDP 调用的返回
type cdpResult struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// cdpCall 在一条已连接的 ws 上执行一个 CDP 命令
func cdpCall(ws *wsConn, id int, method string, params any) (json.RawMessage, error) {
	msg := map[string]any{"id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	b, _ := json.Marshal(msg)
	if err := ws.WriteText(string(b)); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		txt, err := ws.ReadMessage(15 * time.Second)
		if err != nil {
			return nil, err
		}
		var r cdpResult
		if json.Unmarshal([]byte(txt), &r) != nil {
			continue
		}
		// 跳过事件（没有 id 的推送）
		if r.ID != id {
			continue
		}
		if r.Error != nil {
			return nil, fmt.Errorf("CDP %s: %s", method, r.Error.Message)
		}
		return r.Result, nil
	}
	return nil, fmt.Errorf("CDP %s 超时", method)
}

// cdpCookie CDP 返回的 cookie 结构
type cdpCookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	HTTPOnly bool    `json:"httpOnly"`
	Secure   bool    `json:"secure"`
	Expires  float64 `json:"expires"`
}

// browserLogin 打开浏览器让用户扫码，返回拿到的支付宝 Cookie。
//
// 返回后浏览器已被关闭。用户没登录（扫码超时）就返回空列表 + nil error，
// 由调用方决定怎么提示。
func browserLogin(loginURL string, wait time.Duration) ([]AlipayCookie, string, error) {
	exe := findBrowser()
	if exe == "" {
		return nil, "", fmt.Errorf("没找到 Edge 或 Chrome，无法完成扫码登录")
	}

	// 独立 profile，避免污染用户的浏览器
	profile, err := os.MkdirTemp("", "easymonitor-alipay-*")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(profile)

	port := freePort()
	cmd := exec.Command(exe,
		fmt.Sprintf("--remote-debugging-port=%d", port),
		"--remote-allow-origins=*",
		"--user-data-dir="+profile,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-features=Translate",
		"--window-size=520,760",
		loginURL,
	)
	if err := cmd.Start(); err != nil {
		return nil, "", fmt.Errorf("启动浏览器失败：%w", err)
	}
	// 浏览器随时可能被用户关掉，用 Wait 在后台盯着。
	// 收尸统一放在 defer，这里只负责通知。
	exited := make(chan struct{})
	go func() {
		cmd.Wait()
		close(exited)
	}()
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()

	// 等 CDP 端口起来
	deadline := time.Now().Add(cdpStartWait)
	var target *cdpTarget
	for time.Now().Before(deadline) {
		time.Sleep(700 * time.Millisecond)
		list, err := cdpListTargets(port)
		if err != nil {
			continue
		}
		for i := range list {
			if list[i].Type == "page" && list[i].WebSocketDebuggerURL != "" {
				target = &list[i]
				break
			}
		}
		if target != nil {
			break
		}
	}
	if target == nil {
		return nil, "", fmt.Errorf("浏览器调试端口没起来")
	}

	ws, err := wsDial(target.WebSocketDebuggerURL, 10*time.Second)
	if err != nil {
		return nil, "", fmt.Errorf("连接浏览器失败：%w", err)
	}
	defer ws.Close()

	// 浏览器级连接：取整份 cookie 和真实 UA 都走这里
	bwsURL, err := cdpBrowserWS(port)
	if err != nil {
		logWarn("alipay", "连浏览器端点失败（取 cookie 会不准）：%v", err)
	}
	var bws *wsConn
	if bwsURL != "" {
		if c, err := wsDial(bwsURL, 10*time.Second); err == nil {
			bws = c
			defer bws.Close()
		} else {
			logWarn("alipay", "连浏览器端点失败：%v", err)
		}
	}
	cookieWS := ws
	if bws != nil {
		cookieWS = bws
	}

	// 用浏览器真实的 UA 存取后续请求：支付宝会把 UA 和登录态绑在一起，
	// 拿 Chrome/120 的固定 UA 去打 Edge 登录出来的会话，是会被风控的。
	ua := ""
	if bws != nil {
		if raw, err := cdpCall(bws, 99, "Browser.getVersion", nil); err == nil {
			var v struct {
				UserAgent string `json:"userAgent"`
			}
			if json.Unmarshal(raw, &v) == nil {
				ua = strings.TrimSpace(v.UserAgent)
			}
		}
	}
	if ua != "" {
		logInfo("alipay", "登录浏览器 UA: %s", firstN(ua, 90))
	}

	// 轮询：每 2 秒取一次 cookie。两个退出条件：
	//   1. 用 cookie 能访问需要登录的页面 → 成功
	//   2. 用户自己把浏览器关了 → 立刻返回，别傻等到超时
	loginDeadline := time.Now().Add(wait)
	lastCookies := 0
	cookieErrs := 0
	for time.Now().Before(loginDeadline) {
		time.Sleep(2 * time.Second)

		// 浏览器被用户关掉就收工
		select {
		case <-exited:
			return nil, "", fmt.Errorf("登录窗口已关闭")
		default:
		}
		cookies, err := collectAlipayCookies(cookieWS)
		if err != nil {
			cookieErrs++
			logDebug("alipay", "取 cookie 失败：%v", err)
			continue
		}
		lastCookies = len(cookies)
		if len(cookies) == 0 {
			continue
		}
		// 关键：ALIPAYJSESSIONID 只要打开登录页就会下发，不能当登录成功的标志。
		// 必须用这组 Cookie 实际请求一次需要登录的页面，看会不会被踢回登录页。
		if alipayCookiesWork(cookies) {
			// 登录成功后支付宝会补发一批 Cookie，再取一次拿全
			time.Sleep(1500 * time.Millisecond)
			if again, err := collectAlipayCookies(cookieWS); err == nil && len(again) > len(cookies) {
				cookies = again
			}
			return cookies, ua, nil
		}
	}
	// 把诊断信息带上：cookie 一条都没拿到，说明连的不是浏览器端点或者页面没起来
	return nil, ua, fmt.Errorf("扫码超时（%s 内没检测到登录；最后拿到 %d 条 cookie，取 cookie 失败 %d 次，UA=%q）",
		wait, lastCookies, cookieErrs, firstN(ua, 60))
}

// collectAlipayCookies 取当前浏览器里所有 alipay.com 的 cookie
func collectAlipayCookies(ws *wsConn) ([]AlipayCookie, error) {
	// Storage.getCookies 不传 browserContextId 就是默认上下文
	raw, err := cdpCall(ws, 1, "Storage.getCookies", map[string]any{})
	if err != nil {
		return nil, err
	}
	var payload struct {
		Cookies []cdpCookie `json:"cookies"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}

	out := make([]AlipayCookie, 0, len(payload.Cookies))
	seen := map[string]bool{}
	for _, c := range payload.Cookies {
		if !strings.Contains(c.Domain, "alipay.com") {
			continue
		}
		key := c.Name + "@" + c.Domain + c.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, AlipayCookie{
			Name: c.Name, Value: c.Value,
			Domain: c.Domain, Path: c.Path,
			HTTPOnly: c.HTTPOnly, Secure: c.Secure,
		})
	}
	return out, nil
}

// alipayCookiesWork 用这组 Cookie 请求「我的支付宝」，判断是不是真的登录了。
// 未登录会被 302 到 auth.alipay.com/login。
func alipayCookiesWork(list []AlipayCookie) bool {
	parts := make([]string, 0, len(list))
	for _, c := range list {
		if c.Name != "" && c.Value != "" {
			parts = append(parts, c.Name+"="+c.Value)
		}
	}
	if len(parts) == 0 {
		return false
	}
	req, err := http.NewRequest("GET", "https://my.alipay.com/portal/i.htm", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Cookie", strings.Join(parts, "; "))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不要跟随，靠 Location 判断
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		logDebug("alipay", "登录检测：请求失败 %v", err)
		return false
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	logDebug("alipay", "登录检测：HTTP %d Location=%s cookie数=%d",
		resp.StatusCode, firstN(loc, 80), len(list))
	if resp.StatusCode == 200 {
		// 200 还不够：支付宝有时把登录页以 200 返回，要看内容
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		txt := string(body)
		if strings.Contains(txt, "请登录") || strings.Contains(txt, "扫码登录") ||
			strings.Contains(txt, "login") || strings.Contains(txt, "密码登录") {
			logDebug("alipay", "登录检测：200 但内容像登录页，判定未登录")
			return false
		}
		return true
	}
	if loc == "" {
		return false
	}
	return !strings.Contains(loc, "auth.alipay.com") && !strings.Contains(loc, "login")
}

func hasCookie(list []AlipayCookie, name string) bool {
	for _, c := range list {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}

// alipayPIDFromCookies 先从 cookie 里找 PID（部分版本会下发 alipay_pid）
func alipayPIDFromCookies(list []AlipayCookie) string {
	for _, c := range list {
		n := strings.ToUpper(c.Name)
		// CLUB_ALIPAY_COM 是扫码登录成功后支付宝直接下发的账号 ID
		if strings.Contains(n, "CLUB_ALIPAY") {
			v := strings.TrimSpace(c.Value)
			if len(v) >= 16 && strings.HasPrefix(v, "2088") {
				return v
			}
		}
		if strings.Contains(n, "PID") || strings.Contains(n, "USERID") || strings.Contains(n, "USER_ID") {
			v := strings.TrimSpace(c.Value)
			if len(v) >= 16 && strings.HasPrefix(v, "2088") {
				return v
			}
		}
		// ali_apache_tracktmp=uid=2088123456789012
		if strings.Contains(n, "ALI_APACHE_TRACK") || strings.Contains(strings.ToLower(c.Value), "uid=") {
			if m := regexp.MustCompile(`uid=(2088[0-9]{12})`).FindStringSubmatch(c.Value); len(m) > 1 {
				return m[1]
			}
		}
	}
	return ""
}

// alipayFetchPID 用登录后的 Cookie 请求「我的支付宝」，从页面里挖 PID。
// PID 形如 2088123456789012（16 位，2088 开头）。
func alipayFetchPID(list []AlipayCookie) string {
	parts := make([]string, 0, len(list))
	for _, c := range list {
		if c.Name != "" && c.Value != "" {
			parts = append(parts, c.Name+"="+c.Value)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	cookie := strings.Join(parts, "; ")
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	for _, u := range []string{
		"https://my.alipay.com/portal/i.htm",
		"https://consumeprod.alipay.com/record/standard.htm",
	} {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Cookie", cookie)
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Referer", "https://auth.alipay.com/login/index.htm")
		client := &http.Client{Timeout: 12 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if pid := pickPID(string(body)); pid != "" {
			return pid
		}
	}
	return ""
}

var reAlipayPID = []*regexp.Regexp{
	regexp.MustCompile(`\b(2088[0-9]{12})\b`),
	regexp.MustCompile(`(?i)(?:userId|user_id|pid|alipayPid)["\']?\s*[:=]\s*["\']?(2088[0-9]{12})`),
}

func pickPID(s string) string {
	for _, re := range reAlipayPID {
		if m := re.FindStringSubmatch(s); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

// alipayProfileDir 备用：把登录用的 profile 放到 exe 旁边便于排查
func alipayProfileDir() string {
	exe, err := os.Executable()
	dir := "."
	if err == nil {
		dir = filepath.Dir(exe)
	}
	return filepath.Join(dir, "alipay-profile")
}
