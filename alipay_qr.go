package main

// 支付宝扫码登录：在软件界面里直接显示二维码。
//
// 协议（实测抓包，登录页 HTML 里就内嵌了这些配置）：
//
//   GET https://auth.alipay.com/login/index.htm
//     → 下发 ALIPAYJSESSIONID / ctoken / umt / zone / spanner 等 cookie
//     → 页面里带 securityId = "web|authcenter_qrcode_login|<uuid>RZ44"
//     → 页面里带 barcode = "https://qr.alipay.com/_d?_b=PAI_LOGIN_DY&securityId=<双重编码>"
//
//   二维码内容 = barcode（用户用支付宝 App 扫的就是这个 URL）
//
//   轮询扫码状态：
//   GET https://securitycore.alipay.com/barcode/barcodeProcessStatus.json
//       ?securityId=<单次URL编码的 securityId>
//       &_callback=light.request._callbacks.callback1
//   Referer: https://auth.alipay.com/
//     → callback1({"barcodeStatus":"waiting","stat":"ok"})
//
//   barcodeStatus 取值（与登录页 CSS 里的状态类一一对应）：
//     waiting    等待扫码
//     scanned    已扫码，等手机上确认
//     confirmed  已确认，登录成功
//     timeout    二维码失效，要刷新
//     error      出错
//
// 关键点：二维码绑定的是**这一个 HTTP 会话**（那组 cookie）。
// 所以扫码确认后，用同一组 cookie 请求 my.alipay.com 就不再被踢回登录页，
// 不需要额外的换票步骤。

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

const (
	alipayLoginPage   = "https://auth.alipay.com/login/index.htm"
	alipayBarcodeAPI  = "https://securitycore.alipay.com/barcode/barcodeProcessStatus.json"
	alipayBarcodeCB   = "light.request._callbacks.callback1"
	alipayQRPollEvery = 2 * time.Second
	alipayQRExpire    = 5 * time.Minute // 二维码有效期，超时让前端刷新
)

var (
	// 登录页里这几个是隐藏 input，字段名和属性顺序各不相同，按实际 HTML 写：
	//   <input type="hidden" value="..." name="rds_form_token"/>          ← value 在前
	//   <input type="hidden" id="alieditUid" name="alieditUid" value="..."/>  ← 驼峰
	//   <input type="hidden" name="passwordSecurityId" value="..."/>      ← 驼峰
	reRdsToken    = regexp.MustCompile(`value="([^"]{8,80})"\s+name="rds_form_token"`)
	reAlieditUID  = regexp.MustCompile(`id="alieditUid"[^>]*?value="([^"]{8,80})"`)
	rePasswordSID = regexp.MustCompile(`name="passwordSecurityId"\s+value="([^"]{8,140})"`)
	reSecurityID  = regexp.MustCompile(`securityId["']?\s*:\s*["']([^"']{10,160})["']`)
	reBarcode     = regexp.MustCompile(`barcode["']?\s*:\s*["']([^"']{10,400})["']`)
)

// qrLogin 一次扫码登录的运行时状态（不落盘）
type qrLogin struct {
	SessionID  string
	Client     *http.Client // 旧方案用（纯 HTTP），现在主要走浏览器
	WS         *wsConn      // 浏览器 CDP 连接
	SecurityID string
	QRURL      string
	RdsToken   string
	AlieditUID string
	PageInfo   *loginPageInfo
	Status     string // waiting / scanned / confirmed / timeout / error
	Message    string
	StartedAt  time.Time
	Stop       chan struct{}
	Exited     chan struct{}
	Profile    string
	Port       int // >0 表示这次二维码来自无头浏览器（软件内显示，不弹窗口）
	Kill       func()
}

var (
	qrMu    sync.Mutex
	qrStore = map[string]*qrLogin{}
)

// alipayNewQR 新建扫码会话：纯 HTTP 拉登录页，取出 securityId 和二维码内容。
//
// 参考程序（PC三网监控重构版）就是这么做的，没有任何浏览器窗口。
// 除了 securityId，登录页里还带了 rds_form_token / aliedit_uid /
// password_security_id 这几项，扫码确认后要用它们再走一次登录页，
// 服务器才会把真正的登录 Cookie 下发到这个会话。
func alipayNewQR(sessionID string) (*qrLogin, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	page, err := alipayFetchLoginPage(client)
	if err != nil {
		return nil, err
	}

	qr := &qrLogin{
		SessionID:  sessionID,
		Client:     client,
		SecurityID: page.SecurityID,
		QRURL:      page.QRURL,
		RdsToken:   page.RdsToken,
		AlieditUID: page.AlieditUID,
		PageInfo:   page,
		Status:     "waiting",
		StartedAt:  time.Now(),
		Stop:       make(chan struct{}),
	}

	qrMu.Lock()
	if old := qrStore[sessionID]; old != nil {
		close(old.Stop)
	}
	qrStore[sessionID] = qr
	qrMu.Unlock()

	if s, ok := findAlipaySession(sessionID); ok {
		s.Status = "waiting"
		s.QRURL = qr.QRURL
		s.SecurityID = qr.SecurityID
		s.RdsToken = qr.RdsToken
		s.HeartbeatMsg = "等待扫码"
		upsertAlipaySession(s)
		saveAlipaySessions()
	}

	go qrPollLoop(qr)
	return qr, nil
}

// ---------- 无头浏览器扫码（软件内显示二维码，不弹窗口） ----------
//
// 和参考程序（Wails + WebView2）观感一致：二维码画在软件里。
// 但 cookie 仍然由真浏览器产出（整份、按域），不是手搓 HTTP 登录 ——
// 这两点是之前的坑：弹外部窗口用户不接受，纯 HTTP 登录 cookie 不全。

var reQRURLInHTML = regexp.MustCompile("https://qr\\.alipay\\.com/_d\\?[^\"'<>\\s]+")

// alipayStartBrowserQR 起一个无头浏览器，把它的登录二维码交给界面显示。
// 返回的 qrLogin 已经登记到 qrStore，界面用 /api/alipay/qr/image?id= 取图。
func alipayStartBrowserQR(sess AlipaySession) (*qrLogin, error) {
	exe := findBrowser()
	if exe == "" {
		return nil, fmt.Errorf("没找到 Edge 或 Chrome")
	}
	profile, err := os.MkdirTemp("", "easymonitor-qr-*")
	if err != nil {
		return nil, err
	}

	port := freePort()
	cmd := exec.Command(exe,
		"--headless=new",
		fmt.Sprintf("--remote-debugging-port=%d", port),
		"--remote-allow-origins=*",
		"--user-data-dir="+profile,
		"--no-first-run",
		"--no-default-browser-check",
		"--window-size=520,760",
		// 无头 UA 带 HeadlessChrome，支付宝风控会区别对待，换成普通 UA
		"--user-agent="+alipayUA,
		alipayLoginPage,
	)
	if err := cmd.Start(); err != nil {
		os.RemoveAll(profile)
		return nil, fmt.Errorf("启动无头浏览器失败：%w", err)
	}

	q := &qrLogin{
		SessionID: sess.ID,
		Status:    "waiting",
		Message:   "等待扫码",
		StartedAt: time.Now(),
		Stop:      make(chan struct{}),
		Profile:   profile,
		Port:      port,
		Kill: func() {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			os.RemoveAll(profile)
		},
	}

	// 等页面起来并拿到二维码 URL
	qrURL, err := alipayWaitBrowserQR(port, 25*time.Second)
	if err != nil {
		q.Kill()
		return nil, err
	}
	q.QRURL = qrURL

	qrMu.Lock()
	if old := qrStore[sess.ID]; old != nil {
		if old.Kill != nil {
			old.Kill()
		}
		close(old.Stop)
	}
	qrStore[sess.ID] = q
	qrMu.Unlock()

	if s2, ok := findAlipaySession(sess.ID); ok {
		s2.Status = "waiting"
		s2.QRURL = qrURL
		s2.HeartbeatMsg = "等待扫码"
		upsertAlipaySession(s2)
		saveAlipaySessions()
	}

	go qrBrowserLoop(q, port)

	logInfo("alipay", "无头浏览器已就绪，二维码 %s", firstN(qrURL, 70))
	return q, nil
}

// alipayWaitBrowserQR 等浏览器起来，从登录页 HTML 里抠出二维码内容
func alipayWaitBrowserQR(port int, wait time.Duration) (string, error) {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		list, err := cdpListTargets(port)
		if err == nil {
			for i := range list {
				if list[i].Type != "page" || !strings.Contains(list[i].URL, "alipay.com") {
					continue
				}
				pws, err := wsDial(list[i].WebSocketDebuggerURL, 8*time.Second)
				if err != nil {
					continue
				}
				raw, err := cdpCall(pws, 21, "Runtime.evaluate", map[string]any{
					"expression":    "document.documentElement.outerHTML",
					"returnByValue": true,
				})
				pws.Close()
				if err != nil {
					continue
				}
				var out struct {
					Result struct {
						Value string `json:"value"`
					} `json:"result"`
				}
				if json.Unmarshal(raw, &out) != nil {
					continue
				}
				if m := reQRURLInHTML.FindString(html.UnescapeString(out.Result.Value)); m != "" {
					return m, nil
				}
			}
		}
		time.Sleep(600 * time.Millisecond)
	}
	return "", fmt.Errorf("登录页没生成二维码（超时）")
}

// qrBrowserLoop 盯着无头浏览器的 cookie，扫码确认后收尾并关掉浏览器
func qrBrowserLoop(q *qrLogin, port int) {
	defer func() {
		if q.Kill != nil {
			q.Kill()
		}
	}()

	bwsURL, err := cdpBrowserWS(port)
	if err != nil {
		qrSetState(q, "error", "连不上登录窗口")
		return
	}
	bws, err := wsDial(bwsURL, 10*time.Second)
	if err != nil {
		qrSetState(q, "error", "连不上登录窗口")
		return
	}
	defer bws.Close()

	t := time.NewTicker(alipayQRPollEvery)
	defer t.Stop()
	for {
		select {
		case <-q.Stop:
			return
		case <-t.C:
		}
		if time.Since(q.StartedAt) > alipayQRExpire {
			qrSetState(q, "timeout", "二维码已失效，请刷新")
			return
		}
		cookies, err := collectAlipayCookies(bws)
		if err != nil || len(cookies) == 0 {
			continue
		}
		// ALIPAYJSESSIONID 一打开登录页就有，必须真访问一次业务页才算登录成功
		if !alipayCookiesWork(cookies) {
			continue
		}
		// 登录成功后支付宝会补发一批 cookie，再取一次拿全
		time.Sleep(1500 * time.Millisecond)
		if again, err := collectAlipayCookies(bws); err == nil && len(again) > len(cookies) {
			cookies = again
		}
		ua := ""
		if raw, err := cdpCall(bws, 22, "Browser.getVersion", nil); err == nil {
			var v struct {
				UserAgent string `json:"userAgent"`
			}
			if json.Unmarshal(raw, &v) == nil {
				ua = strings.TrimSpace(v.UserAgent)
			}
		}
		finishBrowserLogin(q.SessionID, cookies, ua)
		qrSetState(q, "confirmed", "登录成功")
		return
	}
}

func qrSetState(q *qrLogin, status, msg string) {
	qrMu.Lock()
	q.Status = status
	q.Message = msg
	qrMu.Unlock()
	if status == "confirmed" || status == "timeout" || status == "error" {
		if s, ok := findAlipaySession(q.SessionID); ok && s.Status == "waiting" {
			s.HeartbeatMsg = msg
			upsertAlipaySession(s)
		}
	}
}

// loginPageInfo 登录页里提取出来的参数
type loginPageInfo struct {
	SecurityID  string
	QRURL       string
	RdsToken    string
	AlieditUID  string
	PasswordSID string
	// 登录页 loginForm 里的全部 hidden 字段，提交时要原样带上
	FormFields map[string]string
	// 表单的实际提交地址（从 <form action="..."> 读）
	FormAction string
}

// alipayFetchLoginPage 拉一次登录页并解析参数
func alipayFetchLoginPage(client *http.Client) (*loginPageInfo, error) {
	req, err := http.NewRequest("GET", alipayLoginPage, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", alipayUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("打开支付宝登录页失败：%w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("登录页返回 HTTP %d", resp.StatusCode)
	}

	txt := string(body)
	m := reSecurityID.FindStringSubmatch(txt)
	if len(m) < 2 {
		return nil, fmt.Errorf("登录页里没找到 securityId，支付宝可能改版了")
	}
	info := &loginPageInfo{SecurityID: m[1]}

	// 二维码内容用登录页里的 barcode 字段：securityId 是 %257C 双重编码。
	// 实测对比过：参考程序渲染出来的二维码就是 %257C 版本，
	// 裸竖线版本支付宝 App 扫了没反应。
	if b := reBarcode.FindStringSubmatch(txt); len(b) > 1 {
		info.QRURL = html.UnescapeString(b[1])
	} else {
		// 兜底：自己编码两次
		info.QRURL = "https://qr.alipay.com/_d?_b=PAI_LOGIN_DY&securityId=" +
			url.QueryEscape(url.QueryEscape(info.SecurityID))
	}

	if v := reRdsToken.FindStringSubmatch(txt); len(v) > 1 {
		info.RdsToken = v[1]
	}
	if v := reAlieditUID.FindStringSubmatch(txt); len(v) > 1 {
		info.AlieditUID = v[1]
	}
	if v := rePasswordSID.FindStringSubmatch(txt); len(v) > 1 {
		info.PasswordSID = v[1]
	}

	info.FormFields, info.FormAction = alipayParseLoginForm(txt)
	return info, nil
}

var (
	reFormAction  = regexp.MustCompile(`(?is)<form[^>]*name="loginForm"[^>]*action="([^"]+)"`)
	reHiddenInput = regexp.MustCompile(`(?is)<input[^>]*type="hidden"[^>]*>`)
	reAttrName    = regexp.MustCompile(`(?i)\bname="([^"]*)"`)
	reAttrValue   = regexp.MustCompile(`(?i)\bvalue="([^"]*)"`)
	reAttrID      = regexp.MustCompile(`(?i)\bid="([^"]*)"`)
)

// alipayParseLoginForm 把登录页 loginForm 里的 hidden 字段全部提取出来。
//
// 支付宝的扫码登录最后一步是把这张表单原样 POST 回 auth.alipay.com，
// 服务器才会下发真正的登录 Cookie（ALIPAYJSESSIONID 后缀从 RZ44 变 RZ55）。
// 少一个字段都会失败，所以这里不挑，全部带上。
func alipayParseLoginForm(page string) (map[string]string, string) {
	fields := map[string]string{}
	for _, tag := range reHiddenInput.FindAllString(page, -1) {
		name := ""
		if m := reAttrName.FindStringSubmatch(tag); len(m) > 1 {
			name = m[1]
		}
		if name == "" {
			// 有些 input 只有 id 没 name
			if m := reAttrID.FindStringSubmatch(tag); len(m) > 1 {
				name = m[1]
			}
		}
		if name == "" || name == "password" {
			continue
		}
		val := ""
		if m := reAttrValue.FindStringSubmatch(tag); len(m) > 1 {
			val = html.UnescapeString(m[1])
		}
		fields[name] = val
	}

	action := "https://authea178.alipay.com:443/login/index.htm"
	if m := reFormAction.FindStringSubmatch(page); len(m) > 1 {
		a := html.UnescapeString(m[1])
		if strings.HasPrefix(a, "http") {
			action = a
		}
	}
	return fields, action
}

// alipaySubmitLoginForm 扫码确认后提交登录表单，换回登录 Cookie。
func alipaySubmitLoginForm(qr *qrLogin, info *loginPageInfo) error {
	if len(info.FormFields) == 0 {
		return fmt.Errorf("登录表单字段为空")
	}
	form := url.Values{}
	for k, v := range info.FormFields {
		form.Set(k, v)
	}
	// 这两个是扫码登录的关键，必须显式确保
	form.Set("method", "qrCodeLogin")
	form.Set("qrCodeSecurityId", info.SecurityID)
	if info.RdsToken != "" {
		form.Set("rds_form_token", info.RdsToken)
	}
	if info.AlieditUID != "" {
		form.Set("alieditUid", info.AlieditUID)
	}
	if info.PasswordSID != "" {
		form.Set("passwordSecurityId", info.PasswordSID)
	}

	req, err := http.NewRequest("POST", info.FormAction, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", alipayUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("Origin", "https://auth.alipay.com")
	req.Header.Set("Referer", alipayLoginPage)

	resp, err := qr.Client.Do(req)
	if err != nil {
		return fmt.Errorf("提交登录表单失败：%w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	loc := resp.Header.Get("Location")
	resp.Body.Close()

	logDebug("alipay", "提交登录表单：HTTP %d 落点=%s 长度=%d", resp.StatusCode, firstN(loc, 80), len(body))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("提交登录表单返回 HTTP %d", resp.StatusCode)
	}
	return nil
}

// qrPollLoop 每 2 秒问一次扫码状态
func qrPollLoop(qr *qrLogin) {
	t := time.NewTicker(alipayQRPollEvery)
	defer t.Stop()
	for {
		select {
		case <-qr.Stop:
			return
		case <-t.C:
		}

		if time.Since(qr.StartedAt) > alipayQRExpire {
			qrMu.Lock()
			qr.Status = "timeout"
			qr.Message = "二维码已失效，请刷新"
			qrMu.Unlock()
			markSessionQR(qr.SessionID, "waiting", "二维码已失效，请重新生成")
			return
		}

		st, msg, err := alipayPollBarcodeStatus(qr)
		if err != nil {
			logDebug("alipay", "扫码状态查询失败：%v", err)
			continue
		}

		qrMu.Lock()
		qr.Status = st
		qr.Message = msg
		qrMu.Unlock()

		switch st {
		case "scanned":
			markSessionQR(qr.SessionID, "waiting", "已扫码，请在手机上确认")
		case "confirmed":
			if err := finishQRLogin(qr); err != nil {
				logWarn("alipay", "登录成功但保存失败：%v", err)
				markSessionQR(qr.SessionID, "waiting", "保存登录态失败："+err.Error())
				return
			}
			return
		case "timeout", "error":
			markSessionQR(qr.SessionID, "waiting", msg)
			return
		}
	}
}

// alipayPollBarcodeStatus 查一次扫码状态
func alipayPollBarcodeStatus(qr *qrLogin) (status, msg string, err error) {
	u := fmt.Sprintf("%s?securityId=%s&_callback=%s",
		alipayBarcodeAPI, url.QueryEscape(qr.SecurityID), alipayBarcodeCB)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", alipayUA)
	req.Header.Set("Referer", "https://auth.alipay.com/")
	req.Header.Set("Accept", "*/*")

	resp, err := qr.Client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// 响应是 JSONP：callback1({...})
	txt := strings.TrimSpace(string(body))
	if i := strings.Index(txt, "("); i >= 0 {
		if j := strings.LastIndex(txt, ")"); j > i {
			txt = txt[i+1 : j]
		}
	}
	var out struct {
		BarcodeStatus string `json:"barcodeStatus"`
		Stat          string `json:"stat"`
	}
	if err := json.Unmarshal([]byte(txt), &out); err != nil {
		return "", "", fmt.Errorf("解析状态失败：%w", err)
	}
	if out.Stat != "" && out.Stat != "ok" {
		return "error", out.Stat, nil
	}
	switch out.BarcodeStatus {
	case "waiting":
		return "waiting", "等待扫码", nil
	case "scanned":
		return "scanned", "已扫码，请在手机上确认", nil
	case "confirmed":
		return "confirmed", "登录成功", nil
	case "timeout":
		return "timeout", "二维码已失效", nil
	default:
		return "waiting", out.BarcodeStatus, nil
	}
}

// alipayCompleteLogin 用登录后的会话访问需要登录的页面，让服务器补全 Cookie，
// 顺便把真实 PID 从页面里捞出来。
//
// 为什么必须复用同一个 jar：支付宝在页面响应里会继续 Set-Cookie，
// 如果换成"用 cookie 字符串新建 client"，这些新 cookie 就全丢了，
// 典型表现就是 PID 一直拿不到。
func alipayCompleteLogin(qr *qrLogin) string {
	var pid string
	for _, u := range []string{
		"https://my.alipay.com/portal/i.htm",
		"https://consumeprod.alipay.com/record/standard.htm",
	} {
		body, ok := alipayGetLoggedIn(qr, u)
		if !ok {
			continue
		}
		if p := pickPID(string(body)); p != "" && pid == "" {
			pid = p
			logDebug("alipay", "从 %s 取到 PID=%s", u, maskPid(p))
		}
	}
	return pid
}

// alipayGetLoggedIn 请求一个必须登录才能看的页面。
//
// 关键：必须让重定向跑完（不能 ErrUseLastResponse）。
// 扫码确认只是"服务器知道这次扫码过了"，真正的登录 Cookie 是在
// 后续这一次跳转链里逐跳 Set-Cookie 下来的。
// 之前禁止跟随重定向，结果永远只有扫码阶段那 7 条 Cookie，自然拿不到 PID。
//
// 判断方式：跟随到底后看最终落点 URL —— 还停在 auth.alipay.com/login
// 就是没登录成功，落到业务页就是登录成功。
func alipayGetLoggedIn(qr *qrLogin, u string) ([]byte, bool) {
	// 独立的 client，但共享同一个 cookie jar
	follow := &http.Client{
		Timeout: 20 * time.Second,
		Jar:     qr.Client.Jar,
	}

	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 800 * time.Millisecond)
		}
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return nil, false
		}
		req.Header.Set("User-Agent", alipayUA)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Referer", "https://auth.alipay.com/")

		resp, err := follow.Do(req)
		if err != nil {
			logDebug("alipay", "访问 %s 失败：%v", u, err)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		finalURL := ""
		if resp.Request != nil && resp.Request.URL != nil {
			finalURL = resp.Request.URL.String()
		}
		resp.Body.Close()

		if resp.StatusCode != 200 {
			logDebug("alipay", "访问 %s 最终 HTTP %d，落点 %s", u, resp.StatusCode, firstN(finalURL, 70))
			continue
		}
		// 落到登录页说明还没真正登录
		if strings.Contains(finalURL, "auth.alipay.com/login") || strings.Contains(finalURL, "/login/") {
			logDebug("alipay", "访问 %s 被带去登录页（Cookie 仍未生效），落点 %s", u, firstN(finalURL, 70))
			continue
		}
		if alipayLooksLikeLoginPage(body) {
			logDebug("alipay", "访问 %s 页面内容是登录页", u)
			continue
		}
		logDebug("alipay", "访问 %s 成功，落点 %s，Cookie %d 条",
			u, firstN(finalURL, 70), len(collectJarCookies(qr.Client.Jar)))
		return body, true
	}
	return nil, false
}

// alipayRefreshPID 用已保存的 Cookie 重建会话，再走一次补全流程拿 PID。
// 用于已经登录成功但当时没取到 PID 的情况，避免用户重新扫码。
func alipayRefreshPID(sessionID string) (string, error) {
	s, ok := findAlipaySession(sessionID)
	if !ok {
		return "", fmt.Errorf("会话不存在")
	}
	if len(s.Cookies) == 0 {
		return "", fmt.Errorf("这个会话还没有 Cookie，请先扫码登录")
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	// 按 cookie 自己的 domain 塞回 jar，否则 domain 不匹配会被丢弃
	for _, c := range s.Cookies {
		if c.Name == "" || c.Value == "" || c.Domain == "" {
			continue
		}
		scheme := "https"
		host := strings.TrimPrefix(c.Domain, ".")
		u := &url.URL{Scheme: scheme, Host: host, Path: "/"}
		jar.SetCookies(u, []*http.Cookie{{
			Name: c.Name, Value: c.Value, Domain: c.Domain,
			Path: orDefault(c.Path, "/"), HttpOnly: c.HTTPOnly, Secure: c.Secure,
		}})
	}

	qr := &qrLogin{SessionID: sessionID, Client: &http.Client{
		Timeout: 20 * time.Second,
		Jar:     jar,
	}}

	pid := alipayCompleteLogin(qr)
	if pid == "" {
		return "", fmt.Errorf("访问支付宝页面后仍未取到 PID")
	}

	// 补全后的 cookie 一起存回去
	cookies := collectJarCookies(jar)
	if len(cookies) > len(s.Cookies) {
		s.Cookies = cookies
	}
	s.PID = pid
	s.MaskedID = maskPid(pid)
	s.HeartbeatMsg = "已获取 PID"
	upsertAlipaySession(s)
	saveAlipaySessions()

	ch := s.ChannelFor(GetConfig().Mode)
	if a, had := findAccount(pid); had {
		ch = a.ChannelID
	}
	if err := upsertAccount(Account{
		Type: "alipay", Wxid: pid, Nick: s.Nick,
		ChannelID: ch, ChannelCode: "alipay_app", Enabled: true,
	}); err != nil {
		return "", err
	}
	logInfo("alipay", "重新获取 PID 成功：%s（Cookie %d 条）", maskPid(pid), len(s.Cookies))
	return pid, nil
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// alipayPromoteChipsSession 确保会话里有「登录态」那条 ALIPAYJSESSIONID。
//
// 实测：扫码登录成功后，支付宝会下发两条 session——
//
//	ALIPAYJSESSIONID        = ...RZ44   扫码阶段（auth 域）
//	_CHIPS-ALIPAYJSESSIONID = ...RZ55   已登录（CHIPS 分区 cookie）
//
// 参考程序的做法是**两条都留着**（它的 alipay_sessions.json 里
// ALIPAYJSESSIONID 有 2 个不同值，_CHIPS-ALIPAYJSESSIONID 1 个），
// 请求时各域按自己的 cookie 走。
//
// 旧实现直接拿 RZ55 覆盖掉 ALIPAYJSESSIONID，等于把 auth 域那条 session 弄没了：
// 账单页能撑几分钟，之后既续不上也换不出新的，只能重新扫码。
// 所以这里改成「只在缺失时补一条」，绝不覆盖已有值。
func alipayPromoteChipsSession(cookies []AlipayCookie) []AlipayCookie {
	chips, chipsDomain := "", ""
	for _, c := range cookies {
		if c.Name == "_CHIPS-ALIPAYJSESSIONID" && c.Value != "" {
			chips, chipsDomain = c.Value, c.Domain
			break
		}
	}
	if chips == "" {
		return cookies
	}
	// 已经有登录态那条（同值）就不用动
	for _, c := range cookies {
		if c.Name == "ALIPAYJSESSIONID" && c.Value == chips {
			return cookies
		}
	}
	logDebug("alipay", "补一条登录态 ALIPAYJSESSIONID（RZ 后缀 %s，域 %s）", tail(chips, 4), orDefault(chipsDomain, "?"))
	return append(cookies, AlipayCookie{
		Name: "ALIPAYJSESSIONID", Value: chips,
		Domain: orDefault(chipsDomain, "consumeprod.alipay.com"), Path: "/",
		HTTPOnly: true, Secure: true,
	})
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// collectJarCookies 把 jar 里各域的 cookie 收集成一张表（按域保留，不压缩）。
func collectJarCookies(jar http.CookieJar) []AlipayCookie {
	return alipayCollectJar(jar)
}

// finishQRLogin 扫码确认后落库
func finishQRLogin(qr *qrLogin) error {
	s, ok := findAlipaySession(qr.SessionID)
	if !ok {
		return fmt.Errorf("会话不存在")
	}

	// 核心一步：把登录页那张 form 原样 POST 回去（method=qrCodeLogin）。
	// 支付宝是在这一步才把 ALIPAYJSESSIONID 换成登录态（后缀 RZ44 → RZ55）。
	// 少了这一步，jar 里永远只有扫码阶段的几条 Cookie，访问 my.alipay.com 会被踢回登录页。
	var pidFromPage string
	if qr.PageInfo != nil {
		if err := alipaySubmitLoginForm(qr, qr.PageInfo); err != nil {
			logWarn("alipay", "提交登录表单失败：%v", err)
		} else {
			// 提交成功后访问「我的支付宝」补全 Cookie 并取 PID
			pidFromPage = alipayCompleteLogin(qr)
		}
	}

	cookies := alipayPromoteChipsSession(collectJarCookies(qr.Client.Jar))
	if len(cookies) == 0 {
		return fmt.Errorf("没取到任何 Cookie")
	}

	// PID 优先从 cookie 里直接读：扫码成功后支付宝会下发
	//   CLUB_ALIPAY_COM = 2088123456789012
	pid := alipayPIDFromCookies(cookies)
	if pid == "" {
		pid = pidFromPage
	}
	if pid == "" {
		pid = alipayFetchPID(cookies)
	}

	now := time.Now().Format("2006-01-02T15:04:05Z07:00")
	s.Cookies = cookies
	s.PID = pid
	if pid != "" {
		s.MaskedID = maskPid(pid)
	}
	s.Status = "confirmed"
	s.OnlineSince = now
	s.LastCheck = now
	s.HeartbeatMsg = "登录成功"

	// 一次性验证：直接用这套 cookie 打开收款助手页，拿到 USERID/bizToken/sid。
	// 这样「登录成功」就不再是猜的 —— 后面每 5 秒拉收款记录全靠这两个 token，
	// 拿不到就说明这套 cookie 其实没登录成功。
	if userID, bizToken, sid, err := alipayChatTokens(&s); err != nil {
		logWarn("alipay", "登录后验证收款接口失败：%v", err)
		s.HeartbeatMsg = "登录成功，但收款接口不可用：" + err.Error()
	} else {
		if userID != "" {
			s.PID = userID
			s.MaskedID = maskPid(userID)
		}
		s.BizToken, s.SID = bizToken, sid
		s.HeartbeatMsg = "在线"
		logInfo("alipay", "收款接口已验证：USERID=%s bizToken=%s sid=%s",
			maskPid(s.PID), firstN(bizToken, 8)+"…", firstN(sid, 8)+"…")
	}
	pid = s.PID

	upsertAlipaySession(s)
	if err := saveAlipaySessions(); err != nil {
		return err
	}

	// 同步到上报账号表
	if pid != "" {
		ch := s.ChannelFor(GetConfig().Mode)
		if a, had := findAccount(pid); had {
			ch = a.ChannelID
		}
		if err := upsertAccount(Account{
			Type: "alipay", Wxid: pid, Nick: s.Nick,
			ChannelID: ch, ChannelCode: "alipay_app", Enabled: true,
		}); err != nil {
			return err
		}
	}
	logInfo("alipay", "扫码登录成功，Cookie %d 条，PID=%s", len(cookies), maskPid(pid))

	return nil
}

// markSessionQR 把扫码进度写回 AlipaySession，界面靠它显示状态
func markSessionQR(sessionID, status, msg string) {
	s, ok := findAlipaySession(sessionID)
	if !ok {
		return
	}
	s.Status = status
	s.HeartbeatMsg = msg
	upsertAlipaySession(s)
	saveAlipaySessions()
}

// qrState 给界面用的扫码状态
type qrState struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func getQRState(sessionID string) qrState {
	qrMu.Lock()
	defer qrMu.Unlock()
	if q := qrStore[sessionID]; q != nil {
		return qrState{Status: q.Status, Message: q.Message}
	}
	return qrState{}
}

func closeQR(sessionID string) {
	qrMu.Lock()
	q := qrStore[sessionID]
	delete(qrStore, sessionID)
	qrMu.Unlock()
	if q != nil {
		close(q.Stop)
		if q.Kill != nil {
			q.Kill() // 无头浏览器也要一起收掉
		}
	}
}

// alipayQRPNG 生成二维码 PNG
func alipayQRPNG(sessionID string, size int) ([]byte, error) {
	qrMu.Lock()
	q := qrStore[sessionID]
	qrMu.Unlock()
	if q == nil {
		return nil, fmt.Errorf("二维码不存在或已过期，请重新生成")
	}
	if size < 120 {
		size = 240
	}
	return qrcode.Encode(q.QRURL, qrcode.Medium, size)
}

// alipayPollSecurityStatus 查账单安全校验二维码的扫码状态。
// 用的是和登录同一套接口，只是 securityId 属于 consumeprod_record_list。
func alipayPollSecurityStatus(chk *alipaySecurityCheck) (string, string, error) {
	u := alipayBarcodeAPI + "?securityId=" + url.QueryEscape(chk.SecurityID) +
		"&_callback=" + alipayBarcodeCB
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", alipayUA)
	req.Header.Set("Referer", "https://consumeprod.alipay.com/")

	resp, err := (&http.Client{Timeout: 12 * time.Second}).Do(req)
	if err != nil {
		return "", "", err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()

	txt := string(body)
	if i := strings.Index(txt, "("); i >= 0 {
		if j := strings.LastIndex(txt, ")"); j > i {
			txt = txt[i+1 : j]
		}
	}
	var got struct {
		BarcodeStatus string `json:"barcodeStatus"`
		Stat          string `json:"stat"`
	}
	if err := json.Unmarshal([]byte(txt), &got); err != nil {
		return "", "", err
	}
	switch got.BarcodeStatus {
	case "waiting", "":
		return "waiting", "等待扫码", nil
	case "scanned":
		return "scanned", "已扫码，请在手机上确认", nil
	case "confirmed":
		return "confirmed", "验证通过", nil
	case "timeout":
		return "timeout", "二维码已失效", nil
	default:
		return got.BarcodeStatus, "状态：" + got.BarcodeStatus, nil
	}
}

// qrImagePNG 把任意字符串渲染成二维码 PNG
func qrImagePNG(content string, size int) ([]byte, error) {
	return qrcode.Encode(content, qrcode.Medium, size)
}
