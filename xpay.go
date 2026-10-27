package main

// X-Ypay（XArrPay 商户版）上报实现
//
// 接口（实测于 2026-10-25，平台 pay.example.com）：
//
//	上报  POST /api/report/{pid}/pc      form-urlencoded
//	心跳  GET  /api/report/{pid}/heart   form query
//
// 签名：md5(按 key 字母序拼接的 k=v&k=v + secret)，小写 hex，不含 sign 自身。
//
// 文档没说清、但实测必须的：
//   - channel_account_id 必填（文档写"可选"）
//   - channel_code 必填
//   - pay_time 必须精确到秒 "2006-01-02 15:04:05"，少秒直接 400
//   - out_order_id 可选；不带它时平台按「商户+支付方式+通道+金额+付款时间」匹配

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// xpaySign 计算 X-Ypay 签名
func xpaySign(params map[string]string, secret string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		if k == "sign" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(params[k])
	}
	sb.WriteString(secret)
	return fmt.Sprintf("%x", md5.Sum([]byte(sb.String())))
}

// xpaySite 返回平台地址（去掉末尾斜杠）
func xpaySite(c Config) string {
	s := strings.TrimSpace(c.XPaySite)
	if s == "" {
		s = strings.TrimSpace(c.V1Site) // 兼容老配置
	}
	return strings.TrimRight(s, "/")
}

// xpayPayType 按收款账号判断支付方式
// 微信 → wxpay，支付宝 → alipay
//
// 注意不能用前缀判断：支付宝的通道代码有两种写法
//   alipay_app  —— 前缀就是 alipay
//   jk_alipay   —— 前缀是 jk_，alipay 在后面
// 用 HasPrefix 会把 jk_alipay 判成微信，上报直接被平台拒绝。
func xpayPayType(acc Account) string {
	code := strings.ToLower(strings.TrimSpace(acc.ChannelCode))
	if strings.Contains(code, "alipay") {
		return "alipay"
	}
	return "wxpay"
}

// xpayAmountCents 把元转成分。微信通知里解析出来的金额是 float64。
func xpayAmountCents(yuan float64) int64 {
	return int64(yuan*100 + 0.5)
}

// buildXPayParams 构造 POST /api/report/{pid}/pc 的表单参数。
//
// 单独抽出来是为了能单元测试：支付宝和微信走同一个上报接口，
// 只有 pay_type / channel_code 不同，这两项错了平台会直接 400
// 「通道 ID、插件或支付方式不匹配」，而且不会有任何提示。
//
// 参数语义（实测）：
//   amount             分，整数
//   pay_type           wxpay / alipay
//   channel_code       jk_wechat_pc（微信）/ alipay_app（支付宝）
//   channel_account_id 后台通道 ID
//   coll_user          收款账号（微信 wxid / 支付宝 PID）
//   pay_time           付款时间，必须精确到秒
//   timestamp          当前 Unix 秒
//   sign               md5(按 key 排序的 k=v 用 & 连接 + secret)
func buildXPayParams(m *ChatMsg, acc Account, secret string, now time.Time) map[string]string {
	payTime := time.Unix(int64(m.Time), 0).Format("2006-01-02 15:04:05")
	p := map[string]string{
		"amount":             fmt.Sprintf("%d", xpayAmountCents(m.Amount)),
		"pay_type":           xpayPayType(acc),
		"channel_code":       strings.TrimSpace(acc.ChannelCode),
		"channel_account_id": acc.ChannelFor("xpay"),
		"coll_user":          m.To,
		"pay_time":           payTime,
		"timestamp":          fmt.Sprintf("%d", now.Unix()),
	}
	p["sign"] = xpaySign(p, secret)
	return p
}

// sendXPay 上报一笔支付
func sendXPay(m *ChatMsg, c Config) ReportResult {
	site := xpaySite(c)
	if site == "" || c.XPaySecret == "" || c.XPayPID == "" {
		return ReportResult{Err: "未配置 X-Ypay 域名/商户ID/密钥"}
	}
	if m.Amount <= 0 {
		return ReportResult{Err: "消息里没有识别到金额"}
	}

	acc, ok := findAccount(m.To)
	if !ok {
		return ReportResult{Err: fmt.Sprintf("收款账号 %s 未绑定", short(m.To))}
	}
	chAccID := acc.ChannelFor("xpay")
	chCode := strings.TrimSpace(acc.ChannelCode)
	if chAccID == "" {
		return ReportResult{Err: fmt.Sprintf("账号 %s 未填通道 ID", short(m.To))}
	}
	if chCode == "" {
		return ReportResult{Err: fmt.Sprintf("账号 %s 未填通道代码", short(m.To))}
	}

	params := buildXPayParams(m, acc, c.XPaySecret, time.Now())
	payTime := params["pay_time"]

	u := fmt.Sprintf("%s/api/report/%s/pc", site, url.PathEscape(c.XPayPID))
	logDebug("callback", "XPay 上报 -> %s  amount=%s pay_type=%s pay_time=%s",
		u, params["amount"], params["pay_type"], payTime)
	logDebug("callback", "XPay body: %s", truncate(encodeForm(params), 300))

	req, err := http.NewRequest("POST", u, strings.NewReader(encodeForm(params)))
	if err != nil {
		return ReportResult{Err: err.Error(), URL: u}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "okhttp/4.12.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logError("callback", "XPay 请求失败: %v", err)
		return ReportResult{Err: err.Error(), URL: u}
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	txt := strings.TrimSpace(string(rb))
	logDebug("callback", "XPay 响应 <- %d  %s", resp.StatusCode, truncate(txt, 200))

	// 解析 {code, message, data}
	var out struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal(rb, &out)
	succ := resp.StatusCode == 200 && out.Code == 200

	// 失败时把平台返回的 code/message 也带上，
	// 否则上层只会看到「HTTP 200」，完全看不出哪里不对。
	errMsg := ""
	if !succ {
		if out.Code != 0 || out.Message != "" {
			errMsg = fmt.Sprintf("平台返回 code=%d message=%s", out.Code, out.Message)
		} else {
			errMsg = fmt.Sprintf("HTTP %d 但响应体不是预期 JSON", resp.StatusCode)
		}
		if resp.StatusCode != 200 {
			errMsg = fmt.Sprintf("HTTP %d %s", resp.StatusCode, errMsg)
		}
		logWarn("callback", "XPay 上报被拒：%s  body=%s", errMsg, truncate(txt, 200))
	}

	return ReportResult{
		OK:        succ,
		Code:      resp.StatusCode,
		Body:      txt,
		Err:       errMsg,
		URL:       u,
		Sent:      encodeForm(params),
		Delivered: true,
	}
}

// encodeForm 稳定的 form 编码（按 key 排序，便于日志比对）
func encodeForm(p map[string]string) string {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(p[k]))
	}
	return strings.Join(parts, "&")
}

// xpayHeartbeat 发一次心跳。acc 为空时用 channelID 直接发（客户端级心跳）。
func xpayHeartbeat(c Config, clientName, channelID string) error {
	site := xpaySite(c)
	if site == "" || c.XPaySecret == "" || c.XPayPID == "" {
		return fmt.Errorf("未配置 X-Ypay")
	}
	p := map[string]string{
		"client_name": clientName,
		"timestamp":   fmt.Sprintf("%d", time.Now().Unix()),
	}
	if channelID != "" {
		p["channel_id"] = channelID
	}
	// 平台有两套心跳协议，按 client_name 分流：
	//
	//   A) 通道级（GET + query，带 channel_id）
	//      client_name 随便取（但不能叫"易监控"，见下）
	//      ext_data = {"status":"online"}
	//      → 返回 data.status = online/offline，这个才代表通道是否可派单
	//
	//   B) 客户端级（POST + JSON body，不带 channel_id）
	//      client_name 必须是 "易监控"
	//      ext_data = {"online":1}（整数，字符串会被拒）
	//      → 返回 data 为空，看不到通道状态
	//
	// 注意：client_name 一旦被某个通道用成"易监控"，该名字的 GET 请求会
	// 直接 405（只接受 POST）。所以本程序统一用"通道级"协议，
	// client_name 取 XPayClient（默认 易监控PC），不要用"易监控"。
	p["ext_data"] = `{"status":"online"}`
	p["sign"] = xpaySign(p, c.XPaySecret)

	u := fmt.Sprintf("%s/api/report/%s/heart", site, url.PathEscape(c.XPayPID))
	req, err := http.NewRequest("GET", u+"?"+encodeForm(p), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "okhttp/4.12.0")

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)

	var out struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(rb, &out)
	if out.Code != 200 {
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	return nil
}

var (
	xpayHbMu      sync.Mutex
	xpayHbStarted bool
	xpayHbStop    = make(chan struct{})
)

// ensureXPayHeartbeat 按需启动心跳协程。可重复调用。
//
// 之前只在 main 启动时判断一次 Mode，用户在设置里切到 X-Ypay 后
// 心跳不会开始跑。现在保存配置时也调这个。
// stopXPayHeartbeat 停掉心跳协程（切到不支持心跳的平台时调用）。
// 码支付V1 没有心跳接口，切过去必须彻底停发，否则平台侧通道状态会一直"在线"。
func stopXPayHeartbeat() {
	xpayHbMu.Lock()
	defer xpayHbMu.Unlock()
	if !xpayHbStarted {
		return
	}
	close(xpayHbStop)
	xpayHbStop = make(chan struct{})
	xpayHbStarted = false
	logInfo("xpay", "心跳已停止（当前模式不支持心跳）")
}

func ensureXPayHeartbeat() {
	xpayHbMu.Lock()
	defer xpayHbMu.Unlock()
	if xpayHbStarted {
		return
	}
	c := GetConfig()
	if c.Mode != "xpay" || !c.XPayHeartbeat {
		return
	}
	xpayHbStarted = true
	go xpayHeartbeatLoop(xpayHbStop)
	logInfo("xpay", "心跳已启动，间隔 60 秒")
}

func xpayHeartbeatLoop(stop <-chan struct{}) {
	const interval = 60 * time.Second
	t := time.NewTicker(interval)
	defer t.Stop()
	xpayHeartbeatRound() // 先发一轮，别等 60 秒
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			xpayHeartbeatRound()
		}
	}
}

var hbRoundMu sync.Mutex

func xpayHeartbeatRound() {
	// 单飞：多个触发点（账号保存、看护线程）同时发起时只跑一轮，
	// 否则会对平台形成每秒一次的请求轰炸
	if !hbRoundMu.TryLock() {
		return
	}
	defer hbRoundMu.Unlock()
	c := GetConfig()
	if c.Mode != "xpay" || !c.XPayHeartbeat {
		return
	}
	name := strings.TrimSpace(c.XPayClient)
	if name == "" {
		name = "易监控PC"
	}
	accs := accountsCopy()
	// HK 模式的账号不在账号表里，心跳要把它一起带上，否则平台看不到在线
	if GetConfig().EffectiveWxMode() == "hook" {
		have := map[string]bool{}
		for _, a := range accs {
			have[a.Wxid] = true
		}
		for _, h := range GetConfig().EffectiveHookAccounts() {
			// 账号在线才发心跳：进程已退出就不发
			if h.PID != 0 && !pidAlive(uint32(h.PID)) {
				continue
			}
			if h.Enabled && !have[h.Wxid] {
				accs = append(accs, Account{
					Type: "wechat", Wxid: h.Wxid,
					ChannelID: h.ChannelID, ChannelIDXpay: h.ChannelIDXpay, ChannelIDV1: h.ChannelIDV1,
					ChannelCode: "jk_wechat_pc", Enabled: true,
				})
			}
		}
	}
	for _, a := range accs {
		if !a.Enabled {
			continue
		}
		// 支付宝账号的在线状态取决于登录态：Cookie 失效后账单拉不到，
		// 继续报在线会让平台把单派给收不到通知的通道。
		if accountKind(a) == "alipay" && !alipaySessionOnline(a.Wxid) {
			logWarn("xpay", "支付宝账号 %s 登录态失效，暂不发心跳（通道 %s 视为离线）",
				short(a.Wxid), a.ChannelID)
			continue
		}
		// 账号只要添加并在线就发心跳，不要求先绑通道：
		// 通道为空也照发（平台会返回明确错误，界面上能看到原因）
		cid := a.ChannelFor("xpay")
		if err := xpayHeartbeat(c, name, cid); err != nil {
			logWarn("xpay", "账号 %s 心跳失败（通道 %s）：%v", short(a.Wxid), cid, err)
			markAccountHeartbeat(a.Wxid, false, err.Error())
		} else {
			logDebug("xpay", "账号 %s 心跳成功（通道 %s）", short(a.Wxid), cid)
			markAccountHeartbeat(a.Wxid, true, "")
		}
		time.Sleep(time.Second) // 账号之间错开 1 秒，和参考程序一致
	}
}
