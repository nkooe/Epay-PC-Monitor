package main

// 上报：易简控 YiJianKong / 码支付V1

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ReportResult struct {
	OK   bool
	Code int
	Body string
	Err  string
	Sent string
	URL  string

	// Delivered 表示是否真的向平台发出了 HTTP 请求。
	// 仅记录模式下为 false，用于区分「未上报」和「已回调」。
	Delivered bool
}

// mpay 的 PC 模式只认这两个公众号，其余号会被 source_mismatch 拒掉。
// 名单外（例如微信收款商业版换了 gh_id）自动降级成手机模式：
// from 用 com.tencent.mm，content 只放 title + msg，平台按手机合同解析。
var pcAccounts = map[string]string{
	"gh_3dfda90e39d6": "微信支付",
	"gh_f0a92aa7146c": "微信收款助手",
}

// 手机模式下平台接受的 title（写死在 WechatReceiptPayment::receipt）
var mobileTitles = map[string]bool{
	"微信支付":    true,
	"微信收款助手":  true,
	"微信收款商业版": true,
}

// buildReport 返回 (from, content)。ok=false 表示这条消息没有平台能接受的格式。
func buildReport(m *ChatMsg, channelID string) (from, content string, ok bool) {
	// 微信：名单内公众号优先走 wxtool PC 合同（最贴近真实工具，XML 最完整）
	if name, hit := pcAccounts[m.GHFrom]; hit && strings.HasPrefix(strings.TrimSpace(m.RawText), "<") {
		_ = name
		if f, c, ok := buildReportPC(m, channelID); ok {
			return f, c, true
		}
	}
	// 其它情况（非白名单公众号、支付宝、普通聊天）走手机合同
	return buildReportPhone(m)
}

// buildReportPhone 手机合同：from 用包名，content 是 {"title","msg"}
func buildReportPhone(m *ChatMsg) (from, content string, ok bool) {
	title := strings.TrimSpace(m.Display)
	if title == "" {
		title = strings.TrimSpace(m.Content)
	}

	// 支付宝：MPAY「支付宝手机监听」合同
	if strings.TrimSpace(m.From) == "支付宝" {
		msg := fmt.Sprintf("支付宝收款到账%.2f元", m.Amount)
		obj := map[string]string{"title": "收款通知", "msg": msg}
		b, _ := json.Marshal(obj)
		return "com.eg.android.AlipayGphone", string(b), true
	}

	// 微信公众号：title 必须是平台认可的名字之一
	if m.GHFrom != "" && m.Amount > 0 {
		name := strings.TrimSpace(m.GHName)
		if !mobileTitles[name] {
			name = "微信收款商业版"
		}
		msg := strings.TrimSpace(m.Content)
		if msg == "" || !strings.Contains(msg, "元") {
			msg = fmt.Sprintf("%s 收款到账%.2f元", name, m.Amount)
		}
		obj := map[string]string{"title": name, "msg": msg}
		b, _ := json.Marshal(obj)
		return "com.tencent.mm", string(b), true
	}

	// 普通聊天消息
	obj := map[string]string{
		"title":        title,
		"msg":          m.Content,
		"package_name": "com.tencent.wechat.pc",
		"receive_time": microTime(m.Time),
		"device_name":  "Windows PC",
	}
	b, _ := json.Marshal(obj)
	return "com.tencent.mm", string(b), true
}

// buildReportPC 构造 wxtool 的 PC 事件对象（手机合同被拒时重试用）
func buildReportPC(m *ChatMsg, channelID string) (from, content string, ok bool) {
	if m.GHFrom == "" || !strings.HasPrefix(strings.TrimSpace(m.RawText), "<") {
		return "", "", false
	}
	acc := m.GHFrom
	messageID := reportMessageID(m)
	obj := map[string]any{
		"event":   "wxtool.officialAccount.message",
		"account": map[string]any{"username": acc},
		"message": map[string]any{
			"username":       acc,
			"source":         "message",
			"isFallback":     false,
			"senderUsername": acc,
			"direction":      "incoming",
			"localType":      21474836529,
			"createTime":     int64(m.Time),
			"sortSeq":        m.SortSeq,
			"localId":        m.LocalID,
			"content":        m.RawText,
		},
		"delivery": map[string]any{
			"id": fmt.Sprintf("delivery_%d_%d", messageID, m.Time),
			// MPAY 校验：第一段必须是用 ctype_digit 通过的数字（账号数字ID）。
			// 微信内部数字账号拿不到，就用 wxid 的稳定哈希代替——
			// 同一账号恒定、参与去重，符合"工具实际游标"的要求。
			"messageKey": fmt.Sprintf("%s:%s:%d:%d:%d", accountNumericID(firstNonEmpty(m.To, channelID)), acc, m.SortSeq, m.Time, messageID),
		},
	}
	b, _ := json.Marshal(obj)
	return acc, string(b), true
}

func reportMessageID(m *ChatMsg) uint64 {
	if m.LocalID > 0 {
		return uint64(m.LocalID)
	}
	if m.StableID != "" {
		return hashToUint64(m.StableID)
	}
	return hashMsg(m.From+"|"+m.To+"|"+m.Content, m.Time)
}

// accountNumericID 给 MPAY 的 messageKey 用的账号数字 ID。
// 要求：纯数字、同一账号恒定（参与去重），不要求等于微信内部 ID。
func accountNumericID(account string) string {
	if account == "" {
		return "1"
	}
	var h uint64 = 1469598103934665603
	for i := 0; i < len(account); i++ {
		h ^= uint64(account[i])
		h *= 1099511628211
	}
	v := h % 1000000000
	if v < 1 {
		v = 1
	}
	return strconv.FormatUint(v, 10)
}

// firstNonEmpty 取第一个非空字符串
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// buildInner 兼容旧调用点
func buildInner(m *ChatMsg, channelID string) string {
	_, c, _ := buildReport(m, channelID)
	return c
}

func microTime(ts uint64) string {
	var t time.Time
	if ts > 1e12 {
		t = time.UnixMilli(int64(ts))
	} else if ts > 1e9 {
		t = time.Unix(int64(ts), 0)
	} else {
		t = time.Now()
	}
	return t.Format("2006-01-02 15:04:05") + fmt.Sprintf(".%06d", t.Nanosecond()/1000)
}

// ---------- 易简控 ----------

func calcYjkSign(fields map[string]string, key string) string {
	if key == "" {
		return ""
	}
	names := make([]string, 0, len(fields))
	for k := range fields {
		if k == "sign" || k == "sign_type" {
			continue
		}
		names = append(names, k)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		v := fields[n]
		if strings.TrimSpace(v) == "" {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(n)
		sb.WriteByte('=')
		sb.WriteString(v)
	}
	sb.WriteString(key)
	sum := md5.Sum([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

func sendYjk(m *ChatMsg, c Config) ReportResult {
	site := strings.TrimRight(strings.TrimSpace(c.YjkSite), "/")
	if site == "" || c.YjkPid == "" {
		return ReportResult{Err: "未配置易简控域名或 PID"}
	}
	inner := buildInner(m, c.YjkPid)
	fields := map[string]string{
		"from":      "pc",
		"content":   inner,
		"timestamp": fmt.Sprintf("%d", time.Now().UnixMilli()),
	}
	fields["sign"] = calcYjkSign(fields, c.YjkToken)

	body, _ := json.Marshal(fields)
	u := fmt.Sprintf("%s/api/report/%s?token=%s", site,
		url.QueryEscape(c.YjkPid), url.QueryEscape(c.YjkToken))

	req, err := http.NewRequest("POST", u, strings.NewReader(string(body)))
	if err != nil {
		return ReportResult{Err: err.Error(), URL: u}
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "YiJianKong")
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ReportResult{Err: err.Error(), URL: u, Sent: string(body)}
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	logDebug("callback", "V1 响应 <- %d  %s", resp.StatusCode, truncate(string(rb), 200))
	txt := strings.TrimSpace(string(rb))
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	return ReportResult{OK: ok, Code: resp.StatusCode, Body: txt, URL: u, Sent: string(body), Delivered: true}
}

// ---------- 码支付 V1 ----------

func sendV1(m *ChatMsg, c Config) ReportResult {
	site := strings.TrimRight(strings.TrimSpace(c.V1Site), "/")
	if site == "" || c.V1Secret == "" {
		return ReportResult{Err: "未配置码支付域名/密钥"}
	}

	// 通道 ID 来自账号绑定（收款账号 = m.To），不走全局配置。
	// 码支付路径固定为 /api/pay/{通道}/notify，PID 是商户 ID，不参与拼接。
	acc, ok := findAccount(m.To)
	channel := ""
	if ok {
		channel = acc.ChannelFor(GetConfig().Mode)
	}
	if channel == "" {
		return ReportResult{Err: fmt.Sprintf("收款账号 %s 未绑定通道", short(m.To))}
	}
	sender, inner, _ := buildReport(m, channel)
	return sendV1Payload(m, c, site, channel, sender, inner, true)
}

// sendV1Payload 用指定合同发一次通知
func sendV1Payload(m *ChatMsg, c Config, site, channel, sender, inner string, allowPCFallback bool) ReportResult {
	ts := fmt.Sprintf("%d", time.Now().UnixMilli())

	mac := hmac.New(sha256.New, []byte(c.V1Secret))
	mac.Write([]byte(ts + "\n" + c.V1Secret))
	sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	form := url.Values{}
	form.Set("from", sender)
	form.Set("content", inner)
	form.Set("timestamp", ts)
	form.Set("sign", sign)
	body := form.Encode()

	u := fmt.Sprintf("%s/api/pay/%s/notify", site, url.PathEscape(channel))
	logDebug("callback", "V1 上报 -> %s", u)
	logDebug("callback", "V1 body: %s", truncate(body, 300))
	req, err := http.NewRequest("POST", u, strings.NewReader(body))
	if err != nil {
		return ReportResult{Err: err.Error(), URL: u}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "okhttp/4.12.0")
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logError("callback", "V1 请求失败: %v", err)
		return ReportResult{Err: err.Error(), URL: u, Sent: body}
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	logDebug("callback", "V1 响应 <- %d  %s", resp.StatusCode, truncate(string(rb), 200))
	txt := strings.TrimSpace(string(rb))

	// 码支付V1 的成功标志各家实现不一样：有的返回纯文本 200，
	// 有的返回 {"code":200,...}，还有的返回 success/ok。
	// 只认明确的成功标记，不会把真正的失败当成功。
	succ := resp.StatusCode >= 200 && resp.StatusCode < 300 && v1LooksOK(txt)
	if !succ {
		// 平台业务拒绝时 HTTP 仍是 200，正文形如「400：来源消息认证失败」。
		// 把正文带进记录，否则界面只剩一个 HTTP 200，看不出真实原因。
		logWarn("callback", "V1 上报未成功：HTTP %d 响应=%s", resp.StatusCode, truncate(txt, 200))
	}
	// 手机合同被拒（通道只认 PC 合同）时，用 wxtool 事件对象再发一次
	if allowPCFallback && !succ && strings.Contains(txt, "来源消息格式不符合合同") && m.GHFrom != "" {
		if f2, inner2, ok2 := buildReportPhone(m); ok2 {
			logInfo("callback", "V1 PC 合同被拒，改用手机合同重试（%s）", f2)
			return sendV1Payload(m, c, site, channel, f2, inner2, false)
		}
	}

	errTxt := ""
	if !succ {
		errTxt = fmt.Sprintf("HTTP %d %s", resp.StatusCode, truncate(txt, 160))
	}
	return ReportResult{OK: succ, Code: resp.StatusCode, Body: txt, URL: u, Sent: body,
		Delivered: true, Err: errTxt}
}

// v1LooksOK 判断码支付V1 的响应是不是成功
func v1LooksOK(body string) bool {
	t := strings.TrimSpace(body)
	if t == "200" {
		return true
	}
	switch strings.ToLower(t) {
	case "success", "ok", "true":
		return true
	}
	// {"code":200,...} / {"code":"200"} / {"status":"success"}
	if strings.HasPrefix(t, "{") {
		var v struct {
			Code   any    `json:"code"`
			Status string `json:"status"`
			Msg    string `json:"msg"`
		}
		if json.Unmarshal([]byte(t), &v) == nil {
			switch c := v.Code.(type) {
			case float64:
				if int(c) == 200 {
					return true
				}
			case string:
				if c == "200" || strings.EqualFold(c, "success") {
					return true
				}
			}
			if strings.EqualFold(v.Status, "success") || strings.EqualFold(v.Status, "ok") {
				return true
			}
		}
	}
	return false
}

func Report(m *ChatMsg) ReportResult {
	return ReportWithMode(m, GetConfig().Mode)
}

// ReportWithMode 用指定接口模式上报。重试队列用它锁定入队时的平台，
// 避免重试期间切换 xpay/v1 把旧单发到新平台。
func ReportWithMode(m *ChatMsg, mode string) ReportResult {
	c := GetConfig()
	c.Mode = mode
	switch c.Mode {
	case "yjk":
		return sendYjk(m, c)
	case "v1":
		return sendV1(m, c)
	case "xpay":
		return sendXPay(m, c)
	default:
		// 未配置接口：只记录，不发请求
		return ReportResult{OK: true, Body: "(仅打印，未上报)", Delivered: false}
	}
}

// firstN 取前 n 个字符，用于日志里显示密钥/签名片段
func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
