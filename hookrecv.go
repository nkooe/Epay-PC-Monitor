package main

// Hook 采集模式的接收端。
//
// 协议与逆向得到的参考实现一致（见 docs/参考程序-微信Hook与事件协议.md）：
//   POST /events/wechat?pid=<微信PID>
//   {"version":1,"requestId":"<32hex>","timestamp":<秒>,
//    "nonce":"<base64 12B>","payload":"<base64 密文>","tag":"<base64 16B>"}
//   AAD = "wechat-ipc-v1\ncallback\n/events/wechat\n<requestId>\n<timestamp>"
//   加密 = AES-256-GCM，密钥 = 配置里的 64 位十六进制 hook_key
//
// 明文事件：
//   {"event_type":1001,"msgid":<u64>,"type":49,"timestamp":<秒>,
//    "wxid":"<会话>","sender":"<发送者>","roomid":"","content":"<XML 或文本>"}
//
// 本文件只做「接收 + 校验 + 解密 + 转成统一消息」，过滤/上报走既有管道。

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const hookIpcVersion = "wechat-ipc-v1"

type hookEnvelope struct {
	Version   int    `json:"version"`
	RequestID string `json:"requestId"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Payload   string `json:"payload"`
	Tag       string `json:"tag"`
}

type hookEvent struct {
	EventType int    `json:"event_type"`
	MsgID     uint64 `json:"msgid"`
	Type      int    `json:"type"`
	Timestamp int64  `json:"timestamp"`
	Wxid      string `json:"wxid"`
	Sender    string `json:"sender"`
	RoomID    string `json:"roomid"`
	Content   string `json:"content"`
}

var (
	hookSrvMu  sync.Mutex
	hookSrv    *http.Server
	hookSeenMu sync.Mutex
	hookSeen   = map[string]int64{} // requestId -> 收到时间，防重放
)

// hookEnsureKey 返回当前密钥；没有就生成一个并落盘（DPAPI 加密）
// hookIPCToken 每次安装生成的随机路径令牌（写入配置，接收端与 DLL 共用）
func hookIPCToken() string {
	c := GetConfig()
	if strings.TrimSpace(c.HookIPCToken) != "" {
		return strings.TrimSpace(c.HookIPCToken)
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "wechat"
	}
	tok := hex.EncodeToString(b)
	_ = UpdateConfig(func(cur *Config) error {
		cur.HookIPCToken = tok
		return nil
	})
	return tok
}

func hookEnsureKey() string {
	c := GetConfig()
	if k := strings.TrimSpace(c.HookKey); len(k) == 64 {
		return strings.ToLower(k)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	c.HookKey = hex.EncodeToString(buf)
	if err := SetConfig(c); err != nil {
		logError("hook", "初始化失败：%v", err)
		return ""
	}
	logDebug("hook", "本地密钥已生成")
	return c.HookKey
}

// startHookReceiver 启动回环接收端
func startHookReceiver() {
	c := GetConfig()
	addr := strings.TrimSpace(c.HookListen)
	if addr == "" {
		addr = "127.0.0.1:19100"
	}
	key := hookEnsureKey()
	if key == "" {
		logError("hook", "消息接收服务启动失败")
		return
	}

	mux := http.NewServeMux()
	token := hookIPCToken()
	evPath := "/events/" + token
	mux.HandleFunc(evPath, handleHookEvent)
	// 兼容旧组件：老版本发的是固定路径
	if token != "wechat" {
		mux.HandleFunc("/events/wechat", handleHookEvent)
	}
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		st := hookStateSnapshot()
		st["listen"] = addr
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(st)
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logError("hook", "消息接收服务启动失败：%v", err)
		return
	}

	hookSrvMu.Lock()
	hookSrv = srv
	hookSrvMu.Unlock()

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logError("hook", "消息接收服务已停止：%v", err)
		}
	}()
	// 把接收端地址、密钥与随机路径写给注入的 DLL（同一用户，%TEMP% 下）
	writeHookConfig(addr, key, evPath)
	logInfo("hook", "消息接收服务已启动")
}

// writeHookConfig 生成 DLL 读取的配置：ADDR / KEY
func writeHookConfig(addr, key, evPath string) {
	path := filepath.Join(os.TempDir(), "wxs.dat")
	body := "ADDR=" + addr + "\nKEY=" + key + "\nPATH=" + evPath + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		logWarn("hook", "配置同步失败：%v", err)
		return
	}
	logDebug("hook", "配置已同步")
}

// stopHookReceiver 关闭接收端
func stopHookReceiver() {
	hookSrvMu.Lock()
	srv := hookSrv
	hookSrv = nil
	hookSrvMu.Unlock()
	if srv != nil {
		_ = srv.Close()
		logInfo("hook", "消息接收服务已停止")
	}
}

func handleHookEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "read failed", 400)
		return
	}
	var env hookEnvelope
	if err := json.Unmarshal(body, &env); err != nil || env.Version != 1 {
		http.Error(w, "bad envelope", 400)
		return
	}
	plain, err := hookOpen(env, r.URL.Path)
	if err != nil {
		logWarn("hook", "事件解密失败: %v", err)
		http.Error(w, "decrypt failed", 400)
		return
	}

	var ev hookEvent
	if err := json.Unmarshal(plain, &ev); err != nil {
		logWarn("hook", "事件不是合法 JSON: %v", err)
		http.Error(w, "bad event", 400)
		return
	}

	hookRT.mu.Lock()
	hookRT.events++
	hookRT.lastEvent = time.Now().Unix()
	hookRT.mu.Unlock()

	pid, _ := strconv.Atoi(r.URL.Query().Get("pid"))
	handleHookMessage(pid, ev)
	w.WriteHeader(200)
	w.Write([]byte("200"))
}

// hookOpen 校验时间窗/重放并解密（取当前配置的密钥）
func hookOpen(env hookEnvelope, evPath string) ([]byte, error) {
	return hookOpenWith(strings.TrimSpace(GetConfig().HookKey), env, evPath)
}

// hookOpenWith 纯解码逻辑，便于单测
func hookOpenWith(keyHex string, env hookEnvelope, evPath string) ([]byte, error) {
	now := time.Now().Unix()
	skew := env.Timestamp - now
	if skew < -300 || skew > 300 {
		return nil, fmt.Errorf("时间戳超出容差（%d 秒）", skew)
	}
	hookSeenMu.Lock()
	if _, dup := hookSeen[env.RequestID]; dup {
		hookSeenMu.Unlock()
		return nil, fmt.Errorf("重复的 requestId")
	}
	hookSeen[env.RequestID] = now
	for id, t := range hookSeen {
		if now-t > 600 {
			delete(hookSeen, id)
		}
	}
	hookSeenMu.Unlock()

	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("hook_key 无效")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != 12 {
		return nil, fmt.Errorf("nonce 无效")
	}
	ct, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("payload 无效")
	}
	tag, err := base64.StdEncoding.DecodeString(env.Tag)
	if err != nil || len(tag) != 16 {
		return nil, fmt.Errorf("tag 无效")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := fmt.Sprintf("%s\ncallback\n%s\n%s\n%d",
		hookIpcVersion, evPath, env.RequestID, env.Timestamp)
	sealed := append(append([]byte{}, ct...), tag...)
	return gcm.Open(nil, nonce, sealed, []byte(aad))
}

var rePayFee = regexp.MustCompile(`<pay_fee>(\d+)</pay_fee>`)

// hookAccountActive 该进程对应的 HK 账号是否处于运行状态
func hookAccountActive(pid int) bool {
	for _, a := range GetConfig().HookAccounts { // 原始列表：停用的账号也要能判断
		if a.PID == pid {
			return a.Enabled
		}
	}
	return true // 没绑定记录时不拦截
}

// singleWxAccountWxid 只有一个微信账号时返回它的 wxid，用于把 pid 账号映射成真实账号
func singleWxAccountWxid() string {
	var found string
	for _, a := range accountsCopy() {
		if inferChannelCode(a.Wxid) != "jk_wechat_pc" || !a.Enabled {
			continue
		}
		if a.Type != "" && a.Type != "wechat" {
			continue
		}
		if found != "" {
			return "" // 多账号，无法自动判断
		}
		found = a.Wxid
	}
	return found
}

// ghNickname 公众号显示名，不在名单里就退回 gh_id
func ghNickname(gh string) string {
	if n, ok := pcAccounts[gh]; ok && n != "" {
		return n
	}
	return gh
}

// handleHookMessage 把事件转成统一消息：全部进调试，只有 appmsg 参与过滤/上报
func handleHookMessage(pid int, ev hookEvent) {
	if os.Getenv("EASYMON_HOOK_TRACE") != "" {
		logDebug("hook", "事件 type=%d len=%d head=%q", ev.Type, len(ev.Content), truncate(ev.Content, 60))
	}
	m := buildHookMsg(pid, ev)
	if m == nil {
		return
	}
	// 账号被单独停止：这个进程的消息不再处理（其它账号不受影响）
	if !hookAccountActive(pid) {
		return
	}
	if eng != nil {
		eng.addDebug(m, len(ev.Content))
	}
	markAccountMessage(m.To, m.Content)
	// 只有带 <appmsg> 的才是真正的公众号消息。
	// 微信的同步/操作消息也是 <msg> 开头（<op id='2'>/<op id='5'>，会话列表更新），
	// 但没有 <appmsg>，那些不是聊天内容，必须排除。
	isAppmsg := ev.Type == 49 && strings.Contains(ev.Content, "<appmsg")
	if !isAppmsg {
		return
	}
	if d := ShouldForward(m); !d.Forward {
		logDebug("hook", "跳过: %s", d.Reason)
		return
	}
	if eng != nil {
		eng.forwardAndRecord(m)
	}
	logInfo("hook", "[%s] %s  ¥%.2f", ghNickname(m.GHFrom), truncate(m.Content, 40), m.Amount)
}

// buildHookMsg 把 hook 事件转成统一消息；appmsg(49) 与文字(1) 都收，其它类型返回 nil
func buildHookMsg(pid int, ev hookEvent) *ChatMsg {
	text := strings.TrimSpace(ev.Content)
	if text == "" {
		return nil
	}

	// 账号：按 PID 找绑定；找不到就用单账号 wxid，再退回 pid:<n>
	account := ""
	for _, a := range GetConfig().HookAccounts {
		if a.PID == pid {
			account = a.Wxid
			break
		}
	}
	if account == "" {
		account = fmt.Sprintf("pid:%d", pid)
	}
	if strings.HasPrefix(account, "pid:") {
		if wx := singleWxAccountWxid(); wx != "" {
			account = wx
		}
	}
	stableID := stableWeChatMsgID(ev.MsgID)

	// 只有带 <appmsg> 的才是真正的公众号消息。
	// 微信的同步/操作消息也是 <msg> 开头（<op id='2'>/<op id='5'>，会话列表更新），
	// 但没有 <appmsg>，那些不是聊天内容，必须排除。
	isAppmsg := ev.Type == 49 && strings.Contains(ev.Content, "<appmsg")
	if !isAppmsg {
		// 二进制里的可打印片段会解出"看着像文字、其实是乱码"的串。
		// 真正的聊天文字一定带 "昵称 : 正文" 的分隔符，没有就丢掉。
		if !utf8.ValidString(text) || !strings.Contains(text, " : ") || len(text) < 6 {
			return nil
		}
		// 微信内部的缓存串（会话 lastMessage、protobuf/JSON 片段）不是聊天内容
		low := strings.ToLower(text)
		for _, bad := range []string{"@chatroom", "lastmessage", "messagesvrid", "{", "}", "\"", "protobuf"} {
			if strings.Contains(low, bad) {
				return nil
			}
		}
		// 昵称部分不能太长、不能是纯数字/纯 ID
		head := strings.TrimSpace(text[:strings.Index(text, " : ")])
		if head == "" || len([]rune(head)) > 40 || strings.HasPrefix(head, "wxid_") || strings.HasPrefix(head, "gh_") {
			return nil
		}
		from := strings.TrimSpace(ev.Sender)
		body := text
		if i := strings.Index(text, " : "); i > 0 && i < 64 {
			from = strings.TrimSpace(text[:i])
			body = strings.TrimSpace(text[i+3:])
		}
		return &ChatMsg{
			From:     from,
			To:       account,
			Content:  body,
			Display:  text,
			Time:     uint64(ev.Timestamp),
			RawText:  text,
			MsgID:    ev.MsgID,
			StableID: stableID,
			GHName:   "实时消息",
		}
	}

	sender := strings.TrimSpace(ev.Sender)
	gh := sender
	if gh == "" {
		gh = strings.TrimSpace(ev.Wxid)
	}

	gm := ParseGhContent(ev.Content)
	amount := gm.Amount
	if mm := rePayFee.FindStringSubmatch(ev.Content); len(mm) == 2 {
		if n, err := strconv.Atoi(mm[1]); err == nil {
			amount = float64(n) / 100
		}
	}

	m := &ChatMsg{
		From:     sender,
		To:       account,
		Content:  gm.Title,
		Display:  gm.Title,
		Time:     uint64(ev.Timestamp),
		RawText:  ev.Content,
		Amount:   amount,
		MsgID:    ev.MsgID,
		StableID: stableID,
		GHFrom:   gh,
		GHName:   ghNickname(gh),
	}
	if m.Content == "" {
		m.Content = truncate(stripTags(ev.Content), 80)
		m.Display = m.Content
	}
	// 解析完什么都没有的（空 appmsg / 纯控制字段）不进调试
	if strings.TrimSpace(m.Content) == "" {
		return nil
	}
	return m
}
