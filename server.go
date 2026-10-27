package main

// 内嵌 HTTP 服务：提供 UI 与配置/状态 API

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

//go:embed ui/index.html
var uiHTML []byte

type StatusResp struct {
	Attached      bool   `json:"attached"` // 数据库/日志监控是否在跑
	Live          bool   `json:"live"`
	HookAccounts  int    `json:"hook_accounts"` // 当前模式是否在工作（key=attached，hook=接收端+注入）
	Pid           uint32 `json:"pid"`
	WechatRunning bool   `json:"wechat_running"`
	Scanned       int    `json:"scanned"`
	Parsed        int    `json:"parsed"`
	Forwarded     int    `json:"forwarded"`
	Reported      int    `json:"reported"`
	Failed        int    `json:"failed"`
	Mode          string `json:"mode"`
	ForwardAll    bool   `json:"forward_all"`

	TodaySum     float64 `json:"today_sum"`
	TodayCount   int     `json:"today_count"`
	YesterdaySum float64 `json:"yesterday_sum"`
	YesterdayCnt int     `json:"yesterday_count"`
	WeekSum      float64 `json:"week_sum"`
	WeekCount    int     `json:"week_count"`
	AllSum       float64 `json:"all_sum"`
	AllCount     int     `json:"all_count"`
	SuccessRate  float64 `json:"success_rate"`

	// 各采集点独立计数
	Points []PointStat `json:"points"`

	// 多账号监控状态
	WxMode     string            `json:"wx_mode"`
	WxAccounts []WxMonitorStatus `json:"wx_accounts"`

	// 支付宝账号（总览页「账户状态总览」那张卡用）
	AliAccounts int `json:"ali_accounts"`
	AliOnline   int `json:"ali_online"`
}

type PointStat struct {
	Name    string `json:"name"`
	Scanned int    `json:"scanned"`
	Parsed  int    `json:"parsed"`
}

func writeAPIError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": err.Error()})
}

type MsgView struct {
	ID       string  `json:"id"`
	From     string  `json:"from"`
	To       string  `json:"to"`
	Content  string  `json:"content"`
	RawText  string  `json:"raw_content"` // XML 原文，详情页展示用
	Display  string  `json:"display"`
	Time     uint64  `json:"time"`
	RawID    string  `json:"rawid"`
	StableID string  `json:"stable_id,omitempty"`
	LocalID  int64   `json:"local_id,omitempty"`
	Amount   float64 `json:"amount"`
	PayType  string  `json:"pay_type"`
	Reported bool    `json:"reported"`
	Err      string  `json:"err"`

	// 订单记录字段
	Platform       string `json:"platform"`        // 微信
	ChannelCode    string `json:"channel_code"`    // jk_wechat_pc
	OrderStatus    string `json:"order_status"`    // 已收款 / 未识别
	CallbackStatus string `json:"callback_status"` // 已回调 / 回调失败 / 未上报
	CallbackBody   string `json:"callback_body"`   // 回调响应全文
	CallbackURL    string `json:"callback_url"`    // 实际请求地址

	// 采集来源：模式与账号（记录按这两项分目录存放）
	WxMode  string `json:"wx_mode"`
	Account string `json:"account"`
}

func (e *Engine) snapshot() StatusResp {
	// 支付宝统计要在拿 e.mu 之前取，避免和 alipayPollOne 的锁顺序交叉
	aliTotal, aliOnline := alipayAccountStats()

	e.mu.Lock()
	defer e.mu.Unlock()
	c := GetConfig()

	// 统计全部从已持久化的记录重算：重启后首页不为 0，也方便对账。
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix()
	ydayStart := todayStart - 86400
	weekStart := todayStart - 6*86400

	reported, failed, forwarded := 0, 0, 0
	var todaySum, ydaySum, weekSum, allSum float64
	todayCnt, ydayCnt, weekCnt, allCnt := 0, 0, 0, 0
	for _, m := range e.history {
		switch m.CallbackStatus {
		case "已回调":
			reported++
		case "回调失败":
			failed++
		}
		if m.Amount <= 0 {
			continue
		}
		forwarded++
		ts := int64(m.Time)
		if ts > 1e12 { // 毫秒
			ts /= 1000
		}
		allSum += m.Amount
		allCnt++
		if ts >= weekStart {
			weekSum += m.Amount
			weekCnt++
		}
		if ts >= todayStart {
			todaySum += m.Amount
			todayCnt++
		} else if ts >= ydayStart {
			ydaySum += m.Amount
			ydayCnt++
		}
	}
	rate := 0.0
	if total := reported + failed; total > 0 {
		rate = float64(reported) / float64(total) * 100
	}

	// 监听是否在跑：hook 或任一账号的数据库监控生效即算在线
	dbAll := WxStatusAll()
	dbLive := len(dbAll) > 0
	dbRounds := 0
	for _, s := range dbAll {
		dbRounds += s.PollRounds
	}
	live := e.hooks != nil || dbLive
	pid := e.stats.Pid
	if pid == 0 && GetConfig().EffectiveWxMode() == "hook" {
		if main := MainWeChatPid(); main != 0 {
			pid = main
		} else if ip := injectedPid; ip != 0 {
			pid = ip
		}
	}
	if pid == 0 && dbLive {
		pid = PidByName(WeChatProc)
	}

	return StatusResp{
		WxMode:       GetConfig().EffectiveWxMode(),
		Attached:     live,
		Live:         live || (GetConfig().EffectiveWxMode() == "hook" && hookRunning()),
		HookAccounts: len(GetConfig().EffectiveHookAccounts()),

		Pid:           pid,
		WechatRunning: PidByName(WeChatProc) != 0,
		Scanned:       dbRounds + e.stats.Scanned,
		Parsed:        forwarded,
		Forwarded:     forwarded,
		Reported:      reported,
		Failed:        failed,
		Mode:          c.Mode,
		ForwardAll:    c.ForwardAll,
		TodaySum:      todaySum,
		TodayCount:    todayCnt,
		YesterdaySum:  ydaySum,
		YesterdayCnt:  ydayCnt,
		WeekSum:       weekSum,
		WeekCount:     weekCnt,
		AllSum:        allSum,
		AllCount:      allCnt,
		SuccessRate:   rate,
		Points:        e.pointStatsLocked(),
		WxAccounts:    dbAll,
		AliAccounts:   aliTotal,
		AliOnline:     aliOnline,
	}
}

// DebugItem 调试用：金额识别之前的完整消息结构
type DebugItem struct {
	Mode    string  `json:"mode"` // key / hook，按模式分开看
	Seq     int     `json:"seq"`
	From    string  `json:"from"`
	To      string  `json:"to"`
	Content string  `json:"content"`
	RawText string  `json:"raw_content"` // XML 原文，详情页展示用
	Display string  `json:"display"`
	Time    uint64  `json:"time"`
	MsgID   uint64  `json:"msgid"`
	Amount  float64 `json:"amount"`
	PayType string  `json:"pay_type"`
	Bytes   int     `json:"bytes"`
	RawHead string  `json:"raw_head"`
	At      string  `json:"at"`
}

// 从 XML 消息里提取发送者 / 接收者
var (
	reFromUser = regexp.MustCompile(`fromusername\s*=\s*"([^"]+)"`)
	reToUser   = regexp.MustCompile(`tousername\s*=\s*"([^"]+)"`)
)

const debugMax = 20

// UnkSample 未识别的 pb 结构采样：用来判断某类消息是否经过了 hook
type UnkSample struct {
	Seq   int      `json:"seq"`
	Bytes int      `json:"bytes"`
	At    string   `json:"at"`
	From  string   `json:"from"`
	To    string   `json:"to"`
	Head  string   `json:"head"`
	Texts []string `json:"texts"`
}

const unkMax = 40

func (e *Engine) addUnknown(buf []byte) {
	var fs []PBField
	ParsePB(buf, 0, "", &fs)

	texts := make([]string, 0, 10)
	seen := map[string]bool{}
	for _, f := range fs {
		if f.Wire != 2 || len(f.Bytes) < 2 || len(f.Bytes) >= 120 {
			continue
		}
		s := trimStr(f.Bytes)
		if s == "" || seen[s] || len(texts) >= 10 {
			continue
		}
		seen[s] = true
		texts = append(texts, s)
	}

	n := len(buf)
	if n > 48 {
		n = 48
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.unkSeq++
	it := UnkSample{
		Seq: e.unkSeq, Bytes: len(buf), At: time.Now().Format("15:04:05"),
		Head: fmt.Sprintf("% X", buf[:n]), Texts: texts,
	}
	e.unknowns = append([]UnkSample{it}, e.unknowns...)
	if len(e.unknowns) > unkMax {
		e.unknowns = e.unknowns[:unkMax]
	}
}

func (e *Engine) addDebug(m *ChatMsg, rawLen int) {
	e.addDebugFrom(m, rawLen, "hook")
}

// addDebugFrom src: "hook" = 实时推送；"db" = 数据库监听
// 两者的过滤规则完全不同，调试页按来源分开，避免数据库的缓存串混进实时调试
func (e *Engine) addDebugFrom(m *ChatMsg, rawLen int, src string) {
	mode := GetConfig().EffectiveWxMode()
	if src == "db" {
		mode = "db"
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	head := ""
	if len(m.Raw) > 0 {
		n := len(m.Raw)
		if n > 64 {
			n = 64
		}
		head = fmt.Sprintf("% X", m.Raw[:n])
	}
	e.debugSeq++
	it := DebugItem{
		Mode:    mode,
		PayType: ExtractPayType(m.Display),
		Seq:     e.debugSeq, From: m.From, To: m.To, Content: m.Content,
		Display: m.Display, Time: m.Time, MsgID: m.MsgID, Amount: m.Amount,
		Bytes: rawLen, RawHead: head, At: time.Now().Format("15:04:05"),
	}
	e.debug = append([]DebugItem{it}, e.debug...)
	if len(e.debug) > debugMax {
		e.debug = e.debug[:debugMax]
	}
}

// addHistory 记录一条微信消息。res 为 nil 表示未上报。
func (e *Engine) addHistory(m *ChatMsg, reported bool, errMsg string, res *ReportResult) {
	e.addHistoryEx(m, reported, errMsg, res, "微信", "jk_wechat_pc")
}

// addHistoryEx 记录一条收款记录，平台与通道编码由调用方指定。
// 微信走 addHistory（固定 微信 / jk_wechat_pc），支付宝走这里传 支付宝 / alipay_app。
func (e *Engine) addHistoryEx(m *ChatMsg, reported bool, errMsg string, res *ReportResult, platform, channelCode string) {
	if platform == "" {
		platform = "微信"
	}
	if channelCode == "" {
		channelCode = "jk_wechat_pc"
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	orderStatus := "未识别"
	if m.Amount > 0 {
		orderStatus = "已收款"
	}

	cbStatus := "未上报"
	cbBody := ""
	cbURL := ""
	if res != nil && res.Delivered {
		// 真的向平台发过请求，才谈得上回调成功/失败
		cbURL = res.URL
		cbBody = res.Body
		if reported {
			cbStatus = "已回调"
		} else {
			cbStatus = "回调失败"
			if cbBody == "" {
				cbBody = res.Err
			}
		}
	} else if res != nil {
		// 未配置接口 / 仅记录模式
		cbBody = res.Body
	}

	mode := GetConfig().EffectiveWxMode()
	if platform == "支付宝" {
		mode = "alipay"
	}
	v := MsgView{
		WxMode:  mode,
		Account: m.To,
		From:    m.From, To: m.To, Content: m.Content, RawText: m.RawText, Display: m.Display,
		Time: m.Time, RawID: fmt.Sprintf("%d", m.MsgID), StableID: m.StableID, LocalID: m.LocalID, Amount: m.Amount,
		Reported: reported, Err: errMsg,
		Platform: platform, ChannelCode: channelCode, OrderStatus: orderStatus,
		CallbackStatus: cbStatus, CallbackBody: cbBody, CallbackURL: cbURL,
	}
	e.history = append([]MsgView{v}, e.history...)
	if len(e.history) > recordsMax {
		e.history = e.history[:recordsMax]
	}
	markRecordsDirty()
}

// pointStatsLocked 调用方必须已持有 e.mu（snapshot 已加锁，不能再 Lock）
func (e *Engine) pointStatsLocked() []PointStat {
	out := make([]PointStat, 0, len(e.hooks))
	for _, hk := range e.hooks {
		out = append(out, PointStat{Name: hk.Point.Name, Scanned: hk.Scanned, Parsed: hk.Parsed})
	}
	return out
}

func (e *Engine) historyCopy(limit int) []MsgView {
	e.mu.Lock()
	defer e.mu.Unlock()
	if limit <= 0 || limit > len(e.history) {
		limit = len(e.history)
	}
	out := make([]MsgView, limit)
	copy(out, e.history[:limit])
	return out
}

func startServer() (int, error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		// 版本号只有 main.go 里一份真相，界面用占位符替换，
		// 避免标题栏和「关于」页各写一个数字然后对不上。
		w.Write(bytes.ReplaceAll(uiHTML, []byte("__APP_VERSION__"), []byte(AppVersion)))
	})

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(eng.snapshot())
	})
	mux.HandleFunc("/api/messages", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit := 200
		if v := q.Get("limit"); v != "" {
			fmt.Sscanf(v, "%d", &limit)
		}
		items := eng.historyCopy(limit)
		// 记录按采集模式隔离：默认只看当前模式，?mode=all 才合并
		{
			want := q.Get("mode")
			if want == "" {
				want = GetConfig().EffectiveWxMode()
			}
			if want != "all" {
				keep := make([]MsgView, 0, len(items))
				for _, v := range items {
					switch v.WxMode {
					case "", "alipay":
						keep = append(keep, v)
					case "db":
						if want == "key" {
							keep = append(keep, v)
						}
					default:
						if v.WxMode == want {
							keep = append(keep, v)
						}
					}
				}
				items = keep
			}
		}
		// amount_only=1：只给带金额的（收款记录页用，聊天消息不进列表）
		if q.Get("amount_only") == "1" {
			filtered := make([]MsgView, 0, len(items))
			for _, v := range items {
				if v.Amount > 0 {
					filtered = append(filtered, v)
				}
			}
			items = filtered
		}
		// 每条给一个稳定 id，供删除使用
		for i := range items {
			items[i].ID = msgID(&items[i])
		}
		json.NewEncoder(w).Encode(items)
	})

	const secretMask = "******"

	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// 按要求回传明文，方便核对；仍是本机回环接口，只对本机可读
			c := GetConfig()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(c)
			return
		}
		if r.Method == "POST" {
			var c Config
			if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			// 串行化读-改-写：并发保存不会互相覆盖（账号列表/密钥/模式原子更新）
			var oldWxMode, newWxMode string
			errReject := errors.New("reject")
			rejectMsg := ""
			if err := UpdateConfig(func(cur *Config) error {
				oldWxMode = cur.EffectiveWxMode()
				m := c // 界面提交的快照
				m.DbAccounts = cur.DbAccounts
				m.DbWxid, m.DbKey = cur.DbWxid, cur.DbKey
				m.HookAccounts = cur.HookAccounts
				if m.XPaySecret == "" || m.XPaySecret == secretMask {
					m.XPaySecret = cur.XPaySecret
				}
				if m.V1Secret == "" || m.V1Secret == secretMask {
					m.V1Secret = cur.V1Secret
				}
				if m.YjkToken == "" || m.YjkToken == secretMask {
					m.YjkToken = cur.YjkToken
				}
				newWxMode = m.EffectiveWxMode()
				if newWxMode != oldWxMode {
					if oldWxMode == "hook" && len(cur.EffectiveHookAccounts()) > 0 {
						rejectMsg = "切换前请先删除 HK 模式下的微信账号"
						return errReject
					}
					if oldWxMode == "key" && len(cur.EffectiveDbAccounts()) > 0 {
						rejectMsg = "切换前请先删除通行密钥模式下的微信账号"
						return errReject
					}
				}
				*cur = m
				c = m
				return nil
			}); err != nil {
				if err == errReject {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(409)
					json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": rejectMsg})
					return
				}
				http.Error(w, err.Error(), 500)
				return
			}
			logInfo("config", "配置已更新: mode=%s wx_mode=%s forward_all=%v",
				c.Mode, c.EffectiveWxMode(), c.ForwardAll)
			if newWxMode != oldWxMode {
				switchWxMode(newWxMode)
			}
			// 心跳必须跟随模式：
			//   X-Ypay 有心跳接口 → 切过来立刻拉起并先发一轮；
			//   码支付V1 没有心跳接口 → 切过去必须彻底停发。
			if strings.TrimSpace(c.Mode) == "xpay" {
				ensureXPayHeartbeat()
			} else {
				stopXPayHeartbeat()
			}
			w.Write([]byte(`{"ok":true}`))
			return
		}
		ensureXPayHeartbeat() // 切到 X-Ypay 后让心跳立刻开始跑
		json.NewEncoder(w).Encode(GetConfig())
	})

	// 账号列表
	// ---------- 支付宝账号 ----------
	mux.HandleFunc("/api/alipay", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case "GET":
			json.NewEncoder(w).Encode(alipayViews())
		case "DELETE":
			id := r.URL.Query().Get("id")
			if id == "" {
				http.Error(w, "id required", 400)
				return
			}
			s, ok := findAlipaySession(id)
			if ok && s.PID != "" {
				if err := removeAccount(s.PID); err != nil {
					writeAPIError(w, http.StatusInternalServerError, err)
					return
				}
			}
			removeAlipaySession(id)
			saveAlipaySessions()
			w.Write([]byte(`{"ok":true}`))
		default:
			http.Error(w, "method not allowed", 405)
		}
	})

	// 新建一个待扫码会话
	mux.HandleFunc("/api/alipay/new", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		s := AlipaySession{
			ID:        newAlipaySessionID(),
			Status:    "waiting",
			CreatedAt: time.Now().Format("2006-01-02T15:04:05Z07:00"),
			LoginURL:  alipayLoginURL(),
		}
		upsertAlipaySession(s)
		saveAlipaySessions()
		json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "id": s.ID, "login_url": s.LoginURL,
		})
	})

	// 生成登录二维码（软件内显示，不开浏览器）
	mux.HandleFunc("/api/alipay/qr/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var req struct {
			ID string `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		var sess AlipaySession
		ok := false
		if req.ID != "" {
			sess, ok = findAlipaySession(req.ID)
		}
		if !ok {
			sess = AlipaySession{
				ID:        newAlipaySessionID(),
				Status:    "waiting",
				CreatedAt: time.Now().Format("2006-01-02T15:04:05Z07:00"),
			}
			upsertAlipaySession(sess)
			saveAlipaySessions()
		}

		qr, err := alipayNewQR(sess.ID)
		if err != nil {
			logWarn("alipay", "生成二维码失败：%v", err)
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": err.Error()})
			return
		}
		logInfo("alipay", "已生成登录二维码，等待扫码")
		json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "id": sess.ID, "qr_url": qr.QRURL,
		})
	})

	// 账单安全校验：二维码图片
	mux.HandleFunc("/api/alipay/security/qr", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		chk := getPendingCheck(id)
		if chk == nil {
			http.Error(w, "no pending check", 404)
			return
		}
		png, err := qrImagePNG(chk.QRURL, 240)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(png)
	})

	// 账单安全校验：扫码后提交
	mux.HandleFunc("/api/alipay/security/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		id := r.URL.Query().Get("id")
		chk := getPendingCheck(id)
		if chk == nil {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "没有待验证的请求"})
			return
		}
		s, ok := findAlipaySession(id)
		if !ok {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "会话不存在"})
			return
		}
		// 先查扫码状态
		st, msg, err := alipayPollSecurityStatus(chk)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": err.Error()})
			return
		}
		if st != "confirmed" {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "state": st, "err": msg})
			return
		}
		if err := alipaySubmitSecurityCheck(&s, chk); err != nil {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": err.Error()})
			return
		}
		setPendingCheck(id, nil)
		s.HeartbeatMsg = "安全校验已通过"
		upsertAlipaySession(s)
		saveAlipaySessions()
		go alipayPollOne(s)
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	// 用已有 Cookie 重新获取 PID（登录成功但当时没取到时用）
	mux.HandleFunc("/api/alipay/refresh-pid", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		id := r.URL.Query().Get("id")
		pid, err := alipayRefreshPID(id)
		if err != nil {
			logWarn("alipay", "重新获取 PID 失败：%v", err)
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "pid": pid})
	})

	// 二维码图片
	mux.HandleFunc("/api/alipay/qr/image", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		png, err := alipayQRPNG(id, 240)
		if err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(png)
	})

	// 扫码状态
	mux.HandleFunc("/api/alipay/qr/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		id := r.URL.Query().Get("id")
		st := getQRState(id)
		s, _ := findAlipaySession(id)
		// 浏览器登录时没有二维码状态，message 用会话心跳兜底，
		// 界面才能显示「登录窗口已关闭 / 扫码超时」这类提示
		msg := st.Message
		if msg == "" {
			msg = s.HeartbeatMsg
		}
		json.NewEncoder(w).Encode(map[string]any{
			"qr_status": st.Status, "message": msg,
			"session_status": s.Status, "pid": s.PID,
			// 界面上的 UID：没拿到真实 PID 时用会话 ID，和参考程序一致
			"session_uid": s.ID,
		})
	})

	// 打开浏览器扫码登录。立即返回，登录在后台跑。
	//
	// 和参考程序（Wails + WebView2）保持一致：登录在真浏览器里完成，
	// 一次扫码就把整份 cookie（alipay.com / auth / authsa / authea / my / securitycore）
	// 拿下来，再用收款接口验证一次。自造的 HTTP 表单登录拿不到这么全的 cookie。
	mux.HandleFunc("/api/alipay/login/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var req struct {
			ID string `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		// 先确认本机有可用浏览器，否则让界面退回内置二维码
		if findBrowser() == "" {
			json.NewEncoder(w).Encode(map[string]any{
				"ok": false, "err": "没找到 Edge 或 Chrome，无法用浏览器登录",
			})
			return
		}

		var sess AlipaySession
		ok := false
		if req.ID != "" {
			sess, ok = findAlipaySession(req.ID)
		}
		if !ok {
			sess = AlipaySession{
				ID:        newAlipaySessionID(),
				Status:    "waiting",
				CreatedAt: time.Now().Format("2006-01-02T15:04:05Z07:00"),
				LoginURL:  alipayLoginURL(),
			}
			upsertAlipaySession(sess)
			saveAlipaySessions()
		} else {
			sess.Status = "waiting"
			sess.HeartbeatMsg = "等待扫码…"
			upsertAlipaySession(sess)
			saveAlipaySessions()
		}

		sid := sess.ID
		loginURL := sess.LoginURL
		if loginURL == "" {
			loginURL = alipayLoginURL()
		}

		// 首选：无头浏览器出二维码，画在软件里（和参考程序一样不弹窗口），
		// cookie 仍然是真浏览器产出的整份。
		if q, err := alipayStartBrowserQR(sess); err == nil {
			json.NewEncoder(w).Encode(map[string]any{
				"ok": true, "id": sid, "mode": "qr", "qr_url": q.QRURL,
			})
			return
		} else {
			logWarn("alipay", "无头浏览器扫码不可用，改用可见浏览器窗口：%v", err)
		}

		go func() {
			logInfo("alipay", "已打开登录窗口，等待扫码（最长 5 分钟）")
			cookies, ua, err := browserLogin(loginURL, 5*time.Minute)

			s, found := findAlipaySession(sid)
			if !found {
				return
			}
			if err != nil {
				s.Status = "waiting"
				s.HeartbeatMsg = err.Error()
				upsertAlipaySession(s)
				saveAlipaySessions()
				logWarn("alipay", "登录未完成：%v", err)
				return
			}

			s.Cookies = cookies
			s.UA = ua
			s.Status = "confirmed"
			s.OnlineSince = time.Now().Format("2006-01-02T15:04:05Z07:00")
			s.LastCheck = s.OnlineSince
			s.HeartbeatMsg = "登录成功"

			// 真正的验收：收款接口能把 USERID/bizToken/sid 给我，才算登录成功。
			// 只验证「my.alipay.com 不是登录页」不够 —— 那只能说明有 SSO，
			// 后面每 5 秒拉收款记录靠的是 csmobile 那套。
			var userID, bizToken, csid string
			for attempt := 1; attempt <= 3; attempt++ {
				userID, bizToken, csid, err = alipayChatTokens(&s)
				if err == nil && userID != "" {
					break
				}
				logWarn("alipay", "登录后验证收款接口第 %d 次失败：%v", attempt, err)
				time.Sleep(time.Duration(attempt) * time.Second)
			}
			if err == nil && userID != "" {
				s.PID = userID
				s.MaskedID = maskPid(userID)
				s.BizToken, s.SID = bizToken, csid
				s.HeartbeatMsg = "在线"
			} else {
				s.HeartbeatMsg = "登录成功，但收款接口不可用：" + truncate(fmt.Sprint(err), 80)
			}

			upsertAlipaySession(s)
			saveAlipaySessions()

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
			logInfo("alipay", "登录完成：Cookie %d 条，PID=%s，%s",
				len(cookies), maskPid(s.PID), s.HeartbeatMsg)
		}()

		json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": sid, "mode": "browser"})
	})

	// 把浏览器里拿到的 Cookie 写进会话
	mux.HandleFunc("/api/alipay/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var req struct {
			ID      string         `json:"id"`
			Cookies []AlipayCookie `json:"cookies"`
			PID     string         `json:"pid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "参数不对"})
			return
		}
		s, ok := findAlipaySession(req.ID)
		if !ok {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "会话不存在"})
			return
		}
		s.Cookies = req.Cookies
		if req.PID != "" {
			s.PID = req.PID
			s.MaskedID = maskPid(req.PID)
		}
		s.Status = "confirmed"
		s.OnlineSince = time.Now().Format("2006-01-02T15:04:05Z07:00")
		upsertAlipaySession(s)
		saveAlipaySessions()

		// 同步到上报账号表，Report() 才能找到它
		if s.PID != "" {
			ch := s.ChannelFor(GetConfig().Mode)
			if a, had := findAccount(s.PID); had {
				ch = a.ChannelID
			}
			if err := upsertAccount(Account{
				Type: "alipay", Wxid: s.PID, Nick: s.Nick,
				ChannelID: ch, ChannelCode: "alipay_app", Enabled: true,
			}); err != nil {
				writeAPIError(w, http.StatusInternalServerError, err)
				return
			}
		}
		logInfo("alipay", "账号 %s 登录成功，Cookie %d 条", maskPid(s.PID), len(s.Cookies))
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	// 绑定通道 ID
	mux.HandleFunc("/api/alipay/channel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var req struct {
			ID        string `json:"id"`
			ChannelID string `json:"channel_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "参数不对"})
			return
		}
		s, ok := findAlipaySession(req.ID)
		if !ok {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "会话不存在"})
			return
		}
		if owner, used := channelOwner(GetConfig().Mode, req.ChannelID, s.PID); used {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(409)
			json.NewEncoder(w).Encode(map[string]any{
				"ok": false, "err": fmt.Sprintf("通道 %s 已被账号 %s 占用，同一接口模式下不能重复", req.ChannelID, short(owner)),
			})
			return
		}
		s.SetChannelFor(GetConfig().Mode, req.ChannelID)
		upsertAlipaySession(s)
		saveAlipaySessions()
		if strings.TrimSpace(GetConfig().Mode) == "xpay" {
			ensureXPayHeartbeat()
			go xpayHeartbeatRound()
		}
		if s.PID != "" {
			if err := upsertAccount(Account{
				Type: "alipay", Wxid: s.PID, Nick: s.Nick,
				ChannelID: s.ChannelFor(GetConfig().Mode), ChannelCode: "alipay_app", Enabled: true,
			}); err != nil {
				writeAPIError(w, http.StatusInternalServerError, err)
				return
			}
		}
		logInfo("config", "支付宝账号 %s 绑定通道 %s（模式 %s）", maskPid(s.PID), s.ChannelID, GetConfig().Mode)
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	// 抓一次账单并存原始响应，用于校准解析器
	mux.HandleFunc("/api/alipay/fetch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		id := r.URL.Query().Get("id")
		s, ok := findAlipaySession(id)
		if !ok {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "会话不存在"})
			return
		}
		body, err := alipayFetchBill(&s)
		now := time.Now().Format("2006-01-02T15:04:05Z07:00")
		if err != nil {
			// 抓失败也要把状态写回，否则界面还显示"在线"
			s.LastCheck = now
			s.HeartbeatMsg = err.Error()
			if strings.Contains(err.Error(), "登录已失效") {
				s.Status = "expired"
			}
			upsertAlipaySession(s)
			saveAlipaySessions()
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": err.Error()})
			return
		}
		_ = os.WriteFile(alipayRawFile(), body, 0600)
		bills := alipayParseBills(body)
		s.LastCheck = now
		s.LastHeartbeat = now
		s.HeartbeatMsg = fmt.Sprintf("正常，解析到 %d 笔", len(bills))
		upsertAlipaySession(s)
		saveAlipaySessions()
		logInfo("alipay", "抓账单：%d 字节，解析出 %d 条", len(body), len(bills))
		json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "bytes": len(body), "bills": bills,
			"preview": firstN(string(body), 600),
		})
	})

	// 手动轮询一次
	mux.HandleFunc("/api/alipay/poll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		alipayPollRound()
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/accounts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var a Account
			if err := json.NewDecoder(r.Body).Decode(&a); err != nil || a.Wxid == "" {
				http.Error(w, "bad request", 400)
				return
			}
			// 通道编码不由用户选，按账号类型定
			a.ChannelCode = inferChannelCode(a.Wxid)
			// 同一接口模式下通道号不能重复，否则平台会串账
			if owner, used := channelOwner(GetConfig().Mode, a.ChannelID, a.Wxid); used {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(409)
				json.NewEncoder(w).Encode(map[string]any{
					"ok": false, "err": fmt.Sprintf("通道 %s 已被账号 %s 占用，同一接口模式下不能重复", a.ChannelID, short(owner)),
				})
				return
			}
			// 通道号按平台分存：X-Ypay 与码支付V1 是两套编号
			mode := GetConfig().Mode
			a.SetChannelFor(mode, a.ChannelID)
			if err := upsertAccount(a); err != nil {
				writeAPIError(w, http.StatusInternalServerError, err)
				return
			}
			logInfo("config", "账号通道已保存 wxid=%s 通道=%s（模式 %s）编码=%s",
				a.Wxid, a.ChannelID, mode, a.ChannelCode)
			if strings.TrimSpace(GetConfig().Mode) == "xpay" {
				ensureXPayHeartbeat()
				go xpayHeartbeatRound()
			}
			w.Write([]byte(`{"ok":true}`))
			return
		}
		if err := accountsError(); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		// 默认只给微信账号，支付宝账号走 /api/alipay。
		// 需要全部时加 ?type=all。
		list := accountsCopy()
		if r.URL.Query().Get("type") != "all" {
			only := make([]Account, 0, len(list))
			for _, a := range list {
				if accountKind(a) == "wechat" {
					only = append(only, a)
				}
			}
			list = only
		}
		json.NewEncoder(w).Encode(list)
	})

	mux.HandleFunc("/api/accounts/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		wxid := r.URL.Query().Get("wxid")
		if wxid == "" {
			http.Error(w, "wxid required", 400)
			return
		}
		if err := deleteAccountAll(wxid); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	})

	// 清空指定记录（按 id 列表）
	mux.HandleFunc("/api/messages/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		var req struct {
			IDs []string `json:"ids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.IDs) == 0 {
			http.Error(w, "bad request", 400)
			return
		}
		del := make(map[string]bool, len(req.IDs))
		for _, id := range req.IDs {
			del[id] = true
		}
		removed := eng.deleteRecords(del)
		logInfo("config", "清空记录 %d 条", removed)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "removed": removed})
	})

	mux.HandleFunc("/api/unknown", func(w http.ResponseWriter, r *http.Request) {
		e := eng
		e.mu.Lock()
		out := make([]UnkSample, len(e.unknowns))
		copy(out, e.unknowns)
		e.mu.Unlock()
		json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("/api/sysinfo", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(sysInfo())
	})

	// 扫描本机微信账号目录（只读，不碰微信进程）
	mux.HandleFunc("/api/wx/scan", func(w http.ResponseWriter, r *http.Request) {
		accs := ScanWxAccounts()
		type item struct {
			Wxid    string `json:"wxid"`
			Dir     string `json:"dir"`
			HasBiz  bool   `json:"has_biz"`
			ModTime string `json:"mod_time"`
			Bound   bool   `json:"bound"`
		}
		out := make([]item, 0, len(accs))
		for _, a := range accs {
			_, bound := findAccount(a.Wxid)
			mt := ""
			if !a.ModTime.IsZero() {
				mt = a.ModTime.Format("2006-01-02 15:04")
			}
			out = append(out, item{
				Wxid: a.Wxid, Dir: a.Dir, HasBiz: a.HasBiz,
				ModTime: mt, Bound: bound,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"root":     WeChatRoot(),
			"accounts": out,
		})
	})

	// 自动获取密钥：hook 微信进程，取数据库密钥
	mux.HandleFunc("/api/wx/getkey", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		sec := 12
		if v := r.URL.Query().Get("sec"); v != "" {
			fmt.Sscanf(v, "%d", &sec)
			if sec < 3 {
				sec = 3
			}
			if sec > 60 {
				sec = 60
			}
		}
		res := ExtractKey(time.Duration(sec)*time.Second, r.URL.Query().Get("wxid"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	})

	// 异步扫描密钥（自研内存扫描，带进度）
	mux.HandleFunc("/api/wx/getkey/async", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		StartKeyScan(r.URL.Query().Get("wxid"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/wx/getkey/progress", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scanProgress())
	})

	// 绑定账号：校验密钥 → 保存账号与配置 → 启动监控
	mux.HandleFunc("/api/wx/bind", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		var req struct {
			Wxid        string `json:"wxid"`
			Key         string `json:"key"`
			ChannelID   string `json:"channel_id"`
			ChannelCode string `json:"channel_code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Wxid == "" {
			http.Error(w, "bad request", 400)
			return
		}
		key := strings.TrimSpace(strings.ToLower(req.Key))
		if len(key) != 64 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"ok": false, "err": "密钥必须是 64 位十六进制",
			})
			return
		}
		acc, found := findWxAccount(req.Wxid)
		if !found {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"ok": false, "err": "未找到该账号的数据目录",
			})
			return
		}
		if !acc.HasBiz {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"ok": false, "err": "该账号没有 biz_message_0.db（未登录过微信 PC 端公众号）",
			})
			return
		}

		// 先试打开，密钥不对就不落盘
		db, err := OpenWxDB(acc.BizDB, key)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"ok": false, "err": "密钥校验失败：" + err.Error(),
			})
			return
		}
		tables, _ := db.Tables()
		db.Close()

		// 保存账号：没传通道就保留原来的，避免把已绑定的清掉
		ch := strings.TrimSpace(req.ChannelID)
		code := strings.TrimSpace(req.ChannelCode)
		old, had := findAccount(req.Wxid)
		if ch == "" && had {
			ch = old.ChannelID
		}
		// 通道编码按账号类型定，忽略请求里传来的值
		code = inferChannelCode(req.Wxid)
		nick := req.Wxid
		if had && old.Nick != "" {
			nick = old.Nick
		}
		if err := upsertAccount(Account{
			Wxid: req.Wxid, Nick: nick,
			ChannelID: ch, ChannelCode: code, Enabled: true,
		}); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}

		// 保存到多账号列表（同一 wxid 就更新密钥，不重复添加）
		cfg := GetConfig()
		cfg.DbEnabled = true
		dup := false
		for i := range cfg.DbAccounts {
			if cfg.DbAccounts[i].Wxid == req.Wxid {
				cfg.DbAccounts[i].Key = key
				cfg.DbAccounts[i].Enabled = true
				dup = true
				break
			}
		}
		if !dup {
			cfg.DbAccounts = append(cfg.DbAccounts, DbAccount{
				Wxid: req.Wxid, Key: key, Enabled: true,
			})
		}
		// 主账号字段只在为空时补上，保持向后兼容
		if cfg.DbWxid == "" {
			cfg.DbWxid = req.Wxid
			cfg.DbKey = key
		}
		SetConfig(cfg)

		// 只（重新）启动这个账号，别的账号不受影响
		if err := StartWxMonitor(acc.BizDB, key, acc.Wxid, acc); err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"ok": false, "err": "监控启动失败：" + err.Error(),
			})
			return
		}
		InitDefaultWatches()

		logInfo("config", "账号已绑定 %s（%d 张消息表，共 %d 个账号在监控）",
			req.Wxid, len(tables), len(cfg.EffectiveDbAccounts()))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "tables": len(tables),
		})
	})

	// 解除某个账号的监控（保留订单记录）
	mux.HandleFunc("/api/wx/unbind", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		wxid := r.URL.Query().Get("wxid")
		if wxid == "" {
			http.Error(w, "wxid required", 400)
			return
		}
		StopWxMonitorFor(wxid)

		cfg := GetConfig()
		kept := make([]DbAccount, 0, len(cfg.DbAccounts))
		for _, a := range cfg.DbAccounts {
			if a.Wxid != wxid {
				kept = append(kept, a)
			}
		}
		cfg.DbAccounts = kept
		if cfg.DbWxid == wxid {
			cfg.DbWxid = ""
			cfg.DbKey = ""
		}
		SetConfig(cfg)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/wx/mode", func(w http.ResponseWriter, r *http.Request) {
		c := GetConfig()
		keys := make([]string, 0, len(c.EffectiveDbAccounts()))
		for _, a := range c.EffectiveDbAccounts() {
			keys = append(keys, a.Wxid)
		}
		hooks := c.HookAccounts // 停止的账号也要返回，界面才能显示并重新启动
		type hookView struct {
			HookAccount
			Online bool `json:"online"`
		}
		hookViews := make([]hookView, 0, len(hooks))
		for _, a := range hooks {
			hookViews = append(hookViews, hookView{HookAccount: a, Online: a.PID != 0 && moduleLoaded(uint32(a.PID), "easymon_hook")})
		}
		out := map[string]any{
			"mode": c.EffectiveWxMode(), "key_accounts": keys,
			"hook_accounts": hookViews, "hook": hookStateSnapshot(), "dll": HookDLLInfo(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})

	// 启动一个微信实例，给"新增账号"用
	mux.HandleFunc("/api/wx/launch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		exe := strings.TrimSpace(GetConfig().WeChatExe)
		if exe == "" {
			exe = `D:\Weixin\Weixin.exe`
		}
		if _, err := os.Stat(exe); err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "找不到微信程序：" + exe})
			return
		}
		cmd := exec.Command(exe)
		cmd.Dir = filepath.Dir(exe)
		if err := cmd.Start(); err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": err.Error()})
			return
		}
		logInfo("hook", "已启动微信客户端（用于登录新账号）")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/wx/hook/account", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		var req HookAccount
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
			(req.Wxid == "" && req.PID == 0) {
			http.Error(w, "bad request", 400)
			return
		}
		// 界面只回传 wxid 时，从已有账号里补回 PID，别把 pid 写成 0
		if req.PID == 0 {
			for _, old := range GetConfig().EffectiveHookAccounts() {
				if old.Wxid == req.Wxid && old.PID != 0 {
					req.PID = old.PID
					break
				}
			}
		}
		// 拿不到 wxid 时先按数据目录推断，最后才退回 pid
		if req.Wxid == "" {
			if wx := singleWxidFromDisk(); wx != "" {
				req.Wxid = wx
			} else {
				req.Wxid = fmt.Sprintf("pid:%d", req.PID)
			}
		}
		req.Enabled = true
		c := GetConfig()
		mode := c.Mode
		// 同一接口模式下通道号不能重复（微信与支付宝共用一套编号）
		if owner, used := channelOwner(mode, req.ChannelID, req.Wxid); used {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(409)
			json.NewEncoder(w).Encode(map[string]any{
				"ok": false, "err": fmt.Sprintf("通道 %s 已被账号 %s 占用，同一接口模式下不能重复", req.ChannelID, short(owner)),
			})
			return
		}
		found := false
		for i := range c.HookAccounts {
			if c.HookAccounts[i].Wxid == req.Wxid {
				// 保留另一个接口模式的通道号，切平台不用重绑
				req.ChannelIDXpay = c.HookAccounts[i].ChannelIDXpay
				req.ChannelIDV1 = c.HookAccounts[i].ChannelIDV1
				req.SetChannelFor(mode, req.ChannelID)
				c.HookAccounts[i] = req
				found = true
				break
			}
		}
		if !found {
			req.SetChannelFor(mode, req.ChannelID)
			c.HookAccounts = append(c.HookAccounts, req)
		}
		// 同一进程只保留一个账号：把旧的 pid:xxxx 别名清掉
		dedup := make([]HookAccount, 0, len(c.HookAccounts))
		for _, a := range c.HookAccounts {
			if a.PID == req.PID && a.Wxid != req.Wxid {
				continue
			}
			dedup = append(dedup, a)
		}
		c.HookAccounts = dedup
		if err := SetConfig(c); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		c.HookNoAutoBind = false
		if c.HookBlockedWxid(req.Wxid) {
			kept := make([]string, 0, len(c.HookBlocked))
			for _, x := range c.HookBlocked {
				if x != req.Wxid {
					kept = append(kept, x)
				}
			}
			c.HookBlocked = kept
		}
		if err := SetConfig(c); err != nil {
			logWarn("hook", "保存配置失败：%v", err)
		}
		logInfo("hook", "账号已保存 %s（通道 %s）", req.Wxid, req.ChannelID)
		if c.EffectiveWxMode() == "hook" {
			stopHookSource()
			startHookSource()
		}
		// 新增/修改账号后立刻发一轮心跳，不等 60 秒周期，
		// 否则平台那边会有一分钟看不到这个通道在线。
		if strings.TrimSpace(c.Mode) == "xpay" {
			ensureXPayHeartbeat()
			go xpayHeartbeatRound()
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})

	mux.HandleFunc("/api/wx/hook/dll", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(HookDLLInfo())
	})

	mux.HandleFunc("/api/wx/hook/inject", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		dll := hookDLLPath()
		if dll == "" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":false,"err":"未找到 hook DLL"}`))
			return
		}
		pids := MainPidsOf(WeChatProc)
		if len(pids) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":false,"err":"微信未运行"}`))
			return
		}
		if err := injectDLL(pids[0], dll); err != nil {
			logError("hook", "接入微信失败：%v", err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": err.Error()})
			return
		}
		injectedPid = pids[0]
		logInfo("hook", "已连接微信进程 %d", pids[0])
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "pid": pids[0]})
	})

	// 账号启停：状态独立保存；停止只停这个账号，删除才清账号（订单记录保留）
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(healthSnapshot())
	})

	mux.HandleFunc("/api/accounts/state", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		var req struct {
			Wxid    string `json:"wxid"`
			Enabled bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Wxid == "" {
			http.Error(w, "bad request", 400)
			return
		}
		if err := accountsError(); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		a, ok := findAccount(req.Wxid)
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		found, err := setAccountEnabled(req.Wxid, req.Enabled)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			http.Error(w, "not found", 404)
			return
		}
		a.Enabled = req.Enabled
		if GetConfig().EffectiveWxMode() == "key" {
			if req.Enabled {
				var da DbAccount
				foundDa := false
				for _, x := range GetConfig().EffectiveDbAccounts() {
					if x.Wxid == req.Wxid {
						da, foundDa = x, true
						break
					}
				}
				if foundDa {
					if acc, ok2 := findWxAccount(da.Wxid); ok2 && acc.HasBiz {
						if err := StartWxMonitor(acc.BizDB, da.Key, acc.Wxid, acc); err != nil {
							logWarn("monitor", "账号 %s 启动失败：%v", req.Wxid, err)
						}
					}
				}
			} else {
				StopWxMonitorFor(req.Wxid)
				StopLiveMonitor(req.Wxid)
			}
		}
		logInfo("config", "账号 %s 已%s", req.Wxid, map[bool]string{true: "启动", false: "停止"}[req.Enabled])
		w.Write([]byte(`{"ok":true}`))
	})

	mux.HandleFunc("/api/wx/hook/state", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		var req struct {
			Wxid    string `json:"wxid"`
			Enabled bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Wxid == "" {
			http.Error(w, "bad request", 400)
			return
		}
		c := GetConfig()
		ok := false
		wantPid := 0
		if strings.HasPrefix(req.Wxid, "pid:") {
			fmt.Sscanf(req.Wxid, "pid:%d", &wantPid)
		}
		for i := range c.HookAccounts {
			if c.HookAccounts[i].Wxid == req.Wxid || (wantPid != 0 && c.HookAccounts[i].PID == wantPid) {
				c.HookAccounts[i].Enabled = req.Enabled
				ok = true
			}
		}
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		if err := SetConfig(c); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		logInfo("config", "账号 %s 已%s", req.Wxid, map[bool]string{true: "启动", false: "停止"}[req.Enabled])
		w.Write([]byte(`{"ok":true}`))
	})

	mux.HandleFunc("/api/wx/hook/remove", func(w http.ResponseWriter, r *http.Request) {
		wxid := r.URL.Query().Get("wxid")
		if wxid == "" {
			http.Error(w, "wxid required", 400)
			return
		}
		c := GetConfig()
		kept := make([]HookAccount, 0, len(c.HookAccounts))
		for _, a := range c.HookAccounts {
			if a.Wxid != wxid {
				kept = append(kept, a)
			}
		}
		c.HookAccounts = kept
		// 记入删除黑名单：进程还在时也不自动加回来；删空再额外关掉自动绑定
		if !c.HookBlockedWxid(wxid) {
			c.HookBlocked = append(c.HookBlocked, wxid)
		}
		if len(kept) == 0 {
			c.HookNoAutoBind = true
		}
		if err := SetConfig(c); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		logInfo("hook", "已移除账号 %s", wxid)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})

	mux.HandleFunc("/api/wx/processes", func(w http.ResponseWriter, r *http.Request) {
		type item struct {
			PID   uint32 `json:"pid"`
			Wxid  string `json:"wxid"`
			Bound bool   `json:"bound"`
		}
		bound := map[int]bool{}
		for _, a := range GetConfig().HookAccounts {
			bound[a.PID] = true
		}
		list := make([]item, 0, 4)
		pids := MainWeChatPids() // 双开时会有多个
		if len(pids) == 0 {
			pids = MainPidsOf(WeChatProc)
		}
		for _, p := range pids {
			// 账号 wxid 先留空：注入器接入后由 /api/get_login_info 回填
			list = append(list, item{PID: p, Bound: bound[int(p)]})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"processes": list})
	})

	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit := 300
		if v := q.Get("limit"); v != "" {
			fmt.Sscanf(v, "%d", &limit)
		}
		json.NewEncoder(w).Encode(logsCopy(q.Get("level"), q.Get("module"), limit))
	})

	mux.HandleFunc("/api/logs/clear", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		logsClear()
		w.Write([]byte(`{"ok":true}`))
	})

	// /api/debug/nicks 预热并查看联系人昵称（诊断用）
	mux.HandleFunc("/api/debug/nicks", func(w http.ResponseWriter, r *http.Request) {
		wxid := r.URL.Query().Get("wxid")
		if wxid == "" {
			if c := GetConfig(); c.DbWxid != "" {
				wxid = c.DbWxid
			}
		}
		acc, ok := findWxAccount(wxid)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "找不到账号"})
			return
		}
		keyHex := ""
		for _, da := range GetConfig().EffectiveDbAccounts() {
			if da.Wxid == wxid {
				keyHex = da.Key
				break
			}
		}
		if keyHex == "" && GetConfig().DbWxid == wxid {
			keyHex = GetConfig().DbKey
		}
		// 用 message_0.db 里所有表名反推的 wxid 当待查列表
		tm := loadTableMap(wxid)
		var usernames []string
		for _, v := range tm {
			usernames = append(usernames, v)
		}
		var cdb *WxDB
		if acc.ContactDB != "" {
			if x, err := OpenWxDB(acc.ContactDB, keyHex); err == nil {
				cdb = x
				defer x.Close()
			}
		}
		if cdb == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "contact.db 打不开"})
			return
		}
		nm := WarmNicks(cdb, wxid, usernames)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": len(nm), "map": nm})
	})
	// /api/openlogdir 在资源管理器里打开日志目录
	mux.HandleFunc("/api/openlogdir", func(w http.ResponseWriter, r *http.Request) {
		exe, err := os.Executable()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		dir := filepath.Dir(exe)
		openExplorer(dir)
		http.Redirect(w, r, "/#logs", http.StatusFound)
	})

	// /api/clientlog 前端把 JS 异常报回来，方便排查界面问题
	mux.HandleFunc("/api/clientlog", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Where string `json:"where"`
			Msg   string `json:"msg"`
			Stack string `json:"stack"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		logError("client", "[%s] %s", body.Where, body.Msg)
		if body.Stack != "" {
			logError("client", "  %s", truncate(body.Stack, 300))
		}
		w.WriteHeader(204)
	})
	// /api/debug/live 好友/群聊的实时消息（由 LiveMonitor 每 5 秒轮询 message_0.db）
	mux.HandleFunc("/api/debug/live", func(w http.ResponseWriter, r *http.Request) {
		wxid := r.URL.Query().Get("wxid")
		if wxid == "" {
			if c := GetConfig(); c.DbWxid != "" {
				wxid = c.DbWxid
			}
		}
		events := LiveSnapshot(wxid)
		rows := make([]DebugItem, 0, len(events))
		for i, e := range events {
			rows = append(rows, DebugItem{
				Seq:     i + 1,
				From:    e.From,
				To:      "我",
				Content: e.Preview,
				Display: e.Preview,
				Time:    uint64(e.Time),
				Bytes:   len(e.Preview),
				PayType: e.PayType,
				At:      time.Unix(e.Time, 0).Format("15:04:05"),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": len(rows), "items": rows})
	})
	// /api/debug/recent 立刻拉一批最近的公众号消息给「消息调试」。
	// 否则用户点「开始捕获」后要一直等到有新收款才有东西看。
	mux.HandleFunc("/api/debug/recent", func(w http.ResponseWriter, r *http.Request) {
		wxid := r.URL.Query().Get("wxid")
		if wxid == "" {
			if c := GetConfig(); c.DbWxid != "" {
				wxid = c.DbWxid
			}
		}
		acc, ok := findWxAccount(wxid)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "找不到账号"})
			return
		}
		keyHex := ""
		for _, da := range GetConfig().EffectiveDbAccounts() {
			if da.Wxid == wxid {
				keyHex = da.Key
				break
			}
		}
		if keyHex == "" && GetConfig().DbWxid == wxid {
			keyHex = GetConfig().DbKey
		}
		if keyHex == "" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "该账号还没有通行密钥"})
			return
		}
		db, err := OpenWxDB(acc.BizDB, keyHex)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "打开 biz_message_0.db 失败：" + err.Error()})
			return
		}
		msgs, err := db.PeekAllTables(3)
		db.Close()
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": err.Error()})
			return
		}
		rows := make([]DebugItem, 0, len(msgs))
		for _, m := range msgs {
			gm := ParseGhContent(m.Content)
			// 只保留收款相关的公众号，营销推送不显示
			nick, gh := ghIdentity(gm.Decoded)
			if !isAllowedGh(nick, gh) {
				continue
			}
			display := gm.Title
			if display == "" {
				display = truncate(gm.Decoded, 80)
			}
			if nick == "" {
				nick = m.Table
			}
			rows = append(rows, DebugItem{
				Seq:     len(rows) + 1,
				PayType: ExtractPayType(gm.Title),
				From:    nick,
				To:      wxid,
				Content: gm.Title,
				RawText: gm.Decoded,
				Display: display,
				Time:    uint64(m.CreateAt),
				Amount:  gm.Amount,
				Bytes:   len(m.Content),
				At:      time.Unix(m.CreateAt, 0).Format("15:04:05"),
			})
		}
		sort.Slice(rows, func(a, b int) bool { return rows[a].Time > rows[b].Time })
		if len(rows) > 8 {
			rows = rows[:8]
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": len(rows), "items": rows})
	})
	// /api/debug/scan 扫 message_0.db 的所有表，把好友 / 群聊消息也列出来。
	// 微信 4.x 里每个联系人或群聊对应一张 Msg_<hash> 表。
	mux.HandleFunc("/api/debug/scan", func(w http.ResponseWriter, r *http.Request) {
		wxid := r.URL.Query().Get("wxid")
		if wxid == "" {
			if c := GetConfig(); c.DbWxid != "" {
				wxid = c.DbWxid
			}
		}
		acc, ok := findWxAccount(wxid)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "找不到账号 " + wxid})
			return
		}
		dbPath := acc.MsgDB
		if dbPath == "" || !fileExists(dbPath) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "该账号没有 message_0.db"})
			return
		}
		keyHex := ""
		for _, da := range GetConfig().EffectiveDbAccounts() {
			if da.Wxid == wxid {
				keyHex = da.Key
				break
			}
		}
		if keyHex == "" && GetConfig().DbWxid == wxid {
			keyHex = GetConfig().DbKey
		}
		if keyHex == "" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "该账号还没有通行密钥"})
			return
		}
		db, err := OpenWxDB(dbPath, keyHex)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "打开 message_0.db 失败：" + err.Error()})
			return
		}
		msgs, err := db.PeekAllTables(2)
		if err != nil {
			db.Close()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": err.Error()})
			return
		}
		// 反推表名对应的联系人（带缓存，只查没查过的表）
		seen := map[string]bool{}
		var todo []string
		for _, m := range msgs {
			if m.Table != "" && !seen[m.Table] {
				seen[m.Table] = true
				todo = append(todo, m.Table)
			}
		}
		nameMap := resolveTableNames(db, wxid, todo)
		db.Close()
		// 昵称延后到 rows 建好后再查（要覆盖从消息内容提取出来的 from）
		var cdb *WxDB
		if acc.ContactDB != "" {
			if x, err := OpenWxDB(acc.ContactDB, keyHex); err == nil {
				cdb = x
				defer x.Close()
			}
		}
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": err.Error()})
			return
		}
		type row struct {
			Table   string `json:"table"`
			LocalID int64  `json:"local_id"`
			Time    int64  `json:"time"`
			Preview string `json:"preview"`
			From    string `json:"from"`
		}
		rows := make([]row, 0, len(msgs))
		for _, m := range msgs {
			txt, _, _ := DecodeContent(m.Content)
			from := ""

			// 文本消息：正文常以 "wxid_xxx:" 或 "xxx@chatroom:" 开头
			if i := strings.Index(txt, ":"); i > 0 && i < 64 {
				p := txt[:i]
				if strings.HasPrefix(p, "wxid_") || strings.Contains(p, "@chatroom") {
					from = p
					txt = strings.TrimSpace(txt[i+1:])
				}
			}

			// XML 消息（图片/视频/表情/系统）：正文里有 fromusername / tousername
			if from == "" {
				if m1 := reFromUser.FindStringSubmatch(txt); len(m1) > 1 {
					from = m1[1]
				}
			}
			// 群聊消息把群 ID 也标出来
			if m2 := reToUser.FindStringSubmatch(txt); len(m2) > 1 &&
				strings.Contains(m2[1], "@chatroom") {
				if from == "" {
					from = m2[1]
				} else if !strings.Contains(from, "@chatroom") {
					from = m2[1] + " / " + from
				}
			}

			// 预览：去掉 XML 标签，只留可读文字
			preview := txt
			if strings.HasPrefix(strings.TrimSpace(preview), "<") {
				kind := "XML"
				switch {
				case strings.Contains(preview, "<img"):
					kind = "[图片]"
				case strings.Contains(preview, "<videomsg"):
					kind = "[视频]"
				case strings.Contains(preview, "<emoji"):
					kind = "[表情]"
				case strings.Contains(preview, "<voicemsg"):
					kind = "[语音]"
				case strings.Contains(preview, "revokemsg"):
					kind = "[撤回]"
				case strings.Contains(preview, "sysmsgtemplate"):
					kind = "[系统消息]"
				case strings.Contains(preview, "<appmsg"):
					kind = "[链接/卡片]"
				}
				if kind != "XML" {
					preview = kind
				} else if len(preview) > 100 {
					preview = preview[:100]
				}
			}
			if len(preview) > 120 {
				preview = preview[:120]
			}
			// 自己发的消息标成「我」
			if from == wxid {
				from = "我"
			}
			if from == "" {
				if v, ok := nameMap[m.Table]; ok && v != "" {
					from = v
				} else {
					from = m.Table
				}
			}
			rows = append(rows, row{Table: m.Table, LocalID: m.LocalID, Time: m.CreateAt, Preview: preview, From: from})
		}
		sort.Slice(rows, func(a, b int) bool { return rows[a].Time > rows[b].Time })
		// 统一把 wxid / gh_id / 表名换成中文昵称
		seenN := map[string]bool{}
		var needNicks []string
		for _, rr := range rows {
			if rr.From != "" && rr.From != "我" && !seenN[rr.From] {
				seenN[rr.From] = true
				needNicks = append(needNicks, rr.From)
			}
		}
		nickMap := WarmNicks(cdb, wxid, needNicks)
		for i := range rows {
			if v, ok := nickMap[rows[i].From]; ok && v != "" {
				rows[i].From = v
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": len(rows), "rows": rows})
	})
	mux.HandleFunc("/api/debug", func(w http.ResponseWriter, r *http.Request) {
		// 消息调试按模式隔离：默认只看当前模式，?mode=all 才合并
		want := r.URL.Query().Get("mode")
		if want == "" {
			want = GetConfig().EffectiveWxMode()
		}
		e := eng
		e.mu.Lock()
		out := make([]DebugItem, 0, len(e.debug))
		for _, it := range e.debug {
			if want == "all" || it.Mode == "" || it.Mode == want {
				out = append(out, it)
			}
		}
		e.mu.Unlock()
		json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("/api/reinject", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		go func() {
			eng.detach()
			Sleep(300)
			if id := PidByName(WeChatProc); id != 0 {
				eng.attach()
			}
		}()
		w.Write([]byte(`{"ok":true}`))
	})

	// 找一个空闲端口
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	go http.Serve(ln, mux)
	return port, nil
}

// forwardAndRecord 微信消息的统一上报入口（hook 路径使用）：
// 去重 → 统计 → 上报 → 写收款记录，和数据库路径保持同一套语义。
func (e *Engine) forwardAndRecord(m *ChatMsg) {
	key := messageDedupKey(m)
	e.mu.Lock()
	if e.seen[key] {
		e.mu.Unlock()
		return
	}
	e.seen[key] = true
	e.stats.Forwarded++
	e.mu.Unlock()

	res := Report(m)
	ok := res.Delivered && res.OK
	e.mu.Lock()
	if res.Delivered && !res.OK {
		e.stats.Failed++
		if res.Err == "" {
			res.Err = "HTTP " + itoa(int(res.Code))
		}
		logError("callback", "上报失败：%s", res.Err)
	} else if ok {
		e.stats.Reported++
		logInfo("callback", "上报成功 [%d]", res.Code)
	}
	e.mu.Unlock()

	e.addHistory(m, ok, res.Err, &res)
	markAccountReport(m.To, ok, res.Err)
	// 只有网络层失败才重试；平台明确返回了内容（含业务报错）一律不重试
	if !ok && reportRetryable(res) {
		enqueueReportRetry(m, res, "wechat")
	}
}
