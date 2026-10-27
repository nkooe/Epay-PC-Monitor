package main

// 消息调试的白名单与好友/群聊实时轮询。
//
// 微信数据库里 biz_message_0.db 有几十上百个公众号表，绝大多数是营销推送，
// 调试时全列出来没意义。只保留真正的收款渠道 + 好友/群聊。
//
// 已确认的公众号（从消息 XML 的 <username> 字段读出）：
//   微信收款助手        gh_f0a92aa7146c
//   微信支付            wxzhifu
//   微信收款商业版      wxmaidan
//   微信支付商家助手    WXPayMchPlat

import (
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// debugAllowedNicks 调试里允许显示的公众号昵称
var debugAllowedNicks = []string{
	"微信收款助手",
	"微信支付",
	"微信支付商家助手",
	"微信收款商业版",
}

// debugAllowedGH 已知的 gh_id（备用匹配，昵称取不到时用）
var debugAllowedGH = map[string]bool{
	"gh_f0a92aa7146c": true, // 微信收款助手
	"wxzhifu":         true, // 微信支付
	"wxmaidan":        true, // 微信收款商业版
	"WXPayMchPlat":    true, // 微信支付商家助手
}

var (
	reGhNick   = regexp.MustCompile(`<nickname><!\[CDATA\[([^\]]+)\]\]>`)
	reGhUser   = regexp.MustCompile(`<username><!\[CDATA\[([^\]]+)\]\]>`)
	reGhName2  = regexp.MustCompile(`<nickname>([^<]+)</nickname>`)
	reGhUser2  = regexp.MustCompile(`<username>([^<]+)</username>`)
)

// ghIdentity 从一条公众号消息里认出公众号身份
func ghIdentity(content string) (nick, gh string) {
	if content == "" {
		return "", ""
	}
	if m := reGhNick.FindStringSubmatch(content); len(m) > 1 {
		nick = strings.TrimSpace(m[1])
	}
	if m := reGhUser.FindStringSubmatch(content); len(m) > 1 {
		gh = strings.TrimSpace(m[1])
	}
	if nick == "" {
		if m := reGhName2.FindStringSubmatch(content); len(m) > 1 {
			nick = strings.TrimSpace(m[1])
		}
	}
	if gh == "" {
		if m := reGhUser2.FindStringSubmatch(content); len(m) > 1 {
			gh = strings.TrimSpace(m[1])
		}
	}
	return nick, gh
}

// isAllowedGh 这个公众号该不该出现在消息调试里
func isAllowedGh(nick, gh string) bool {
	for _, n := range debugAllowedNicks {
		if nick != "" && strings.Contains(nick, n) {
			return true
		}
	}
	if gh != "" && debugAllowedGH[gh] {
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// 好友 / 群聊实时轮询
// ---------------------------------------------------------------------------

// liveMsg 一条实时消息（好友、群聊或收款公众号）
type liveMsg struct {
	Table   string
	From    string
	Preview string
	Time    int64
	LocalID int64
	IsGh    bool
	PayType string
	GName   string // 公众号名（收款助手 / 微信支付）
}

// LiveMonitor 轮询 message_0.db，把新消息推给「消息调试」
type LiveMonitor struct {
	mu      sync.Mutex
	running bool
	stop    chan struct{}
	// 每张表最近处理过的 local_id
	last map[string]int64
	// 最近的实时消息（环形缓冲）
	events []liveMsg
	// 首次采样时只记游标，不推消息
	primed bool
	fails  int  // 连续失败轮数，用于限流告警
	db     *WxDB
	cdb    *WxDB // contact.db，用来查昵称
	wxid   string
	pushed int64
}

var (
	liveMonMu sync.Mutex
	liveMons  = map[string]*LiveMonitor{} // wxid -> monitor
)

const liveKeep = 40

// StartLiveMonitor 开始轮询某个账号的 message_0.db
func StartLiveMonitor(wxid, dbPath, contactPath, keyHex string) error {
	// 先从表里摘掉旧实例再停，否则两个 goroutine 同时启动会各建一份连接，
	// 其中一份永远没人关。
	liveMonMu.Lock()
	old := liveMons[wxid]
	delete(liveMons, wxid)
	liveMonMu.Unlock()
	if old != nil {
		old.Stop()
	}

	db, err := OpenWxDB(dbPath, keyHex)
	if err != nil {
		return err
	}
	m := &LiveMonitor{
		stop: make(chan struct{}),
		last: map[string]int64{},
		db:   db,
		wxid: wxid,
	}
	// 昵称需要查 contact.db，单独开一个连接
	if contactPath != "" {
		if cdb, err := OpenWxDB(contactPath, keyHex); err == nil {
			m.cdb = cdb
		} else {
			logWarn("livemsg", "账号 %s 打开 contact.db 失败（昵称将显示为 wxid）：%v", wxid, err)
		}
	}
	liveMonMu.Lock()
	liveMons[wxid] = m
	liveMonMu.Unlock()

	m.running = true
	go m.loop()
	logInfo("livemsg", "账号 %s 实时监控启动，库=%s", wxid, dbPath)
	return nil
}

// StopLiveMonitor 停止某个账号的实时监控
// StopAllLiveMonitors 停掉所有实时消息监控（切模式/停采集时用）
func StopAllLiveMonitors() {
	liveMonMu.Lock()
	ids := make([]string, 0, len(liveMons))
	for wxid := range liveMons {
		ids = append(ids, wxid)
	}
	liveMonMu.Unlock()
	for _, wxid := range ids {
		StopLiveMonitor(wxid)
	}
}

func StopLiveMonitor(wxid string) {
	liveMonMu.Lock()
	m := liveMons[wxid]
	delete(liveMons, wxid)
	liveMonMu.Unlock()
	if m != nil {
		m.Stop()
		logInfo("monitor", "账号 %s 好友/群聊实时监控已停止", wxid)
	}
}

// Stop 内部停止
func (m *LiveMonitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return
	}
	m.running = false
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
	if m.db != nil {
		m.db.Close()
	}
	if m.cdb != nil {
		m.cdb.Close()
	}
}

func (m *LiveMonitor) loop() {
	// 5 秒一轮：message_0.db 有一百多张表，全扫一次要 1-2 秒，
	// 再快会挤占资源
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	m.pollOnce() // 首次立刻采样
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.pollOnce()
		}
	}
}

func (m *LiveMonitor) pollOnce() {
	if m.db == nil {
		return
	}
	t0 := time.Now()
	tables, err := m.db.Tables()
	if err != nil {
		m.mu.Lock()
		m.fails++
		n := m.fails
		m.mu.Unlock()
		// 前 3 次每次都记，之后每 20 次记一次，避免刷屏
		if n <= 3 || n%20 == 0 {
			logWarn("livemsg", "[%s] 读表失败（连续 %d 次）：%v", m.wxid, n, err)
		}
		return
	}
	// 成功一轮就把失败计数清零
	m.mu.Lock()
	if m.fails > 0 {
		logInfo("livemsg", "[%s] 读表恢复正常（此前连续失败 %d 次）", m.wxid, m.fails)
		m.fails = 0
	}
	m.mu.Unlock()
	var fresh []liveMsg
	primed := m.primed

	for _, t := range tables {
		if !strings.HasPrefix(t, "Msg_") {
			continue
		}
		msgs, err := m.db.Messages(t, 5, 0, false) // 最新 5 条
		if err != nil {
			// 单表失败不打断整轮，但记下来（限流）
			m.mu.Lock()
			m.fails++
			n := m.fails
			m.mu.Unlock()
			if n <= 3 || n%20 == 0 {
				logWarn("livemsg", "[%s] 读表 %s 失败（连续 %d 次）：%v", m.wxid, t, n, err)
			}
			continue
		}
		if len(msgs) == 0 {
			continue
		}
		// 表内按 local_id 正序处理
		for i := len(msgs) - 1; i >= 0; i-- {
			raw := msgs[i]
			if raw.LocalID <= m.last[t] {
				continue
			}
			m.last[t] = raw.LocalID
			// 首次采样只记游标，不推历史；之后（primed=true）才是新消息
			if !primed {
				continue
			}
			txt, _, _ := DecodeContent(raw.Content)
			from := ""
			if i := strings.Index(txt, ":"); i > 0 && i < 64 {
				p := txt[:i]
				if strings.Contains(p, "@") || strings.HasPrefix(p, "wxid_") {
					from = p
					txt = strings.TrimSpace(txt[i+1:])
				}
			}
			if from == "" {
				if p := guessPeerFromMsg(txt, m.wxid); p != "" {
					from = p
					// 顺手把这张表的映射记下来，下次直接用
					tm := loadTableMap(m.wxid)
					if _, ok := tm[t]; !ok {
						tm[t] = p
						saveTableMap(m.wxid, tm)
					}
				} else if v, ok := loadTableMap(m.wxid)[t]; ok {
					from = v
				}
			}
			if from == m.wxid {
				from = "我"
			}
			if from == "" {
				from = t
			}
			prev := txt
			if strings.HasPrefix(strings.TrimSpace(prev), "<") {
				switch {
				case strings.Contains(prev, "<img"):
					prev = "[图片]"
				case strings.Contains(prev, "<videomsg"):
					prev = "[视频]"
				case strings.Contains(prev, "<emoji"):
					prev = "[表情]"
				case strings.Contains(prev, "<voicemsg"):
					prev = "[语音]"
				case strings.Contains(prev, "revokemsg"):
					prev = "[撤回]"
				case strings.Contains(prev, "sysmsgtemplate"):
					prev = "[系统消息]"
				case strings.Contains(prev, "<appmsg"):
					prev = "[链接/卡片]"
				default:
					if len(prev) > 100 {
						prev = prev[:100]
					}
				}
			}
			if len(prev) > 150 {
				prev = prev[:150]
			}
			logInfo("livemsg", "[%s] 新消息 t=%s id=%d %s | %s",
				m.wxid, time.Unix(raw.CreateAt, 0).Format("15:04:05"),
				raw.LocalID, from, truncate(prev, 30))
			fresh = append(fresh, liveMsg{
				Table: t, From: from, Preview: prev,
				Time: raw.CreateAt, LocalID: raw.LocalID,
				PayType: ExtractPayType(prev),
			})
		}
	}

	// 批量补昵称：把 from 里还是 wxid 的换成中文名
	if len(fresh) > 0 {
		var need []string
		seenU := map[string]bool{}
		for _, f := range fresh {
			if f.From != "" && f.From != "我" && !seenU[f.From] {
				seenU[f.From] = true
				need = append(need, f.From)
			}
		}
		nm := WarmNicks(m.cdb, m.wxid, need)
		for i := range fresh {
			if v, ok := nm[fresh[i].From]; ok && v != "" {
				fresh[i].From = v
			}
		}
	}

	// 按时间倒序（跨表收集时顺序是乱的）
	sort.SliceStable(fresh, func(a, b int) bool { return fresh[a].Time > fresh[b].Time })

	// 每轮都记耗时，超过轮询间隔就说明跟不上
	cost := time.Since(t0)
	// 详细模式下每轮留一条，方便确认轮询真的在跑
	logDebug("livemsg", "[%s] 轮询 %d 表，新消息 %d 条，耗时 %dms",
		m.wxid, len(tables), len(fresh), cost.Milliseconds())
	if len(fresh) > 0 {
		logInfo("livemsg", "[%s] 扫描 %d 表 → %d 条新消息，耗时 %dms（primed=%v）",
			m.wxid, len(tables), len(fresh), cost.Milliseconds(), primed)
	} else if cost > 2500*time.Millisecond {
		logWarn("livemsg", "[%s] 扫描 %d 表耗时 %dms，超过轮询间隔",
			m.wxid, len(tables), cost.Milliseconds())
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !primed {
		// 首次采样：只留最新的 8 条做参考（fresh 已按时间倒序，取头部）
		if len(fresh) > 20 {
			fresh = fresh[:20]
		}
		m.events = append(fresh, m.events...)
		if len(m.events) > liveKeep {
			m.events = m.events[:liveKeep]
		}
		m.pushed += int64(len(fresh))
	} else if len(fresh) > 0 {
		// 之后每轮的都是新消息，直接推
		m.events = append(fresh, m.events...)
		if len(m.events) > liveKeep {
			m.events = m.events[:liveKeep]
		}
		m.pushed += int64(len(fresh))
	}
	m.primed = true
}

// Snapshot 取最近的实时消息
func (m *LiveMonitor) Snapshot() []liveMsg {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]liveMsg, len(m.events))
	copy(out, m.events)
	return out
}

// LiveSnapshot 取某个账号的实时消息；账号不存在返回空
func LiveSnapshot(wxid string) []liveMsg {
	liveMonMu.Lock()
	m := liveMons[wxid]
	liveMonMu.Unlock()
	if m == nil {
		return nil
	}
	return m.Snapshot()
}





