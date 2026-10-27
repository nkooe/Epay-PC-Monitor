package main

// 易监控PC版 —— 微信 PC 端收款消息监听与上报
//
// 原理：hook Weixin.dll+0x67B7D0（protobuf 序列化），
//       抓取每次序列化的 (buffer, len)，解析出聊天消息。
//       只读，不修改微信逻辑，不碰数据库。

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	AppName    = "易监控PC版"
	AppVersion = "1.67"
	WeChatProc = "Weixin.exe"
)

type Engine struct {
	mu       sync.Mutex
	hooks    []*Hooks
	seen     map[string]bool
	history  []MsgView
	debug    []DebugItem
	debugSeq int
	unknowns []UnkSample
	unkSeq   int
	debugged bool
	dbgCount int
	dbgMsg   int
	stopCh   chan struct{}
	stats    Stats
}

type Stats struct {
	InjectedAt time.Time
	Pid        uint32
	Scanned    int
	Parsed     int
	Forwarded  int
	Reported   int
	Failed     int
	LastMsg    string

	// 收款统计（只统计识别出金额的消息）
	TodaySum     float64
	TodayCount   int
	YesterdaySum float64
	YesterdayCnt int
	WeekSum      float64
	WeekCount    int
	AllSum       float64
	AllCount     int
}

var eng = &Engine{seen: make(map[string]bool), stopCh: make(chan struct{})}

func logf(format string, a ...interface{}) {
	logL("INFO", "system", format, a...)
}

func (e *Engine) attach() bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.hooks) > 0 {
		return true
	}
	pid := PidByName(WeChatProc)
	if pid == 0 {
		return false
	}

	ok := 0
	for _, pt := range HookPoints {
		hk, err := AttachAt(pid, pt)
		if err != nil {
			logWarn("inject", "采集点 %s 接入失败: %v", pt.Name, err)
			continue
		}
		// 只处理新消息：先丢掉缓冲里残留的旧数据，再记下注入时刻作为下限
		hk.ResetBuffer()
		hk.StartUnix = time.Now().Unix()
		e.hooks = append(e.hooks, hk)
		ok++
		logInfo("inject", "采集点 %s 已接入", pt.Name)
	}

	if ok == 0 {
		logError("inject", "接入失败：请确认微信正在运行")
		return false
	}

	e.stats.InjectedAt = time.Now()
	e.stats.Pid = pid
	logInfo("inject", "程序启动成功 pid=%d（%d 个采集点）", pid, ok)
	return true
}

func (e *Engine) detach() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.hooks) > 0 {
		for _, hk := range e.hooks {
			hk.Detach()
		}
		e.hooks = nil
		logInfo("inject", "已断开微信")
	}
}

func (e *Engine) poll() {
	e.mu.Lock()
	hooks := make([]*Hooks, len(e.hooks))
	copy(hooks, e.hooks)
	e.mu.Unlock()

	for _, hk := range hooks {
		e.pollOne(hk)
	}
}

func (e *Engine) pollOne(hk *Hooks) {
	if hk == nil {
		return
	}

	for idx := 0; idx < Slots; idx++ {
		_, rdx, r8, _, ok := hk.Slot(idx)
		if !ok || rdx == 0 || r8 == 0 || r8 > 2<<20 {
			continue
		}
		e.stats.Scanned++
		hk.Scanned++
		buf := hk.ReadAt(rdx, int(r8))
		if buf == nil {
			continue
		}
		m := ExtractMsg(buf)
		if m == nil {
			// 采样未识别结构，帮助判断某类消息是否经过 hook
			if r8 > 200 && r8 < 8000 {
				e.mu.Lock()
				n := len(e.unknowns)
				e.mu.Unlock()
				if n < unkMax {
					e.addUnknown(buf)
				}
			}
			if os.Getenv("EASYDEBUG") == "1" && r8 > 600 && r8 < 1200 && e.dbgMsg < 10 {
				e.dbgMsg++
				var fs []PBField
				ParsePB(buf, 0, "", &fs)
				all := make([]string, 0, 20)
				for _, f := range fs {
					if f.Wire == 2 && len(f.Bytes) >= 1 && len(f.Bytes) < 80 {
						s := trimStr(f.Bytes)
						if s != "" {
							all = append(all, f.Path+"="+s)
						}
					}
					if len(all) >= 14 {
						break
					}
				}
				logDebug("monitor", "未知结构 len=%d 字段=%d: %v", r8, len(fs), all)
			}
			continue
		}
		// 只处理注入之后的新消息：早于注入时刻的一律丢弃。
		// 微信的时间字段可能是秒也可能是毫秒，先归一化到秒再比较。
		if hk.StartUnix > 0 && m.Time > 0 {
			ts := int64(m.Time)
			if ts > 1e12 {
				ts /= 1000
			}
			if ts < hk.StartUnix {
				continue
			}
		}

		// 去重优先使用来源确认的消息 ID；无可信 ID 时退回正文与时间指纹。
		key := messageDedupKey(m)
		e.mu.Lock()
		if e.seen[key] {
			e.mu.Unlock()
			continue
		}
		if len(e.seen) > 20000 {
			e.seen = make(map[string]bool)
		}
		e.seen[key] = true
		e.stats.Parsed++
		hk.Parsed++
		e.mu.Unlock()

		e.addDebugFrom(m, len(buf), "db")

		// 收款金额统计（不管是否转发都统计）
		if m.Amount > 0 {
			e.mu.Lock()
			day := msgDay(m.Time)
			now := time.Now()
			today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
			yday := today.AddDate(0, 0, -1)
			week := today.AddDate(0, 0, -6)
			e.stats.AllSum += m.Amount
			e.stats.AllCount++
			if day.Equal(today) {
				e.stats.TodaySum += m.Amount
				e.stats.TodayCount++
			}
			if day.Equal(yday) {
				e.stats.YesterdaySum += m.Amount
				e.stats.YesterdayCnt++
			}
			if !day.Before(week) {
				e.stats.WeekSum += m.Amount
				e.stats.WeekCount++
			}
			e.mu.Unlock()
		}

		// 从收款消息里发现收款账号，自动建档（方便后续绑定通道）
		if m.Amount > 0 && m.To != "" {
			if err := ensureAccount(m.To); err != nil {
				logWarn("config", "自动保存账号 %s 失败：%v", short(m.To), err)
			}
		}

		d := ShouldForward(m)
		if !d.Forward {
			markAccountMessage(m.To, m.Content)
			e.addHistory(m, false, "未命中关键词", nil)
			continue
		}
		e.mu.Lock()
		e.stats.Forwarded++
		e.stats.LastMsg = m.Content
		e.mu.Unlock()

		logInfo("monitor", "消息 %s → %s: %s", short(m.From), short(m.To), truncate(m.Content, 60))
		res := Report(m)
		// 成功判定必须看 OK：平台返回 4xx/5xx 时 Err 可能是空的，只看 Err 会把失败当成功。
		reportOK := res.Delivered && res.OK
		e.mu.Lock()
		if res.Delivered && !res.OK {
			e.stats.Failed++
			reason := res.Err
			if reason == "" {
				reason = fmt.Sprintf("HTTP %d: %s", res.Code, truncate(res.Body, 120))
			}
			logError("callback", "上报失败: %s", reason)
			if res.Err == "" {
				res.Err = reason
			}
		} else if reportOK {
			e.stats.Reported++
			logInfo("callback", "上报成功 [%d] %s", res.Code, truncate(res.Body, 40))
		}
		e.mu.Unlock()
		markAccountMessage(m.To, m.Content)
		markAccountReport(m.To, reportOK, res.Err)
		e.addHistory(m, reportOK, res.Err, &res)
	}
}

// msgDay 把消息时间戳归一化成当天 0 点（本地时区）
func msgDay(ts uint64) time.Time {
	var t time.Time
	if ts > 1e12 {
		t = time.UnixMilli(int64(ts))
	} else if ts > 1e9 {
		t = time.Unix(int64(ts), 0)
	} else {
		t = time.Now()
	}
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

func hashMsg(s string, t uint64) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	h ^= t
	return h
}

// messageDedupKey prefers source identifiers with a known stable meaning.
// The content/time fingerprint remains a fallback for sources without one.
func messageDedupKey(m *ChatMsg) string {
	if m == nil {
		return ""
	}
	scope := m.To + "\x00" + m.From
	identity := ""
	switch {
	case m.StableID != "":
		identity = "source\x00" + scope + "\x00" + m.StableID
	case m.LocalID != 0:
		identity = fmt.Sprintf("local\x00%s\x00%d", scope, m.LocalID)
	default:
		identity = fmt.Sprintf("fallback\x00%s\x00%s\x00%d", scope, m.Content, m.Time)
	}
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])
}

func short(s string) string {
	if len(s) > 14 {
		return s[:14]
	}
	return s
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func (e *Engine) run() {
	tick := time.NewTicker(120 * time.Millisecond)
	defer tick.Stop()
	recheck := time.NewTicker(3 * time.Second)
	defer recheck.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-recheck.C:
			if len(e.hooks) > 0 {
				if PidByName(WeChatProc) != e.stats.Pid {
					logWarn("inject", "微信进程已变化，正在重新连接")
					e.detach()
				}
			} else {
				if GetConfig().AutoInject && e.attach() {
					continue
				}
			}
		case <-tick.C:
			e.poll()
		}
	}
}

func main() {
	// 打包时用：EasyMonitorPC.exe --write-integrity
	if handleIntegrityCmd(os.Args[1:]) {
		return
	}

	// 启动就把可能附带的控制台藏起来，避免黑窗口刷屏
	hideConsoleWindow()

	// 自校验：发现 exe 被改过就在日志里留痕
	if ok, why := verifySelfIntegrity(); !ok {
		logError("system", "⚠ 完整性校验失败：%s", why)
		logError("system", "⚠ 如果你没有自己修改过程序，请重新下载官方版本")
	}

	// 只允许一个实例：否则两个进程会同时轮询同一份数据库，
	// 同一笔收款被上报两次
	if !ensureSingleInstance("EasyMonitorPC_SingleInstance_v1") {
		logWarn("system", "程序已经在运行，本次启动退出")
		return
	}
	fmt.Printf("%s v%s\n", AppName, AppVersion)
	fmt.Println("─────────────────────────────────────────")

	if err := LoadConfig(); err != nil {
		logError("config", "配置加载失败: %v", err)
	}
	c := GetConfig()
	checkChannelConflicts()
	LoadRetryQueue()
	// 首次运行：自动探测微信安装路径并落盘，用户不用手填
	// 路径为空、或文件已不存在（换设备/微信重装后路径会变），都重新探测
	needDetect := c.WeChatExe == ""
	if !needDetect {
		if st, err := os.Stat(c.WeChatExe); err != nil || st.IsDir() {
			needDetect = true
			logWarn("system", "配置里的微信路径已失效（%s），重新探测", c.WeChatExe)
		}
	}
	if needDetect {
		if p := detectWeChatExe(); p != "" {
			c.WeChatExe = p
			SetConfig(c)
			logInfo("config", "已自动识别微信路径: %s", p)
		} else {
			logWarn("config", "未找到微信安装路径，可在设置中手动指定")
		}
	}
	mode := map[string]string{"yjk": "易简控", "v1": "码支付V1", "xpay": "X-Ypay", "none": "仅打印"}[c.Mode]
	filterMode := "全量转发"
	if !c.ForwardAll {
		filterMode = "关键词: " + fmt.Sprint(c.Keywords)
	}
	logInfo("config", "上报模式: %s   过滤: %s", mode, filterMode)
	logInfo("config", "配置文件: %s", configPath())
	if err := loadAccounts(); err != nil {
		logError("config", "账号配置不可用，已禁用账号写入以保护原文件: %v", err)
	}
	logInfo("config", "账号绑定: %d 个", len(accountsCopy()))

	// 把上次运行的收款记录读回来（只恢复本程序自己抓到的数据，不碰微信历史）
	if old := loadRecords(); len(old) > 0 {
		eng.mu.Lock()
		eng.history = old
		eng.mu.Unlock()
		logInfo("config", "已恢复收款记录: %d 条", len(old))
	}
	go recordsFlusher(eng.stopCh)

	if PidByName(WeChatProc) == 0 {
		logWarn("monitor", "未检测到 %s，等待启动…", WeChatProc)
	}

	// 数据库监控：读取公众号/服务号消息（收款助手、微信支付、赞赏通知）
	// 支持多账号同时监控：每个账号独立密钥、独立数据库连接
	// 微信采集：按模式二选一（key=读库 / hook=事件推送）
	if c.EffectiveWxMode() == "hook" {
		startHookSource()
	} else {
		startWxMonitorsFromConfig()
	}

	go eng.run()

	// 支付宝：加载登录态（心跳要用它判断通道是否在线，必须先加载）
	loadAlipaySessions()

	// X-Ypay 心跳：60 秒一次，每账号。配置里切到 X-Ypay 后也会自动启动
	ensureXPayHeartbeat()

	// 支付宝轮询
	startAlipayMonitor()

	// 启动界面
	port, err := startServer()
	if err != nil {
		logError("system", "界面服务启动失败: %v", err)
	} else {
		logInfo("system", "界面: http://127.0.0.1:%d/", port)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	statusTk := time.NewTicker(30 * time.Second)
	defer statusTk.Stop()

	// 顶层窗口用 WebView2 承载（原生窗口，不是浏览器）
	go func() {
		for {
			select {
			case <-sig:
				logInfo("system", "正在退出…")
				flushRecordsNow()
				close(eng.stopCh)
				eng.detach()
				os.Exit(0)
			case <-statusTk.C:
				eng.mu.Lock()
				s := eng.stats
				attached := eng.hooks != nil
				eng.mu.Unlock()
				if attached {
					logDebug("monitor", "运行中 扫描=%d 消息=%d 转发=%d 上报=%d 失败=%d",
						s.Scanned, s.Parsed, s.Forwarded, s.Reported, s.Failed)
				} else {
					logDebug("monitor", "等待微信启动…")
				}
			}
		}
	}()

	if port == 0 {
		// 端口没起来就退回终端模式
		select {}
	}
	runWindow(port)
}
