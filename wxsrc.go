package main

// 微信采集源的两种模式：
//   key  —— 通行密钥读 WCDB（默认，零侵入）
//   hook —— 注入 hook 接收消息事件（实时，需要注入器）
//
// 两种模式互斥：同一时刻只有一种在跑，切换时先停旧源再起新源。

import (
	"sync"
	"time"
)

// hookRuntimeState Hook 模式的运行态（接收端接入前只有状态，没有数据）
type hookRuntimeState struct {
	mu        sync.Mutex
	running   bool
	note      string
	events    int64
	lastEvent int64
	startedAt int64
}

var hookRT hookRuntimeState

func hookStateSnapshot() map[string]any {
	hookRT.mu.Lock()
	defer hookRT.mu.Unlock()
	return map[string]any{
		"running":    hookRT.running,
		"note":       hookRT.note,
		"events":     hookRT.events,
		"last_event": hookRT.lastEvent,
		"started_at": hookRT.startedAt,
	}
}

// startHookSource 启动 Hook 采集源。
// 当前版本只负责模式状态与账号绑定；事件接收端（回环 HTTP + AES-GCM）
// 与注入器在后续版本接入，这里必须诚实地显示“未就绪”，不能假装在收消息。
func startHookSource() {
	c := GetConfig()
	accs := c.EffectiveHookAccounts()

	hookRT.mu.Lock()
	hookRT.running = true
	hookRT.startedAt = time.Now().Unix()
	hookRT.note = "Hook 模式已启用，接收端就绪（等待注入器推送）"
	hookRT.mu.Unlock()

	if len(accs) == 0 {
		logInfo("hook", "消息接收已就绪，等待添加账号")
	}
	startHookReceiver()
	// 自动注入 + 微信重启后自动重挂
	startHookWatcher()
	for _, a := range accs {
		logInfo("hook", "账号 %s 已就绪（通道 %s）", a.Wxid, a.ChannelID)
	}
}

// stopHookSource 停止 Hook 采集源
func stopHookSource() {
	hookRT.mu.Lock()
	was := hookRT.running
	hookRT.running = false
	hookRT.note = "未启用"
	hookRT.events = 0
	hookRT.lastEvent = 0
	hookRT.mu.Unlock()
	stopHookReceiver()
	stopHookWatcher()
	if was {
		logInfo("hook", "消息接收已停止")
	}
}

// startWxMonitorsFromConfig 按配置启动密钥模式的数据库监控
func startWxMonitorsFromConfig() {
	c := GetConfig()
	if !c.DbEnabled {
		logInfo("monitor", "数据库监控未启用")
		return
	}
	accounts := c.EffectiveDbAccounts()
	if len(accounts) == 0 {
		logInfo("monitor", "数据库监控未启用（还没有配置微信账号）")
		return
	}
	for _, da := range accounts {
		if !da.Enabled {
			continue // 账号被单独停止，不启动监控
		}
		acc, ok := findWxAccount(da.Wxid)
		if !ok {
			logWarn("monitor", "未找到微信账号 %s 的数据目录", da.Wxid)
			continue
		}
		if !acc.HasBiz {
			logWarn("monitor", "账号 %s 没有 biz_message_0.db，跳过", da.Wxid)
			continue
		}
		if err := StartWxMonitor(acc.BizDB, da.Key, acc.Wxid, acc); err != nil {
			logError("monitor", "账号 %s 监控启动失败: %v", da.Wxid, err)
		}
		if acc.MsgDB != "" {
			if err := StartLiveMonitor(acc.Wxid, acc.MsgDB, acc.ContactDB, da.Key); err != nil {
				logWarn("monitor", "账号 %s 实时消息监控启动失败: %v", da.Wxid, err)
			}
		}
	}
	InitDefaultWatches()
}

// switchWxMode 切换采集模式：先停旧源，再起新源。幂等。
func switchWxMode(mode string) {
	// 真正切换模式时恢复自动绑定（用户删光账号导致的关闭状态只影响当前这一次）
	if mode == "hook" {
		// 重新切进 HK 模式视为重新开始：清掉"删空不再自动绑定"和删除黑名单
		c := GetConfig()
		if c.HookNoAutoBind || len(c.HookBlocked) > 0 {
			c.HookNoAutoBind = false
			c.HookBlocked = nil
			_ = SetConfig(c)
		}
	}
	mode = normalizeWxMode(mode)
	current := GetConfig().EffectiveWxMode()
	if mode == current && (mode == "hook") == hookRunning() {
		return
	}

	// 两个方向都先停，避免两种源同时上报
	StopAllWxMonitors()
	StopAllLiveMonitors()
	stopHookSource()

	switch mode {
	case "hook":
		startHookSource()
		logInfo("config", "运行模式已切换为 HK，原模式已停止")
	default:
		startWxMonitorsFromConfig()
		logInfo("config", "运行模式已切换为通行密钥，原模式已停止")
	}
}

func normalizeWxMode(m string) string {
	if m == "hook" {
		return "hook"
	}
	return "key"
}

func hookRunning() bool {
	hookRT.mu.Lock()
	defer hookRT.mu.Unlock()
	return hookRT.running
}
