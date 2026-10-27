package main

// 账号健康状态：每个账号最后一条消息、最后一次心跳、最后一次上报的结果。
// 只放内存，重启清零——它的用途是"现在这个账号是不是活着"，不是历史统计。

import (
	"sync"
	"time"
)

type AccountHealth struct {
	Account string `json:"account"`
	Kind    string `json:"kind"` // wechat / hook / alipay

	LastMsgAt   int64  `json:"last_msg_at"`
	LastMsgText string `json:"last_msg_text"`

	LastHBAt  int64  `json:"last_hb_at"`
	LastHBOK  bool   `json:"last_hb_ok"`
	LastHBErr string `json:"last_hb_err"`

	LastReportAt  int64  `json:"last_report_at"`
	LastReportOK  bool   `json:"last_report_ok"`
	LastReportErr string `json:"last_report_err"`

	MsgCount  int64 `json:"msg_count"`
	FailCount int64 `json:"fail_count"`
}

var (
	healthMu sync.Mutex
	health   = map[string]*AccountHealth{}
)

func healthOf(account, kind string) *AccountHealth {
	h, ok := health[account]
	if !ok {
		h = &AccountHealth{Account: account, Kind: kind}
		health[account] = h
	}
	if kind != "" {
		h.Kind = kind
	}
	return h
}

func kindOfAccount(account string) string {
	for _, a := range accountsCopy() {
		if a.Wxid == account {
			if accountKind(a) == "alipay" {
				return "alipay"
			}
			return "wechat"
		}
	}
	for _, h := range GetConfig().HookAccounts {
		if h.Wxid == account {
			return "hook"
		}
	}
	return ""
}

// markAccountMessage 收到一条该账号的消息
func markAccountMessage(account, text string) {
	if account == "" {
		return
	}
	healthMu.Lock()
	defer healthMu.Unlock()
	h := healthOf(account, kindOfAccount(account))
	h.LastMsgAt = time.Now().Unix()
	h.LastMsgText = truncate(text, 40)
	h.MsgCount++
}

// markAccountHeartbeat 心跳结果（ok=false 且 err 为空表示"跳过"，不覆盖状态）
func markAccountHeartbeat(account string, ok bool, errText string) {
	if account == "" {
		return
	}
	healthMu.Lock()
	defer healthMu.Unlock()
	h := healthOf(account, kindOfAccount(account))
	h.LastHBAt = time.Now().Unix()
	h.LastHBOK = ok
	h.LastHBErr = truncate(errText, 120)
}

// markAccountReport 上报结果
func markAccountReport(account string, ok bool, errText string) {
	if account == "" {
		return
	}
	healthMu.Lock()
	defer healthMu.Unlock()
	h := healthOf(account, kindOfAccount(account))
	h.LastReportAt = time.Now().Unix()
	h.LastReportOK = ok
	h.LastReportErr = truncate(errText, 120)
	if !ok {
		h.FailCount++
	}
}

// healthSnapshot 返回当前所有账号的状态（按账号名排序稳定输出）
func healthSnapshot() []AccountHealth {
	healthMu.Lock()
	defer healthMu.Unlock()
	out := make([]AccountHealth, 0, len(health))
	for _, h := range health {
		out = append(out, *h)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Account < out[i].Account {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
