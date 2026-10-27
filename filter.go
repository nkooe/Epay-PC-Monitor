package main

// 关键词过滤

import "strings"

type Decision struct {
	Forward bool
	Reason  string
}

func ShouldForward(m *ChatMsg) Decision {
	c := GetConfig()
	text := m.Content
	if text == "" {
		text = m.Display
	}
	if text == "" {
		return Decision{false, "空内容"}
	}

	if c.IgnoreSelf && m.From != "" && strings.HasPrefix(m.From, "wxid_") &&
		strings.HasPrefix(m.To, "wxid_") && m.From == selfWxid() {
		return Decision{false, "自己发出"}
	}

	if c.ForwardAll {
		return Decision{true, "全量转发"}
	}

	for _, kw := range c.Keywords {
		kw = strings.TrimSpace(kw)
		if kw == "" {
			continue
		}
		if strings.Contains(text, kw) {
			return Decision{true, "命中关键词:" + kw}
		}
	}
	return Decision{false, "未命中关键词"}
}

var cachedSelf string

func selfWxid() string {
	return cachedSelf
}

func SetSelfWxid(w string) { cachedSelf = w }
