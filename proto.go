package main

// protobuf wire format 解析（只取需要的字段，不依赖 .proto）

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type PBField struct {
	Path  string
	Wire  int
	Var   uint64
	Bytes []byte
}

func readVarint(d []byte, i int) (uint64, int, bool) {
	var v uint64
	var s uint
	for i < len(d) && s < 64 {
		b := d[i]
		i++
		v |= uint64(b&0x7F) << s
		if b&0x80 == 0 {
			return v, i, true
		}
		s += 7
	}
	return 0, i, false
}

func extractMessageServerID(fields []PBField) uint64 {
	var shortPath, longPath uint64
	for _, f := range fields {
		if f.Wire != 0 || f.Var == 0 {
			continue
		}
		switch f.Path {
		case "2.2.2.2.1":
			if shortPath == 0 {
				shortPath = f.Var
			}
		case "2.2.2.2.2.1":
			if longPath == 0 {
				longPath = f.Var
			}
		}
	}
	if longPath != 0 {
		return longPath
	}
	return shortPath
}

func stableWeChatMsgID(id uint64) string {
	if id == 0 {
		return ""
	}
	return "wechat-server:" + strconv.FormatUint(id, 10)
}

// ParsePB 递归解析，path 用点号表示层级
func ParsePB(d []byte, depth int, prefix string, out *[]PBField) {
	i := 0
	n := len(d)
	for i < n {
		tag := d[i]
		i++
		field := int(tag >> 3)
		wire := int(tag & 7)
		if field == 0 {
			return
		}
		path := fmt.Sprintf("%d", field)
		if prefix != "" {
			path = prefix + "." + path
		}
		switch wire {
		case 0:
			v, ni, ok := readVarint(d, i)
			if !ok {
				return
			}
			i = ni
			*out = append(*out, PBField{Path: path, Wire: 0, Var: v})
		case 1:
			if i+8 > n {
				return
			}
			*out = append(*out, PBField{Path: path, Wire: 1})
			i += 8
		case 2:
			ln, ni, ok := readVarint(d, i)
			if !ok || ln > uint64(n) {
				return
			}
			i = ni
			if i+int(ln) > n {
				return
			}
			blob := d[i : i+int(ln)]
			i += int(ln)
			*out = append(*out, PBField{Path: path, Wire: 2, Bytes: blob})
			if depth < 9 && len(blob) > 1 && len(blob) <= 8192 {
				ParsePB(blob, depth+1, path, out)
			}
		case 5:
			if i+4 > n {
				return
			}
			*out = append(*out, PBField{Path: path, Wire: 5})
			i += 4
		default:
			return
		}
	}
}

type ChatMsg struct {
	From     string
	To       string
	Content  string
	Display  string
	Time     uint64
	MsgID    uint64
	StableID string  // 源提供且语义明确的消息 ID；protobuf 猜测值不填入这里
	Amount   float64 // 从正文提取的金额（元），0 表示识别不到
	Raw      []byte
	RawText  string // 原始消息文本（XML 消息保留完整报文，便于排查）

	// 公众号消息专用字段（wxtool 合同）
	SortSeq int64
	LocalID int64
	GHFrom  string // 公众号 gh_id（= From）
	GHName  string // 公众号显示名（微信收款商业版 等）
}

// ExtractMsg 从 protobuf 里提取聊天消息，不是消息就返回 nil
func ExtractMsg(d []byte) *ChatMsg {
	if len(d) < 8 || len(d) > 2<<20 {
		return nil
	}
	// DER 证书（登录握手）跳过
	if len(d) > 2 && d[0] == 0x30 && d[1] == 0x82 {
		return nil
	}
	var fields []PBField
	ParsePB(d, 0, "", &fields)

	m := &ChatMsg{Raw: d}
	for _, f := range fields {
		if f.Wire != 2 {
			continue
		}
		// 微信消息有两种结构，字段路径相差一层：
		//   短：2.2.2.2.{2.1,3.1,5.1,11}
		//   长：2.2.2.2.2.{2.1,3.1,5.1,11}
		switch f.Path {
		case "2.2.2.2.2.1", "2.2.2.2.2.2.1":
			if m.From == "" {
				m.From = trimStr(f.Bytes)
			}
		case "2.2.2.2.3.1", "2.2.2.2.2.3.1":
			if m.To == "" {
				m.To = trimStr(f.Bytes)
			}
		case "2.2.2.2.5.1", "2.2.2.2.2.5.1":
			if m.Content == "" {
				m.Content = trimStr(f.Bytes)
			}
		case "2.2.2.2.11", "2.2.2.2.2.11":
			if m.Display == "" {
				m.Display = trimStr(f.Bytes)
			}
		}
	}
	// In the long layout, the shallower field 1 is a container counter;
	// the nested field is the stable server message ID.
	m.MsgID = extractMessageServerID(fields)
	m.StableID = stableWeChatMsgID(m.MsgID)

	// 数字字段
	for _, f := range fields {
		if f.Wire != 0 {
			continue
		}
		switch f.Path {
		case "2.2.2.2.9", "2.2.2.2.2.9":
			if m.Time == 0 {
				m.Time = f.Var
			}
		}
	}
	if m.Content == "" && m.Display == "" {
		return nil
	}
	if m.From == "" {
		return nil
	}
	// 微信支付/商家收款的通知是 XML appmsg，标题形如：
	//   <appmsg><title><![CDATA[微信支付收款0.10元(朋友到店)]]></title>...
	// 这类消息必须保留：它就是收款通知本身。仅对 XML 提取 <title>。
	if strings.HasPrefix(strings.TrimSpace(m.Content), "<") {
		m.RawText = m.Content // 原始 XML 全文
		t := xmlTitle(m.Content)
		if t == "" {
			return nil // 文件传输、名片等没有 title 的系统消息，丢弃
		}
		m.Content = t
		if m.Display == "" {
			m.Display = t
		}
	}

	// 金额：优先从正文提取「收款X元 / ￥X / ¥X」
	m.Amount = extractAmount(m.Content)
	return m
}

// xmlTitle 从微信 appmsg XML 里取 <title> 的文本（含 CDATA）
func xmlTitle(s string) string {
	const open, close = "<title>", "</title>"
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	rest := s[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		return ""
	}
	v := rest[:j]
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "<![CDATA[")
	v = strings.TrimSuffix(v, "]]>")
	v = strings.TrimSpace(v)
	return v
}

var (
	// 「0.50元」「3.00 元」「12.34元」——最通用，优先
	amtReYuan = regexp.MustCompile(`([0-9]{1,7}(?:\.[0-9]{1,2})?)\s*元`)
	// 「￥0.10」「¥88.88」
	amtReSym = regexp.MustCompile(`[￥¥]\s*([0-9]{1,7}(?:\.[0-9]{1,2})?)`)
	// 「收款成功 3.00」「已转入余额 12.34」「付款 0.5」——关键词后 8 字内出现数字
	amtReKw = regexp.MustCompile(`(?:收款|到账|付款|金额|余额|转入)[^0-9]{0,8}([0-9]{1,7}(?:\.[0-9]{1,2})?)`)
)

func amtFromMatch(re *regexp.Regexp, text string) float64 {
	if m := re.FindStringSubmatch(text); len(m) == 2 {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil && v > 0 && v < 1e7 {
			return v
		}
	}
	return 0
}

// extractAmount 返回金额（元），取不到返回 0。
// 依次尝试三种模式：数字+元 → 货币符号 → 关键词+数字。
func extractAmount(text string) float64 {
	if v := amtFromMatch(amtReYuan, text); v > 0 {
		return v
	}
	if v := amtFromMatch(amtReSym, text); v > 0 {
		return v
	}
	return amtFromMatch(amtReKw, text)
}

func trimStr(b []byte) string {
	s := string(b)
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	if !isPrintable(s) {
		return ""
	}
	return s
}

func isPrintable(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x20 && r != '\n' && r != '\t' && r != '\r' {
			return false
		}
		if r == 0xFFFD {
			return false
		}
	}
	return true
}

var _ = binary.LittleEndian
