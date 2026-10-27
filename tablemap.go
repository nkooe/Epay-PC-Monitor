package main

// 从消息内容反推 Msg_<hash> 表对应的联系人。
//
// 微信 4.x 里 message_0.db 每个联系人/群一张 Msg_<hash> 表，
// 但 hash 不是 md5(username)，反推不出来。
// contact / name2id 这些表又被 wxtool_wcdb.dll 的只读白名单挡住，
// 所以只能从消息正文里的 fromusername / tousername 反查：
//
//   对方发的文本：  "wxid_xxx: 内容"        → wxid_xxx
//   群聊 / 开放平台："123456@chatroom" / "xxx@openim"
//   XML 消息：      fromusername="xxx" tousername="yyy"，不是自己那个就是对方
//
// 实测能覆盖约 40% 的表，剩下的表里消息全是自己发的，没有对方标识。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

var (
	reMsgFrom   = regexp.MustCompile(`fromusername\s*=\s*"([^"]+)"`)
	reMsgTo     = regexp.MustCompile(`tousername\s*=\s*"([^"]+)"`)
	reMsgChat   = regexp.MustCompile(`chatroomusername\s*=\s*"([^"]+)"`)
	reMsgPrefix = regexp.MustCompile(`^([A-Za-z0-9_\-]+@[A-Za-z0-9_.]+|wxid_[A-Za-z0-9_\-]+):`)
)

// tableMap 表名 → 联系人，按账号缓存在磁盘上
type tableMapFile struct {
	Wxid string            `json:"wxid"`
	Map  map[string]string `json:"map"`
}

var (
	tmapMu    sync.Mutex
	tmapCache = map[string]map[string]string{} // wxid -> (table -> peer)
)

func tmapPath(wxid string) string {
	return filepath.Join(filepath.Dir(configPath()), "tablemap_"+wxid+".json")
}

// loadTableMap 返回副本，理由同 loadNicks：
// 调用方在锁外改 map 会和别的 goroutine 撞车，导致 fatal error。
func loadTableMap(wxid string) map[string]string {
	tmapMu.Lock()
	if m, ok := tmapCache[wxid]; ok {
		cp := make(map[string]string, len(m))
		for k, v := range m {
			cp[k] = v
		}
		tmapMu.Unlock()
		return cp
	}
	m := map[string]string{}
	if b, err := os.ReadFile(tmapPath(wxid)); err == nil {
		var f tableMapFile
		if json.Unmarshal(b, &f) == nil && f.Map != nil {
			m = f.Map
		}
	}
	tmapCache[wxid] = m
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	tmapMu.Unlock()
	return cp
}

func saveTableMap(wxid string, m map[string]string) {
	tmapMu.Lock()
	defer tmapMu.Unlock()
	tmapCache[wxid] = m
	f := tableMapFile{Wxid: wxid, Map: m}
	if b, err := json.MarshalIndent(f, "", " "); err == nil {
		atomicWriteFile(tmapPath(wxid), b, 0644)
	}
}

// guessPeerFromMsg 从一条消息内容里推断对方标识
func guessPeerFromMsg(content, self string) string {
	if content == "" {
		return ""
	}
	// 自己不是联系人，直接排除
	isSelf := func(v string) bool {
		return v == "" || v == self
	}
	if m := reMsgChat.FindStringSubmatch(content); len(m) > 1 {
		if v := m[1]; !isSelf(v) {
			return v
		}
	}
	fm := reMsgFrom.FindStringSubmatch(content)
	tm := reMsgTo.FindStringSubmatch(content)
	if len(fm) > 1 && len(tm) > 1 {
		fv, tv := fm[1], tm[1]
		// 群聊优先用群 ID
		if strings.Contains(tv, "@chatroom") && !isSelf(tv) {
			return tv
		}
		if strings.Contains(fv, "@chatroom") && !isSelf(fv) {
			return fv
		}
		if !isSelf(fv) {
			return fv
		}
		if !isSelf(tv) {
			return tv
		}
	}
	if !strings.HasPrefix(strings.TrimSpace(content), "<") {
		if m := reMsgPrefix.FindStringSubmatch(content); len(m) > 1 {
			if v := m[1]; !isSelf(v) {
				return v
			}
		}
	}
	return ""
}

// resolveTableNames 反推若干张表对应的联系人，结果写回缓存。
// 已缓存的表直接跳过；unknown 是待查的表名列表。
func resolveTableNames(db *WxDB, wxid string, tables []string) map[string]string {
	m := loadTableMap(wxid)
	changed := false
	for _, t := range tables {
		if _, ok := m[t]; ok {
			continue
		}
		peer := ""
		// 先看最新 300 条，再看最旧 2000 条
		for _, probe := range []struct {
			limit int
			asc   bool
		}{{300, false}, {2000, true}} {
			msgs, err := db.Messages(t, probe.limit, 0, probe.asc)
			if err != nil {
				break
			}
			for _, raw := range msgs {
				txt, _, _ := DecodeContent(raw.Content)
				if p := guessPeerFromMsg(txt, wxid); p != "" {
					peer = p
					break
				}
			}
			if peer != "" {
				break
			}
		}
		if peer != "" && peer != wxid && len(peer) >= 6 {
			m[t] = peer
			changed = true
		}
	}
	if changed {
		saveTableMap(wxid, m)
	}
	return m
}


