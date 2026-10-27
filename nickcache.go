package main

// 联系人昵称缓存。
//
// wxtool_wcdb.dll 的 contact op 能按 username 批量查昵称，
// 但每轮轮询都查一遍太浪费，所以缓存到磁盘。
//
// 用法：
//   nick := NickOf(wxid, usernames)   // 批量预热
//   name := NickName(wxid, from)      // 单个取

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type nickFile struct {
	Wxid string            `json:"wxid"`
	Map  map[string]string `json:"map"`
}

var (
	nickMu    sync.Mutex
	nickCache = map[string]map[string]string{} // 账号 -> (username -> 昵称)
)

func nickPath(wxid string) string {
	return filepath.Join(filepath.Dir(configPath()), "nicks_"+wxid+".json")
}

// loadNicks 返回缓存的**副本**。
// 直接返回引用的话，调用方在锁外改 map 会和别的 goroutine 撞车，
// Go 里 concurrent map writes 是 fatal error，整个进程直接挂。
func loadNicks(wxid string) map[string]string {
	nickMu.Lock()
	m, ok := nickCache[wxid]
	if !ok {
		m = map[string]string{}
		if b, err := os.ReadFile(nickPath(wxid)); err == nil {
			var f nickFile
			if json.Unmarshal(b, &f) == nil && f.Map != nil {
				m = f.Map
			}
		}
		nickCache[wxid] = m
	}
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	nickMu.Unlock()
	return cp
}

func saveNicks(wxid string, m map[string]string) {
	nickMu.Lock()
	defer nickMu.Unlock()
	nickCache[wxid] = m
	f := nickFile{Wxid: wxid, Map: m}
	if b, err := json.MarshalIndent(f, "", " "); err == nil {
		atomicWriteFile(nickPath(wxid), b, 0644)
	}
}

// NickName 取一个 username 的显示名；没缓存就原样返回
func NickName(wxid, username string) string {
	if username == "" {
		return ""
	}
	if username == wxid {
		return "我"
	}
	m := loadNicks(wxid)
	if v, ok := m[username]; ok && v != "" {
		return v
	}
	return username
}

// WarmNicks 批量补齐昵称。db 可以为 nil（只用缓存）。
// 返回 username -> 显示名 的映射（含缓存命中和新查到的）。
func WarmNicks(db *WxDB, wxid string, usernames []string) map[string]string {
	m := loadNicks(wxid)
	if len(usernames) == 0 {
		return m
	}
	// 挑出没缓存的
	var miss []string
	seen := map[string]bool{}
	for _, u := range usernames {
		if u == "" || u == wxid || seen[u] {
			continue
		}
		seen[u] = true
		if v, ok := m[u]; ok && v != "" {
			continue
		}
		miss = append(miss, u)
	}
	if len(miss) == 0 || db == nil {
		return m
	}
	// 一次最多查 200 个，避免请求过大
	const chunk = 200
	changed := false
	for i := 0; i < len(miss); i += chunk {
		end := i + chunk
		if end > len(miss) {
			end = len(miss)
		}
		cs, err := db.Contacts(miss[i:end])
		if err != nil {
			break
		}
		for _, c := range cs {
			n := c.Display()
			if n == "" || n == c.Username {
				continue
			}
			m[c.Username] = n
			changed = true
		}
	}
	if changed {
		saveNicks(wxid, m)
	}
	return m
}
