package main

// 收款记录持久化：重启不丢数据。
//
// 存放结构（按「采集模式 + 账号」分开，避免两套通道的数据混在一起）：
//
//	records/key/wxid_xxx.json     通行密钥模式的记录
//	records/hook/pid_41484.json   Hook 模式的记录
//
// 旧版单文件 records.json 会在启动时自动迁移到 records/key/ 下。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	recordsMax      = 2000
	recordsRootDir  = "records"
	legacyRecordsFn = "records.json"
)

var (
	recMu       sync.Mutex
	recDirty    bool
	recRoot     string
	recLoaded   = map[string]bool{} // 成功读进来的桶文件，用于安全清理
	recLoadedMu sync.Mutex
)

func recordsRoot() string {
	if recRoot != "" {
		return recRoot
	}
	recRoot = filepath.Join(exeDir(), recordsRootDir)
	return recRoot
}

// sanitizeName 文件名只保留安全字符
func sanitizeName(s string) string {
	if s == "" {
		return "default"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}

// recordBucketFile records/<mode>/<account>.json
func recordBucketFile(mode, account string) string {
	if mode != "hook" && mode != "alipay" {
		mode = "key"
	}
	return filepath.Join(recordsRoot(), mode, sanitizeName(account)+".json")
}

// loadRecords 启动时把所有桶读回来；顺便迁移旧版 records.json
func loadRecords() []MsgView {
	recMu.Lock()
	defer recMu.Unlock()

	all := make([]MsgView, 0, 256)
	if err := filepath.WalkDir(recordsRoot(), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var items []MsgView
		if json.Unmarshal(b, &items) != nil {
			return nil
		}
		recLoadedMu.Lock()
		recLoaded[path] = true
		recLoadedMu.Unlock()
		all = append(all, items...)
		return nil
	}); err != nil && !os.IsNotExist(err) {
		logWarn("records", "读取记录目录失败: %v", err)
	}

	// 旧版单文件：迁移到 key 桶
	legacy := filepath.Join(exeDir(), legacyRecordsFn)
	if b, err := os.ReadFile(legacy); err == nil {
		var items []MsgView
		if json.Unmarshal(b, &items) == nil {
			for i := range items {
				if items[i].WxMode == "" {
					items[i].WxMode = "key"
				}
				if items[i].Account == "" {
					items[i].Account = items[i].To
				}
			}
			all = append(all, items...)
			_ = os.Rename(legacy, legacy+".migrated")
			logInfo("records", "已迁移旧记录 %d 条到 records/key/", len(items))
		}
	}

	// 支付宝记录与微信采集模式无关，统一挪到 alipay 桶，避免切模式后"看不到"
	migratedAlipay := false
	for i := range all {
		if all[i].Platform == "支付宝" && all[i].WxMode != "alipay" {
			all[i].WxMode = "alipay"
			migratedAlipay = true
		}
	}

	sort.Slice(all, func(i, j int) bool { return all[i].Time > all[j].Time })
	if migratedAlipay {
		saveRecordsBuckets(all)
		logInfo("records", "支付宝记录已归入独立分类")
	}

	// 首次从旧单文件迁移后立刻按桶落盘，避免"迁移了但目录还是空的"
	if len(all) > 0 {
		if _, err := os.Stat(recordsRoot()); err != nil {
			saveRecordsBuckets(all)
			logInfo("records", "已按模式/账号拆分落盘 %d 条", len(all))
		}
	}
	return all
}

// saveRecordsBuckets 按 (模式, 账号) 分组落盘
func saveRecordsBuckets(items []MsgView) {
	groups := map[string][]MsgView{}
	for _, it := range items {
		mode := it.WxMode
		if mode != "hook" && mode != "alipay" {
			mode = "key"
		}
		acc := it.Account
		if acc == "" {
			acc = it.To
		}
		key := mode + "|" + acc
		groups[key] = append(groups[key], it)
	}

	written := map[string]bool{}
	for key, list := range groups {
		parts := strings.SplitN(key, "|", 2)
		mode, acc := parts[0], parts[1]
		if len(list) > recordsMax {
			list = list[:recordsMax]
		}
		b, err := json.MarshalIndent(list, "", " ")
		if err != nil {
			continue
		}
		path := recordBucketFile(mode, acc)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			continue
		}
		tmp := path + ".tmp"
		if atomicWriteFile(tmp, b, 0o644) != nil {
			continue
		}
		if os.Rename(tmp, path) == nil {
			written[path] = true
		}
	}
	// 只清理「启动时成功读入、但本次没有内容」的桶，避免记录删了又复活。
	// 读盘失败的桶不在 recLoaded 里，绝不会被删。
	recLoadedMu.Lock()
	for path := range recLoaded {
		if !written[path] {
			_ = os.Remove(path)
			delete(recLoaded, path)
		}
	}
	recLoadedMu.Unlock()
}

// markRecordsDirty 标记有待落盘的数据
func markRecordsDirty() {
	recMu.Lock()
	recDirty = true
	recMu.Unlock()
}

// recordsFlusher 后台定时落盘：合并短时间内的多次写入，避免频繁 IO
func recordsFlusher(stop <-chan struct{}) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			recMu.Lock()
			dirty := recDirty
			recDirty = false
			recMu.Unlock()
			if !dirty {
				continue
			}
			eng.mu.Lock()
			items := make([]MsgView, len(eng.history))
			copy(items, eng.history)
			eng.mu.Unlock()
			saveRecordsBuckets(items)
		}
	}
}

// flushRecordsNow 立刻落盘（退出、清空记录时用）
func flushRecordsNow() {
	eng.mu.Lock()
	items := make([]MsgView, len(eng.history))
	copy(items, eng.history)
	eng.mu.Unlock()
	saveRecordsBuckets(items)
	recMu.Lock()
	recDirty = false
	recMu.Unlock()
}

// msgID 记录的唯一标识；有稳定源 ID 时优先使用它。
func msgID(v *MsgView) string {
	return messageDedupKey(&ChatMsg{
		From: v.From, To: v.To, Content: v.Content, Time: v.Time,
		StableID: v.StableID, LocalID: v.LocalID,
	})
}

// deleteRecords 删除指定 id 的记录，返回删除条数
func (e *Engine) deleteRecords(ids map[string]bool) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]MsgView, 0, len(e.history))
	removed := 0
	for i := range e.history {
		v := e.history[i]
		v.ID = msgID(&v)
		if ids[v.ID] {
			removed++
			continue
		}
		out = append(out, v)
	}
	if removed > 0 {
		e.history = out
		markRecordsDirty()
	}
	return removed
}
