package main

// 通行密钥提取（自研，不依赖外部 DLL）
//
// 依据微信 4.1+ WCDB/SQLCipher 的实际存储方式：
//   1. 密钥在内存里以 MSVC std::string 存放，内容经过 XOR 混淆
//   2. XOR 常量来自 Weixin.dll 里 4 条相邻的 `mov rdx, imm64`（4×8 = 32 字节）
//   3. 解密后 32 字节即数据库密钥
//
// 所以不需要 hook、不需要重启微信，直接读内存即可。

import (
	"context"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sort"
	"time"
	"unsafe"
)

var procVirtualQueryEx = kernel32.NewProc("VirtualQueryEx")

// 密钥扫描进度（给 UI 轮询）
var (
	scanMu       sync.Mutex
	scanRunning  bool
	scanDone     int
	scanTotal    int
	scanPhase    string
	scanResult   KeyResult
)

// ScanProgress 当前扫描进度
type ScanProgress struct {
	Running bool   `json:"running"`
	Done    int    `json:"done"`
	Total   int    `json:"total"`
	Phase   string `json:"phase"`
	OK      bool   `json:"ok"`
	Key     string `json:"key"`
	Note    string `json:"note"`
}

func scanProgress() ScanProgress {
	scanMu.Lock()
	defer scanMu.Unlock()
	return ScanProgress{
		Running: scanRunning, Done: scanDone, Total: scanTotal,
		Phase: scanPhase, OK: scanResult.OK, Key: scanResult.Key, Note: scanResult.Note,
	}
}

func setPhase(s string) {
	scanMu.Lock(); scanPhase = s; scanMu.Unlock()
}

// MemoryBasicInformation 对应 MEMORY_BASIC_INFORMATION
type memBasicInfo struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	_                 uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	_                 uint32
}

const (
	memCommit  = 0x1000
	memPrivate = 0x20000

	pageReadOnly  = 0x02
	pageReadWrite = 0x04
	pageWriteCopy = 0x08
	pageExecuteR  = 0x20
	pageExecuteW  = 0x80
)

// xorKeysInDLL 在 Weixin.dll 里找 XOR 常量链。
// 每组返回 32 字节（4 个 little-endian imm64 拼接）。
func xorKeysInDLL(dllPath string) ([][]byte, error) {
	d, err := os.ReadFile(dllPath)
	if err != nil {
		return nil, err
	}

	type hit struct {
		off int
		imm uint64
	}
	var hits []hit
	for i := 0; i+10 <= len(d); i++ {
		if d[i] == 0x48 && d[i+1] == 0xBA { // mov rdx, imm64
			hits = append(hits, hit{i, binary.LittleEndian.Uint64(d[i+2 : i+10])})
			i += 9
		}
	}
	if len(hits) == 0 {
		return nil, fmt.Errorf("Weixin.dll 里没有 mov rdx,imm64")
	}

	var out [][]byte
	for a := 0; a < len(hits); a++ {
		chain := []hit{hits[a]}
		idx := a
		for step := 0; step < 3; step++ {
			found := false
			for b := idx + 1; b < len(hits) && b < idx+8; b++ {
				gap := hits[b].off - (hits[idx].off + 10)
				if gap >= 3 && gap <= 8 {
					chain = append(chain, hits[b])
					idx = b
					found = true
					break
				}
			}
			if !found {
				break
			}
		}
		if len(chain) != 4 {
			continue
		}
		// 链尾后面应出现 test rax, rax（48 85 C0）
		end := chain[3].off + 10
		if end+3 > len(d) || d[end] != 0x48 || d[end+1] != 0x85 || d[end+2] != 0xC0 {
			// 再给几个字节的容差
			win := d[end:min(end+12, len(d))]
			if !bytes.Contains(win, []byte{0x48, 0x85, 0xC0}) {
				continue
			}
		}
		key := make([]byte, 32)
		for i, c := range chain {
			binary.LittleEndian.PutUint64(key[i*8:], c.imm)
		}
		out = append(out, key)
	}
	return out, nil
}

// keyCandidate 一个候选，带所在内存区域的信息（用于排序）
type keyCandidate struct {
	Raw        []byte
	RegionBase uintptr
	RegionSize uintptr
}

// scanStringCandidates 扫微信进程内存，返回所有 size=32/cap=47 的 std::string 内容。
//
// 关键：按「内存区域大小降序」排序后再验证。实测真密钥落在大区域（堆/消息缓冲）里，
// 排序后命中位置从 1109 提前到 57，验证耗时从数分钟降到十几秒。
func scanStringCandidates(pid uint32, h Handle) []keyCandidate {
	var cands []keyCandidate
	var mbi memBasicInfo
	addr := uintptr(0)
	const limit = 0x7FFFFFFFFFFF

	for addr < limit {
		r, _, _ := procVirtualQueryEx.Call(
			uintptr(h), addr,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if r == 0 {
			break
		}
		base, size := mbi.BaseAddress, mbi.RegionSize
		if size == 0 {
			break
		}

		readable := (mbi.Protect & 0xFF) == pageReadOnly ||
			(mbi.Protect&0xFF) == pageReadWrite ||
			(mbi.Protect&0xFF) == pageWriteCopy ||
			(mbi.Protect&0xFF) == pageExecuteR ||
			(mbi.Protect&0xFF) == pageExecuteW

		if mbi.State == memCommit && mbi.Type == memPrivate && readable && size <= 0x40000000 {
			const chunk = uintptr(4 << 20)
			for off := uintptr(0); off < size; off += chunk {
				n := chunk
				if off+n > size {
					n = size - off
				}
				buf, err := h.Read(base+off, int(n))
				if err != nil || len(buf) < 32 {
					continue
				}
				for i := 0; i+32 <= len(buf); i += 8 {
					// MSVC std::string（堆模式）：
					//   offset 0  : ptr
					//   offset 8  : 未用（必须为 0）
					//   offset 16 : size
					//   offset 24 : capacity
					sz := binary.LittleEndian.Uint64(buf[i+16:])
					if sz != 32 {
						continue
					}
					// capacity：MSVC 对 32 字节字符串通常分配 47，
					// 但不同编译器/版本可能不同，放宽到 33..64。
					// 放宽只影响候选数量，最终由 HMAC 验证兜底，不会误判。
					cp := binary.LittleEndian.Uint64(buf[i+24:])
					if cp < 33 || cp > 64 {
						continue
					}
					// 第二 qword 为 0 这个条件能把候选砍掉一大半
					if binary.LittleEndian.Uint64(buf[i+8:]) != 0 {
						continue
					}
					ptr := binary.LittleEndian.Uint64(buf[i:])
					if ptr < 0x10000 || ptr > limit {
						continue
					}
					raw, err := h.Read(uintptr(ptr), 32)
					if err != nil || len(raw) < 32 {
						continue
					}
					cands = append(cands, keyCandidate{
						Raw: raw, RegionBase: base, RegionSize: size,
					})
				}
			}
		}

		next := base + size
		if next <= addr {
			break
		}
		addr = next
	}

	return cands
}

// extractKeyByScan 当前进程方案：读内存 + XOR 解密
func extractKeyByScan(weixinExe, targetWxid string) KeyResult {
	// 微信多开时会有多个主进程，每个进程持有一个已登录账号的密钥，
	// 必须全部扫一遍，否则永远找不到第二个账号的密钥。
	pids := PidsByName(WeChatProc)
	if len(pids) == 0 {
		return KeyResult{Note: "微信没有运行，请先启动微信并登录"}
	}

	// 找 Weixin.dll：微信 4.x 把它放在版本子目录（D:\Weixin\4.1.13.63\Weixin.dll）
	findDLL := func(exe string) string {
		if exe == "" {
			return ""
		}
		dir := filepath.Dir(exe)
		direct := filepath.Join(dir, "Weixin.dll")
		if _, err := os.Stat(direct); err == nil {
			return direct
		}
		// 版本子目录
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				cand := filepath.Join(dir, e.Name(), "Weixin.dll")
				if _, err := os.Stat(cand); err == nil {
					return cand
				}
			}
		}
		return ""
	}
	// 优先从运行中的微信进程模块列表取 Weixin.dll 的真实路径，
	// 换设备/改安装目录后照样能命中；拿不到再退回从 exe 路径推导。
	dllPath := ""
	for _, pid := range PidsByName(WeChatProc) {
		if p := findModulePath(pid, "Weixin.dll"); p != "" {
			dllPath = p
			break
		}
	}
	if dllPath == "" {
		dllPath = findDLL(weixinExe)
	}
	if dllPath == "" {
		dllPath = findDLL(detectWeChatExe())
	}
	if dllPath == "" {
		return KeyResult{Note: "找不到 Weixin.dll，请在设置里确认微信安装路径"}
	}

	keys, err := xorKeysInDLL(dllPath)
	if err != nil || len(keys) == 0 {
		return KeyResult{Note: "无法从 Weixin.dll 解析 XOR 常量"}
	}

	// 快速路径：只沿用「这个账号自己」已保存的密钥。
	// 多账号时绝不能拿别的账号的密钥去验证，否则会串号。
	if targetWxid != "" {
		if cfg := GetConfig(); cfg.DbKey != "" && cfg.DbWxid == targetWxid {
			if vAcc, ok := findWxAccount(targetWxid); ok && vAcc.HasBiz {
				if verifyKeyFast(cfg.DbKey, vAcc.BizDB) {
					return KeyResult{OK: true, Key: cfg.DbKey, Note: "沿用该账号已保存的密钥"}
				}
			}
		}
		for _, da := range GetConfig().EffectiveDbAccounts() {
			if da.Wxid != targetWxid || da.Key == "" {
				continue
			}
			if vAcc, ok := findWxAccount(targetWxid); ok && vAcc.HasBiz {
				if verifyKeyFast(da.Key, vAcc.BizDB) {
					return KeyResult{OK: true, Key: da.Key, Note: "沿用该账号已保存的密钥"}
				}
			}
			break
		}
	}

	// 遍历所有微信主进程收集候选。
	// 只保留真正持有 Weixin.dll 的主进程（子进程里没有密钥）。
	start := time.Now()
	var cands []keyCandidate
	scanned := 0
	for _, pid := range pids {
		if !processHasModule(pid, "Weixin.dll") {
			continue
		}
		h, err := OpenProcess(pid, uint32(PROCESS_ALL_ACCESS))
		if err != nil {
			logWarn("monitor", "密钥扫描：打开进程 %d 失败: %v", pid, err)
			continue
		}
		one := scanStringCandidates(pid, h)
		h.Close()
		scanned++
		if len(one) > 0 {
			logInfo("monitor", "密钥扫描：进程 %d 找到 %d 个候选", pid, len(one))
		}
		cands = append(cands, one...)
	}
	if scanned == 0 {
		return KeyResult{Note: "没能打开任何微信进程（需要管理员权限）"}
	}
	if len(cands) == 0 {
		return KeyResult{Note: "内存里没找到密钥结构，请确认微信已登录"}
	}
	// 所有进程的候选放在一起按「内存区域大小降序」排：
	// 真密钥落在大块堆内存里，排前面能让命中位置从几千降到几十。
	sort.SliceStable(cands, func(a, b int) bool {
		if cands[a].RegionSize != cands[b].RegionSize {
			return cands[a].RegionSize > cands[b].RegionSize
		}
		if cands[a].RegionBase != cands[b].RegionBase {
			return cands[a].RegionBase < cands[b].RegionBase
		}
		return a < b
	})
	logInfo("monitor", "密钥扫描：%d 个进程共 %d 个原始候选，用时 %d ms",
		scanned, len(cands), time.Since(start).Milliseconds())

	// 去重 + 过滤明显无效的（全 0、全 FF、重复字节）
	seen := map[string]bool{}
	var uniq []string
	for _, cand := range cands {
		raw := cand.Raw
		for _, k := range keys {
			dec := make([]byte, 32)
			var same byte
			allSame := true
			for i := 0; i < 32; i++ {
				dec[i] = raw[i] ^ k[i]
				if i == 0 {
					same = dec[i]
				} else if dec[i] != same {
					allSame = false
				}
			}
			if allSame { // 全 0 / 全 FF 之类
				continue
			}
			hx := fmt.Sprintf("%x", dec)
			if seen[hx] {
				continue
			}
			seen[hx] = true
			uniq = append(uniq, hx)
		}
	}
	logInfo("monitor", "密钥扫描：去重后 %d 个候选，开始验证", len(uniq))

	// 保持扫描顺序：大内存区域在前（真密钥通常落在堆里），
	// 实测这比按出现次数排序快得多。
	order := uniq

	// 用「目标账号自己的数据库」验证，不能拿别的账号的库
	wxid := targetWxid
	if wxid == "" {
		wxid = GetConfig().DbWxid
	}
	if wxid == "" {
		for _, a := range ScanWxAccounts() {
			if a.HasBiz {
				wxid = a.Wxid
				break
			}
		}
	}
	acc, ok := findWxAccount(wxid)
	if !ok || !acc.HasBiz {
		return KeyResult{Note: "没有可用于验证的微信数据库"}
	}

	// 用 SQLCipher 第一页 HMAC 验证，不打开数据库：
	//   · 单次只需一次 PBKDF2（约 85ms），比 wxtool_open 快 2 倍多
	//   · 纯计算，没有全局锁，可以多线程并行（8 线程后约 16ms/个）
	// 这是能做到「几十秒扫完」的关键。早先用 wxtool_open 串行扫要 6 分钟。
	page1Path := acc.SessionDB
	if page1Path == "" || !fileExists(page1Path) {
		page1Path = acc.BizDB
	}
	page1, err := readFirstPage(page1Path)
	if err != nil {
		return KeyResult{Note: "读取数据库首页失败: " + err.Error()}
	}
	logInfo("monitor", "密钥验证：目标=%q 库=%s 候选=%d 并行验证",
		acc.Wxid, filepath.Base(page1Path), len(order))

	scanMu.Lock()
	scanTotal = len(order)
	scanDone = 0
	scanPhase = "验证候选"
	scanMu.Unlock()

	workers := runtime.NumCPU()
	if workers < 4 {
		workers = 4
	}
	if workers > 16 {
		workers = 16
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	idxCh := make(chan int, workers*2)
	foundCh := make(chan string, 1)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range idxCh {
				select {
				case <-ctx.Done():
					return
				default:
				}
				hx := order[idx]
				key := hexTo32(hx)
				if key == nil {
					continue
				}
				if scVerifyPage1(key, page1) {
					select {
					case foundCh <- hx:
					default:
					}
					cancel()
					return
				}
				scanMu.Lock()
				scanDone++
				scanMu.Unlock()
			}
		}()
	}

	go func() {
		defer close(idxCh)
		for i := range order {
			select {
			case <-ctx.Done():
				return
			case idxCh <- i:
			}
		}
	}()

	wg.Wait()
	cancel()

	select {
	case hx := <-foundCh:
		// 用同一把密钥再确认一次 biz 库（监控读的是它）
		if page1Path != acc.BizDB {
			if b1, e := readFirstPage(acc.BizDB); e == nil {
				if !verifyKeyByHMAC(hx, []scSample{{Path: acc.BizDB, Page1: b1}}) {
					logWarn("monitor", "密钥 %s 能开 session.db 但开不了 biz 库", hx[:16])
				}
			}
		}
		scanMu.Lock()
		scanDone = scanTotal
		scanMu.Unlock()
		return KeyResult{
			OK: true, Key: hx,
			Note:  fmt.Sprintf("已从微信内存取到密钥（%d ms，%d 线程）", time.Since(start).Milliseconds(), workers),
			Waits: len(order),
		}
	default:
	}

	scanMu.Lock()
	tried := scanDone
	scanMu.Unlock()
	return KeyResult{
		Note:  fmt.Sprintf("扫描 %d 个候选、验证 %d 个，都打不开数据库", len(uniq), tried),
		Waits: tried,
	}
}

// hexTo32 把 64 位十六进制转成 32 字节
func hexTo32(s string) []byte {
	if len(s) != 64 {
		return nil
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hi := hexVal(s[i*2])
		lo := hexVal(s[i*2+1])
		if hi < 0 || lo < 0 {
			return nil
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
// StartKeyScan 异步启动扫描
func StartKeyScan(targetWxid string) {
	scanMu.Lock()
	if scanRunning {
		scanMu.Unlock()
		return
	}
	scanRunning = true
	scanDone, scanTotal = 0, 0
	scanPhase = "扫描内存"
	scanResult = KeyResult{}
	scanMu.Unlock()

	go func() {
		cfg := GetConfig()
		res := extractKeyByScan(cfg.WeChatExe, targetWxid)
		scanMu.Lock()
		scanRunning = false
		scanPhase = "完成"
		scanResult = res
		scanMu.Unlock()
		if !res.OK {
			logInfo("monitor", "自动获取失败：%s", res.Note)
			return
		}
		// 只写回目标账号，绝不覆盖别的账号
		cfg = GetConfig()
		hit := false
		for i := range cfg.DbAccounts {
			if cfg.DbAccounts[i].Wxid == targetWxid {
				cfg.DbAccounts[i].Key = res.Key
				cfg.DbAccounts[i].Enabled = true
				hit = true
				break
			}
		}
		if !hit && targetWxid != "" {
			cfg.DbAccounts = append(cfg.DbAccounts, DbAccount{
				Wxid: targetWxid, Key: res.Key, Enabled: true,
			})
		}
		if targetWxid == "" || cfg.DbWxid == "" || cfg.DbWxid == targetWxid {
			cfg.DbWxid = targetWxid
			cfg.DbKey = res.Key
		}
		SetConfig(cfg)
		logInfo("monitor", "账号 %s 的通行密钥已获取并保存", targetWxid)
	}()
}

// verifyKeyFast 直接调 wxtool_open 验证密钥（不走 goroutine，快且不干扰监控）
func verifyKeyFast(keyHex, dbPath string) bool {
	if err := wcdbInit(); err != nil {
		return false
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	p := append([]byte(dbPath), 0)
	k := append([]byte(keyHex), 0)
	var h, es uintptr
	r, _, _ := wcdbOpen.Call(
		uintptr(unsafe.Pointer(&p[0])),
		uintptr(unsafe.Pointer(&k[0])),
		4096, 0,
		uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(&es)),
	)
	runtime.KeepAlive(p)
	runtime.KeepAlive(k)
	if int32(r) != 0 {
		if es != 0 {
			wcdbFree.Call(es)
		}
		return false
	}
	wcdbClose.Call(h)
	return true
}

var _ = runtime.KeepAlive

















