package main

// Hook DLL 的注入与看护：
//   - 启用 Hook 模式时，把 native\easymon_hook*.dll 注入当前微信主进程；
//   - 微信重启（新 PID）后自动重新注入；
//   - 注入失败只记日志，不影响程序其它功能。

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"unsafe"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

var (
	hookWatchMu   sync.Mutex
	hookWatchStop chan struct{}
	injectedPid   uint32
)

// hookDLLPath 选一个存在的 DLL（优先 easymon_hook.dll，其次带版本后缀的）
func hookDLLPath() string {
	exe, err := os.Executable()
	base := "."
	if err == nil {
		base = filepath.Dir(exe)
	}
	// 发布版用中性文件名；开发时仍可用 easymon_hook*.dll
	matches, _ := filepath.Glob(filepath.Join(base, "native", "easymon_hook*.dll"))
	cands := matches
	prod, _ := filepath.Glob(filepath.Join(base, "native", "wxrt*.dll"))
	cands = append(cands, prod...)
	// 取最新的一个：换版本时直接丢新文件进 native 目录即可，不用改名
	best := ""
	var bestTime time.Time
	for _, p := range cands {
		st, err := os.Stat(p)
		if err != nil || st.Size() == 0 {
			continue
		}
		if best == "" || st.ModTime().After(bestTime) {
			best, bestTime = p, st.ModTime()
		}
	}
	return best
}

// injectDLL 用 LoadLibraryW 远程线程把 DLL 注入目标进程
// verifyDLL 注入前校验 DLL 哈希：随包发布时带 .sha256 旁文件，
// 不匹配就拒绝注入，避免把改坏的/被替换的组件送进微信进程。
func verifyDLL(path string) error {
	sumFile := strings.TrimSuffix(path, filepath.Ext(path)) + ".sha256"
	want, err := os.ReadFile(sumFile)
	if err != nil {
		// 开发环境没有旁文件：允许，但记一条
		logWarn("hook", "消息组件没有校验文件，按开发模式注入")
		return nil
	}
	expect := strings.ToLower(strings.TrimSpace(string(want)))
	if i := strings.IndexByte(expect, ' '); i > 0 {
		expect = expect[:i]
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("打开消息组件失败: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("读取消息组件失败: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != expect {
		return fmt.Errorf("消息组件校验失败（期望 %s，实际 %s）", expect[:12], got[:12])
	}
	return nil
}

func injectDLL(pid uint32, dllPath string) error {
	if err := verifyDLL(dllPath); err != nil {
		return err
	}
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	pOpen := k32.NewProc("OpenProcess")
	pAlloc := k32.NewProc("VirtualAllocEx")
	pWrite := k32.NewProc("WriteProcessMemory")
	pThread := k32.NewProc("CreateRemoteThread")
	pWait := k32.NewProc("WaitForSingleObject")
	pFree := k32.NewProc("VirtualFreeEx")
	pClose := k32.NewProc("CloseHandle")
	pLoadLib := k32.NewProc("LoadLibraryW")
	pGetExit := k32.NewProc("GetExitCodeThread")

	const (
		processAllAccess = 0x1F0FFF
		memCommit        = 0x1000
		memReserve       = 0x2000
		memRelease       = 0x8000
		pageReadWrite    = 0x04
	)

	h, _, err := pOpen.Call(processAllAccess, 0, uintptr(pid))
	if h == 0 {
		return fmt.Errorf("OpenProcess: %v", err)
	}
	defer pClose.Call(h)

	path, err := syscall.UTF16FromString(dllPath)
	if err != nil {
		return err
	}
	size := uintptr(len(path) * 2)
	remote, _, err := pAlloc.Call(h, 0, size, memCommit|memReserve, pageReadWrite)
	if remote == 0 {
		return fmt.Errorf("VirtualAllocEx: %v", err)
	}
	defer pFree.Call(h, remote, 0, memRelease)

	var written uintptr
	ok, _, err := pWrite.Call(h, remote, uintptr(unsafe.Pointer(&path[0])), size,
		uintptr(unsafe.Pointer(&written)))
	if ok == 0 {
		return fmt.Errorf("WriteProcessMemory: %v", err)
	}

	th, _, err := pThread.Call(h, 0, 0, pLoadLib.Addr(), remote, 0, 0)
	if th == 0 {
		return fmt.Errorf("CreateRemoteThread: %v", err)
	}
	defer pClose.Call(th)

	pWait.Call(th, 6000)
	var code uint32
	pGetExit.Call(th, uintptr(unsafe.Pointer(&code)))
	if code == 0 {
		return fmt.Errorf("LoadLibraryW 返回 0（注入被拒或路径不可达）")
	}
	return nil
}

// startHookWatcher 看护微信进程：没有注入就注入，换进程就重注；多开时逐个接管
func startHookWatcher() {
	hookWatchMu.Lock()
	if hookWatchStop != nil {
		hookWatchMu.Unlock()
		return
	}
	stop := make(chan struct{})
	hookWatchStop = stop
	hookWatchMu.Unlock()

	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				if GetConfig().EffectiveWxMode() != "hook" {
					continue
				}
				pids := MainWeChatPids()
				if len(pids) == 0 {
					continue
				}
				dll := hookDLLPath()
				if dll == "" {
					logWarn("hook", "缺少消息组件，请重新安装本程序")
					continue
				}
				// 每个实例打开的是自己的账号目录，据此得到 pid -> wxid
				wxidOf := WxidForPids(pids)
				// 目标 DLL 文件名：进程里加载的不是这一个就重挂
				wantDLL := strings.ToLower(filepath.Base(dll))
				for _, pid := range pids {
					if !loadedHookModule(pid, wantDLL) {
						before := hookLogSize()
						if err := injectDLL(pid, dll); err != nil {
							logError("hook", "接入微信失败（%d）：%v", pid, err)
							continue
						}
						time.Sleep(600 * time.Millisecond)
						if !hookLogHasSince(before, "hook 已安装") && !hookLogHasSince(before, "序言不匹配") {
							logWarn("hook", "消息组件尚未确认就绪（%d）", pid)
						}
						logInfo("hook", "已连接微信进程 %d", pid)
					}
					injectedPid = pid
					ensureHookAccountForPid(pid, wxidOf[pid])
				}
				pruneDeadHookAccounts(pids)
			}
		}
	}()
}

// singleWxidFromDisk 从微信数据目录推出当前登录的 wxid。
// 目录名形如 wxid_xxx_5d71，活跃账号的 db_storage 最近被写过，按修改时间取最新的那个。
func singleWxidFromDisk() string {
	root := WeChatRoot()
	if root == "" {
		return ""
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	strip := func(name string) string {
		if i := strings.LastIndex(name, "_"); i > 0 && len(name)-i == 5 {
			return name[:i]
		}
		return name
	}
	type cand struct {
		name string
		mod  time.Time
	}
	var list []cand
	for _, e := range ents {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "wxid_") {
			continue
		}
		// 活跃账号的消息库一直在写，用它的修改时间判断
		dbFile := filepath.Join(root, e.Name(), "db_storage", "message", "message_0.db")
		st, err := os.Stat(dbFile)
		if err != nil {
			dbFile = filepath.Join(root, e.Name(), "db_storage")
			st, err = os.Stat(dbFile)
		}
		if err != nil {
			continue
		}
		list = append(list, cand{name: strip(e.Name()), mod: st.ModTime()})
	}
	if len(list) == 0 {
		return ""
	}
	best := list[0]
	for _, c := range list[1:] {
		if c.mod.After(best.mod) {
			best = c
		}
	}
	return best.name
}

func ensureHookAccountForPid(pid uint32, knownWxid string) {
	pidInt := int(pid)
	wxid := knownWxid
	if wxid == "" && len(MainWeChatPids()) <= 1 {
		wxid = singleWxidFromDisk()
	}

	created := false
	err := UpdateConfig(func(c *Config) error {
		accounts := c.HookAccounts
		kept := make([]HookAccount, 0, len(accounts)+1)
		done := false
		changed := false
		for _, a := range accounts {
			if a.PID == pidInt {
				if done {
					changed = true
					continue
				}
				if wxid != "" && a.Wxid != wxid {
					a.Wxid = wxid
					changed = true
				}
				kept = append(kept, a)
				done = true
				continue
			}
			if wxid != "" && a.Wxid == wxid {
				if done {
					changed = true
					continue
				}
				if a.PID != pidInt {
					a.PID = pidInt
					changed = true
				}
				kept = append(kept, a)
				done = true
				continue
			}
			kept = append(kept, a)
		}

		if !done {
			if c.HookNoAutoBind && len(accounts) == 0 {
				return nil
			}
			if wxid != "" && c.HookBlockedWxid(wxid) {
				return nil
			}
			name := wxid
			if name == "" {
				name = fmt.Sprintf("pid:%d", pid)
			}
			kept = append(kept, HookAccount{Wxid: name, PID: pidInt, Enabled: true})
			changed = true
			created = true
		}
		if !changed {
			return nil
		}
		c.HookAccounts = kept
		return nil
	})
	if err != nil {
		logWarn("hook", "更新账号失败：%v", err)
		return
	}
	if created {
		logInfo("hook", "已自动绑定当前微信进程 pid=%d", pid)
		// 只有账号真的新增时才补发一轮心跳，避免每 5 秒都打平台一次
		if GetConfig().Mode == "xpay" {
			ensureXPayHeartbeat()
			go xpayHeartbeatRound()
		}
	}
}

// clearHookBlocked 用户手动添加账号时解除删除黑名单
func clearHookBlocked(wxid string) {
	c := GetConfig()
	out := make([]string, 0, len(c.HookBlocked))
	changed := false
	for _, x := range c.HookBlocked {
		if x == wxid {
			changed = true
			continue
		}
		out = append(out, x)
	}
	if !changed {
		return
	}
	c.HookBlocked = out
	_ = SetConfig(c)
}

func pruneDeadHookAccounts(alivePids []uint32) {
	alive := make(map[int]bool, len(alivePids))
	for _, p := range alivePids {
		alive[int(p)] = true
	}
	c := GetConfig()
	kept := make([]HookAccount, 0, len(c.HookAccounts))
	changed := false
	for _, a := range c.HookAccounts {
		if a.PID != 0 && !alive[a.PID] && !pidAlive(uint32(a.PID)) {
			changed = true
			continue
		}
		kept = append(kept, a)
	}
	if !changed {
		return
	}
	c.HookAccounts = kept
	if err := SetConfig(c); err != nil {
		logWarn("hook", "清理失效账号失败：%v", err)
		return
	}
	logInfo("hook", "已清理已退出的微信账号")
}

// pidAlive 进程是否还活着
func pidAlive(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

// snapshotModules 列出目标进程已加载的模块名
func snapshotModules(pid uint32) ([]string, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))
	var out []string
	if err := windows.Module32First(snap, &me); err != nil {
		return nil, err
	}
	for {
		out = append(out, windows.UTF16ToString(me.Module[:]))
		if err := windows.Module32Next(snap, &me); err != nil {
			break
		}
	}
	return out, nil
}

// stopHookWatcher 停止看护线程
func stopHookWatcher() {
	hookWatchMu.Lock()
	if hookWatchStop != nil {
		close(hookWatchStop)
		hookWatchStop = nil
	}
	hookWatchMu.Unlock()
}

// moduleLoaded 目标进程里是否已加载以 prefix 开头的模块
func moduleLoaded(pid uint32, prefix string) bool {
	mods, err := snapshotModules(pid)
	if err != nil {
		return false
	}
	prefix = strings.ToLower(prefix)
	for _, n := range mods {
		if strings.HasPrefix(strings.ToLower(n), prefix) {
			return true
		}
	}
	return false
}

// loadedHookModule 目标进程里是否已加载指定文件名的 hook 模块
func loadedHookModule(pid uint32, want string) bool {
	mods, err := snapshotModules(pid)
	if err != nil {
		return false
	}
	want = strings.ToLower(want)
	for _, n := range mods {
		if strings.ToLower(n) == want {
			return true
		}
	}
	return false
}

// HookDLLInfo 供界面显示
func HookDLLInfo() map[string]any {
	dll := hookDLLPath()
	return map[string]any{
		"exists":       dll != "",
		"path":         dll,
		"name":         filepath.Base(dll),
		"injected_pid": injectedPid,
	}
}

func hookLogPath() string { return filepath.Join(os.TempDir(), "easymon_hook.log") }

func hookLogSize() int64 {
	st, err := os.Stat(hookLogPath())
	if err != nil {
		return 0
	}
	return st.Size()
}

func hookLogHasSince(offset int64, needle string) bool {
	f, err := os.Open(hookLogPath())
	if err != nil {
		return false
	}
	defer f.Close()
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return false
		}
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return false
	}
	return strings.Contains(string(b), needle)
}

