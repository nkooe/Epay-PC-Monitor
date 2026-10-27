package main

// Windows API 封装（只用 syscall，无外部依赖）

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	procShellExecute  = shell32.NewProc("ShellExecuteW")
	procOpenProcess   = kernel32.NewProc("OpenProcess")
	procCloseHandle   = kernel32.NewProc("CloseHandle")
	procVirtualAllocEx = kernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx = kernel32.NewProc("VirtualFreeEx")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	procReadProcessMemory  = kernel32.NewProc("ReadProcessMemory")
	procVirtualProtectEx   = kernel32.NewProc("VirtualProtectEx")
	procCreateSnapshot     = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First     = kernel32.NewProc("Process32FirstW")
	procProcess32Next      = kernel32.NewProc("Process32NextW")
	procGetModuleHandle    = kernel32.NewProc("GetModuleHandleW")
	procCreateThread       = kernel32.NewProc("CreateThread")
	procSleep              = kernel32.NewProc("Sleep")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
	procGetConsoleWindow      = kernel32.NewProc("GetConsoleWindow")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procFreeConsole           = kernel32.NewProc("FreeConsole")
	procCreateMutexW          = kernel32.NewProc("CreateMutexW")
)

const (
	SW_SHOWNORMAL          = 1
	PROCESS_ALL_ACCESS     = 0x1F0FFF
	PROCESS_VM_READ        = 0x0010
	PROCESS_QUERY_INFO     = 0x0400
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	MEM_COMMIT_RESERVE     = 0x3000
	PAGE_READWRITE         = 0x04
	PAGE_EXECUTE_READWRITE = 0x40
	TH32CS_SNAPPROCESS     = 0x00000002
)

type PROCESSENTRY32W struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

func PidByName(name string) uint32 {
	snap, _, _ := procCreateSnapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snap == 0 || snap == uintptr(syscall.InvalidHandle) {
		return 0
	}
	defer procCloseHandle.Call(snap)

	var pe PROCESSENTRY32W
	pe.Size = uint32(unsafe.Sizeof(pe))
	r, _, _ := procProcess32First.Call(snap, uintptr(unsafe.Pointer(&pe)))
	for r != 0 {
		exe := syscall.UTF16ToString(pe.ExeFile[:])
		if equalFold(exe, name) {
			return pe.ProcessID
		}
		r, _, _ = procProcess32Next.Call(snap, uintptr(unsafe.Pointer(&pe)))
	}
	return 0
}

// PidsByName 返回所有同名进程（微信多开时会有多个）
func PidsByName(name string) []uint32 {
	snap, _, _ := procCreateSnapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snap == 0 || snap == uintptr(syscall.InvalidHandle) {
		return nil
	}
	defer procCloseHandle.Call(snap)

	var out []uint32
	var pe PROCESSENTRY32W
	pe.Size = uint32(unsafe.Sizeof(pe))
	r, _, _ := procProcess32First.Call(snap, uintptr(unsafe.Pointer(&pe)))
	for r != 0 {
		exe := syscall.UTF16ToString(pe.ExeFile[:])
		if equalFold(exe, name) {
			out = append(out, pe.ProcessID)
		}
		r, _, _ = procProcess32Next.Call(snap, uintptr(unsafe.Pointer(&pe)))
	}
	return out
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

type Handle uintptr

func OpenProcess(pid uint32, access uint32) (Handle, error) {
	h, _, err := procOpenProcess.Call(uintptr(access), 0, uintptr(pid))
	if h == 0 {
		return 0, fmt.Errorf("OpenProcess(%d) 失败: %v", pid, err)
	}
	return Handle(h), nil
}

func (h Handle) Close() { procCloseHandle.Call(uintptr(h)) }

func (h Handle) Alloc(size int, protect uint32) (uintptr, error) {
	a, _, err := procVirtualAllocEx.Call(uintptr(h), 0, uintptr(size), MEM_COMMIT_RESERVE, uintptr(protect))
	if a == 0 {
		return 0, fmt.Errorf("VirtualAllocEx 失败: %v", err)
	}
	return a, nil
}

func (h Handle) Write(addr uintptr, data []byte) error {
	var written uintptr
	r, _, err := procWriteProcessMemory.Call(uintptr(h), addr,
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&written)))
	runtime.KeepAlive(data)
	if r == 0 {
		return fmt.Errorf("WriteProcessMemory 失败: %v", err)
	}
	if int(written) != len(data) {
		return fmt.Errorf("只写入 %d/%d 字节", written, len(data))
	}
	return nil
}

func (h Handle) Read(addr uintptr, size int) ([]byte, error) {
	buf := make([]byte, size)
	var got uintptr
	r, _, err := procReadProcessMemory.Call(uintptr(h), addr,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&got)))
	// 必须：GC 不知道系统调用仍在引用 buf
	runtime.KeepAlive(buf)
	if r == 0 {
		return nil, fmt.Errorf("ReadProcessMemory 失败(addr=0x%X,size=%d): %v", addr, size, err)
	}
	if got > uintptr(size) {
		got = uintptr(size)
	}
	return buf[:got], nil
}

func (h Handle) Protect(addr uintptr, size int, newProt uint32) (uint32, error) {
	var old uint32
	r, _, err := procVirtualProtectEx.Call(uintptr(h), addr, uintptr(size),
		uintptr(newProt), uintptr(unsafe.Pointer(&old)))
	if r == 0 {
		return 0, fmt.Errorf("VirtualProtectEx 失败: %v", err)
	}
	return old, nil
}

// ModuleBase 通过读 PE 头从 PEB 拿模块基址（简化：用 CreateToolhelp32Snapshot 的模块枚举）
func (h Handle) FindModuleBase(dllName string) (uintptr, uint32, error) {
	return findModule(uint32(h), dllName)
}

func Sleep(ms int) { procSleep.Call(uintptr(ms)) }


// wechatExeFromProcess 通过运行中的微信进程拿 exe 完整路径。
// 比猜安装目录可靠得多——换设备、装到别的盘都能找到。
func wechatExeFromProcess() string {
	for _, pid := range PidsByName("Weixin.exe") {
		h, err := syscall.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			continue
		}
		buf := make([]uint16, syscall.MAX_PATH)
		size := uint32(len(buf))
		r, _, _ := procQueryFullProcessImageNameW.Call(
			uintptr(h),
			0,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
		)
		syscall.CloseHandle(h)
		if r != 0 && size > 0 {
			return syscall.UTF16ToString(buf[:size])
		}
	}
	return ""
}

// hideConsoleWindow 隐藏程序附带的控制台窗口。
// GUI 子系统本来没有控制台，但从命令行/某些启动器拉起时
// stdout 可能连到控制台，日志会刷屏。这里直接把它藏起来。
// 只在控制台归本进程独占时隐藏，避免把用户自己的 cmd 窗口关掉。
func hideConsoleWindow() {
	// 1) 有可见控制台就藏起来
	r, _, _ := procGetConsoleWindow.Call()
	if r != 0 {
		hwnd := r
		// 控制台只属于本进程时才隐藏，避免影响用户自己的 cmd
		pidBuf := make([]uint32, 4)
		n, _, _ := procGetConsoleProcessList.Call(
			uintptr(unsafe.Pointer(&pidBuf[0])),
			uintptr(len(pidBuf)),
		)
		if n <= 1 {
			procShowWindow.Call(hwnd, SW_HIDE)
		}
	}
	// 2) 完全脱离控制台：这样 conhost.exe 会退出，
	//    也不会因为后台 Printf 又冒出来
	procFreeConsole.Call()
}

// openExplorer 用资源管理器打开指定目录
func openExplorer(dir string) {
	verb, err := syscall.UTF16PtrFromString("open")
	if err != nil {
		return
	}
	path, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return
	}
	procShellExecute.Call(0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(path)),
		0, 0, SW_SHOWNORMAL)
}

// ensureSingleInstance 保证同时只有一个实例在跑。
// 没有这个保护的话，双击两次会起两个进程：
// 两个都在轮询同一个数据库、都在往平台上报，同一笔收款会重复入账。
// 返回 true 表示本进程是唯一实例。
func ensureSingleInstance(name string) bool {
	np, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return true
	}
	h, _, e := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(np)))
	if h == 0 {
		logWarn("system", "创建互斥体失败: %v", e)
		return true // 创建不了就别拦着用户
	}
	// ERROR_ALREADY_EXISTS = 183
	if errno, ok := e.(syscall.Errno); ok && errno == 183 {
		procCloseHandle.Call(h)
		return false
	}
	// 句柄故意不关：进程退出时系统自动释放
	return true
}
