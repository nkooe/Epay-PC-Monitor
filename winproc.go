package main

// 枚举「有可见窗口」的进程，用来从多个 Weixin.exe 里挑出主进程
// （微信多开时会有一堆渲染/工具子进程，只绑主进程才不会被误导）。

import (
	"strings"
	"syscall"
	"unsafe"
)

var (
	procGetClassNameW = user32.NewProc("GetClassNameW")
)

var (
	user32              = syscall.NewLazyDLL("user32.dll")
	procEnumWindows             = user32.NewProc("EnumWindows")
	procGetWindowThreadPid      = user32.NewProc("GetWindowThreadProcessId")
	procIsWindowVisible         = user32.NewProc("IsWindowVisible")
	procGetWindowTextW          = user32.NewProc("GetWindowTextW")
)

// VisiblePids 返回拥有可见顶层窗口的进程号集合
func VisiblePids() map[uint32]bool {
	out := map[uint32]bool{}
	cb := syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		if v, _, _ := procIsWindowVisible.Call(hwnd); v == 0 {
			return 1 // 继续枚举
		}
		var pid uint32
		procGetWindowThreadPid.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if pid != 0 {
			out[pid] = true
		}
		return 1
	})
	procEnumWindows.Call(cb, 0)
	return out
}

// MainPidsOf 只保留有可见窗口的同名进程；一个都没有时退回全部
func MainPidsOf(name string) []uint32 {
	all := PidsByName(name)
	if len(all) == 0 {
		return nil
	}
	vis := VisiblePids()
	kept := make([]uint32, 0, len(all))
	for _, p := range all {
		if vis[p] {
			kept = append(kept, p)
		}
	}
	if len(kept) == 0 {
		return all
	}
	return kept
}

// MainWeChatPid 找微信主窗口所属进程：窗口类名 WeChatMainWndForPC 或标题「微信」
func MainWeChatPid() uint32 {
	var found uint32
	cb := syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		var buf [128]uint16
		n, _, _ := procGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 128)
		class := syscall.UTF16ToString(buf[:n])
		ok := strings.Contains(class, "WeChatMainWndForPC")
		if !ok {
			n2, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 128)
			title := syscall.UTF16ToString(buf[:n2])
			ok = title == "微信" || title == "WeChat"
		}
		if ok {
			var pid uint32
			procGetWindowThreadPid.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
			if pid != 0 {
				found = pid
				return 0 // 找到就停
			}
		}
		return 1
	})
	procEnumWindows.Call(cb, 0)
	return found
}

// MainWeChatPids 所有微信主窗口的进程（双开时会有多个）
func MainWeChatPids() []uint32 {
	var out []uint32
	seen := map[uint32]bool{}
	cb := syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		var buf [128]uint16
		n, _, _ := procGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 128)
		class := syscall.UTF16ToString(buf[:n])
		ok := strings.Contains(class, "WeChatMainWndForPC")
		if !ok {
			n2, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 128)
			title := syscall.UTF16ToString(buf[:n2])
			ok = title == "微信" || title == "WeChat"
		}
		if ok {
			var pid uint32
			procGetWindowThreadPid.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
			if pid != 0 && !seen[pid] {
				seen[pid] = true
				out = append(out, pid)
			}
		}
		return 1
	})
	procEnumWindows.Call(cb, 0)
	return out
}
