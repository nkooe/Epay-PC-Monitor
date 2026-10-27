package main

// 通过枚举微信进程打开的文件句柄，找到它自己的 db_storage 路径，
// 从而得到 pid → wxid（多开时每个实例对应一个账号目录）。
// 只读：复制句柄 + 查询对象名，不修改目标进程，也不碰微信内存。

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ntdllWhoami                  = windows.NewLazySystemDLL("ntdll.dll")
	procNtQuerySystemInformation = ntdllWhoami.NewProc("NtQuerySystemInformation")
	procNtQueryObject            = ntdllWhoami.NewProc("NtQueryObject")
	procGetFileTypeWhoami        = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetFileType")
)

const (
	systemExtendedHandleInformation = 64
	objectNameInformation           = 1
	statusInfoLengthMismatch        = 0xC0000004
	fileTypeDisk                    = 2
	fileTypePipe                    = 3
)

type sysHandleEntryEx struct {
	Object           uintptr
	UniqueProcessID  uintptr
	HandleValue      uintptr
	GrantedAccess    uint32
	ObjectTypeIndex  uint16
	HandleAttributes uint16
	Reserved         uint32
}

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

func snapshotHandles() []sysHandleEntryEx {
	size := uint32(1 << 23)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		var ret uint32
		r, _, _ := procNtQuerySystemInformation.Call(
			systemExtendedHandleInformation,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(size),
			uintptr(unsafe.Pointer(&ret)))
		if uint32(r) == statusInfoLengthMismatch {
			size = ret + 1<<20
			continue
		}
		if r != 0 {
			return nil
		}
		count := *(*uintptr)(unsafe.Pointer(&buf[0]))
		if count == 0 || count > 1<<22 {
			return nil
		}
		base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(uintptr(0))*2
		esz := unsafe.Sizeof(sysHandleEntryEx{})
		out := make([]sysHandleEntryEx, 0, count)
		for i := uintptr(0); i < count; i++ {
			e := (*sysHandleEntryEx)(unsafe.Pointer(base + i*esz))
			out = append(out, *e)
		}
		return out
	}
	return nil
}

// objectName 取句柄对应的对象名（文件路径形如 \Device\HarddiskVolume3\...）
func objectName(h windows.Handle) string {
	// 只跳过管道：同步管道上查询名字可能永久阻塞。
	// 目录/设备的类型可能是 0，不能一刀切过滤掉。
	if t, _, _ := procGetFileTypeWhoami.Call(uintptr(h)); uint32(t) == fileTypePipe {
		return ""
	}
	return objectNameAny(h)
}

// objectNameAny 不做类型过滤，仅用于诊断
func objectNameAny(h windows.Handle) string {
	buf := make([]uint16, 1024)
	var ret uint32
	st, _, _ := procNtQueryObject.Call(uintptr(h), objectNameInformation,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2),
		uintptr(unsafe.Pointer(&ret)))
	if uint32(st) == statusInfoLengthMismatch && ret > 0 && ret < 1<<20 {
		buf = make([]uint16, int(ret)/2+2)
		st, _, _ = procNtQueryObject.Call(uintptr(h), objectNameInformation,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2),
			uintptr(unsafe.Pointer(&ret)))
	}
	if st != 0 {
		return ""
	}
	us := (*unicodeString)(unsafe.Pointer(&buf[0]))
	if us.Length == 0 || us.Buffer == nil {
		return ""
	}
	n := int(us.Length) / 2
	if n <= 0 || n > len(buf) {
		return ""
	}
	return windows.UTF16ToString(unsafe.Slice(us.Buffer, n))
}

// wxidFromPath 从 \...\xwechat_files\wxid_xxx_abcd\db_storage\... 里取出 wxid
func wxidFromPath(p string) string {
	low := strings.ToLower(p)
	i := strings.Index(low, `\xwechat_files\`)
	if i < 0 {
		i = strings.Index(low, `\wechat files\`)
		if i < 0 {
			return ""
		}
	}
	rest := p[i+len(`\xwechat_files\`):]
	if j := strings.IndexByte(rest, '\\'); j >= 0 {
		rest = rest[:j]
	}
	if !strings.HasPrefix(strings.ToLower(rest), "wxid_") {
		return ""
	}
	// 目录名带 4 位后缀：wxid_xxx_5d71
	if k := strings.LastIndex(rest, "_"); k > 0 && len(rest)-k == 5 {
		rest = rest[:k]
	}
	return rest
}

// WxidForPid 目标进程打开的微信账号目录 → wxid；拿不到返回空
func WxidForPid(pid uint32) string {
	proc, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(proc)

	entries := snapshotHandles()
	if entries == nil {
		return ""
	}
	me := windows.CurrentProcess()
	for _, e := range entries {
		if uint32(e.UniqueProcessID) != pid {
			continue
		}
		var dup windows.Handle
		if err := windows.DuplicateHandle(proc, windows.Handle(e.HandleValue), me,
			&dup, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
			continue
		}
		name := objectName(dup)
		windows.CloseHandle(dup)
		if name == "" {
			continue
		}
		if wxid := wxidFromPath(name); wxid != "" {
			return wxid
		}
	}
	return ""
}

// WxidForPids 批量映射，拿不到的进程不出现在结果里
func WxidForPids(pids []uint32) map[uint32]string {
	out := make(map[uint32]string, len(pids))
	for _, p := range pids {
		if wxid := WxidForPid(p); wxid != "" {
			out[p] = wxid
		}
	}
	return out
}

// mustWeixinPids 所有微信主窗口进程（诊断用）
func mustWeixinPids() []uint32 { return MainWeChatPids() }
