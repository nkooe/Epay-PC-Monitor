package main

// 模块枚举（单独文件，用 psapi）

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	psapi                    = syscall.NewLazyDLL("psapi.dll")
	procEnumProcessModulesEx = psapi.NewProc("EnumProcessModulesEx")
	procGetModuleBaseNameW   = psapi.NewProc("GetModuleBaseNameW")
	procGetModuleFileNameExW  = psapi.NewProc("GetModuleFileNameExW")
	procGetModuleInformation = psapi.NewProc("GetModuleInformation")
)

const LIST_MODULES_ALL = 0x03

type MODULEINFO struct {
	LpBaseOfDll   uintptr
	SizeOfImage   uint32
	EntryPoint    uintptr
}

func findModule(pid uint32, dllName string) (uintptr, uint32, error) {
	h, err := OpenProcess(pid, PROCESS_VM_READ|PROCESS_QUERY_INFO)
	if err != nil {
		return 0, 0, err
	}
	defer h.Close()

	mods := make([]uintptr, 2048)
	var needed uint32
	r, _, e := procEnumProcessModulesEx.Call(uintptr(h), uintptr(unsafe.Pointer(&mods[0])),
		uintptr(len(mods)*8), uintptr(unsafe.Pointer(&needed)), LIST_MODULES_ALL)
	if r == 0 {
		return 0, 0, fmt.Errorf("EnumProcessModulesEx 失败: %v", e)
	}
	n := int(needed) / 8
	for i := 0; i < n; i++ {
		var name [260]uint16
		procGetModuleBaseNameW.Call(uintptr(h), mods[i], uintptr(unsafe.Pointer(&name[0])), 260)
		if equalFold(syscall.UTF16ToString(name[:]), dllName) {
			var mi MODULEINFO
			procGetModuleInformation.Call(uintptr(h), mods[i], uintptr(unsafe.Pointer(&mi)), unsafe.Sizeof(mi))
			return mi.LpBaseOfDll, mi.SizeOfImage, nil
		}
	}
	return 0, 0, fmt.Errorf("未找到模块 %s", dllName)
}

// processHasModule 判断进程是否加载了指定模块。
// 微信多开时只有主进程加载 Weixin.dll，子进程没有，用这个筛选。
func processHasModule(pid uint32, dllName string) bool {
	_, _, err := findModule(pid, dllName)
	return err == nil
}

// findModulePath 从进程的模块列表里取某个 DLL 的完整磁盘路径。
// 比从 exe 路径推导可靠：微信装在哪、DLL 放在哪个子目录都能拿到。
func findModulePath(pid uint32, dllName string) string {
	base, _, err := findModule(pid, dllName)
	if err != nil || base == 0 {
		return ""
	}
	h, err := OpenProcess(pid, PROCESS_VM_READ|PROCESS_QUERY_INFO)
	if err != nil {
		return ""
	}
	defer h.Close()

	buf := make([]uint16, syscall.MAX_LONG_PATH)
	n, _, _ := procGetModuleFileNameExW.Call(
		uintptr(h),
		uintptr(base),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if n == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}
