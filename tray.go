package main

// 系统托盘：图标、提示、右键菜单、双击恢复

import (
	"syscall"
	"unsafe"
)

var (
	shell32             = syscall.NewLazyDLL("shell32.dll")
	procShellNotifyIcon = shell32.NewProc("Shell_NotifyIconW")

	procCreatePopupMenu      = u32.NewProc("CreatePopupMenu")
	procAppendMenuW          = u32.NewProc("AppendMenuW")
	procTrackPopupMenu       = u32.NewProc("TrackPopupMenu")
	procDestroyMenu          = u32.NewProc("DestroyMenu")
	procSetForegroundWindow  = u32.NewProc("SetForegroundWindow")
	procGetCursorPos         = u32.NewProc("GetCursorPos")
	procPostMessageW         = u32.NewProc("PostMessageW")
	procShowWindow           = u32.NewProc("ShowWindow")
	procSetWindowLongPtrW    = u32.NewProc("SetWindowLongPtrW")
	procCallWindowProcW      = u32.NewProc("CallWindowProcW")
	procDefWindowProcW       = u32.NewProc("DefWindowProcW")
	procGetMessageW          = u32.NewProc("GetMessageW")
	procTranslateMessage     = u32.NewProc("TranslateMessage")
	procDispatchMessageW     = u32.NewProc("DispatchMessageW")
	procRegisterClassExW     = u32.NewProc("RegisterClassExW")
	procCreateWindowExW      = u32.NewProc("CreateWindowExW")
	procDestroyWindow        = u32.NewProc("DestroyWindow")
	procPostQuitMessage      = u32.NewProc("PostQuitMessage")
)

const (
	NIM_ADD    = 0x00000000
	NIM_MODIFY = 0x00000001
	NIM_DELETE = 0x00000002

	NIF_MESSAGE = 0x00000001
	NIF_ICON    = 0x00000002
	NIF_TIP     = 0x00000004

	WM_APP        = 0x8000
	WM_TRAYICON   = WM_APP + 1
	WM_LBUTTONDBLCLK = 0x0203
	WM_RBUTTONUP     = 0x0205
	WM_COMMAND       = 0x0111
	WM_CLOSE         = 0x0010
	WM_DESTROY       = 0x0002

	SW_HIDE   = 0
	SW_SHOW   = 5
	SW_RESTORE = 9

	MF_STRING    = 0x0000
	MF_SEPARATOR = 0x0800

	TPM_RIGHTBUTTON = 0x0002
	TPM_RETURNCMD   = 0x0100

	IDM_SHOW = 1001
	IDM_QUIT = 1002
)

type NOTIFYICONDATA struct {
	CbSize           uint32
	HWnd             syscall.Handle
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            syscall.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         syscall.GUID
	HBalloonIcon     syscall.Handle
}

type POINT struct {
	X, Y int32
}

var (
	trayAdded bool
	trayHwnd  syscall.Handle
)

// addTray 把图标放进系统托盘
func addTray(hwnd uintptr, iconPath string) {
	trayHwnd = syscall.Handle(hwnd)

	hIcon := loadAppIcon(iconPath)
	if hIcon == 0 {
		return
	}

	var nid NOTIFYICONDATA
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = syscall.Handle(hwnd)
	nid.UID = 1
	nid.UFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
	nid.UCallbackMessage = WM_TRAYICON
	nid.HIcon = syscall.Handle(hIcon)
	tip := syscall.StringToUTF16(AppName)
	copy(nid.SzTip[:], tip)

	r, _, _ := procShellNotifyIcon.Call(NIM_ADD, uintptr(unsafe.Pointer(&nid)))
	trayAdded = r != 0
}

// updateTrayTip 更新托盘提示文字
func updateTrayTip(tip string) {
	if !trayAdded {
		return
	}
	var nid NOTIFYICONDATA
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = trayHwnd
	nid.UID = 1
	nid.UFlags = NIF_TIP
	t := syscall.StringToUTF16(tip)
	copy(nid.SzTip[:], t)
	procShellNotifyIcon.Call(NIM_MODIFY, uintptr(unsafe.Pointer(&nid)))
}

// removeTray 移出托盘
func removeTray() {
	if !trayAdded {
		return
	}
	var nid NOTIFYICONDATA
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = trayHwnd
	nid.UID = 1
	procShellNotifyIcon.Call(NIM_DELETE, uintptr(unsafe.Pointer(&nid)))
	trayAdded = false
}

// showTrayMenu 在鼠标位置弹出右键菜单，返回被点中的命令
func showTrayMenu(hwnd uintptr) int {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return 0
	}
	defer procDestroyMenu.Call(menu)

	show := syscall.StringToUTF16("显示主界面")
	quit := syscall.StringToUTF16("退出易监控")
	procAppendMenuW.Call(menu, MF_STRING, IDM_SHOW, uintptr(unsafe.Pointer(&show[0])))
	procAppendMenuW.Call(menu, MF_SEPARATOR, 0, 0)
	procAppendMenuW.Call(menu, MF_STRING, IDM_QUIT, uintptr(unsafe.Pointer(&quit[0])))

	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(hwnd)
	r, _, _ := procTrackPopupMenu.Call(menu,
		TPM_RIGHTBUTTON|TPM_RETURNCMD,
		uintptr(pt.X), uintptr(pt.Y), 0, hwnd, 0)
	return int(r)
}

// hideToTray 隐藏主窗口
func hideToTray(hwnd uintptr) {
	procShowWindow.Call(hwnd, SW_HIDE)
	logInfo("system", "已最小化到托盘")
}

// showMainWindow 从托盘恢复
func showMainWindow(hwnd uintptr) {
	procShowWindow.Call(hwnd, SW_RESTORE)
	procShowWindow.Call(hwnd, SW_SHOW)
	procSetForegroundWindow.Call(hwnd)
	procSetForegroundWindow.Call(hwnd) // 某些情况下第一次不生效
}



