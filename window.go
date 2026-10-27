package main

// 原生窗口：WebView2 承载界面 + 关闭确认 + 系统托盘

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"github.com/jchv/go-webview2"
)

var (
	u32                 = syscall.NewLazyDLL("user32.dll")

	procFindWindowW     = u32.NewProc("FindWindowW")
	procLoadImageW      = u32.NewProc("LoadImageW")
	procSendMessageW    = u32.NewProc("SendMessageW")
	procLoadIconW       = u32.NewProc("LoadIconW")
	procSetWindowLong   = u32.NewProc("SetWindowLongPtrW")
)

const (
	WM_SETICON      = 0x0080
	ICON_SMALL      = 0
	ICON_BIG        = 1
	IMAGE_ICON      = 1
	LR_LOADFROMFILE = 0x00000010
	IDI_APPLICATION = 32512
	GWLP_WNDPROC    = ^uintptr(3) // -4
)

var (
	gHwnd     uintptr
	gWebView  webview2.WebView
	gOrigProc uintptr
)

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func webviewDataDir() string { return filepath.Join(exeDir(), "webview-data") }

func loadAppIcon(iconPath string) uintptr {
	p, err := syscall.UTF16PtrFromString(iconPath)
	if err != nil {
		return 0
	}
	h, _, _ := procLoadImageW.Call(0, uintptr(unsafe.Pointer(p)), IMAGE_ICON, 32, 32, LR_LOADFROMFILE)
	return h
}

func setWindowIcons(hwnd uintptr) {
	icoPath := filepath.Join(exeDir(), "app.ico")
	p, err := syscall.UTF16PtrFromString(icoPath)
	if err != nil {
		return
	}
	big, _, _ := procLoadImageW.Call(0, uintptr(unsafe.Pointer(p)), IMAGE_ICON, 32, 32, LR_LOADFROMFILE)
	small, _, _ := procLoadImageW.Call(0, uintptr(unsafe.Pointer(p)), IMAGE_ICON, 16, 16, LR_LOADFROMFILE)
	if big == 0 {
		hInst, _, _ := procGetModuleHandle.Call(0)
		big, _, _ = procLoadIconW.Call(hInst, IDI_APPLICATION)
	}
	if big != 0 {
		procSendMessageW.Call(hwnd, WM_SETICON, ICON_BIG, big)
	}
	if small != 0 {
		procSendMessageW.Call(hwnd, WM_SETICON, ICON_SMALL, small)
	}
}

// quitApp 真正退出程序
func quitApp() {
	flushRecordsNow()
	removeTray()
	logInfo("system", "正在退出…")
	select {
	case <-eng.stopCh:
	default:
		close(eng.stopCh)
	}
	eng.detach()
	os.Exit(0)
}

// wndProc 子类化后的窗口过程
func wndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	switch msg {
	case WM_CLOSE:
		// 不直接关闭：让页面弹确认框
		if gWebView != nil {
			gWebView.Eval("window.__showCloseDialog && window.__showCloseDialog()")
		}
		return 0

	case WM_TRAYICON:
		switch lparam & 0xFFFF {
		case WM_LBUTTONDBLCLK:
			showMainWindow(hwnd)
		case WM_RBUTTONUP:
			switch showTrayMenu(hwnd) {
			case IDM_SHOW:
				showMainWindow(hwnd)
			case IDM_QUIT:
				quitApp()
			}
		}
		return 0

	case WM_COMMAND:
		switch wparam & 0xFFFF {
		case IDM_SHOW:
			showMainWindow(hwnd)
			return 0
		case IDM_QUIT:
			quitApp()
			return 0
		}
	}
	r, _, _ := procCallWindowProcW.Call(gOrigProc, hwnd, msg, wparam, lparam)
	return r
}

func runWindow(port int) {
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	title := AppName + "  v" + AppVersion

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		// Debug 同时控制「右键菜单」与「DevTools」：go-webview2 把两者绑在同一个开关上。
		// 关掉 Debug 会导致输入框无法右键复制/粘贴，所以这里必须开着。
		Debug:     true,
		AutoFocus: true,
		DataPath:  webviewDataDir(),
		WindowOptions: webview2.WindowOptions{
			Title:  title,
			Width:  1180,
			Height: 772,
			Center: true,
		},
	})
	if w == nil {
		logError("system", "WebView2 初始化失败：请确认已安装 WebView2 运行时")
		logWarn("system", "也可以手动打开 %s 使用", url)
		select {}
	}
	gWebView = w
	defer w.Destroy()

	// 绑定给页面的接口
	w.Bind("goQuit", func() string { quitApp(); return "" })
	w.Bind("goHideToTray", func() string {
		if gHwnd != 0 {
			hideToTray(gHwnd)
			updateTrayTip(AppName + " · 已在后台运行")
		}
		return ""
	})
	w.Bind("goCancelClose", func() string { return "" })

	w.Navigate(url)
	w.SetSize(1180, 772, webview2.HintNone)
	// WebView2 起来后可能又带出控制台，再清一次
	hideConsoleWindow()

	// 窗口就绪后：设置图标、上托盘、子类化拦截 WM_CLOSE
	go func() {
		for i := 0; i < 80; i++ {
			hwnd := uintptr(w.Window())
			if hwnd != 0 {
				gHwnd = hwnd
				setWindowIcons(hwnd)
				addTray(hwnd, filepath.Join(exeDir(), "app.ico"))

				// 子类化：接管窗口消息
				cb := syscall.NewCallback(wndProc)
				orig, _, _ := procSetWindowLong.Call(hwnd, GWLP_WNDPROC, cb)
				if orig != 0 {
					gOrigProc = orig
				}
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	w.Run() // 阻塞直到真正退出

	flushRecordsNow()
	removeTray()
	select {
	case <-eng.stopCh:
	default:
		close(eng.stopCh)
	}
	eng.detach()
}








