package main

// 本机运行环境采集：内存、CPU 负载、运行时长

import (
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

var (
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemTimes       = kernel32.NewProc("GetSystemTimes")
)

type MEMORYSTATUSEX struct {
	DwLength                uint32
	DwMemoryLoad            uint32
	UllTotalPhys            uint64
	UllAvailPhys            uint64
	UllTotalPageFile        uint64
	UllAvailPageFile        uint64
	UllTotalVirtual         uint64
	UllAvailVirtual         uint64
	UllAvailExtendedVirtual uint64
}

type FILETIME struct {
	LowDateTime  uint32
	HighDateTime uint32
}

var (
	startedAt = time.Now()

	cpuMu      sync.Mutex
	lastIdle   uint64
	lastKernel uint64
	lastUser   uint64
	lastCPUAt  time.Time
	lastCPU    float64
)

func ftToU64(ft FILETIME) uint64 {
	return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
}

// cpuUsage 返回 0..100 的 CPU 使用率（两次采样差分）
func cpuUsage() float64 {
	var idle, kern, user FILETIME
	r, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kern)),
		uintptr(unsafe.Pointer(&user)),
	)
	if r == 0 {
		return 0
	}

	i, k, u := ftToU64(idle), ftToU64(kern), ftToU64(user)

	cpuMu.Lock()
	defer cpuMu.Unlock()

	now := time.Now()
	if lastCPUAt.IsZero() {
		lastIdle, lastKernel, lastUser, lastCPUAt = i, k, u, now
		return 0
	}
	// 采样间隔太短会有噪声，至少 300ms 才算一次
	if now.Sub(lastCPUAt) < 300*time.Millisecond {
		return lastCPU
	}

	di, dk, du := i-lastIdle, k-lastKernel, u-lastUser
	total := dk + du // kernel 已含 idle
	var pct float64
	if total > 0 {
		busy := total - di
		pct = float64(busy) / float64(total) * 100
		if pct < 0 {
			pct = 0
		}
		if pct > 100 {
			pct = 100
		}
	}
	lastIdle, lastKernel, lastUser, lastCPUAt, lastCPU = i, k, u, now, pct
	return pct
}

func memInfo() (usedGB, totalGB float64, loadPct int) {
	var ms MEMORYSTATUSEX
	ms.DwLength = uint32(unsafe.Sizeof(ms))
	r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	if r == 0 {
		return 0, 0, 0
	}
	const gb = 1024 * 1024 * 1024
	total := float64(ms.UllTotalPhys) / gb
	avail := float64(ms.UllAvailPhys) / gb
	return total - avail, total, int(ms.DwMemoryLoad)
}

func fmtDuration(d time.Duration) string {
	t := int(d.Seconds())
	h, m, s := t/3600, (t%3600)/60, t%60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

type SysInfo struct {
	Uptime    string  `json:"uptime"`
	CPUPct    float64 `json:"cpu_pct"`
	MemUsedGB float64 `json:"mem_used_gb"`
	MemTotalGB float64 `json:"mem_total_gb"`
	MemPct    int     `json:"mem_pct"`
	GoRoutines int    `json:"goroutines"`
	MemAllocMB float64 `json:"mem_alloc_mb"`
}

func sysInfo() SysInfo {
	used, total, mp := memInfo()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return SysInfo{
		Uptime:     fmtDuration(time.Since(startedAt)),
		CPUPct:     cpuUsage(),
		MemUsedGB:  round1(used),
		MemTotalGB: round1(total),
		MemPct:     mp,
		GoRoutines: runtime.NumGoroutine(),
		MemAllocMB: round1(float64(m.Alloc) / (1024 * 1024)),
	}
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}



