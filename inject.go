package main

// 注入器：往 Weixin.dll 的 0x67B7D0 打 hook，抓 protobuf 序列化参数

import (
	"encoding/binary"
	"fmt"
)

const (
	HookRVA   = 0x67B7D0
	HookLen   = 18
	Slots     = 512
	slotBytes = 32 // rcx, rdx, r8, r9
)

// HookPoint 一个可 hook 的函数入口
type HookPoint struct {
	Name string
	RVA  uintptr
	Len  int
	Orig []byte
}

// HookPoints 所有采集点。
// 主点抓聊天消息；副点用于服务号/公众号消息（pcmon 使用的位置）。
var HookPoints = []HookPoint{
	{
		Name: "chat", RVA: 0x67B7D0, Len: 18,
		Orig: []byte{
			0x55, 0x56, 0x53, 0x48, 0x81, 0xEC, 0x80, 0x00, 0x00,
			0x00, 0x48, 0x8D, 0xAC, 0x24, 0x80, 0x00, 0x00, 0x00,
		},
	},
	{
		Name: "service", RVA: 0x3A29C50, Len: 19,
		Orig: []byte{
			0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x54, 0x56, 0x57, 0x53,
			0x48, 0x83, 0xEC, 0x70, 0x48, 0x8D, 0x6C, 0x24, 0x70,
		},
	},
}

// Weixin 4.1.13.63 在 0x67B7D0 的原始字节
var origBytes = []byte{
	0x55, 0x56, 0x53, 0x48, 0x81, 0xEC, 0x80, 0x00, 0x00,
	0x00, 0x48, 0x8D, 0xAC, 0x24, 0x80, 0x00, 0x00, 0x00,
}

type Hooks struct {
	Pid      uint32
	Base     uintptr
	BufAddr  uintptr // 槽数组
	CntAddr  uintptr // 计数器
	CodeAddr uintptr
	TrampAddr uintptr
	h        Handle

	// StartUnix 注入时刻（秒）。早于它的消息一律丢弃 —— 只处理新消息。
	StartUnix int64

	// 该 hook 属于哪个采集点
	Point HookPoint

	// 该点的运行计数
	Scanned int
	Parsed  int
}

func (hk *Hooks) Detach() {
	if hk.h != 0 {
		hk.restore()
		hk.h.Close()
		hk.h = 0
	}
}

func (hk *Hooks) restore() error {
	if hk.Base == 0 {
		return fmt.Errorf("基址未知")
	}
	t := hk.Base + hk.Point.RVA
	old, err := hk.h.Protect(t, hk.Point.Len, PAGE_EXECUTE_READWRITE)
	if err != nil {
		return err
	}
	if werr := hk.h.Write(t, hk.Point.Orig); werr != nil {
		hk.h.Protect(t, hk.Point.Len, old)
		return werr
	}
	hk.h.Protect(t, hk.Point.Len, old)
	return nil
}

// Attach 在主采集点安装 hook（兼容旧调用）
func Attach(pid uint32) (*Hooks, error) {
	return AttachAt(pid, HookPoints[0])
}

// AttachAt 在指定采集点安装 hook
func AttachAt(pid uint32, pt HookPoint) (*Hooks, error) {
	h, err := OpenProcess(pid, PROCESS_ALL_ACCESS)
	if err != nil {
		return nil, err
	}
	base, _, err := findModule(pid, "Weixin.dll")
	if err != nil {
		h.Close()
		return nil, err
	}

	hk := &Hooks{Pid: pid, Base: base, h: h, Point: pt}

	// 当前字节校验
	cur, err := h.Read(base+pt.RVA, pt.Len)
	if err != nil {
		h.Close()
		return nil, err
	}
	if string(cur) != string(pt.Orig) {
		// 尝试还原（被别的工具或旧版本自己 hook 过）
		if cur[0] == 0x48 && cur[1] == 0xB8 && cur[10] == 0xFF && cur[11] == 0xE0 {
			if err := hk.restore(); err == nil {
				cur, _ = h.Read(base+pt.RVA, pt.Len)
			}
		}
		if string(cur) != string(pt.Orig) {
			h.Close()
			return nil, fmt.Errorf("[%s] hook 点字节不匹配(可能是别的版本): % X", pt.Name, cur)
		}
	}

	// 分配
	if hk.BufAddr, err = h.Alloc(Slots*slotBytes, PAGE_READWRITE); err != nil {
		h.Close(); return nil, err
	}
	if hk.CntAddr, err = h.Alloc(16, PAGE_READWRITE); err != nil {
		h.Close(); return nil, err
	}
	if hk.CodeAddr, err = h.Alloc(0x200, PAGE_EXECUTE_READWRITE); err != nil {
		h.Close(); return nil, err
	}
	if hk.TrampAddr, err = h.Alloc(0x100, PAGE_EXECUTE_READWRITE); err != nil {
		h.Close(); return nil, err
	}

	// trampoline：原 18 字节 + jmp [rip+0] -> 目标+18
	tramp := append([]byte{}, pt.Orig...)
	tramp = append(tramp, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00)
	var q [8]byte
	binary.LittleEndian.PutUint64(q[:], uint64(base+pt.RVA+uintptr(pt.Len)))
	tramp = append(tramp, q[:]...)
	if err := h.Write(hk.TrampAddr, tramp); err != nil {
		h.Close(); return nil, err
	}

	// shellcode：
	//   mov r11, cnt ; lock inc dword [r11]
	//   mov r10, [r11] ; and r10, 0x1FF ; shl r10, 5
	//   mov r11, buf ; add r11, r10
	//   mov [r11], rcx ; mov [r11+8], rdx
	//   mov [r11+0x10], r8 ; mov [r11+0x18], r9
	//   mov rax, tramp ; jmp rax
	sc := []byte{}
	sc = append(sc, 0x49, 0xBB)                                            // mov r11, imm64
	sc = appendU64(sc, uint64(hk.CntAddr))
	sc = append(sc, 0xF0, 0x41, 0xFF, 0x03)                                // lock inc dword [r11]
	sc = append(sc, 0x4D, 0x8B, 0x13)                                      // mov r10, [r11]
	sc = append(sc, 0x49, 0x81, 0xE2, 0xFF, 0x01, 0x00, 0x00)              // and r10, 0x1FF
	sc = append(sc, 0x49, 0xC1, 0xE2, 0x05)                                // shl r10, 5
	sc = append(sc, 0x49, 0xBB)                                            // mov r11, imm64
	sc = appendU64(sc, uint64(hk.BufAddr))
	sc = append(sc, 0x4D, 0x01, 0xD3)                                      // add r11, r10
	sc = append(sc, 0x49, 0x89, 0x0B)                                      // mov [r11], rcx
	sc = append(sc, 0x49, 0x89, 0x53, 0x08)                                // mov [r11+8], rdx
	sc = append(sc, 0x4D, 0x89, 0x43, 0x10)                                // mov [r11+0x10], r8
	sc = append(sc, 0x4D, 0x89, 0x4B, 0x18)                                // mov [r11+0x18], r9
	sc = append(sc, 0x48, 0xB8)                                            // mov rax, imm64
	sc = appendU64(sc, uint64(hk.TrampAddr))
	sc = append(sc, 0xFF, 0xE0)                                            // jmp rax
	if err := h.Write(hk.CodeAddr, sc); err != nil {
		h.Close(); return nil, err
	}

	// patch 目标
	patch := []byte{0x48, 0xB8}
	patch = appendU64(patch, uint64(hk.CodeAddr))
	patch = append(patch, 0xFF, 0xE0)
	for len(patch) < pt.Len {
		patch = append(patch, 0x90)
	}
	old, err := h.Protect(base+pt.RVA, pt.Len, PAGE_EXECUTE_READWRITE)
	if err != nil {
		h.Close(); return nil, err
	}
	if err := h.Write(base+pt.RVA, patch); err != nil {
		h.Protect(base+pt.RVA, pt.Len, old)
		h.Close(); return nil, err
	}
	h.Protect(base+pt.RVA, pt.Len, old)

	return hk, nil
}

func appendU64(b []byte, v uint64) []byte {
	var q [8]byte
	binary.LittleEndian.PutUint64(q[:], v)
	return append(b, q[:]...)
}

// ResetBuffer 清空槽数组并把计数器归零。
// 注入后立刻调用，保证不会读到注入之前残留在缓冲里的旧消息。
func (hk *Hooks) ResetBuffer() {
	if hk.h == 0 || hk.BufAddr == 0 {
		return
	}
	zeros := make([]byte, Slots*slotBytes)
	if err := hk.h.Write(hk.BufAddr, zeros); err != nil {
		logWarn("inject", "清空缓冲区失败: %v", err)
	}
	cnt := make([]byte, 4)
	if err := hk.h.Write(hk.CntAddr, cnt); err != nil {
		logWarn("inject", "重置计数器失败: %v", err)
	}
}

// Counter 读当前计数
func (hk *Hooks) Counter() uint32 {
	b, err := hk.h.Read(hk.CntAddr, 4)
	if err != nil || len(b) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

// Drain 读取 index 这条记录（rcx, rdx, r8, r9）
func (hk *Hooks) Slot(i int) (rcx, rdx, r8, r9 uint64, ok bool) {
	b, err := hk.h.Read(hk.BufAddr+uintptr(i)*slotBytes, slotBytes)
	if err != nil || len(b) < 32 {
		return 0, 0, 0, 0, false
	}
	return binary.LittleEndian.Uint64(b[0:8]),
		binary.LittleEndian.Uint64(b[8:16]),
		binary.LittleEndian.Uint64(b[16:24]),
		binary.LittleEndian.Uint64(b[24:32]), true
}

func (hk *Hooks) ReadAt(addr uint64, size int) []byte {
	if addr < 0x10000 || addr >= 0x7FFFFFFFFFFF || size <= 0 || size > 4<<20 {
		return nil
	}
	b, err := hk.h.Read(uintptr(addr), size)
	if err != nil {
		return nil
	}
	return b
}






