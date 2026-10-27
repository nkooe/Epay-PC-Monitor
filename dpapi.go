package main

// Windows DPAPI 加解密。
//
// 作用：把 config.json 里的密钥（数据库密钥、商户密钥）加密，
// 使得配置文件即使被拷走，换一台机器/换一个 Windows 用户也解不开。
//
// 限制（必须知道）：
//   - 绑定当前 Windows 用户。重装系统、换用户、换机器都解不开。
//   - 只防「文件被拷走」，不防「本机进程被调试」。
//     （同一个用户身份下，任何进程都能调 CryptUnprotectData）

import (
	"encoding/base64"
	"strings"
	"syscall"
	"unsafe"
)

const encPrefix = "enc:v1:"

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32          = syscall.NewLazyDLL("crypt32.dll")
	procCryptProtect   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotect = crypt32.NewProc("CryptUnprotectData")
	procLocalFree      = kernel32.NewProc("LocalFree")
	procLocalAlloc     = kernel32.NewProc("LocalAlloc")
)

func blobFromBytes(b []byte) (*dataBlob, error) {
	if len(b) == 0 {
		return &dataBlob{}, nil
	}
	r, _, _ := procLocalAlloc.Call(0x40, uintptr(len(b))) // LPTR = LMEM_FIXED|LMEM_ZEROINIT
	if r == 0 {
		return nil, syscall.Errno(14) // ERROR_OUTOFMEMORY
	}
	p := r
	copy(unsafe.Slice((*byte)(unsafe.Pointer(p)), len(b)), b)
	return &dataBlob{cbData: uint32(len(b)), pbData: (*byte)(unsafe.Pointer(p))}, nil
}

func blobBytes(b *dataBlob) []byte {
	if b == nil || b.pbData == nil || b.cbData == 0 {
		return nil
	}
	return unsafe.Slice(b.pbData, int(b.cbData))
}

func blobFree(b *dataBlob) {
	if b != nil && b.pbData != nil {
		procLocalFree.Call(uintptr(unsafe.Pointer(b.pbData)))
		b.pbData = nil
	}
}

// dpapiEncrypt 用当前用户身份加密。返回 "enc:v1:<base64>"
func dpapiEncrypt(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	in, err := blobFromBytes([]byte(plain))
	if err != nil {
		return "", err
	}
	defer blobFree(in)

	var out dataBlob
	r, _, e := procCryptProtect.Call(
		uintptr(unsafe.Pointer(in)),
		0, 0, 0, 0,
		0x1, // CRYPTPROTECT_UI_FORBIDDEN
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return "", e
	}
	defer blobFree(&out)
	return encPrefix + base64.StdEncoding.EncodeToString(blobBytes(&out)), nil
}

// dpapiDecrypt 解密 "enc:v1:..."。不是这个前缀就原样返回（兼容明文老配置）。
func dpapiDecrypt(s string) (string, error) {
	if !strings.HasPrefix(s, encPrefix) {
		return s, nil
	}
	raw, err := base64.StdEncoding.DecodeString(s[len(encPrefix):])
	if err != nil {
		return "", err
	}
	in, err := blobFromBytes(raw)
	if err != nil {
		return "", err
	}
	defer blobFree(in)

	var out dataBlob
	r, _, e := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(in)),
		0, 0, 0, 0,
		0x1,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return "", e
	}
	defer blobFree(&out)
	return string(blobBytes(&out)), nil
}

// isEncrypted 判断某个值是否已经加密
func isEncrypted(s string) bool {
	return strings.HasPrefix(s, encPrefix)
}
