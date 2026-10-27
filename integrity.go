package main

// 程序自校验。
//
// 局限必须说清：
//   校验值放在 exe 旁边的 integrity.dat，能改 exe 的人也能改这个文件。
//   所以它只能挡住「随手改个字符串」这类低成本篡改，
//   挡不住有决心的人。真正可靠的校验必须放到服务端
//   （例如上报时带上版本指纹，平台侧核对白名单）。

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

const integrityFile = "integrity.dat"

// sha256File 算文件哈希
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifySelfIntegrity 校验自身是否被改动。
// 返回 (是否通过, 说明)。没有 integrity.dat 时视为「未启用校验」，返回 true。
func verifySelfIntegrity() (bool, string) {
	exe, err := os.Executable()
	if err != nil {
		return true, "拿不到自身路径"
	}
	exe, _ = filepath.Abs(exe)
	exe = strings.TrimSuffix(exe, ".tmp")

	data, err := os.ReadFile(filepath.Join(filepath.Dir(exe), integrityFile))
	if err != nil {
		return true, "未启用完整性校验"
	}
	want := strings.TrimSpace(string(data))
	if want == "" || len(want) != 64 {
		return true, "校验文件格式不对，忽略"
	}
	got, err := sha256File(exe)
	if err != nil {
		return true, "读自身失败: " + err.Error()
	}
	if !strings.EqualFold(got, want) {
		return false, "程序文件已被修改"
	}
	return true, ""
}

// writeIntegrity 生成 integrity.dat（打包时由 -write-integrity 调用）
func writeIntegrity() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	h, err := sha256File(exe)
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(filepath.Dir(exe), integrityFile), []byte(h+"\n"), 0644)
}

// handleIntegrityCmd 处理 --write-integrity 参数。
// 打包脚本在生成 exe 之后调用一次，写出 integrity.dat。
// 返回 true 表示已处理完，主流程应该直接退出。
func handleIntegrityCmd(args []string) bool {
	for _, a := range args {
		if a == "--write-integrity" {
			if err := writeIntegrity(); err != nil {
				os.Stderr.WriteString("写 integrity.dat 失败: " + err.Error() + "\n")
				os.Exit(1)
			}
			os.Stdout.WriteString("integrity.dat 已生成\n")
			return true
		}
	}
	return false
}
