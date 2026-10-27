package main

// native DLL 从 exe 旁边的 native 目录加载。
//
// 之前这里用 //go:embed 把两个 DLL 打包进 exe，但 nativeDir() 又是
// "优先用外部目录"，结果嵌入的那份从来没被用到，代价却全背了：
//   - exe 从 18MB 涨到 33MB
//   - 嵌入的 WCDB.dll 带进 17673 个 C++ mangled 符号，
//     反编译时能直接看出"用了腾讯官方 WCDB"
//   - SQLCipher 的 pbkdf2 / sqlcipher 等字符串原样暴露
//     （garble 只混淆 Go 源码里的字符串，嵌入的二进制字节动不了）
//
// 现在只走外部目录。分发时 native/ 目录和 exe 一起放即可。

import (
	"fmt"
	"os"
	"path/filepath"
)

var nativeDirCached string

// nativeDir 返回 DLL 所在目录
func nativeDir() (string, error) {
	if nativeDirCached != "" {
		return nativeDirCached, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("拿不到自身路径: %w", err)
	}
	dir := filepath.Join(filepath.Dir(exe), "native")
	if _, e := os.Stat(filepath.Join(dir, "WCDB.dll")); e != nil {
		return "", fmt.Errorf("缺少 native\\WCDB.dll，请确认 native 目录和程序放在一起")
	}
	nativeDirCached = dir
	return dir, nil
}
