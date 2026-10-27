package main

// 原子写文件：先写同目录下的 .tmp，fsync 后再 rename 覆盖。
// 直接 os.WriteFile 的问题是写到一半崩溃/断电会留下半截文件，
// config.json 一旦损坏程序就起不来了。

import (
	"os"
	"path/filepath"
)

// atomicWriteFile 原子写入。perm 一般传 0644。
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		// 目录不可写时退回普通写，至少能用
		return os.WriteFile(path, data, perm)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName) // rename 成功后这里是空操作
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	// 目录 fsync 才能保证 rename 落盘（Windows 上语义弱一些，尽力而为）
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
