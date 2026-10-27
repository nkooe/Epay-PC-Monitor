package main

// 通行密钥提取：直接读微信进程内存（自研，不依赖外部 DLL）
//
// 实现见 wxkeyscan.go：在 Weixin.dll 里找 XOR 常量链，
// 扫内存找 std::string(size=32, cap=47) 的候选，XOR 解密后用
// WCDB 打开数据库验证。

import "time"

// KeyResult 密钥提取结果
type KeyResult struct {
	OK    bool   `json:"ok"`
	Key   string `json:"key"`
	Note  string `json:"note"`
	Waits int    `json:"waits"`
}

// ExtractKey 同步提取（内部会阻塞到扫完）
func ExtractKey(timeout time.Duration, targetWxid string) KeyResult {
	cfg := GetConfig()
	return extractKeyByScan(cfg.WeChatExe, targetWxid)
}

