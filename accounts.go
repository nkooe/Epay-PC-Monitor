package main

// 账号通道绑定：每个微信账号（wxid）可以单独配置通道值

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Account struct {
	// Type 账号类型：wechat / alipay。留空时按 Wxid 前缀推断。
	//   wxid_*  → wechat
	//   2088*   → alipay
	Type          string `json:"type"`
	Wxid          string `json:"wxid"`            // 微信 wxid_xxx / 支付宝 PID 2088...
	Nick          string `json:"nick"`            // 备注名，可手动填
	ChannelID     string `json:"channel_id"`      // 通用通道 ID（旧字段，作为两个平台的兜底）
	ChannelIDXpay string `json:"channel_id_xpay"` // X-Ypay 的通道 ID
	ChannelIDV1   string `json:"channel_id_v1"`   // 码支付V1 的通道 ID
	ChannelCode   string `json:"channel_code"`    // X-Ypay 通道代码：jk_wechat_pc / jk_wechat_app / alipay_app / jk_alipay
	Secret        string `json:"secret"`          // 商户密钥 / token（可选，空则用全局）
	MerchantID    string `json:"merchant_id"`     // 商户号 / PID（可选）
	Enabled       bool   `json:"enabled"`         // 是否启用该账号的上报
	Note          string `json:"note"`
}

var (
	accMu      sync.Mutex
	accList    []Account
	accPath    string
	accLoadErr error
	accLoaded  bool
)

func accountsFile() string {
	if accPath != "" {
		return accPath
	}
	exe, err := os.Executable()
	dir := "."
	if err == nil {
		dir = filepath.Dir(exe)
	}
	accPath = filepath.Join(dir, "accounts.json")
	return accPath
}

func loadAccounts() error {
	accMu.Lock()
	defer accMu.Unlock()
	b, err := os.ReadFile(accountsFile())
	if errors.Is(err, os.ErrNotExist) {
		accList = []Account{}
		accLoadErr = nil
		accLoaded = true
		return nil
	}
	if err != nil {
		accLoadErr = err
		accLoaded = true
		return fmt.Errorf("读取账号配置失败: %w", err)
	}
	var v []Account
	if err := json.Unmarshal(b, &v); err != nil {
		accLoadErr = err
		accLoaded = true
		return fmt.Errorf("解析账号配置失败: %w", err)
	}
	accList = v
	accLoadErr = nil
	accLoaded = true
	return nil
}

func saveAccounts() error {
	accMu.Lock()
	defer accMu.Unlock()
	if err := accountsWriteErrorLocked(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(accList, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(accountsFile(), b, 0644)
}

func accountsWriteErrorLocked() error {
	if !accLoaded {
		return errors.New("账号配置尚未加载，拒绝写入")
	}
	if accLoadErr != nil {
		return fmt.Errorf("账号配置加载失败，拒绝覆盖原文件: %w", accLoadErr)
	}
	return nil
}

func accountsError() error {
	accMu.Lock()
	defer accMu.Unlock()
	return accountsWriteErrorLocked()
}

// updateAccounts commits the in-memory change only after the atomic file write succeeds.
func updateAccounts(change func([]Account) ([]Account, bool, error)) (bool, error) {
	accMu.Lock()
	defer accMu.Unlock()
	if err := accountsWriteErrorLocked(); err != nil {
		return false, err
	}
	list := append([]Account(nil), accList...)
	updated, matched, err := change(list)
	if err != nil || !matched {
		return matched, err
	}
	b, err := json.MarshalIndent(updated, "", "  ")
	if err != nil {
		return false, err
	}
	if err := atomicWriteFile(accountsFile(), b, 0644); err != nil {
		return false, err
	}
	accList = updated
	return true, nil
}

func accountsCopy() []Account {
	accMu.Lock()
	defer accMu.Unlock()
	out := make([]Account, len(accList))
	copy(out, accList)
	return out
}

// findAccount 按 wxid 查账号配置
// inferChannelCode 按账号类型决定通道编码，不需要用户选。
//
//	微信（wxid_ 开头）  → jk_wechat_pc
//	其它（2088... 支付宝） → alipay_app
//
// accountType 判断账号类型。
// 显式写了 Type 就用它，否则按 ID 前缀推断。
func accountType(id string) string {
	id = strings.TrimSpace(id)
	if strings.HasPrefix(strings.ToLower(id), "wxid_") {
		return "wechat"
	}
	if strings.HasPrefix(id, "2088") {
		return "alipay"
	}
	return "wechat"
}

// accountKind 取账号的实际类型（优先用字段）
func accountKind(a Account) string {
	if t := strings.TrimSpace(a.Type); t == "alipay" || t == "wechat" {
		return t
	}
	return accountType(a.Wxid)
}

// inferChannelCode 通道编码由账号类型决定，不让用户选。
//
//	微信   → jk_wechat_pc
//	支付宝 → alipay_app
func inferChannelCode(id string) string {
	if accountType(id) == "alipay" {
		return "alipay_app"
	}
	return "jk_wechat_pc"
}

func findAccount(wxid string) (Account, bool) {
	accMu.Lock()
	for _, a := range accList {
		if a.Wxid == wxid {
			accMu.Unlock()
			return a, true
		}
	}
	accMu.Unlock()
	// HK 模式的账号不在账号表里，回落到 hook_accounts，否则上报会报"未绑定"
	if GetConfig().EffectiveWxMode() == "hook" {
		for _, h := range GetConfig().EffectiveHookAccounts() {
			if h.Wxid == wxid {
				return Account{
					Type: "wechat", Wxid: h.Wxid,
					ChannelID: h.ChannelID, ChannelIDXpay: h.ChannelIDXpay, ChannelIDV1: h.ChannelIDV1,
					ChannelCode: "jk_wechat_pc", Enabled: h.Enabled,
				}, true
			}
		}
	}
	return Account{}, false
}

// channelOwner 同一接口模式下，通道号是否已被别的账号占用。
// 微信账号（含 HK）和支付宝账号共用一套编号，必须一起查，
// 否则两个账号绑同一个通道，平台会把 A 的钱记到 B 头上。
func channelOwner(mode, channelID, exceptWxid string) (string, bool) {
	ch := strings.TrimSpace(channelID)
	if ch == "" {
		return "", false
	}
	for _, a := range accountsCopy() {
		if a.Wxid == exceptWxid {
			continue
		}
		if strings.TrimSpace(a.ChannelFor(mode)) == ch {
			return a.Wxid, true
		}
	}
	for _, h := range GetConfig().HookAccounts {
		if h.Wxid == exceptWxid {
			continue
		}
		if strings.TrimSpace(h.ChannelFor(mode)) == ch {
			return h.Wxid, true
		}
	}
	return "", false
}

// checkChannelConflicts 启动自检：同一接口模式下通道号重复会导致平台串账，
// 已有的历史配置在这里报出来（不自动改，避免动用户数据）。
func checkChannelConflicts() {
	for _, mode := range []string{"xpay", "v1"} {
		used := map[string]string{}
		report := func(wxid, ch string) {
			ch = strings.TrimSpace(ch)
			if ch == "" || wxid == "" {
				return
			}
			if prev, ok := used[ch]; ok && prev != wxid {
				logWarn("config", "通道 %s 在 %s 模式下被账号 %s 和 %s 同时占用，会上报串账，请改掉一个",
					ch, mode, short(prev), short(wxid))
				return
			}
			used[ch] = wxid
		}
		for _, a := range accountsCopy() {
			report(a.Wxid, a.ChannelFor(mode))
		}
		for _, h := range GetConfig().HookAccounts {
			report(h.Wxid, h.ChannelFor(mode))
		}
	}
}

// setAccountEnabled 显式设置启用状态。
// 不走 upsertAccount 的合并规则（那里为了保留通道字段用了 OR，会把"停用"盖回去）。
func setAccountEnabled(wxid string, enabled bool) (bool, error) {
	return updateAccounts(func(list []Account) ([]Account, bool, error) {
		for i := range list {
			if list[i].Wxid == wxid {
				list[i].Enabled = enabled
				return list, true, nil
			}
		}
		return list, false, nil
	})
}

// upsertAccount 新增或更新一个账号
func upsertAccount(a Account) error {
	_, err := updateAccounts(func(list []Account) ([]Account, bool, error) {
		for i := range list {
			if list[i].Wxid == a.Wxid {
				old := list[i]
				// 合并而不是整条替换：界面每次只送当前平台的字段，
				// 直接覆盖会把另一个平台的通道号、备注、密钥清空。
				if a.ChannelIDXpay == "" {
					a.ChannelIDXpay = old.ChannelIDXpay
				}
				if a.ChannelIDV1 == "" {
					a.ChannelIDV1 = old.ChannelIDV1
				}
				if a.Nick == "" {
					a.Nick = old.Nick
				}
				if a.Secret == "" {
					a.Secret = old.Secret
				}
				if a.MerchantID == "" {
					a.MerchantID = old.MerchantID
				}
				if a.Note == "" {
					a.Note = old.Note
				}
				if a.ChannelCode == "" {
					a.ChannelCode = old.ChannelCode
				}
				if a.Type == "" {
					a.Type = old.Type
				}
				a.Enabled = a.Enabled || old.Enabled
				list[i] = a
				return list, true, nil
			}
		}
		return append(list, a), true, nil
	})
	return err
}

func removeAccount(wxid string) error {
	_, err := updateAccounts(func(list []Account) ([]Account, bool, error) {
		out := make([]Account, 0, len(list))
		found := false
		for _, a := range list {
			if a.Wxid == wxid {
				found = true
				continue
			}
			out = append(out, a)
		}
		return out, found, nil
	})
	return err
}

// deleteAccountAll 删除一个账号的全部配置：账号记录、通道绑定、数据库监控、密钥。
// 订单记录（records.json）和支付信息一律保留，方便对账。
func deleteAccountAll(wxid string) error {
	if err := removeAccount(wxid); err != nil {
		return err
	}

	// 停掉该账号的数据库监控和实时消息监控（不影响其他账号）
	StopWxMonitorFor(wxid)
	StopLiveMonitor(wxid)
	logInfo("config", "已停止账号 %s 的数据库监控", wxid)

	// 从多账号配置里移除该账号
	c := GetConfig()
	cfg := c
	kept := make([]DbAccount, 0, len(cfg.DbAccounts))
	changed := false
	for _, a := range cfg.DbAccounts {
		if a.Wxid == wxid {
			changed = true
			continue
		}
		kept = append(kept, a)
	}
	cfg.DbAccounts = kept
	// 旧版单账号字段指向它时一并清掉
	if cfg.DbWxid == wxid {
		cfg.DbWxid = ""
		cfg.DbKey = ""
		changed = true
	}
	if changed {
		SetConfig(cfg)
		logInfo("config", "已清除账号 %s 的数据库配置", wxid)
	}

	// 支付宝：账号=会话，删除账号必须把会话一起停掉，
	// 否则轮询会继续拉账单、继续产生记录（账号看着"删了还在跑"）
	removed := 0
	for _, se := range alipaySessionsCopy() {
		if se.PID == wxid || se.ID == wxid {
			removeAlipaySession(se.ID)
			removed++
		}
	}
	if removed > 0 {
		_ = saveAlipaySessions()
		logInfo("alipay", "已停止账号 %s 的账单轮询", maskPid(wxid))
	}

	logInfo("config", "账号已删除 %s（订单记录与支付信息保留）", wxid)
	return nil
}

// ensureAccount 从消息里发现新账号时自动建档
func ensureAccount(wxid string) error {
	if wxid == "" {
		return nil
	}
	_, err := updateAccounts(func(list []Account) ([]Account, bool, error) {
		for _, a := range list {
			if a.Wxid == wxid {
				return list, false, nil
			}
		}
		return append(list, Account{Wxid: wxid, Enabled: true}), true, nil
	})
	return err
}

// ChannelFor 按当前接口模式取通道 ID：优先该平台专有值，未设置时回落到通用字段。
// X-Ypay 与码支付V1 的通道号是两套，切换平台不该要求重新绑定。
func (a Account) ChannelFor(mode string) string {
	switch mode {
	case "v1":
		if x := strings.TrimSpace(a.ChannelIDV1); x != "" {
			return x
		}
	case "xpay":
		if x := strings.TrimSpace(a.ChannelIDXpay); x != "" {
			return x
		}
	}
	return strings.TrimSpace(a.ChannelID)
}

// SetChannelFor 按平台写入通道 ID，同时同步旧字段，兼容旧版本读取
func (a *Account) SetChannelFor(mode, id string) {
	id = strings.TrimSpace(id)
	a.ChannelID = id
	switch mode {
	case "v1":
		a.ChannelIDV1 = id
	case "xpay":
		a.ChannelIDXpay = id
	}
}
