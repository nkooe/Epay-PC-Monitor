package main

// 微信数据库读取（WCDB）
//
// 走腾讯官方 WCDB 引擎解密 biz_message_0.db，读取服务号/公众号消息。
// 这一层覆盖了 hook 抓不到的场景：微信收款助手、微信支付的收款/赞赏通知。

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows/registry"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ---------- DLL 绑定 ----------

var (
	wcdbOnce  sync.Once
	wcdbErr   error
	wcdbOpen  *syscall.Proc
	wcdbQuery *syscall.Proc
	wcdbClose *syscall.Proc
	wcdbFree  *syscall.Proc
)

func wcdbInit() error {
	wcdbOnce.Do(func() {
		dir, err := nativeDir()
		if err != nil {
			wcdbErr = err
			return
		}
		// WCDB.dll 是 wxtool_wcdb.dll 的依赖，必须先加载
		if _, err := syscall.LoadDLL(filepath.Join(dir, "WCDB.dll")); err != nil {
			wcdbErr = fmt.Errorf("加载 WCDB.dll 失败: %w", err)
			return
		}
		d, err := syscall.LoadDLL(filepath.Join(dir, "wxtool_wcdb.dll"))
		if err != nil {
			wcdbErr = fmt.Errorf("加载 wxtool_wcdb.dll 失败: %w", err)
			return
		}
		var e error
		if wcdbOpen, e = d.FindProc("wxtool_open"); e != nil {
			wcdbErr = e
			return
		}
		if wcdbQuery, e = d.FindProc("wxtool_query"); e != nil {
			wcdbErr = e
			return
		}
		if wcdbClose, e = d.FindProc("wxtool_close"); e != nil {
			wcdbErr = e
			return
		}
		if wcdbFree, e = d.FindProc("wxtool_free_string"); e != nil {
			wcdbErr = e
			return
		}
	})
	return wcdbErr
}

func cStrGo(p uintptr) string {
	if p == 0 {
		return ""
	}
	n := 0
	for n < 1<<20 {
		if *(*byte)(unsafe.Pointer(p + uintptr(n))) == 0 {
			break
		}
		n++
	}
	if n == 0 {
		return ""
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(p)), n))
}

// ---------- 数据库句柄 ----------

// WxDB 一个已解密的微信数据库
// 注意：wxtool 的句柄只能在创建它的 OS 线程上使用，
// 所以创建时用 runtime.LockOSThread 绑定，且所有操作必须在同一 goroutine。
type WxDB struct {
	handle   uintptr
	path     string
	mu       sync.Mutex
	submitMu sync.Mutex
	closed   bool
	closing  bool
	reqCh    chan dbReq
	done     chan struct{}
}

// OpenWxDB 用密钥打开一个微信数据库
// 打开动作和后续查询全部在同一个锁定线程上完成。
func OpenWxDB(dbPath, keyHex string) (*WxDB, error) {
	if err := wcdbInit(); err != nil {
		return nil, err
	}
	if len(keyHex) != 64 {
		return nil, fmt.Errorf("密钥必须是 64 位十六进制")
	}
	d := &WxDB{path: dbPath, reqCh: make(chan dbReq, 8), done: make(chan struct{})}

	type openResp struct {
		handle uintptr
		err    error
	}
	openCh := make(chan openResp, 1)

	go func() {
		defer close(d.done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		p := append([]byte(dbPath), 0)
		k := append([]byte(keyHex), 0)
		var h, es uintptr
		r, _, _ := wcdbOpen.Call(
			uintptr(unsafe.Pointer(&p[0])),
			uintptr(unsafe.Pointer(&k[0])),
			4096, 0,
			uintptr(unsafe.Pointer(&h)),
			uintptr(unsafe.Pointer(&es)),
		)
		runtime.KeepAlive(p)
		runtime.KeepAlive(k)
		if int32(r) != 0 {
			msg := cStrGo(es)
			if es != 0 {
				wcdbFree.Call(es)
			}
			if msg == "" {
				msg = "打开失败"
			}
			openCh <- openResp{err: fmt.Errorf("%s", msg)}
			return
		}

		// 同一个线程继续处理所有查询
		openCh <- openResp{handle: h}
		d.serveRequests(d.rawQuery)
	}()

	r := <-openCh
	if r.err != nil {
		return nil, r.err
	}
	d.handle = r.handle
	return d, nil
}

type dbReq struct {
	op   string
	args map[string]any
	resp chan dbResp
}

type dbResp struct {
	v   any
	err error
}

func (d *WxDB) serveRequests(run func(string, map[string]any) (any, error)) {
	for {
		req, ok := <-d.reqCh
		if !ok {
			return
		}
		v, err := run(req.op, req.args)
		if req.resp != nil {
			req.resp <- dbResp{v: v, err: err}
		}
		if req.op == "__close__" {
			return
		}
	}
}

// Close 关闭数据库
func (d *WxDB) Close() {
	if d == nil {
		return
	}
	d.submitMu.Lock()
	if d.closing {
		done := d.done
		d.submitMu.Unlock()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		return
	}
	d.closing = true
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case d.reqCh <- dbReq{op: "__close__", resp: make(chan dbResp, 1)}:
		d.submitMu.Unlock()
	case <-d.done:
		d.submitMu.Unlock()
		return
	case <-timer.C:
		d.closing = false
		d.submitMu.Unlock()
		return
	}
	select {
	case <-d.done:
	case <-timer.C:
	}
}

// query 执行结构化查询（转发到专用线程）
func (d *WxDB) query(op string, args map[string]any) (any, error) {
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	ch := make(chan dbResp, 1)
	select {
	case <-d.done:
		return nil, fmt.Errorf("数据库已关闭")
	default:
	}
	d.submitMu.Lock()
	if d.closing {
		d.submitMu.Unlock()
		return nil, fmt.Errorf("数据库已关闭")
	}
	select {
	case d.reqCh <- dbReq{op: op, args: args, resp: ch}:
		d.submitMu.Unlock()
	case <-d.done:
		d.submitMu.Unlock()
		return nil, fmt.Errorf("数据库已关闭")
	case <-timer.C:
		d.submitMu.Unlock()
		return nil, fmt.Errorf("查询超时")
	}
	select {
	case r := <-ch:
		return r.v, r.err
	case <-d.done:
		select {
		case r := <-ch:
			return r.v, r.err
		default:
			return nil, fmt.Errorf("数据库已关闭")
		}
	case <-timer.C:
		return nil, fmt.Errorf("查询超时")
	}
}

// rawQuery 真正的查询（只在 run 的锁定线程上调用）
func (d *WxDB) rawQuery(op string, args map[string]any) (any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, fmt.Errorf("数据库已关闭")
	}
	if op == "__close__" {
		wcdbClose.Call(d.handle)
		d.closed = true
		d.handle = 0
		return nil, nil
	}
	if args == nil {
		args = map[string]any{}
	}
	payload, err := json.Marshal(map[string]any{"op": op, "args": args})
	if err != nil {
		return nil, err
	}
	buf := append(payload, 0)
	var out, e2 uintptr
	r, _, _ := wcdbQuery.Call(d.handle,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&out)),
		uintptr(unsafe.Pointer(&e2)))
	runtime.KeepAlive(buf)
	if int32(r) != 0 {
		msg := cStrGo(e2)
		if e2 != 0 {
			wcdbFree.Call(e2)
		}
		if msg == "" {
			msg = "查询失败"
		}
		return nil, fmt.Errorf("%s", msg)
	}
	s := cStrGo(out)
	if out != 0 {
		wcdbFree.Call(out)
	}
	var v any
	if s != "" {
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// Tables 列出所有表
func (d *WxDB) Tables() ([]string, error) {
	v, err := d.query("tables", nil)
	if err != nil {
		return nil, err
	}
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, it := range list {
		if m, ok := it.(map[string]any); ok {
			if n, ok := m["name"].(string); ok {
				out = append(out, n)
			}
		}
	}
	return out, nil
}

// Count 某表行数
func (d *WxDB) Count(table string) (int64, error) {
	v, err := d.query("count", map[string]any{"table": table})
	if err != nil {
		return 0, err
	}
	list, _ := v.([]any)
	if len(list) == 0 {
		return 0, nil
	}
	m, _ := list[0].(map[string]any)
	if c, ok := m["count"].(float64); ok {
		return int64(c), nil
	}
	return 0, nil
}

// RawMsg 原始消息行
type RawMsg struct {
	LocalID   int64
	ServerID  int64
	LocalType int64
	SortSeq   int64
	CreateAt  int64
	Content   string // hex 编码（可能是 zstd 压缩）
	IsZstd    bool
	Table     string // 来源表名（Msg_<hash>）
}

// Messages 读取消息
func (d *WxDB) Messages(table string, limit int, since int64, ascending bool) ([]RawMsg, error) {
	args := map[string]any{
		"table":     table,
		"limit":     limit,
		"ascending": ascending,
	}
	if since > 0 {
		args["since_seconds"] = since
	}
	v, err := d.query("messages", args)
	if err != nil {
		return nil, err
	}
	list, _ := v.([]any)
	out := make([]RawMsg, 0, len(list))
	for _, it := range list {
		m, _ := it.(map[string]any)
		r := RawMsg{}
		if f, ok := m["local_id"].(float64); ok {
			r.LocalID = int64(f)
		}
		if f, ok := m["server_id"].(float64); ok {
			r.ServerID = int64(f)
		}
		if f, ok := m["local_type"].(float64); ok {
			r.LocalType = int64(f)
		}
		if f, ok := m["sort_seq"].(float64); ok {
			r.SortSeq = int64(f)
		}
		if f, ok := m["create_time"].(float64); ok {
			r.CreateAt = int64(f)
		}
		if s, ok := m["message_content"].(string); ok {
			r.Content = s
			r.IsZstd = strings.HasPrefix(strings.ToLower(s), "28b52ffd")
		}
		if ct, ok := m["WCDB_CT_message_content"].(float64); ok && ct == 4 {
			r.IsZstd = true
		}
		out = append(out, r)
	}
	return out, nil
}

// ---------- 公众号表映射 ----------

// GhTable 公众号 gh_id 对应的消息表名
// 规则：Msg_ + md5(gh_id)
func GhTable(ghID string) string {
	sum := md5.Sum([]byte(ghID))
	return "Msg_" + hex.EncodeToString(sum[:])
}

// ---------- 本地账号发现 ----------

// WxAccount 本地微信账号目录
type WxAccount struct {
	Wxid      string // 从目录名解析
	Dir       string // 完整路径
	BizDB     string // biz_message_0.db 路径
	MsgDB     string // message_0.db 路径
	ContactDB string // contact.db 路径
	SessionDB string // session.db 路径（最小，验证密钥最快）
	HasBiz    bool
	ModTime   time.Time
}

// WeChatRoot 微信数据根目录
// isWxDataRoot 判断某个目录本身是不是微信数据根目录
func isWxDataRoot(p string) bool {
	st, err := os.Stat(p)
	if err != nil || !st.IsDir() {
		return false
	}
	if _, err := os.Stat(filepath.Join(p, "all_users")); err == nil {
		return true
	}
	ents, err := os.ReadDir(p)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), "wxid_") {
			return true
		}
	}
	return false
}

// weChatRootFromRegistry 读注册表里微信记录的存储路径。
// 用户把数据目录改到别的盘时，这里能拿到；默认值写作 "MyDocument:"。
func weChatRootFromRegistry() []string {
	var out []string
	home, _ := os.UserHomeDir()

	readPath := func(key, value string) {
		k, err := registry.OpenKey(registry.CURRENT_USER, key, registry.QUERY_VALUE)
		if err != nil {
			return
		}
		v, _, e := k.GetStringValue(value)
		k.Close()
		if e != nil || v == "" {
			return
		}
		v = strings.TrimSpace(v)
		if strings.HasPrefix(strings.ToLower(v), "mydocument") {
			v = filepath.Join(home, "Documents")
		}
		v = strings.TrimRight(v, "\\/")
		if v != "" {
			out = append(out, v)
		}
	}

	readPath(`SOFTWARE\Tencent\Weixin`, "FileSavePath")
	readPath(`SOFTWARE\Tencent\Weixin`, "OldFileSavePath")
	readPath(`SOFTWARE\Tencent\WeChat`, "FileSavePath")
	return out
}

// WeChatRoot 找微信数据根目录（xwechat_files）。
// 顺序：注册表记录的路径 -> 文档目录 -> 各盘常见位置。
// 换设备、用户把数据目录改到别的盘时都能命中。
func WeChatRoot() string {
	home, _ := os.UserHomeDir()

	checkBase := func(base string) string {
		for _, sub := range []string{"xwechat_files", "WeChat Files"} {
			p := filepath.Join(base, sub)
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				return p
			}
		}
		if isWxDataRoot(base) {
			return base
		}
		return ""
	}

	for _, base := range weChatRootFromRegistry() {
		if p := checkBase(base); p != "" {
			return p
		}
		if p := checkBase(filepath.Dir(base)); p != "" {
			return p
		}
	}

	if p := checkBase(filepath.Join(home, "Documents")); p != "" {
		return p
	}

	for _, drive := range []string{"C", "D", "E", "F", "G", "H"} {
		base := drive + ":" + string(os.PathSeparator)
		if p := checkBase(base); p != "" {
			return p
		}
		if p := checkBase(filepath.Join(base, "Tencent")); p != "" {
			return p
		}
	}
	return ""
}

// ScanWxAccounts 扫描本机所有微信账号
func ScanWxAccounts() []WxAccount {
	root := WeChatRoot()
	if root == "" {
		return nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	out := make([]WxAccount, 0, 4)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "all_users" || name == "Backup" {
			continue
		}
		// 目录名形如 wxid_xxx_abcd
		wxid := name
		if i := strings.LastIndex(name, "_"); i > 0 {
			wxid = name[:i]
		}
		if !strings.HasPrefix(wxid, "wxid_") {
			continue
		}
		dir := filepath.Join(root, name)
		acc := WxAccount{Wxid: wxid, Dir: dir}
		acc.BizDB = filepath.Join(dir, "db_storage", "message", "biz_message_0.db")
		acc.MsgDB = filepath.Join(dir, "db_storage", "message", "message_0.db")
		acc.ContactDB = filepath.Join(dir, "db_storage", "contact", "contact.db")
		acc.SessionDB = filepath.Join(dir, "db_storage", "session", "session.db")
		if st, err := os.Stat(acc.BizDB); err == nil {
			acc.HasBiz = true
			acc.ModTime = st.ModTime()
		}
		out = append(out, acc)
	}
	return out
}

// findWxAccount 按 wxid 找本地账号
func findWxAccount(wxid string) (WxAccount, bool) {
	for _, a := range ScanWxAccounts() {
		if a.Wxid == wxid {
			return a, true
		}
	}
	return WxAccount{}, false
}

// PeekAllTables 扫所有 Msg_ 表，各取最新 perTable 条。
// 用来在「消息调试」里展示好友 / 群聊消息（message_0.db 里每个联系人一张表）。
func (d *WxDB) PeekAllTables(perTable int) ([]RawMsg, error) {
	tables, err := d.Tables()
	if err != nil {
		return nil, err
	}
	var out []RawMsg
	for _, t := range tables {
		if !strings.HasPrefix(t, "Msg_") {
			continue
		}
		msgs, err := d.Messages(t, perTable, 0, false)
		if err != nil {
			continue
		}
		for _, m := range msgs {
			m.Table = t
			out = append(out, m)
		}
	}
	return out, nil
}

// Contact 联系人/公众号/群聊的基本信息
type Contact struct {
	Username  string `json:"username"`
	NickName  string `json:"nick_name"`
	Remark    string `json:"remark"`
	Alias     string `json:"alias"`
	LocalType int64  `json:"local_type"`
	Flag      int64  `json:"flag"`
}

// Display 优先备注名，其次昵称，都没有就用 username
func (c Contact) Display() string {
	if c.Remark != "" {
		return c.Remark
	}
	if c.NickName != "" {
		return c.NickName
	}
	return c.Username
}

// Contacts 批量查联系人昵称。
// wxtool_wcdb.dll 的 contact op 一次可以传多个 username，
// 这是唯一能拿到昵称的途径（contact 表本身读不了行）。
func (d *WxDB) Contacts(usernames []string) ([]Contact, error) {
	if len(usernames) == 0 {
		return nil, nil
	}
	v, err := d.query("contact", map[string]any{"usernames": usernames})
	if err != nil {
		return nil, err
	}
	list, _ := v.([]any)
	out := make([]Contact, 0, len(list))
	for _, it := range list {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		c := Contact{}
		if x, ok := m["username"].(string); ok {
			c.Username = x
		}
		if x, ok := m["nick_name"].(string); ok {
			c.NickName = x
		}
		if x, ok := m["remark"].(string); ok {
			c.Remark = x
		}
		if x, ok := m["alias"].(string); ok {
			c.Alias = x
		}
		if x, ok := m["local_type"].(float64); ok {
			c.LocalType = int64(x)
		}
		if x, ok := m["flag"].(float64); ok {
			c.Flag = int64(x)
		}
		out = append(out, c)
	}
	return out, nil
}
