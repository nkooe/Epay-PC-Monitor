package main

// 上报重试：只在「网络抖动」时重试（请求根本没拿到 HTTP 响应）。
// 平台明确返回了内容（任何状态码、任何业务错误）都视为最终结果，不再重试。
// 最多重试 3 次，每次间隔 5 秒。
//
// 队列落盘到 retry_queue.json：程序崩溃/重启后继续把未完成的上报发出去。
// 每条任务锁定入队时的接口模式，重试期间切平台不会把旧单发到新平台。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	reportRetryMax      = 3
	reportRetryInterval = 5 * time.Second
)

type retryJob struct {
	M        *ChatMsg `json:"m"`
	Mode     string   `json:"mode"` // 入队时的接口模式，重试时锁定
	Platform string   `json:"platform"`
	Attempts int      `json:"attempts"`
	NextAt   int64    `json:"next_at"`
	LastErr  string   `json:"last_err"`
}

var (
	retryMu   sync.Mutex
	retryJobs = map[string]*retryJob{}
	retryOnce sync.Once
)

// reportRetryable 只有传输层失败才值得重试：
// URL 已经拼好（说明配置没问题）、没拿到响应、没有状态码。
func reportRetryable(res ReportResult) bool {
	return res.URL != "" && !res.Delivered && res.Code == 0 && res.Err != ""
}

func retryKey(m *ChatMsg, platform string) string {
	return platform + "|" + messageDedupKey(m)
}

func retryQueueFile() string {
	return filepath.Join(exeDir(), "retry_queue.json")
}

// saveRetryQueueLocked 调用方必须已持有 retryMu
func saveRetryQueueLocked() {
	list := make([]*retryJob, 0, len(retryJobs))
	for _, j := range retryJobs {
		list = append(list, j)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	_ = atomicWriteFile(retryQueueFile(), b, 0600)
}

// LoadRetryQueue 启动时恢复未完成的重试任务
func LoadRetryQueue() {
	b, err := os.ReadFile(retryQueueFile())
	if err != nil {
		return
	}
	var list []*retryJob
	if err := json.Unmarshal(b, &list); err != nil {
		logWarn("callback", "重试队列读取失败：%v", err)
		return
	}
	retryMu.Lock()
	for _, j := range list {
		if j == nil || j.M == nil {
			continue
		}
		if j.NextAt < time.Now().Unix() {
			j.NextAt = time.Now().Add(reportRetryInterval).Unix()
		}
		retryJobs[retryKey(j.M, j.Platform)] = j
	}
	n := len(retryJobs)
	retryMu.Unlock()
	if n > 0 {
		logInfo("callback", "恢复待重试上报 %d 条", n)
		startReportRetryWorker()
	}
}

// enqueueReportRetry 上报因网络问题失败时排队重试（锁定当前接口模式）
func enqueueReportRetry(m *ChatMsg, res ReportResult, platform string) {
	mode := GetConfig().Mode
	if mode == "none" {
		return
	}
	k := retryKey(m, platform)
	retryMu.Lock()
	if _, ok := retryJobs[k]; ok {
		retryMu.Unlock()
		return
	}
	retryJobs[k] = &retryJob{
		M: m, Mode: mode, Platform: platform,
		NextAt: time.Now().Add(reportRetryInterval).Unix(), LastErr: res.Err,
	}
	saveRetryQueueLocked()
	retryMu.Unlock()
	logWarn("callback", "上报网络异常，%d 秒后重试（最多 %d 次，平台 %s）：%s",
		int(reportRetryInterval/time.Second), reportRetryMax, mode, res.Err)
	startReportRetryWorker()
}

func startReportRetryWorker() {
	retryOnce.Do(func() {
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for range t.C {
				runDueRetries(time.Now())
			}
		}()
	})
}

func runDueRetries(now time.Time) {
	type due struct {
		key string
		job retryJob
	}
	var list []due
	retryMu.Lock()
	for k, j := range retryJobs {
		if now.Unix() < j.NextAt {
			continue
		}
		list = append(list, due{key: k, job: *j})
	}
	retryMu.Unlock()

	for _, d := range list {
		res := ReportWithMode(d.job.M, d.job.Mode) // 锁定原平台，避免切平台后发错
		ok := res.Delivered && res.OK
		attempt := d.job.Attempts + 1
		if ok {
			retryMu.Lock()
			delete(retryJobs, d.key)
			saveRetryQueueLocked()
			retryMu.Unlock()
			updateRecordCallback(d.job.M, true, res)
			logInfo("callback", "重试成功（第 %d 次，平台 %s）", attempt, d.job.Mode)
			continue
		}
		if reportRetryable(res) && attempt < reportRetryMax {
			retryMu.Lock()
			if j, ok2 := retryJobs[d.key]; ok2 {
				j.Attempts = attempt
				j.NextAt = time.Now().Add(reportRetryInterval).Unix()
				j.LastErr = res.Err
				saveRetryQueueLocked()
			}
			retryMu.Unlock()
			logWarn("callback", "第 %d 次重试仍失败：%s", attempt, res.Err)
			continue
		}
		retryMu.Lock()
		delete(retryJobs, d.key)
		saveRetryQueueLocked()
		retryMu.Unlock()
		if res.Err == "" && !res.Delivered {
			res.Err = d.job.LastErr
		}
		updateRecordCallback(d.job.M, false, res)
		logError("callback", "重试结束，仍失败：%s", res.Err)
	}
}

// updateRecordCallback 回写同一条记录的失败/成功状态（不新增记录）
func updateRecordCallback(m *ChatMsg, ok bool, res ReportResult) {
	e := eng
	if e == nil {
		return
	}
	identity := messageDedupKey(m)
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range e.history {
		v := &e.history[i]
		if msgID(v) != identity || v.Account != m.To {
			continue
		}
		v.Reported = ok
		if ok {
			v.CallbackStatus = "已回调"
			v.Err = ""
		} else {
			v.CallbackStatus = "回调失败"
			if res.Err != "" {
				v.Err = res.Err
			}
		}
		if res.URL != "" {
			v.CallbackURL = res.URL
		}
		if res.Body != "" {
			v.CallbackBody = res.Body
		} else if !ok && res.Err != "" {
			v.CallbackBody = res.Err
		}
		markRecordsDirty()
		return
	}
}
