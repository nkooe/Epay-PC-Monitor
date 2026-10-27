package main

// 运行日志：级别 + 模块 + 环形缓冲，供界面查询

import (
	"path/filepath"
	"os"
	"fmt"
	"sync"
	"time"
)

type LogEntry struct {
	Time   string `json:"time"`
	Level  string `json:"level"`  // DEBUG / INFO / WARN / ERROR
	Module string `json:"module"` // monitor / callback / config / system / inject
	Msg    string `json:"msg"`
	Seq    int    `json:"seq"`
}

const logMax = 1000

var (
	logMu  sync.Mutex
	logBuf []LogEntry
	logSeq int
)

// logL 记录一条结构化日志：既打到控制台，也进环形缓冲
func logL(level, module, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	ts := time.Now()

	logMu.Lock()
	logSeq++
	e := LogEntry{
		Time:   ts.Format("2006/01/02 15:04:05"),
		Level:  level,
		Module: module,
		Msg:    msg,
		Seq:    logSeq,
	}
	// 头插，最新的在最前
	logBuf = append([]LogEntry{e}, logBuf...)
	if len(logBuf) > logMax {
		logBuf = logBuf[:logMax]
	}
	logMu.Unlock()

	// 写文件日志。不再往 stdout 打——GUI 程序一旦连到控制台，
	// 会把整个黑窗口弹出来刷屏，很难看。
	// 需要看实时输出时设环境变量 EASY_LOG_STDOUT=1。
	if logToStdout {
		func() {
			defer func() { recover() }()
			fmt.Printf("[%s] [%s] %s\n", ts.Format("15:04:05"), level, msg)
		}()
	}
	writeLogFile(ts, level, module, msg)
}

func logInfo(module, format string, args ...interface{})  { logL("INFO", module, format, args...) }
func logWarn(module, format string, args ...interface{})  { logL("WARN", module, format, args...) }
func logError(module, format string, args ...interface{}) { logL("ERROR", module, format, args...) }
func logDebug(module, format string, args ...interface{}) { logL("DEBUG", module, format, args...) }

// logsCopy 按条件取日志
func logsCopy(level, module string, limit int) []LogEntry {
	logMu.Lock()
	defer logMu.Unlock()
	out := make([]LogEntry, 0, len(logBuf))
	for _, e := range logBuf {
		if level != "" && e.Level != level {
			continue
		}
		if module != "" && e.Module != module {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func logsClear() {
	logMu.Lock()
	logBuf = nil
	logMu.Unlock()
}

// logToStdout 是否同时往控制台打。默认关闭，避免弹黑窗口。
var logToStdout = os.Getenv("EASY_LOG_STDOUT") == "1"

var (
	logFileMu sync.Mutex
	logFile   *os.File
	logWrites int64
)

// writeLogFile 追加到程序目录下的 run.log
const logRotateBytes = 8 << 20 // 8MB

// logFilePath 返回 run.log 的完整路径
func logFilePath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "run.log")
}

// openLogFileLocked 打开（必要时先轮转）。调用方必须已持有 logFileMu。
func openLogFileLocked() {
	p := logFilePath()
	if p == "" {
		return
	}
	// 超过上限就先挪走旧文件
	if st, err := os.Stat(p); err == nil && st.Size() > logRotateBytes {
		if logFile != nil {
			logFile.Close()
			logFile = nil
		}
		os.Remove(p + ".old")
		os.Rename(p, p+".old")
	}
	if logFile != nil {
		return
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		logFile = f
	}
}

func writeLogFile(ts time.Time, level, module, msg string) {
	if !logFileEnabled(level) {
		return
	}
	logFileMu.Lock()
	defer logFileMu.Unlock()

	openLogFileLocked()
	if logFile == nil {
		return
	}
	fmt.Fprintf(logFile, "%s [%s] [%s] %s\n",
		ts.Format("2006-01-02 15:04:05"), level, module, msg)

	// 每 200 条查一次大小。之前只在启动时检查，
	// 程序跑一个月不重启日志会涨到几个 GB。
	logWrites++
	if logWrites%200 == 0 {
		if st, err := logFile.Stat(); err == nil && st.Size() > logRotateBytes {
			openLogFileLocked()
		}
	}
}

// logFileEnabled 按配置的日志级别决定这条要不要落盘。
// 界面的「运行日志」不受影响，始终保留全部级别。
func logFileEnabled(level string) bool {
	lv := GetConfig().LogLevel
	switch lv {
	case "off":
		return false
	case "debug":
		return true
	default: // 基本：不写 DEBUG
		return level != "DEBUG"
	}
}
