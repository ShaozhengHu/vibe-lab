package gui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// auditLogger 写本地审计日志（JSON Lines，逐条追加）。
// 安全约定：只记录操作类型与结果，绝不记录密码明文、凭据标题/账号等
// 敏感内容——审计关注"发生了什么"，不暴露"内容是什么"。
// 文件与库文件同目录（.password-vault/audit.log），权限 0600。
type auditLogger struct {
	mu   sync.Mutex
	path string
}

// auditEvent 是一条审计记录。
type auditEvent struct {
	TS     string `json:"ts"`     // 本地时间，格式 2006-01-02 15:04:05
	Action string `json:"action"` // 操作类型
	Result string `json:"result"` // 成功 / 失败（失败不含具体原因以外的细节）
}

func newAuditLogger(dir string) *auditLogger {
	return &auditLogger{path: filepath.Join(dir, "audit.log")}
}

// Log 追加一条审计记录。日志写入失败不影响业务操作（记录尽力而为）。
func (a *auditLogger) Log(action, result string) {
	if a == nil || a.path == "" {
		return
	}
	ev := auditEvent{TS: time.Now().Format("2006-01-02 15:04:05"), Action: action, Result: result}
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	line = append(line, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(line)
}
