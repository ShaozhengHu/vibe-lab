package storage

import (
	"encoding/json"
	"fmt"
	"time"
)

// Entry 是一条凭据的明文形态，仅在解锁后的内存中存在，绝不落盘。
// 磁盘上保存的是其 JSON 序列化经 SM4-GCM 加密后的密文（见 crypto.SealedEntry）。
// Deleted 标记软删除（回收站）：旧库条目无此字段，读取时默认为 false，无需升级库格式。
// Address/Port/Note 为可选补充字段（如服务器 IP、端口、备注）：旧库条目缺省为空，
// JSON 反序列化天然兼容，无需升级库版本。
//
type Entry struct {
	Title     string `json:"title"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Address   string `json:"address,omitempty"` // 地址：IP / 域名 / URL（可选）
	Port      int    `json:"port,omitempty"`    // 端口（可选，0 表示未填写）
	Note      string `json:"note,omitempty"`    // 备注（可选）
	CreatedAt int64  `json:"created_at"`        // Unix 秒
	Internal  bool   `json:"internal,omitempty"`
	Deleted   bool   `json:"deleted,omitempty"`
}

// NewEntry 构造一条普通凭据，空字段会被拒绝。
func NewEntry(title, username, password string) (*Entry, error) {
	if title == "" || username == "" || password == "" {
		return nil, fmt.Errorf("storage: 标题、账号、密码均不能为空")
	}
	return &Entry{
		Title:     title,
		Username:  username,
		Password:  password,
		CreatedAt: time.Now().Unix(),
	}, nil
}

// Encode 将凭据序列化为明文 JSON（随后由调用方加密）。
func (e *Entry) Encode() ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("storage: 凭据序列化失败: %w", err)
	}
	return b, nil
}

// DecodeEntry 解析凭据明文 JSON，并校验必要字段。
func DecodeEntry(b []byte) (*Entry, error) {
	var e Entry
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("storage: 凭据明文解析失败: %w", err)
	}
	if e.Title == "" || e.Username == "" || e.Password == "" {
		return nil, fmt.Errorf("storage: 凭据明文字段缺失（标题/账号/密码）")
	}
	return &e, nil
}
