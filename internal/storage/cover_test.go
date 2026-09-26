package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCoverFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.bin")
	orig := bytes.Repeat([]byte{0xAB}, 5000)
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CoverFile(path); err != nil {
		t.Fatalf("CoverFile 失败: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(orig) {
		t.Fatalf("覆盖后长度变化: %d -> %d", len(orig), len(got))
	}
	if bytes.Equal(got, orig) {
		t.Fatal("覆盖后内容不应与原内容相同")
	}
	// 两次覆盖结果应不同（随机）。
	got2, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// 重新覆盖一次再比较。
	if err := CoverFile(path); err != nil {
		t.Fatal(err)
	}
	got3, _ := os.ReadFile(path)
	if bytes.Equal(got2, got3) {
		t.Log("警告：两次随机覆盖恰好相同（概率极低，仅提示）")
	}
}

func TestReplaceWithCover(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.vault")
	v1 := NewVaultOrFail(t)
	if err := v1.WriteFile(path); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)

	v2 := NewVaultOrFail(t) // 不同盐的新库内容
	if err := ReplaceWithCover(path, v2); err != nil {
		t.Fatalf("ReplaceWithCover 失败: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(after, before) {
		t.Fatal("替换后文件内容应不同")
	}
	// 新文件可被 Read 完整解析且盐一致。
	got, err := ReadFile(path)
	if err != nil {
		t.Fatalf("替换后库文件无法读取: %v", err)
	}
	if !bytes.Equal(got.Salt, v2.Salt) {
		t.Fatal("替换后库文件内容与 v2 不一致")
	}
}

// NewVaultOrFail 简化测试辅助。
func NewVaultOrFail(t *testing.T) *VaultFile {
	t.Helper()
	v, err := NewVault()
	if err != nil {
		t.Fatalf("NewVault 失败: %v", err)
	}
	return v
}
