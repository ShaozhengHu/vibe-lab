package storage

import (
	"os"
	"path/filepath"
	"testing"

	"password-vault/internal/crypto"
)

func TestBackupRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "vault.vault")
	dst := filepath.Join(dir, "backup.vault")

	// 构造一个含条目的库文件。
	v, err := NewVault()
	if err != nil {
		t.Fatal(err)
	}
	se := fakeSealedEntry(t)
	v.Entries = append(v.Entries, se)
	if err := v.WriteFile(src); err != nil {
		t.Fatal(err)
	}

	if err := WriteBackup(src, dst); err != nil {
		t.Fatalf("备份失败: %v", err)
	}
	info, err := os.Stat(dst)
	if err != nil || info.Size() == 0 {
		t.Fatalf("备份文件应存在且非空: %v", err)
	}

	// 用备份覆盖一个不同的库位置，应能完整还原。
	target := filepath.Join(dir, "restored.vault")
	if err := v.WriteFile(target); err != nil {
		t.Fatal(err)
	}
	// 先污染目标库，验证恢复确实覆盖。
	if err := os.WriteFile(target, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RestoreBackup(dst, target); err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	got, err := ReadFile(target)
	if err != nil {
		t.Fatalf("恢复后的库无法解析: %v", err)
	}
	if len(got.Entries) != 1 || got.Entries[0].ID != se.ID {
		t.Fatalf("恢复后的库内容不一致: %+v", got.Entries)
	}
}

func TestBackupRejectsTampered(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "vault.vault")
	dst := filepath.Join(dir, "backup.vault")

	v, err := NewVault()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.WriteFile(src); err != nil {
		t.Fatal(err)
	}
	if err := WriteBackup(src, dst); err != nil {
		t.Fatal(err)
	}

	// 篡改一个数据字节：SM3 摘要应拒绝。
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	data[backupHeaderLen] ^= 0x01
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "restored.vault")
	if err := v.WriteFile(target); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile(target)
	if err := RestoreBackup(dst, target); err == nil {
		t.Fatal("篡改的备份应被拒绝")
	}
	after, _ := os.ReadFile(target)
	if string(orig) != string(after) {
		t.Fatal("恢复失败后不得触碰目标库")
	}
}

func TestBackupRejectsNonBackup(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "fake.vault")
	if err := os.WriteFile(fake, []byte("not a backup at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "restored.vault")
	if err := RestoreBackup(fake, target); err == nil {
		t.Fatal("非备份文件应被拒绝")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("拒绝后不得创建/修改目标库")
	}
}

// fakeSealedEntry 构造一条密封条目（直接字段赋值，不依赖加密包内部）。
func fakeSealedEntry(t *testing.T) crypto.SealedEntry {
	t.Helper()
	se := crypto.SealedEntry{}
	for i := range se.ID {
		se.ID[i] = byte(i)
	}
	se.Ciphertext = []byte("cipher")
	se.Nonce1 = make([]byte, crypto.IVBytes)
	se.Tag1 = make([]byte, crypto.TagBytes)
	se.EncryptedKey = make([]byte, crypto.DataKeyBytes)
	se.Nonce2 = make([]byte, crypto.IVBytes)
	se.Tag2 = make([]byte, crypto.TagBytes)
	return se
}
