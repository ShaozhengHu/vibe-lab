package storage

import (
	"bytes"
	"strings"
	"testing"

	"password-vault/internal/crypto"
)

func TestFormatConstants(t *testing.T) {
	if len(FileMagic) != 4 {
		t.Fatalf("文件魔数必须为 4 字节: %q", FileMagic)
	}
	if FormatVersion == 0 {
		t.Fatal("格式版本不得为 0")
	}
}

// helper 构造一个含一条密封条目的库。
func testVault(t *testing.T) (*VaultFile, []byte) {
	t.Helper()
	mk := bytes.Repeat([]byte{0x5a}, crypto.MasterKeyBytes)
	id, err := crypto.NewEntryID()
	if err != nil {
		t.Fatal(err)
	}
	se, err := crypto.SealEntry(mk, []byte(`{"title":"t","username":"u","password":"p"}`), id)
	if err != nil {
		t.Fatal(err)
	}
	v := &VaultFile{
		Salt:       bytes.Repeat([]byte{0x5b}, crypto.KDFSaltBytes),
		Iterations: 12345,
		Entries:    []crypto.SealedEntry{*se},
	}
	return v, mk
}

func TestVaultFileRoundTrip(t *testing.T) {
	v, mk := testVault(t)

	var buf bytes.Buffer
	if err := v.Write(&buf); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Salt, v.Salt) {
		t.Fatalf("盐不一致: %x != %x", got.Salt, v.Salt)
	}
	if got.Iterations != v.Iterations {
		t.Fatalf("迭代次数不一致: %d != %d", got.Iterations, v.Iterations)
	}
	if len(got.Entries) != 1 {
		t.Fatalf("条目数不一致: %d", len(got.Entries))
	}
	if got.Entries[0].ID != v.Entries[0].ID {
		t.Fatal("条目 ID 不一致")
	}
	if !bytes.Equal(got.Entries[0].Ciphertext, v.Entries[0].Ciphertext) {
		t.Fatal("密文不一致")
	}
	// 读回的密封条目必须能用同一主密钥解开。
	plain, err := crypto.OpenEntry(mk, &got.Entries[0])
	if err != nil {
		t.Fatalf("读回条目无法解密: %v", err)
	}
	if string(plain) != `{"title":"t","username":"u","password":"p"}` {
		t.Fatalf("明文不一致: %s", plain)
	}
}

func TestReadRejectsBadMagic(t *testing.T) {
	v, _ := testVault(t)
	var buf bytes.Buffer
	if err := v.Write(&buf); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	raw[0] = 'X' // 破坏魔数
	_, err := Read(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("魔数错误必须拒绝打开")
	}
	if !strings.Contains(err.Error(), "魔数") {
		t.Fatalf("错误信息应指明魔数: %v", err)
	}
}

func TestReadRejectsBadVersion(t *testing.T) {
	v, _ := testVault(t)
	var buf bytes.Buffer
	if err := v.Write(&buf); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	raw[5] = 0x02 // 版本改为 2
	if _, err := Read(bytes.NewReader(raw)); err == nil {
		t.Fatal("未知版本必须拒绝打开")
	}
}

func TestReadRejectsTrailingData(t *testing.T) {
	v, _ := testVault(t)
	var buf bytes.Buffer
	if err := v.Write(&buf); err != nil {
		t.Fatal(err)
	}
	raw := append(buf.Bytes(), 0x00) // 追加 1 字节多余数据
	if _, err := Read(bytes.NewReader(raw)); err == nil {
		t.Fatal("尾部多余数据必须拒绝打开")
	}
}

func TestReadRejectsTruncated(t *testing.T) {
	v, _ := testVault(t)
	var buf bytes.Buffer
	if err := v.Write(&buf); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()[:len(buf.Bytes())-5] // 截断尾部
	if _, err := Read(bytes.NewReader(raw)); err == nil {
		t.Fatal("截断文件必须拒绝打开")
	}
}

func TestEntryEncodeDecode(t *testing.T) {
	e, err := NewEntry("标题", "账号", "密码")
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeEntry(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Title != "标题" || got.Username != "账号" || got.Password != "密码" {
		t.Fatalf("编解码不一致: %+v", got)
	}
	if _, err := DecodeEntry([]byte(`{"title":"t"}`)); err == nil {
		t.Fatal("字段缺失必须报错")
	}
	if _, err := NewEntry("", "u", "p"); err == nil {
		t.Fatal("空标题必须报错")
	}
}
