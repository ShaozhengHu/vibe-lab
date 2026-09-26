package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
)

// TestSM3StandardVector 使用国标测试向量（GB/T 32905-2016 附录示例）验证 SM3：
// SM3("abc") = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0。
func TestSM3StandardVector(t *testing.T) {
	sum := sm3.Sum([]byte("abc"))
	want := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("SM3(\"abc\") = %s，期望 %s", got, want)
	}
}

// TestSM4StandardVector 使用国标测试向量（GB/T 32907-2016 示例 1）验证 SM4 单块加密：
// 密钥与明文均为 0123456789abcdeffedcba9876543210，密文为 681edf34d206965e86b3e94f536e4246。
func TestSM4StandardVector(t *testing.T) {
	key, err := hex.DecodeString("0123456789abcdeffedcba9876543210")
	if err != nil {
		t.Fatal(err)
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	in, err := hex.DecodeString("0123456789abcdeffedcba9876543210")
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 16)
	block.Encrypt(out, in)
	want := "681edf34d206965e86b3e94f536e4246"
	if got := hex.EncodeToString(out); got != want {
		t.Fatalf("SM4 单块加密 = %s，期望 %s", got, want)
	}
}

// TestDeriveMasterKey 验证 KDF：同参数确定性、盐敏感性、迭代次数敏感性。
func TestDeriveMasterKey(t *testing.T) {
	salt := bytes.Repeat([]byte{0x11}, KDFSaltBytes)

	k1, err := DeriveMasterKey("测试主密码Abc123!", salt, 1000)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveMasterKey("测试主密码Abc123!", salt, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("相同参数必须派生出相同主密钥")
	}
	if len(k1) != MasterKeyBytes {
		t.Fatalf("主密钥长度 = %d，期望 %d", len(k1), MasterKeyBytes)
	}

	salt2 := bytes.Repeat([]byte{0x22}, KDFSaltBytes)
	k3, err := DeriveMasterKey("测试主密码Abc123!", salt2, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k3) {
		t.Fatal("盐不同必须派生出不同主密钥")
	}

	k4, err := DeriveMasterKey("测试主密码Abc123!", salt, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k4) {
		t.Fatal("迭代次数不同必须派生出不同主密钥")
	}

	if _, err := DeriveMasterKey("x", salt[:8], 1000); err == nil {
		t.Fatal("盐长度错误必须报错")
	}
}

// TestSealOpenRoundTrip 验证信封加密往返、篡改检测与错误主密钥拒绝。
func TestSealOpenRoundTrip(t *testing.T) {
	salt := bytes.Repeat([]byte{0x33}, KDFSaltBytes)
	mk, err := DeriveMasterKey("正确主密码Abc123!", salt, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(mk)

	id, err := NewEntryID()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"title":"内网数据库","username":"ops","password":"s3cr3t"}`)

	se, err := SealEntry(mk, plaintext, id)
	if err != nil {
		t.Fatal(err)
	}

	// 往返：解密结果与原文一致。
	got, err := OpenEntry(mk, se)
	if err != nil {
		t.Fatalf("OpenEntry 失败: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("往返不一致: %q != %q", got, plaintext)
	}

	// 篡改密文 1 字节必须失败。
	se2 := cloneEntry(se)
	se2.Ciphertext[0] ^= 0x01
	if _, err := OpenEntry(mk, se2); err == nil {
		t.Fatal("篡改密文必须解密失败")
	}

	// 篡改认证标签必须失败。
	se3 := cloneEntry(se)
	se3.Tag1[0] ^= 0x01
	if _, err := OpenEntry(mk, se3); err == nil {
		t.Fatal("篡改认证标签必须解密失败")
	}

	// 篡改条目 ID（AAD）必须失败。
	se4 := cloneEntry(se)
	se4.ID[0] ^= 0x01
	if _, err := OpenEntry(mk, se4); err == nil {
		t.Fatal("篡改条目 ID 必须解密失败")
	}

	// 错误主密钥必须失败。
	mkWrong, err := DeriveMasterKey("错误主密码Abc123!", salt, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(mkWrong)
	if _, err := OpenEntry(mkWrong, se); err == nil {
		t.Fatal("错误主密钥必须解密失败")
	}

	// 密封条目字段长度非法必须报错。
	se5 := cloneEntry(se)
	se5.Nonce1 = se5.Nonce1[:8]
	if _, err := OpenEntry(mk, se5); err == nil {
		t.Fatal("字段长度非法必须报错")
	}
}

// TestSealEntryKeyLen 验证非法主密钥长度被拒绝。
func TestSealEntryKeyLen(t *testing.T) {
	id, _ := NewEntryID()
	if _, err := SealEntry(make([]byte, 8), []byte("x"), id); err == nil {
		t.Fatal("非法主密钥长度必须报错")
	}
}

func cloneEntry(se *SealedEntry) *SealedEntry {
	c := *se
	c.Ciphertext = append([]byte(nil), se.Ciphertext...)
	c.Nonce1 = append([]byte(nil), se.Nonce1...)
	c.Tag1 = append([]byte(nil), se.Tag1...)
	c.EncryptedKey = append([]byte(nil), se.EncryptedKey...)
	c.Nonce2 = append([]byte(nil), se.Nonce2...)
	c.Tag2 = append([]byte(nil), se.Tag2...)
	return &c
}
