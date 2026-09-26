package crypto

import (
	"crypto/cipher"
	"fmt"

	"github.com/emmansun/gmsm/sm4"
)

// SealedEntry 是一条凭据的密文形态（信封加密）：
//
//   - 凭据明文用独立数据密钥 DK_i 以 SM4-GCM 加密（随机 IV，AAD=条目 ID）；
//   - DK_i 用主密钥 MK 以 SM4-GCM 封装（随机 IV，AAD=条目 ID）；
//   - 条目 ID 同时作为两条密文的 AAD：绑定密文与条目身份，防止内容替换与篡改。
//
// 磁盘上只存在 SealedEntry，明文仅存在于解锁后的内存中。
type SealedEntry struct {
	ID           [16]byte // 条目唯一标识（AAD）
	Ciphertext   []byte   // 凭据明文密文
	Nonce1       []byte   // IVBytes 字节，凭据加密随机数（每次唯一）
	Tag1         []byte   // TagBytes 字节，凭据认证标签
	EncryptedKey []byte   // DataKeyBytes 字节，DK_i 密文
	Nonce2       []byte   // IVBytes 字节，DK_i 封装随机数
	Tag2         []byte   // TagBytes 字节，DK_i 认证标签
}

// SealEntry 用主密钥 mk 将凭据明文加密为 SealedEntry。
// 返回的 SealedEntry 各字段均为新分配的独立切片，可直接持久化。
func SealEntry(mk []byte, plaintext []byte, id [16]byte) (*SealedEntry, error) {
	if len(mk) != MasterKeyBytes {
		return nil, fmt.Errorf("crypto: 主密钥长度必须为 %d 字节，实际 %d", MasterKeyBytes, len(mk))
	}

	// 1) 随机生成该条凭据的数据密钥 DK_i（信封加密：每条凭据独立）。
	dk, err := randomBytes(DataKeyBytes)
	if err != nil {
		return nil, err
	}
	defer clear(dk)

	// 2) 凭据明文用 DK_i + SM4-GCM 加密。
	nonce1, err := randomBytes(IVBytes)
	if err != nil {
		return nil, err
	}
	aead1, err := sm4GCM(dk)
	if err != nil {
		return nil, err
	}
	sealed := aead1.Seal(nil, nonce1, plaintext, id[:])
	tag1 := append([]byte(nil), sealed[len(sealed)-TagBytes:]...)
	ct := append([]byte(nil), sealed[:len(sealed)-TagBytes]...)

	// 3) DK_i 用主密钥 MK + SM4-GCM 封装。
	nonce2, err := randomBytes(IVBytes)
	if err != nil {
		return nil, err
	}
	aead2, err := sm4GCM(mk)
	if err != nil {
		return nil, err
	}
	sealedKey := aead2.Seal(nil, nonce2, dk, id[:])
	tag2 := append([]byte(nil), sealedKey[len(sealedKey)-TagBytes:]...)
	ek := append([]byte(nil), sealedKey[:len(sealedKey)-TagBytes]...)

	return &SealedEntry{
		ID:           id,
		Ciphertext:   ct,
		Nonce1:       nonce1,
		Tag1:         tag1,
		EncryptedKey: ek,
		Nonce2:       nonce2,
		Tag2:         tag2,
	}, nil
}

// OpenEntry 校验并解密 SealedEntry，返回凭据明文。
//
// 任何篡改（密文、随机数、认证标签、条目 ID）或主密钥错误都会导致
// SM4-GCM 认证失败并返回错误；调用方不得忽略该错误。
func OpenEntry(mk []byte, se *SealedEntry) ([]byte, error) {
	if len(mk) != MasterKeyBytes {
		return nil, fmt.Errorf("crypto: 主密钥长度必须为 %d 字节，实际 %d", MasterKeyBytes, len(mk))
	}
	if len(se.Nonce1) != IVBytes || len(se.Tag1) != TagBytes ||
		len(se.Nonce2) != IVBytes || len(se.Tag2) != TagBytes {
		return nil, fmt.Errorf("crypto: 密封条目字段长度非法（库文件可能已损坏）")
	}

	// 1) 解封数据密钥 DK_i：认证失败说明主密码错误或库文件被篡改。
	aead2, err := sm4GCM(mk)
	if err != nil {
		return nil, err
	}
	sealedKey := concat(se.EncryptedKey, se.Tag2)
	dk, err := aead2.Open(nil, se.Nonce2, sealedKey, se.ID[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: 数据密钥校验失败（主密码错误或库文件被篡改）: %w", err)
	}
	defer clear(dk)

	// 2) 解密凭据明文。
	aead1, err := sm4GCM(dk)
	if err != nil {
		return nil, err
	}
	sealedCt := concat(se.Ciphertext, se.Tag1)
	plaintext, err := aead1.Open(nil, se.Nonce1, sealedCt, se.ID[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: 凭据解密校验失败（库文件被篡改）: %w", err)
	}
	return plaintext, nil
}

// sm4GCM 构造 SM4 的 GCM 认证加密器。SM4 为 128 位分组密码，
// 与标准库 cipher.NewGCM 直接兼容（GCM 推荐 12 字节随机数）。
func sm4GCM(key []byte) (cipher.AEAD, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: SM4 初始化失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: GCM 模式初始化失败: %w", err)
	}
	return aead, nil
}

// concat 拼接两段字节到新切片，避免 append 修改底层数组。
func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}
