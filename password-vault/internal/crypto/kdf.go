// Package crypto 提供密码保险箱的全部密码学原语。
//
// 合规约束（依据 GB/T 39786-2021、《中华人民共和国密码法》及《商用密码管理条例》）：
//   - 只使用国家标准商用密码算法 SM2/SM3/SM4，不自行实现或自由组合算法；
//   - 算法实现一律采用经过验证的第三方库（emmansun/gmsm），并以国标测试向量校验（见 crypto_test.go）；
//   - 任何加密逻辑改动都必须通过测试向量与回归测试后方可合入（见 docs/acceptance-checklist.md）。
//
// 第 2 阶段已实现：PBKDF2-HMAC-SM3 主密钥派生、SM4-GCM 信封加密（SealEntry/OpenEntry）。
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"hash"

	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/pbkdf2"
)

// 密钥派生与加密参数。库文件头会持久化其中与派生相关的参数（盐、迭代次数），
// 以保证库文件可被未来版本以兼容方式读取。
const (
	// KDFIterations 是主密码派生主密钥的 PBKDF2 迭代次数。
	// 选取原则：在目标硬件上使单次派生耗时处于 0.1~0.5 秒量级，以对抗暴力破解。
	KDFIterations = 600000

	// KDFSaltBytes 是随机盐长度（字节）。每个库文件独立生成，避免预计算攻击。
	KDFSaltBytes = 16

	// MasterKeyBytes 是主密钥长度（字节）。SM4 使用 128 位密钥，
	// 取 PBKDF2 输出（32 字节）的前 16 字节作为主密钥。
	MasterKeyBytes = 16

	// DataKeyBytes 是单条凭据数据密钥长度（字节）。每条凭据独立随机生成（信封加密）。
	DataKeyBytes = 16

	// IVBytes 是 SM4-GCM 初始向量长度（字节）。GCM 模式推荐 12 字节，每次加密随机生成。
	IVBytes = 12

	// TagBytes 是 SM4-GCM 认证标签长度（字节），用于数据完整性与真实性校验。
	TagBytes = 16
)

// DeriveMasterKey 由主密码派生 SM4 主密钥（128 位）。
//
// 算法为 PBKDF2-HMAC-SM3：以国密 SM3 作为底层杂凑的 PBKDF2 密钥派生，
// 盐与迭代次数由库文件头持久化。主密钥从不落盘，仅存内存，使用后应清零。
func DeriveMasterKey(masterPassword string, salt []byte, iterations int) ([]byte, error) {
	if len(salt) != KDFSaltBytes {
		return nil, fmt.Errorf("crypto: 盐长度必须为 %d 字节，实际 %d", KDFSaltBytes, len(salt))
	}
	if iterations < 1 {
		return nil, fmt.Errorf("crypto: 迭代次数必须为正数")
	}
	// PBKDF2 输出 32 字节（SM3 摘要长度），取前 16 字节作为 SM4 主密钥。
	derived := pbkdf2.Key([]byte(masterPassword), salt, iterations, 32, func() hash.Hash { return sm3.New() })
	mk := make([]byte, MasterKeyBytes)
	copy(mk, derived)
	// 派生过程的敏感中间值立即清零。
	clear(derived)
	return mk, nil
}

// NewSalt 生成库文件专用的随机盐。
func NewSalt() ([]byte, error) {
	return randomBytes(KDFSaltBytes)
}

// NewEntryID 生成条目唯一标识（同时用作 SM4-GCM 的 AAD）。
func NewEntryID() ([16]byte, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, fmt.Errorf("crypto: 生成条目 ID 失败: %w", err)
	}
	return id, nil
}

// VerifySM3 计算 SM3 摘要（供测试向量与完整性场景使用）。
func VerifySM3(data []byte) [32]byte {
	return sm3.Sum(data)
}

// HMACSM3 计算 HMAC-SM3（SM3 的 HMAC 构造）。
func HMACSM3(key, data []byte) []byte {
	mac := hmac.New(sm3.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("crypto: 安全随机数生成失败: %w", err)
	}
	return b, nil
}
