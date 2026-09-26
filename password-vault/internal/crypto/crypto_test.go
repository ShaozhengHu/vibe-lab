package crypto

import "testing"

// 本文件为加密核心的测试脚手架。
// 第 2 阶段将补充：SM3/SM4/SM2 国标测试向量（GB/T 32905/32907/32918 标准示例）、
// KDF 正确性与耗时、SM4-GCM 加解密往返、密文篡改检测等用例。
// 验收要求见 docs/acceptance-checklist.md。

func TestFormatConstants(t *testing.T) {
	// 这些常量是库文件格式与加密参数的基础，修改必须同步更新文件头格式与兼容策略。
	if KDFIterations < 100000 {
		t.Fatalf("KDF 迭代次数过低: %d（要求不低于 10 万）", KDFIterations)
	}
	if KDFSaltBytes < 16 {
		t.Fatalf("随机盐过短: %d（要求至少 16 字节）", KDFSaltBytes)
	}
	if MasterKeyBytes != 16 {
		t.Fatalf("SM4 主密钥必须为 16 字节: %d", MasterKeyBytes)
	}
	if DataKeyBytes != 16 {
		t.Fatalf("数据密钥必须为 16 字节: %d", DataKeyBytes)
	}
	if IVBytes != 12 {
		t.Fatalf("SM4-GCM 初始向量必须为 12 字节: %d", IVBytes)
	}
	if TagBytes != 16 {
		t.Fatalf("SM4-GCM 认证标签必须为 16 字节: %d", TagBytes)
	}
}
