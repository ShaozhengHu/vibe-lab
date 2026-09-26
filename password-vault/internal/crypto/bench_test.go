package crypto

import (
	"bytes"
	"testing"
)

// BenchmarkDeriveMasterKey 记录真实迭代参数（KDFIterations）下单次派生耗时，
// 验收要求处于 0.1~0.5 秒量级（见 docs/acceptance-checklist.md 第 2 节）。
// 运行: go test -bench=BenchmarkDeriveMasterKey -benchtime=1x -run '^$'
func BenchmarkDeriveMasterKey(b *testing.B) {
	salt := bytes.Repeat([]byte{0x77}, KDFSaltBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mk, err := DeriveMasterKey("bench-主密码-123456!", salt, KDFIterations)
		if err != nil {
			b.Fatal(err)
		}
		clear(mk)
	}
}
