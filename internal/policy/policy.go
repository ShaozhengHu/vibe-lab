// Package policy 提供主密码强度策略，供 CLI 与 GUI 共用，
// 对齐等保 2.0 身份鉴别中对口令复杂度的要求。
package policy

import "errors"

// ErrTooShort 主密码长度不足。
var ErrTooShort = errors.New("主密码长度至少 12 位")

// ErrWeak 主密码字符组合不足：需包含大写字母、小写字母、数字、特殊符号中的至少三类。
var ErrWeak = errors.New("主密码需包含大写、小写、数字、符号中的至少三类")

// CheckPassword 校验主密码强度：长度 ≥ 12 位，且四类字符（大写/小写/数字/符号）
// 至少出现三类。返回 nil 表示通过。
func CheckPassword(p string) error {
	if len(p) < 12 {
		return ErrTooShort
	}
	classes := 0
	for _, r := range p {
		switch {
		case 'a' <= r && r <= 'z':
			classes |= 1
		case 'A' <= r && r <= 'Z':
			classes |= 2
		case '0' <= r && r <= '9':
			classes |= 4
		default:
			classes |= 8
		}
		if popcount(classes) >= 3 {
			return nil
		}
	}
	return ErrWeak
}

func popcount(b int) int {
	c := 0
	for b != 0 {
		b &= b - 1
		c++
	}
	return c
}
