package policy

import "testing"

func TestCheckPassword(t *testing.T) {
	cases := []struct {
		name string
		pwd  string
		want error
	}{
		{"过短", "short1", ErrTooShort},
		{"刚好12位纯数字", "123456789012", ErrWeak},
		{"小写+数字两类", "abcdefghijkl1234", ErrWeak},
		{"大小写+数字三类", "Abcdefgh123456", nil},
		{"大小写+符号三类", "Abcdefgh!@#$%^", nil},
		{"四类齐全", "Abcd1234!@#$efgh", nil},
		{"16位含空格符号", "Abcdefghij 123456!", nil},
	}
	for _, c := range cases {
		got := CheckPassword(c.pwd)
		if (got == nil) != (c.want == nil) {
			t.Errorf("%s: CheckPassword(%q) = %v, want %v", c.name, c.pwd, got, c.want)
		}
	}
}
