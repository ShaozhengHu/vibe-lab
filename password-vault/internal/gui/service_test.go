package gui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestService 构造使用临时库路径与假剪贴板的服务。
func newTestService(t *testing.T) (*Service, *[]string) {
	t.Helper()
	var copied []string
	dir := t.TempDir()
	s := &Service{
		ctx:   context.Background(),
		path:  filepath.Join(dir, "vault.vault"),
		audit: newAuditLogger(dir),
		setClipboard: func(_ context.Context, text string) error {
			copied = append(copied, text)
			return nil
		},
	}
	return s, &copied
}

func TestCreateUnlockFlow(t *testing.T) {
	s, _ := newTestService(t)

	// 短密码拒绝。
	if err := s.CreateVault("short"); err == nil {
		t.Fatal("短主密码必须被拒绝")
	}
	if err := s.CreateVault("正确主密码Abc123!"); err != nil {
		t.Fatalf("创建库失败: %v", err)
	}
	// 错误密码解锁失败，且不泄露细节。
	if _, err := s.Unlock("错误主密码Abc123!"); err == nil {
		t.Fatal("错误主密码必须解锁失败")
	}
	// 正确密码解锁成功，初始无凭据。
	views, err := s.Unlock("正确主密码Abc123!")
	if err != nil {
		t.Fatalf("解锁失败: %v", err)
	}
	if len(views) != 0 {
		t.Fatalf("新库应无凭据，实际 %d 条", len(views))
	}
}

func TestAddGetCopyLock(t *testing.T) {
	s, copied := newTestService(t)
	if err := s.CreateVault("正确主密码Abc123!"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unlock("正确主密码Abc123!"); err != nil {
		t.Fatal(err)
	}

	v, err := s.Add("生产数据库", "dbadmin", "P@ssw0rd#2026")
	if err != nil {
		t.Fatalf("Add 失败: %v", err)
	}
	views, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].ID != v.ID {
		t.Fatalf("列表与新增不一致: %+v", views)
	}

	d, err := s.Get(v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Password != "P@ssw0rd#2026" || d.Username != "dbadmin" {
		t.Fatalf("详情不一致: %+v", d)
	}

	if err := s.CopyPassword(v.ID); err != nil {
		t.Fatalf("复制失败: %v", err)
	}
	if len(*copied) != 1 || (*copied)[0] != "P@ssw0rd#2026" {
		t.Fatalf("剪贴板内容不正确: %v", *copied)
	}

	// 无效 ID 拒绝。
	if _, err := s.Get("zzzz"); err == nil {
		t.Fatal("无效 ID 必须报错")
	}

	// 锁定后必须拒绝访问。
	s.Lock()
	if _, err := s.Get(v.ID); err == nil {
		t.Fatal("锁定后 Get 必须失败")
	}
	if _, err := s.Add("a", "b", "c"); err == nil {
		t.Fatal("锁定后 Add 必须失败")
	}
}


// TestAddFullUpdate 验证扩展字段（地址/端口/备注）的新增、展示与编辑。
func TestAddFullUpdate(t *testing.T) {
	s, _ := newTestService(t)
	if err := s.CreateVault("正确主密码Abc123!"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unlock("正确主密码Abc123!"); err != nil {
		t.Fatal(err)
	}

	// AddFull：完整字段写入。
	v, err := s.AddFull("生产数据库", "dbadmin", "P@ssw0rd#2026", "192.168.1.10", 3306, "生产环境")
	if err != nil {
		t.Fatalf("AddFull 失败: %v", err)
	}
	if v.Address != "192.168.1.10" {
		t.Fatalf("列表地址不一致: %+v", v)
	}

	d, err := s.Get(v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Address != "192.168.1.10" || d.Port != 3306 || d.Note != "生产环境" {
		t.Fatalf("详情字段不一致: %+v", d)
	}

	// Update：修改地址/端口/备注与密码，创建时间保持。
	u, err := s.Update(v.ID, "生产数据库", "dbadmin", "New@Passw0rd", "10.0.0.5", 3307, "迁移至新网段")
	if err != nil {
		t.Fatalf("Update 失败: %v", err)
	}
	d2, err := s.Get(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Address != "10.0.0.5" || d2.Port != 3307 || d2.Note != "迁移至新网段" || d2.Password != "New@Passw0rd" {
		t.Fatalf("更新后详情不正确: %+v", d2)
	}
	if d2.CreatedAt != d.CreatedAt {
		t.Fatalf("更新不应改变创建时间: %d vs %d", d2.CreatedAt, d.CreatedAt)
	}

	// 未知 ID 更新必须报错。
	if _, err := s.Update("zzzz", "t", "u", "p@A1", "", 0, ""); err == nil {
		t.Fatal("未知 ID 更新必须报错")
	}

	// 旧库兼容：三参 Add 产生的条目扩展字段为空。
	v2, err := s.Add("VPN网关", "vpn", "Vpn@2026")
	if err != nil {
		t.Fatal(err)
	}
	d3, err := s.Get(v2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d3.Address != "" || d3.Port != 0 || d3.Note != "" {
		t.Fatalf("三参 Add 的扩展字段应为空: %+v", d3)
	}
}


// TestChangeMasterPassword 验证修改主密码：原密码验证、新密码强度、
// 改后旧密码失效、新密码可解锁且数据完整。
func TestChangeMasterPassword(t *testing.T) {
	s, _ := newTestService(t)
	if err := s.CreateVault("OldPassw0rd!234"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unlock("OldPassw0rd!234"); err != nil {
		t.Fatal(err)
	}
	v, err := s.AddFull("生产数据库", "dbadmin", "P@ssw0rd#2026", "192.168.1.10", 3306, "生产环境")
	if err != nil {
		t.Fatal(err)
	}

	// 当前密码错误：拒绝。
	if err := s.ChangeMasterPassword("WrongPassw0rd!", "NewPassw0rd!234"); err == nil {
		t.Fatal("当前主密码错误必须被拒绝")
	}
	// 新密码过弱：拒绝。
	if err := s.ChangeMasterPassword("OldPassw0rd!234", "short"); err == nil {
		t.Fatal("弱新主密码必须被拒绝")
	}
	// 成功修改。
	if err := s.ChangeMasterPassword("OldPassw0rd!234", "NewPassw0rd!234"); err != nil {
		t.Fatalf("修改主密码失败: %v", err)
	}
	// 会话保持解锁，内存数据仍可读。
	d, err := s.Get(v.ID)
	if err != nil || d.Password != "P@ssw0rd#2026" {
		t.Fatalf("修改后会话内数据异常: %+v err=%v", d, err)
	}

	// 锁定后旧密码必须失败。
	s.Lock()
	if _, err := s.Unlock("OldPassw0rd!234"); err == nil {
		t.Fatal("旧主密码必须失效")
	}
	// 新密码解锁成功且数据完整。
	views, err := s.Unlock("NewPassw0rd!234")
	if err != nil {
		t.Fatalf("新主密码解锁失败: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("解锁后凭据数不对: %d", len(views))
	}
	d2, err := s.Get(views[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Password != "P@ssw0rd#2026" || d2.Address != "192.168.1.10" || d2.Port != 3306 {
		t.Fatalf("改密后数据不完整: %+v", d2)
	}
}

func TestTrashFlow(t *testing.T) {
	s, _ := newTestService(t)
	if err := s.CreateVault("正确主密码Abc123!"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unlock("正确主密码Abc123!"); err != nil {
		t.Fatal(err)
	}
	a, err := s.Add("A系统", "u-a", "passA@123")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Add("B系统", "u-b", "passB@123")
	if err != nil {
		t.Fatal(err)
	}

	// 软删除：进入回收站，普通列表不再显示，但数据仍在（可恢复、可读取）。
	if err := s.Remove(a.ID); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	views, _ := s.List()
	if len(views) != 1 || views[0].ID != b.ID {
		t.Fatalf("软删除后列表不正确: %+v", views)
	}
	deleted, _ := s.ListDeleted()
	if len(deleted) != 1 || deleted[0].ID != a.ID {
		t.Fatalf("回收站列表不正确: %+v", deleted)
	}
	if _, err := s.Get(a.ID); err != nil {
		t.Fatalf("回收站条目应仍可读取（未彻底删除）: %v", err)
	}

	// 恢复：回到普通列表。
	if err := s.Restore(a.ID); err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	views, _ = s.List()
	if len(views) != 2 {
		t.Fatalf("恢复后列表应为 2 条: %+v", views)
	}
	if d, _ := s.ListDeleted(); len(d) != 0 {
		t.Fatalf("恢复后回收站应为空: %+v", d)
	}

	// 再次删除后彻底删除：数据真正移除。
	if err := s.Remove(a.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Purge(a.ID); err != nil {
		t.Fatalf("彻底删除失败: %v", err)
	}
	if d, _ := s.ListDeleted(); len(d) != 0 {
		t.Fatalf("彻底删除后回收站应为空: %+v", d)
	}
	if _, err := s.Get(a.ID); err == nil {
		t.Fatal("彻底删除后 Get 必须失败")
	}

	// 软删除状态持久化：重新解锁后回收站条目仍在。
	c, _ := s.Add("C系统", "u-c", "passC@123")
	if err := s.Remove(c.ID); err != nil {
		t.Fatal(err)
	}
	s.Lock()
	if _, err := s.Unlock("正确主密码Abc123!"); err != nil {
		t.Fatal(err)
	}
	views, _ = s.List()
	if len(views) != 1 || views[0].ID != b.ID {
		t.Fatalf("重新解锁后普通列表不正确: %+v", views)
	}
	deleted, _ = s.ListDeleted()
	if len(deleted) != 1 || deleted[0].ID != c.ID {
		t.Fatalf("重新解锁后回收站不一致: %+v", deleted)
	}
}

func TestCreateVaultPasswordPolicy(t *testing.T) {
	s, _ := newTestService(t)
	for _, weak := range []string{
		"abcdefghijkl",   // 仅小写
		"ABCDEFGHIJKL",   // 仅大写
		"123456789012",   // 仅数字
		"abcdefgh12345",  // 小写+数字两类
	} {
		if err := s.CreateVault(weak); err == nil {
			t.Fatalf("弱主密码必须被拒绝: %q", weak)
		}
	}
	if err := s.CreateVault("Abcdefgh12345"); err != nil { // 三类：大写+小写+数字
		t.Fatalf("三类字符组合应通过: %v", err)
	}
}

func TestPersistAcrossUnlock(t *testing.T) {
	s, _ := newTestService(t)
	if err := s.CreateVault("正确主密码Abc123!"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unlock("正确主密码Abc123!"); err != nil {
		t.Fatal(err)
	}
	v, err := s.Add("内网VPN", "vpn-remote", "vpn@2026")
	if err != nil {
		t.Fatal(err)
	}
	s.Lock()

	// 重新解锁后凭据仍在（验证写盘与读取）。
	views, err := s.Unlock("正确主密码Abc123!")
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].ID != v.ID {
		t.Fatalf("持久化不一致: %+v", views)
	}
	d, err := s.Get(v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Password != "vpn@2026" {
		t.Fatalf("密码不一致: %q", d.Password)
	}
}

func TestUnlockBackoff(t *testing.T) {
	s, _ := newTestService(t)
	if err := s.CreateVault("正确主密码Abc123!"); err != nil {
		t.Fatal(err)
	}

	// 前 2 次失败：正常报错，不进入退避。
	for i := 0; i < 2; i++ {
		if _, err := s.Unlock("错误主密码Abc123!"); err == nil {
			t.Fatal("错误密码必须解锁失败")
		}
	}
	// 第 3 次失败：进入退避。
	if _, err := s.Unlock("错误主密码Abc123!"); err == nil {
		t.Fatal("错误密码必须解锁失败")
	}
	// 退避期间：正确密码也会被拦截，且不泄露"密码正确"的信息。
	if _, err := s.Unlock("正确主密码Abc123!"); err == nil || !strings.Contains(err.Error(), "秒") {
		t.Fatalf("退避期间应拒绝任何尝试: %v", err)
	}

	// 退避期过后：正确密码解锁成功，计数重置。
	s.lockUntil = time.Now().Add(-time.Second)
	if _, err := s.Unlock("正确主密码Abc123!"); err != nil {
		t.Fatalf("退避结束后应能解锁: %v", err)
	}
	if s.failCount != 0 {
		t.Fatalf("解锁成功应清零失败计数，实际 %d", s.failCount)
	}
	// 退避状态已清除：再次错误密码不受退避拦截（仅普通报错）。
	if _, err := s.Unlock("错误主密码Abc123!"); err == nil || strings.Contains(err.Error(), "秒") {
		t.Fatalf("计数清零后不应再触发退避: %v", err)
	}
}

func TestAuditLog(t *testing.T) {
	s, _ := newTestService(t)
	if err := s.CreateVault("正确主密码Abc123!"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unlock("正确主密码Abc123!"); err != nil {
		t.Fatal(err)
	}
	v, err := s.Add("审计测试条目", "u", "SecretPass#2026")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CopyPassword(v.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(v.ID); err != nil {
		t.Fatal(err)
	}
	s.Lock()

	data, err := os.ReadFile(filepath.Join(filepath.Dir(s.path), "audit.log"))
	if err != nil {
		t.Fatalf("审计日志未生成: %v", err)
	}
	text := string(data)
	for _, want := range []string{"创建保险箱", "解锁", "新增凭据", "复制密码", "移入回收站", "锁定"} {
		if !strings.Contains(text, want) {
			t.Fatalf("审计日志缺少 %q 记录: %s", want, text)
		}
	}
	if strings.Contains(text, "SecretPass#2026") || strings.Contains(text, "审计测试条目") {
		t.Fatal("审计日志不得包含密码明文或凭据标题")
	}
}
