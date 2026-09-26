// Package gui 提供桌面 GUI 的后端服务层：桥接 Wails 前端与加密核心
// （internal/crypto / internal/storage）。服务实例持有解锁后的内存状态，
// 锁定即清空；明文仅存在于解锁期间的内存。
package gui

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"password-vault/internal/crypto"
	"password-vault/internal/policy"
	"password-vault/internal/storage"
)

const (
	defaultDirName  = ".password-vault"
	defaultFileName = "vault.vault"

	// 解锁失败退避：连续失败达到 backoffStart 次后进入等待，
	// 等待时长从 2 秒起每次翻倍，上限 backoffCap 秒（等保"登录失败处理"）。
	backoffStart = 3
	backoffCap   = 60
)

// Service 是绑定到 Wails 前端的后端服务。
// 方法均为前端可调用（导出、可 JSON 序列化返回值）。
type Service struct {
	ctx context.Context
	path string

	// 解锁后的内存状态；Lock 时全部清空。
	vault   *storage.VaultFile
	mk      []byte
	entries map[[16]byte]*storage.Entry // 明文缓存（不包含内部验证条目）

	// 解锁失败计数与退避截止时间（进程内有效；重启后清零，
	// 用于抵御同一会话内的暴力尝试）。
	failCount int
	lockUntil time.Time

	// audit 本地审计日志（与库文件同目录，见 audit.go）。
	audit *auditLogger

	// setClipboard 可替换以便测试；默认走 Wails 运行时剪贴板。
	setClipboard func(ctx context.Context, text string) error
}

// NewService 构造服务，库文件使用默认路径（用户主目录/.password-vault/vault.vault）。
func NewService() *Service {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}
	return &Service{
		ctx:          context.Background(),
		path:         filepath.Join(home, defaultDirName, defaultFileName),
		audit:        newAuditLogger(filepath.Join(home, defaultDirName)),
		setClipboard: runtime.ClipboardSetText,
	}
}

// OnStartup 由 Wails 在应用启动时调用，保存运行时上下文。
func (s *Service) OnStartup(ctx context.Context) {
	s.ctx = ctx
}

// OnShutdown 由 Wails 在应用退出时调用，清空内存中的密钥与明文。
func (s *Service) OnShutdown(_ context.Context) {
	s.Lock()
}

// ---------- 窗口尺寸 ----------

// SetAuthWindow 将窗口缩为登录/创建小框并居中（类似微信/飞书登录窗口的形态）。
func (s *Service) SetAuthWindow() {
	runtime.WindowSetSize(s.ctx, 380, 540)
	runtime.WindowCenter(s.ctx)
}

// SetMainWindow 将窗口恢复为主界面尺寸并居中。
func (s *Service) SetMainWindow() {
	runtime.WindowSetSize(s.ctx, 920, 620)
	runtime.WindowCenter(s.ctx)
}

// ---------- 窗口拖动（无边框自绘标题栏） ----------
// Wails 无边框窗口不支持 CSS -webkit-app-region 拖拽，故由前端在标题栏
// 按下鼠标时启动拖动，移动过程中按增量调用本方法移动窗口。

var (
	dragBaseX, dragBaseY int // 开始拖动时的窗口位置（逻辑像素）
)

// StartDrag 记录拖动基准位置，由前端在标题栏 mousedown 时调用。
func (s *Service) StartDrag() {
	dragBaseX, dragBaseY = runtime.WindowGetPosition(s.ctx)
}

// DragBy 按相对位移移动窗口（每次调用在基准上累加，避免丢帧导致漂移）。
func (s *Service) DragBy(dx, dy int) {
	dragBaseX += dx
	dragBaseY += dy
	runtime.WindowSetPosition(s.ctx, dragBaseX, dragBaseY)
}

// ---------- 状态查询 ----------

// InitStateResult 描述启动时的库文件状态。
type InitStateResult struct {
	VaultExists bool   `json:"vaultExists"`
	Path        string `json:"path"`
}

// InitState 返回默认库文件是否存在（存在则进入解锁，否则引导创建）。
func (s *Service) InitState() (InitStateResult, error) {
	_, err := os.Stat(s.path)
	exists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return InitStateResult{}, fmt.Errorf("检查库文件失败: %w", err)
	}
	return InitStateResult{VaultExists: exists, Path: s.path}, nil
}

// ---------- 创建与解锁 ----------

// CreateVault 在默认路径创建新库并写入内部验证条目。
func (s *Service) CreateVault(password string) (err error) {
	defer func() {
		if err != nil {
			s.audit.Log("创建保险箱", "失败")
		} else {
			s.audit.Log("创建保险箱", "成功")
		}
	}()
	if err = policy.CheckPassword(password); err != nil {
		return err
	}
	if s.isUnlocked() {
		return errors.New("当前已解锁，请先锁定")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("创建库目录失败: %w", err)
	}

	v, err := storage.NewVault()
	if err != nil {
		return err
	}
	mk, err := crypto.DeriveMasterKey(password, v.Salt, v.Iterations)
	if err != nil {
		return err
	}
	defer clear(mk)

	verifySecret, err := crypto.NewSalt()
	if err != nil {
		return err
	}
	ve := &storage.Entry{
		Title:     "vault-verify",
		Username:  "system",
		Password:  hex.EncodeToString(verifySecret),
		CreatedAt: time.Now().Unix(),
		Internal:  true,
	}
	plain, err := ve.Encode()
	if err != nil {
		return err
	}
	id, err := crypto.NewEntryID()
	if err != nil {
		return err
	}
	se, err := crypto.SealEntry(mk, plain, id)
	if err != nil {
		return err
	}
	v.Entries = append(v.Entries, *se)

	return v.WriteFile(s.path)
}

// Unlock 解锁默认库文件并载入全部凭据明文。
// 连续失败达到阈值后进入指数退避：退避期间即使密码正确也拒绝尝试。
func (s *Service) Unlock(password string) (views []EntryView, err error) {
	defer func() {
		if err != nil {
			s.audit.Log("解锁", "失败")
		} else {
			s.audit.Log("解锁", "成功")
		}
	}()
	if !s.lockUntil.IsZero() {
		if wait := time.Until(s.lockUntil); wait > 0 {
			return nil, fmt.Errorf("尝试次数过多，请 %d 秒后再试", int(wait.Seconds())+1)
		}
		s.lockUntil = time.Time{}
	}
	v, err := storage.ReadFile(s.path)
	if err != nil {
		return nil, errors.New("无法读取库文件，或文件已损坏")
	}
	mk, err := crypto.DeriveMasterKey(password, v.Salt, v.Iterations)
	if err != nil {
		return nil, errors.New("主密码错误，或库文件已损坏")
	}
	if err := verifyMasterKey(mk, v); err != nil {
		clear(mk)
		s.recordFail()
		return nil, errors.New("主密码错误，或库文件已损坏")
	}
	s.recordSuccess()

	s.vault = v
	s.mk = mk
	s.entries = make(map[[16]byte]*storage.Entry)
	for i := range v.Entries {
		se := &v.Entries[i]
		plain, err := crypto.OpenEntry(mk, se)
		if err != nil {
			continue // 单条无法解密：跳过，不中断解锁
		}
		e, err := storage.DecodeEntry(plain)
		clear(plain)
		if err != nil || e.Internal {
			continue
		}
		s.entries[se.ID] = e
	}
	return s.listLocked(false), nil
}

// recordFail 记录一次解锁失败；达到阈值后设置退避截止时间
// （第 3 次起等待 2 秒，之后每次翻倍，上限 60 秒）。
func (s *Service) recordFail() {
	s.failCount++
	if s.failCount < backoffStart {
		return
	}
	wait := 1 << uint(s.failCount-backoffStart+1) // 3 次→2s、4 次→4s、5 次→8s…
	if wait > backoffCap {
		wait = backoffCap
	}
	s.lockUntil = time.Now().Add(time.Duration(wait) * time.Second)
}

// recordSuccess 解锁成功：清零失败计数与退避状态。
func (s *Service) recordSuccess() {
	s.failCount = 0
	s.lockUntil = time.Time{}
}

// verifyMasterKey 通过内部验证条目校验主密码（与 CLI 一致的口径）。
func verifyMasterKey(mk []byte, v *storage.VaultFile) error {
	for i := range v.Entries {
		plain, err := crypto.OpenEntry(mk, &v.Entries[i])
		if err != nil {
			continue
		}
		e, err := storage.DecodeEntry(plain)
		clear(plain)
		if err != nil {
			continue
		}
		if e.Internal {
			return nil
		}
	}
	return errors.New("主密码错误，或库文件已损坏")
}

// ---------- 凭据操作 ----------

// EntryView 是列表条目（不含密码明文）。Deleted 标记回收站状态。
type EntryView struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Username  string `json:"username"`
	Address   string `json:"address"`
	CreatedAt int64  `json:"createdAt"`
	Deleted   bool   `json:"deleted"`
}

// EntryDetail 是详情（含密码明文，仅解锁期间可取得）。
type EntryDetail struct {
	EntryView
	Password string `json:"password"`
	Port     int    `json:"port"`
	Note     string `json:"note"`
}

// List 返回凭据列表（按创建时间倒序，不含回收站条目）。
func (s *Service) List() ([]EntryView, error) {
	if !s.isUnlocked() {
		return nil, errors.New("尚未解锁")
	}
	return s.listLocked(false), nil
}

// ListDeleted 返回回收站条目列表（软删除但尚未彻底删除的凭据）。
func (s *Service) ListDeleted() ([]EntryView, error) {
	if !s.isUnlocked() {
		return nil, errors.New("尚未解锁")
	}
	return s.listLocked(true), nil
}

func (s *Service) listLocked(deletedOnly bool) []EntryView {
	out := make([]EntryView, 0, len(s.entries))
	for id, e := range s.entries {
		if e.Deleted != deletedOnly {
			continue
		}
		out = append(out, EntryView{
			ID:        hex.EncodeToString(id[:]),
			Title:     e.Title,
			Username:  e.Username,
			Address:   e.Address,
			CreatedAt: e.CreatedAt,
			Deleted:   e.Deleted,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

// Add 新增一条凭据（标题/账号/密码），其余字段留空。
// 完整字段（含地址/端口/备注）请使用 AddFull。
func (s *Service) Add(title, username, password string) (EntryView, error) {
	return s.AddFull(title, username, password, "", 0, "")
}

// AddFull 新增一条凭据并写回库文件。address（IP/域名/URL）、port（端口）、
// note（备注）均为可选字段，留空不影响保存。
func (s *Service) AddFull(title, username, password, address string, port int, note string) (view EntryView, err error) {
	defer func() {
		if err != nil {
			s.audit.Log("新增凭据", "失败")
		} else {
			s.audit.Log("新增凭据", "成功")
		}
	}()
	if !s.isUnlocked() {
		return EntryView{}, errors.New("尚未解锁")
	}
	e, err := storage.NewEntry(title, username, password)
	if err != nil {
		return EntryView{}, err
	}
	e.Address = address
	e.Port = port
	e.Note = note
	plain, err := e.Encode()
	if err != nil {
		return EntryView{}, err
	}
	id, err := crypto.NewEntryID()
	if err != nil {
		return EntryView{}, err
	}
	se, err := crypto.SealEntry(s.mk, plain, id)
	if err != nil {
		return EntryView{}, err
	}
	s.vault.Entries = append(s.vault.Entries, *se)
	if err := s.vault.WriteFile(s.path); err != nil {
		return EntryView{}, fmt.Errorf("写入库文件失败: %w", err)
	}
	s.entries[id] = e
	return EntryView{
		ID:        hex.EncodeToString(id[:]),
		Title:     e.Title,
		Username:  e.Username,
		Address:   e.Address,
		CreatedAt: e.CreatedAt,
	}, nil
}

// Update 编辑一条凭据的全部字段并写回库文件。内部验证条目不可编辑；
// 创建时间与回收站状态保持不变。
func (s *Service) Update(idHex, title, username, password, address string, port int, note string) (view EntryView, err error) {
	defer func() {
		if err != nil {
			s.audit.Log("编辑凭据", "失败")
		} else {
			s.audit.Log("编辑凭据", "成功")
		}
	}()
	if !s.isUnlocked() {
		return EntryView{}, errors.New("尚未解锁")
	}
	id, err := parseID(idHex)
	if err != nil {
		return EntryView{}, err
	}
	old, ok := s.entries[id]
	if !ok {
		return EntryView{}, errors.New("未找到该凭据")
	}
	if old.Internal {
		return EntryView{}, errors.New("系统条目不可编辑")
	}
	ne, err := storage.NewEntry(title, username, password)
	if err != nil {
		return EntryView{}, err
	}
	ne.Address = address
	ne.Port = port
	ne.Note = note
	ne.CreatedAt = old.CreatedAt // 创建时间不变
	ne.Deleted = old.Deleted     // 回收站状态不变
	if err := s.resealEntry(id, ne); err != nil {
		return EntryView{}, fmt.Errorf("编辑失败: %w", err)
	}
	s.entries[id] = ne
	return EntryView{
		ID:        hex.EncodeToString(id[:]),
		Title:     ne.Title,
		Username:  ne.Username,
		Address:   ne.Address,
		CreatedAt: ne.CreatedAt,
		Deleted:   ne.Deleted,
	}, nil
}

// Get 按 32 位十六进制 ID 返回凭据详情（含密码明文）。
func (s *Service) Get(idHex string) (EntryDetail, error) {
	if !s.isUnlocked() {
		return EntryDetail{}, errors.New("尚未解锁")
	}
	id, err := parseID(idHex)
	if err != nil {
		return EntryDetail{}, err
	}
	e, ok := s.entries[id]
	if !ok {
		return EntryDetail{}, errors.New("未找到该凭据")
	}
	return EntryDetail{
		EntryView: EntryView{
			ID:        hex.EncodeToString(id[:]),
			Title:     e.Title,
			Username:  e.Username,
			Address:   e.Address,
			CreatedAt: e.CreatedAt,
			Deleted:   e.Deleted,
		},
		Password: e.Password,
		Port:     e.Port,
		Note:     e.Note,
	}, nil
}

// CopyPassword 将指定凭据的密码复制到剪贴板，30 秒后自动清空。
func (s *Service) CopyPassword(idHex string) (err error) {
	defer func() {
		if err != nil {
			s.audit.Log("复制密码", "失败")
		} else {
			s.audit.Log("复制密码", "成功")
		}
	}()
	d, err := s.Get(idHex)
	if err != nil {
		return err
	}
	if s.setClipboard == nil {
		return errors.New("剪贴板不可用")
	}
	if err := s.setClipboard(s.ctx, d.Password); err != nil {
		return fmt.Errorf("写入剪贴板失败: %w", err)
	}
	// 30 秒后自动清空，避免密码残留（与界面提示一致）。
	time.AfterFunc(30*time.Second, func() {
		_ = s.setClipboard(s.ctx, "")
	})
	return nil
}

// resealEntry 用新随机数重新密封指定条目（改变明文后调用）并原子写回库文件。
func (s *Service) resealEntry(id [16]byte, e *storage.Entry) error {
	plain, err := e.Encode()
	if err != nil {
		return err
	}
	se, err := crypto.SealEntry(s.mk, plain, id)
	if err != nil {
		return err
	}
	for i := range s.vault.Entries {
		if s.vault.Entries[i].ID == id {
			s.vault.Entries[i] = *se
			return s.vault.WriteFile(s.path)
		}
	}
	return errors.New("库文件中未找到该凭据")
}

// Remove 将凭据移入回收站（软删除）：标记 Deleted 并重新密封写回。
// 条目仍在库中可恢复；彻底删除请用 Purge（触发密文覆盖）。
// 内部验证条目不可删除。
func (s *Service) Remove(idHex string) (err error) {
	defer func() {
		if err != nil {
			s.audit.Log("移入回收站", "失败")
		} else {
			s.audit.Log("移入回收站", "成功")
		}
	}()
	if !s.isUnlocked() {
		return errors.New("尚未解锁")
	}
	id, err := parseID(idHex)
	if err != nil {
		return err
	}
	e, ok := s.entries[id]
	if !ok {
		return errors.New("未找到该凭据")
	}
	if e.Internal {
		return errors.New("系统条目不可删除")
	}
	if e.Deleted {
		return errors.New("该凭据已在回收站")
	}
	e.Deleted = true
	if err := s.resealEntry(id, e); err != nil {
		e.Deleted = false // 写盘失败：回滚内存标记
		return fmt.Errorf("移入回收站失败: %w", err)
	}
	return nil
}

// Restore 从回收站恢复一条凭据（清除 Deleted 标记并重新密封写回）。
func (s *Service) Restore(idHex string) (err error) {
	defer func() {
		if err != nil {
			s.audit.Log("恢复凭据", "失败")
		} else {
			s.audit.Log("恢复凭据", "成功")
		}
	}()
	if !s.isUnlocked() {
		return errors.New("尚未解锁")
	}
	id, err := parseID(idHex)
	if err != nil {
		return err
	}
	e, ok := s.entries[id]
	if !ok {
		return errors.New("未找到该凭据")
	}
	if !e.Deleted {
		return errors.New("该凭据不在回收站")
	}
	e.Deleted = false
	if err := s.resealEntry(id, e); err != nil {
		e.Deleted = true // 写盘失败：回滚内存标记
		return fmt.Errorf("恢复凭据失败: %w", err)
	}
	return nil
}

// Purge 彻底删除回收站中的凭据：先从库文件移除，再以随机数据覆盖旧库文件
// 抹除密文残留，最后原子写入新库（等保"剩余信息保护"）。
func (s *Service) Purge(idHex string) (err error) {
	defer func() {
		if err != nil {
			s.audit.Log("彻底删除", "失败")
		} else {
			s.audit.Log("彻底删除", "成功")
		}
	}()
	if !s.isUnlocked() {
		return errors.New("尚未解锁")
	}
	id, err := parseID(idHex)
	if err != nil {
		return err
	}
	e, ok := s.entries[id]
	if !ok {
		return errors.New("未找到该凭据")
	}
	if !e.Deleted {
		return errors.New("请先将凭据移入回收站")
	}
	idx := -1
	for i := range s.vault.Entries {
		if s.vault.Entries[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return errors.New("库文件中未找到该凭据")
	}
	s.vault.Entries = append(s.vault.Entries[:idx], s.vault.Entries[idx+1:]...)
	delete(s.entries, id)
	if err := storage.ReplaceWithCover(s.path, s.vault); err != nil {
		return fmt.Errorf("彻底删除失败: %w", err)
	}
	return nil
}

// Backup 将库文件整体备份为带完整性校验的密文副本（用户选择保存位置）。
// 备份内容全部为密文；恢复时以 SM3 摘要校验完整性。
func (s *Service) Backup() (err error) {
	defer func() {
		if err != nil {
			s.audit.Log("备份", "失败")
		} else {
			s.audit.Log("备份", "成功")
		}
	}()
	if !s.isUnlocked() {
		return errors.New("尚未解锁")
	}
	name := "password-vault-backup-" + time.Now().Format("20060102-150405") + ".vault"
	path, err := runtime.SaveFileDialog(s.ctx, runtime.SaveDialogOptions{
		Title:           "选择备份保存位置",
		DefaultFilename: name,
		Filters:         []runtime.FileFilter{{DisplayName: "密码保险箱备份 (*.vault)", Pattern: "*.vault"}},
	})
	if err != nil {
		return fmt.Errorf("打开保存对话框失败: %w", err)
	}
	if path == "" {
		return errors.New("已取消备份")
	}
	if err := storage.WriteBackup(s.path, path); err != nil {
		return fmt.Errorf("备份失败: %w", err)
	}
	return nil
}

// RestoreFromBackup 从备份文件恢复库（用户选择备份文件）：先完整校验备份
// 完整性（魔数/版本/SM3 摘要/库格式），全部通过才原子替换当前库。
// 恢复后立即清空当前会话，强制重新解锁。
func (s *Service) RestoreFromBackup() (err error) {
	defer func() {
		if err != nil {
			s.audit.Log("恢复备份", "失败")
		} else {
			s.audit.Log("恢复备份", "成功")
		}
	}()
	if !s.isUnlocked() {
		return errors.New("尚未解锁")
	}
	path, err := runtime.OpenFileDialog(s.ctx, runtime.OpenDialogOptions{
		Title:   "选择要恢复的备份文件",
		Filters: []runtime.FileFilter{{DisplayName: "密码保险箱备份 (*.vault)", Pattern: "*.vault"}},
	})
	if err != nil {
		return fmt.Errorf("打开文件对话框失败: %w", err)
	}
	if path == "" {
		return errors.New("已取消恢复")
	}
	if err := storage.RestoreBackup(path, s.path); err != nil {
		return fmt.Errorf("恢复失败: %w", err)
	}
	// 库文件已替换：清空会话状态（不额外记"锁定"，恢复本身已在审计）。
	s.clearSession()
	return nil
}

// ChangeMasterPassword 修改主密码（设置入口）。
// 流程：校验当前主密码 → 生成新盐并派生新主密钥 → 信封重封装全部条目
// （仅重封数据密钥，不重加密凭据内容）→ 原子写回 → 内存切换为新密钥，会话保持。
// 等保"修改口令前验证原口令"：当前密码错误时拒绝，审计记录成败。
func (s *Service) ChangeMasterPassword(oldPassword, newPassword string) (err error) {
	defer func() {
		if err != nil {
			s.audit.Log("修改主密码", "失败")
		} else {
			s.audit.Log("修改主密码", "成功")
		}
	}()
	if !s.isUnlocked() {
		return errors.New("尚未解锁")
	}
	if err := policy.CheckPassword(newPassword); err != nil {
		return err
	}
	// 验证当前主密码（独立派生，不依赖内存密钥——防止仅凭会话状态放行）。
	candidate, err := crypto.DeriveMasterKey(oldPassword, s.vault.Salt, s.vault.Iterations)
	if err != nil {
		return err
	}
	defer clear(candidate)
	if err := verifyMasterKey(candidate, s.vault); err != nil {
		return errors.New("当前主密码错误")
	}
	// 新盐 + 新主密钥。
	newSalt, err := crypto.NewSalt()
	if err != nil {
		return err
	}
	newMk, err := crypto.DeriveMasterKey(newPassword, newSalt, s.vault.Iterations)
	if err != nil {
		return err
	}
	defer func() {
		if newMk != nil {
			clear(newMk)
		}
	}()
	// 重封装全部条目（条目 ID 不变，AAD 不变）。
	sealed := make([]crypto.SealedEntry, 0, len(s.vault.Entries))
	for i := range s.vault.Entries {
		se := &s.vault.Entries[i]
		plain, err := crypto.OpenEntry(s.mk, se)
		if err != nil {
			return fmt.Errorf("条目解密失败（库文件可能损坏）: %w", err)
		}
		nse, err := crypto.SealEntry(newMk, plain, se.ID)
		clear(plain)
		if err != nil {
			return err
		}
		sealed = append(sealed, *nse)
	}
	s.vault.Salt = newSalt
	s.vault.Entries = sealed
	if err := s.vault.WriteFile(s.path); err != nil {
		return fmt.Errorf("写入库文件失败: %w", err)
	}
	// 内存切换为新主密钥；newMk 所有权移交后置 nil，避免 defer 二次清零。
	clear(s.mk)
	s.mk = newMk
	newMk = nil
	return nil
}

// clearSession 清空解锁后的内存状态（与 Lock 相同，但不再写审计）。
func (s *Service) clearSession() {
	if s.mk != nil {
		clear(s.mk)
	}
	s.mk = nil
	s.vault = nil
	s.entries = nil
}

// Lock 锁定：清空内存中的密钥、库引用与明文缓存。
func (s *Service) Lock() {
	s.audit.Log("锁定", "成功")
	s.clearSession()
}

func (s *Service) isUnlocked() bool {
	return s.vault != nil && s.mk != nil && s.entries != nil
}

func parseID(idHex string) ([16]byte, error) {
	var id [16]byte
	b, err := hex.DecodeString(idHex)
	if err != nil || len(b) != 16 {
		return id, errors.New("无效的凭据 ID")
	}
	copy(id[:], b)
	return id, nil
}
