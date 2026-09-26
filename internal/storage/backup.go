package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"password-vault/internal/crypto"
)

// 备份文件布局（全部小端序，固定头 54 字节 + 库文件密文）：
//
//	魔数     "PVLB"      4 字节
//	版本     uint16      2 字节
//	创建时间 int64       8 字节（Unix 秒）
//	数据长度 int64       8 字节（库文件密文总长）
//	SM3 摘要 [32]byte    32 字节（对库文件密文计算，防篡改/防损坏）
const (
	BackupMagic    = "PVLB"
	BackupVersion  = 1
	backupHeaderLen = 4 + 2 + 8 + 8 + 32
)

// WriteBackup 将库文件整体复制为带完整性校验的备份文件。
// 备份内容全部为密文，不包含任何明文；SM3 摘要用于恢复时识别
// 文件是否被篡改或损坏。
func WriteBackup(srcVaultPath, dstPath string) error {
	data, err := os.ReadFile(srcVaultPath)
	if err != nil {
		return fmt.Errorf("storage: 读取库文件失败: %w", err)
	}
	// 防御：拒绝备份非库文件（库文件本身应已通过本包校验）。
	if _, err := Read(bytes.NewReader(data)); err != nil {
		return fmt.Errorf("storage: 库文件校验失败，拒绝备份: %w", err)
	}

	var hdr [backupHeaderLen]byte
	copy(hdr[0:4], BackupMagic)
	binary.LittleEndian.PutUint16(hdr[4:6], BackupVersion)
	binary.LittleEndian.PutUint64(hdr[6:14], uint64(time.Now().Unix()))
	binary.LittleEndian.PutUint64(hdr[14:22], uint64(len(data)))
	sum := crypto.VerifySM3(data)
	copy(hdr[22:54], sum[:])

	f, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("storage: 创建备份文件失败: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(hdr[:]); err != nil {
		return fmt.Errorf("storage: 写入备份文件头失败: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("storage: 写入备份数据失败: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("storage: 同步备份文件失败: %w", err)
	}
	return nil
}

// RestoreBackup 校验备份文件的完整性（魔数/版本/长度/SM3 摘要/库格式）后，
// 将库文件密文原子写回 vaultPath。任何一步校验失败都不会触碰目标库。
func RestoreBackup(backupPath, vaultPath string) error {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("storage: 读取备份文件失败: %w", err)
	}
	if len(data) < backupHeaderLen {
		return errors.New("storage: 备份文件过短（不是有效的备份文件）")
	}
	if string(data[0:4]) != BackupMagic {
		return errors.New("storage: 不是有效的 password-vault 备份文件（魔数不匹配）")
	}
	if binary.LittleEndian.Uint16(data[4:6]) != BackupVersion {
		return errors.New("storage: 备份文件版本不受支持")
	}
	size := int64(binary.LittleEndian.Uint64(data[14:22]))
	if size <= 0 || backupHeaderLen+size != int64(len(data)) {
		return errors.New("storage: 备份文件长度与头部记录不一致（文件可能被篡改或损坏）")
	}
	payload := data[backupHeaderLen:]
	sum := crypto.VerifySM3(payload)
	if !bytes.Equal(sum[:], data[22:54]) {
		return errors.New("storage: 备份文件完整性校验失败（SM3 摘要不匹配，文件可能被篡改或损坏）")
	}
	// 备份内的库文件必须能被本包完整解析，才允许覆盖当前库。
	if _, err := Read(bytes.NewReader(payload)); err != nil {
		return fmt.Errorf("storage: 备份内的库文件无法解析: %w", err)
	}

	// 原子替换：先写临时文件并同步，再改名覆盖；任一步失败不破坏现有库。
	tmp := vaultPath + ".restore.tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("storage: 创建恢复临时文件失败: %w", err)
	}
	committed := false
	defer func() {
		_ = f.Close()
		if !committed {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(payload); err != nil {
		return fmt.Errorf("storage: 写入恢复临时文件失败: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("storage: 同步恢复临时文件失败: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("storage: 关闭恢复临时文件失败: %w", err)
	}
	committed = true
	if err := os.Rename(tmp, vaultPath); err != nil {
		return fmt.Errorf("storage: 替换库文件失败: %w", err)
	}
	return nil
}
