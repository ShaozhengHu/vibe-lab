// Package storage 负责加密库文件（.vault）的读写与格式版本管理。
// 磁盘布局中的全部数据均为密文（crypto.SealedEntry），本包不接触任何明文。
package storage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"password-vault/internal/crypto"
)

// FileMagic 是库文件魔数，用于快速识别文件类型并拒绝无关文件。
const FileMagic = "PVLT"

// FormatVersion 是当前库文件格式版本。版本化设计允许未来在不破坏
// 既有库文件的前提下升级算法或派生参数（升级时按版本号分支读取）。
const FormatVersion uint16 = 1

// 磁盘布局（全部小端序）：
//
//	文件头（26 字节）:
//	  魔数     "PVLT"      4 字节
//	  版本     uint16      2 字节
//	  KDF 盐               16 字节
//	  迭代次数 uint32      4 字节
//	条目区:
//	  条目数   uint32      4 字节
//	  条目 × N（每条含 4 字节长度前缀，长度不含该前缀本身）:
//	    条目 ID   16 字节
//	    凭据密文  变长
//	    加密随机数 nonce1  12 字节
//	    认证标签 tag1      16 字节
//	    数据密钥密文       16 字节
//	    封装随机数 nonce2  12 字节
//	    认证标签 tag2      16 字节
const (
	headerLen      = 26
	entryFixedLen  = 16 + 12 + 16 + 16 + 12 + 16 // ID + nonce1 + tag1 + DK + nonce2 + tag2
	maxEntryCount  = 1_000_000                   // 防御性上限
	maxEntryLength = 1 << 20                     // 单条密文总长上限 1 MiB
)

// VaultFile 是加密库文件的磁盘形态（全部密文，不含任何明文）。
type VaultFile struct {
	Salt       []byte // KDF 随机盐，16 字节
	Iterations int    // KDF 迭代次数
	Entries    []crypto.SealedEntry
}

// NewVault 创建一个空库：随机盐 + 默认派生参数。
func NewVault() (*VaultFile, error) {
	salt, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}
	return &VaultFile{Salt: salt, Iterations: crypto.KDFIterations}, nil
}

// Write 将库文件序列化到 w。保证写入的字节流可被 Read 完整还原。
func (v *VaultFile) Write(w io.Writer) error {
	if len(v.Salt) != crypto.KDFSaltBytes {
		return fmt.Errorf("storage: 盐长度必须为 %d 字节，实际 %d", crypto.KDFSaltBytes, len(v.Salt))
	}
	var hdr [headerLen]byte
	copy(hdr[0:4], FileMagic)
	binary.LittleEndian.PutUint16(hdr[4:6], FormatVersion)
	copy(hdr[6:22], v.Salt)
	binary.LittleEndian.PutUint32(hdr[22:26], uint32(v.Iterations))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}

	var count [4]byte
	binary.LittleEndian.PutUint32(count[:], uint32(len(v.Entries)))
	if _, err := w.Write(count[:]); err != nil {
		return err
	}
	for i := range v.Entries {
		if err := writeEntry(w, &v.Entries[i]); err != nil {
			return fmt.Errorf("storage: 写入第 %d 个条目失败: %w", i, err)
		}
	}
	return nil
}

// writeEntry 写入单条密封条目（4 字节长度前缀 + 条目体）。
func writeEntry(w io.Writer, se *crypto.SealedEntry) error {
	if len(se.Nonce1) != crypto.IVBytes || len(se.Tag1) != crypto.TagBytes ||
		len(se.EncryptedKey) != crypto.DataKeyBytes ||
		len(se.Nonce2) != crypto.IVBytes || len(se.Tag2) != crypto.TagBytes {
		return errors.New("storage: 密封条目字段长度非法")
	}
	payloadLen := entryFixedLen + len(se.Ciphertext)
	if payloadLen > maxEntryLength {
		return fmt.Errorf("storage: 条目长度超过上限 %d", maxEntryLength)
	}
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(payloadLen))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	for _, b := range [][]byte{se.ID[:], se.Ciphertext, se.Nonce1, se.Tag1, se.EncryptedKey, se.Nonce2, se.Tag2} {
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	return nil
}

// Read 从 r 解析库文件，校验魔数、格式版本、条目数与尾部完整性。
func Read(r io.Reader) (*VaultFile, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("storage: 读取文件头失败（文件不存在或不是库文件）: %w", err)
	}
	if string(hdr[0:4]) != FileMagic {
		return nil, errors.New("storage: 不是有效的 password-vault 库文件（魔数不匹配）")
	}
	ver := binary.LittleEndian.Uint16(hdr[4:6])
	if ver != FormatVersion {
		return nil, fmt.Errorf("storage: 不支持的库文件版本 %d（当前支持 %d）", ver, FormatVersion)
	}

	v := &VaultFile{
		Salt:       append([]byte(nil), hdr[6:22]...),
		Iterations: int(binary.LittleEndian.Uint32(hdr[22:26])),
	}

	var countBuf [4]byte
	if _, err := io.ReadFull(r, countBuf[:]); err != nil {
		return nil, fmt.Errorf("storage: 读取条目数失败: %w", err)
	}
	n := int(binary.LittleEndian.Uint32(countBuf[:]))
	if n > maxEntryCount {
		return nil, fmt.Errorf("storage: 条目数异常: %d", n)
	}
	v.Entries = make([]crypto.SealedEntry, 0, n)
	for i := 0; i < n; i++ {
		se, err := readEntry(r)
		if err != nil {
			return nil, fmt.Errorf("storage: 读取第 %d 个条目失败: %w", i, err)
		}
		v.Entries = append(v.Entries, *se)
	}

	// 拒绝尾部多余数据：防止拼接攻击与静默截断。
	var extra [1]byte
	if nRead, err := r.Read(extra[:]); nRead > 0 || (err != nil && err != io.EOF) {
		return nil, errors.New("storage: 库文件尾部存在多余数据，拒绝打开")
	}
	return v, nil
}

// readEntry 读取单条密封条目。
func readEntry(r io.Reader) (*crypto.SealedEntry, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	payloadLen := int(binary.LittleEndian.Uint32(lenBuf[:]))
	if payloadLen < entryFixedLen {
		return nil, errors.New("storage: 条目长度非法（小于最小固定长度）")
	}
	if payloadLen > maxEntryLength {
		return nil, errors.New("storage: 条目长度超过上限")
	}
	buf := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	se := &crypto.SealedEntry{}
	copy(se.ID[:], buf[0:16])
	off := 16
	ctLen := payloadLen - entryFixedLen
	se.Ciphertext = append([]byte(nil), buf[off:off+ctLen]...)
	off += ctLen
	se.Nonce1 = append([]byte(nil), buf[off:off+crypto.IVBytes]...)
	off += crypto.IVBytes
	se.Tag1 = append([]byte(nil), buf[off:off+crypto.TagBytes]...)
	off += crypto.TagBytes
	se.EncryptedKey = append([]byte(nil), buf[off:off+crypto.DataKeyBytes]...)
	off += crypto.DataKeyBytes
	se.Nonce2 = append([]byte(nil), buf[off:off+crypto.IVBytes]...)
	off += crypto.IVBytes
	se.Tag2 = append([]byte(nil), buf[off:off+crypto.TagBytes]...)
	return se, nil
}

// WriteFile 将库原子写入磁盘：先写临时文件并同步，再改名覆盖，
// 避免写入中途崩溃导致库文件损坏。
func (v *VaultFile) WriteFile(path string) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = f.Close()
		if !committed {
			_ = os.Remove(tmp)
		}
	}()

	if err := v.Write(f); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	committed = true
	return os.Rename(tmp, path)
}

// ReadFile 从磁盘读取库文件。
func ReadFile(path string) (*VaultFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f)
}
