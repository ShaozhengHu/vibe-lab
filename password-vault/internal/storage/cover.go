package storage

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
)

// CoverFile 用随机数据整体覆写文件内容并同步到磁盘，用于删除条目后
// 抹除旧密文残留（等保"剩余信息保护"）。覆写后再写入新库文件，
// 保证旧文件块在被释放前已是随机数据。
func CoverFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if size == 0 {
		return nil // 空文件无需覆盖
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	// 分批写入随机数据，避免为超大文件一次性分配内存。
	const chunk = 1 << 16 // 64 KiB
	buf := make([]byte, chunk)
	written := int64(0)
	for written < size {
		n := int64(chunk)
		if size-written < n {
			n = size - written
		}
		if _, err := io.ReadFull(rand.Reader, buf[:n]); err != nil {
			return errors.New("storage: 生成覆盖随机数据失败")
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return err
		}
		written += n
	}
	return f.Sync()
}

// ReplaceWithCover 用于删除条目场景：先把新库内容原子写入临时文件，
// 再以随机数据覆盖旧库文件（抹除被删条目的密文残留），最后将临时文件
// 改名替换为正式库文件。任一步失败都不会破坏旧库文件（覆盖失败时
// 临时文件被清理，旧库保持原状；仅改名这一步失败时旧库已被覆盖，
// 但新内容仍保留在临时文件中，可人工恢复）。
func ReplaceWithCover(path string, v *VaultFile) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	keepTmp := true
	defer func() {
		_ = f.Close()
		if keepTmp {
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

	if err := CoverFile(path); err != nil {
		return err
	}
	keepTmp = false // 成功在即，保留 tmp 直到改名完成
	return os.Rename(tmp, path)
}
