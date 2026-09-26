// password-vault 是个人单机、桌面端使用的密码保险箱：
// 可加密存储并解密取回明文密码（凭据），加密体系全部采用国家标准商用密码算法（SM2/SM3/SM4）。
//
// 当前为第 2 阶段（加密核心最小闭环）：CLI 支持建库、新增、列表、取出四条命令。
// 第 3 阶段接入 GUI。
//
// 安全约定：
//   - 主密码只从终端（隐藏输入）或标准输入读取，绝不写入磁盘或命令行参数；
//   - 主密钥由主密码现场派生、用完清零，从不落盘；
//   - 库文件全量 SM4-GCM 加密，任何篡改都会导致拒绝打开。
package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"password-vault/internal/crypto"
	"password-vault/internal/policy"
	"password-vault/internal/storage"
)

const usageText = `password-vault — 国密加密的凭据保险箱（第 2 阶段：CLI）

用法:
  password-vault init <库文件路径>      创建新库（设置主密码）
  password-vault add <库文件路径>       新增一条凭据
  password-vault list <库文件路径>      列出凭据（ID 与标题、账号）
  password-vault get <库文件路径> <ID>  取出一条凭据（显示账号与密码）
  password-vault help                  显示本帮助

说明:
  - 加密算法: PBKDF2-HMAC-SM3 密钥派生 + SM4-GCM 认证加密（信封加密）
  - 主密码不会落盘，丢失即数据不可恢复，请妥善保管并定期备份库文件
  - 非终端环境（脚本/管道）下主密码与字段从标准输入按行读取
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usageText)
		os.Exit(2)
	}
	cmd := os.Args[1]
	switch cmd {
	case "init":
		runInit(os.Args[2:])
	case "add":
		runAdd(os.Args[2:])
	case "list":
		runList(os.Args[2:])
	case "get":
		runGet(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n", cmd)
		fmt.Print(usageText)
		os.Exit(2)
	}
}

// ---------- 命令实现 ----------

// runInit 创建新库：设置主密码，写入内部验证条目后落盘。
func runInit(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "用法: password-vault init <库文件路径>")
		os.Exit(2)
	}
	path := args[0]
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(os.Stderr, "错误: 文件已存在，不会覆盖: %s\n", path)
		os.Exit(1)
	}

	pass, err := readPasswordTwice()
	if err != nil {
		fatal(err)
	}

	v, err := storage.NewVault()
	if err != nil {
		fatal(err)
	}
	mk, err := deriveAndClear(pass, v.Salt, v.Iterations)
	if err != nil {
		fatal(err)
	}
	defer clear(mk)

	// 内部验证条目：解锁时用它校验主密码是否正确（等保"身份鉴别"）。
	verifySecret, err := crypto.NewSalt()
	if err != nil {
		fatal(err)
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
		fatal(err)
	}
	id, err := crypto.NewEntryID()
	if err != nil {
		fatal(err)
	}
	se, err := crypto.SealEntry(mk, plain, id)
	if err != nil {
		fatal(err)
	}
	v.Entries = append(v.Entries, *se)

	if err := v.WriteFile(path); err != nil {
		fatal(err)
	}
	fmt.Printf("已创建库文件: %s\n", path)
	fmt.Println("安全提示: 主密码无法找回，丢失即数据不可恢复；请立即对库文件做加密备份。")
}

// runAdd 解锁后新增一条凭据并写回。
func runAdd(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "用法: password-vault add <库文件路径>")
		os.Exit(2)
	}
	path := args[0]
	v, mk, err := unlock(path)
	if err != nil {
		fatal(err)
	}
	defer clear(mk)

	title, err := readLine("标题: ")
	if err != nil {
		fatal(err)
	}
	username, err := readLine("账号: ")
	if err != nil {
		fatal(err)
	}
	password, err := readLine("密码: ")
	if err != nil {
		fatal(err)
	}
	e, err := storage.NewEntry(strings.TrimSpace(title), strings.TrimSpace(username), password)
	if err != nil {
		fatal(err)
	}
	plain, err := e.Encode()
	if err != nil {
		fatal(err)
	}
	id, err := crypto.NewEntryID()
	if err != nil {
		fatal(err)
	}
	se, err := crypto.SealEntry(mk, plain, id)
	if err != nil {
		fatal(err)
	}
	v.Entries = append(v.Entries, *se)
	if err := v.WriteFile(path); err != nil {
		fatal(err)
	}
	fmt.Printf("已保存凭据: %s（ID: %x）\n", e.Title, id)
}

// runList 解锁后列出全部非内部凭据。
func runList(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "用法: password-vault list <库文件路径>")
		os.Exit(2)
	}
	path := args[0]
	v, mk, err := unlock(path)
	if err != nil {
		fatal(err)
	}
	defer clear(mk)

	fmt.Println("ID                                  标题            账号")
	count := 0
	for i := range v.Entries {
		plain, err := crypto.OpenEntry(mk, &v.Entries[i])
		if err != nil {
			continue // 该条目无法解密：跳过（不中断整个列表）
		}
		e, err := storage.DecodeEntry(plain)
		clear(plain)
		if err != nil {
			continue
		}
		if e.Internal {
			continue
		}
		if e.Deleted {
			continue // 回收站条目不在普通列表显示（软删除）
		}
		fmt.Printf("%x  %-16s %s\n", v.Entries[i].ID, e.Title, e.Username)
		count++
	}
	fmt.Printf("共 %d 条凭据\n", count)
}

// runGet 解锁后按条目 ID 取出一条凭据并显示账号与密码。
func runGet(args []string) {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "用法: password-vault get <库文件路径> <ID>")
		os.Exit(2)
	}
	path, idHex := args[0], args[1]
	idBytes, err := hex.DecodeString(idHex)
	if err != nil || len(idBytes) != 16 {
		fatal(errors.New("无效的条目 ID（应为 32 位十六进制，可由 list 命令获得）"))
	}
	var target [16]byte
	copy(target[:], idBytes)

	v, mk, err := unlock(path)
	if err != nil {
		fatal(err)
	}
	defer clear(mk)

	for i := range v.Entries {
		if v.Entries[i].ID != target {
			continue
		}
		plain, err := crypto.OpenEntry(mk, &v.Entries[i])
		if err != nil {
			fatal(errors.New("凭据无法解密（库文件可能被篡改）"))
		}
		e, err := storage.DecodeEntry(plain)
		clear(plain)
		if err != nil {
			fatal(errors.New("凭据内容损坏"))
		}
		fmt.Printf("标题: %s\n账号: %s\n密码: %s\n", e.Title, e.Username, e.Password)
		if e.Address != "" {
			fmt.Printf("地址: %s\n", e.Address)
		}
		if e.Port > 0 {
			fmt.Printf("端口: %d\n", e.Port)
		}
		if e.Note != "" {
			fmt.Printf("备注: %s\n", e.Note)
		}
		fmt.Println("提示: 密码已显示在终端，使用后请清除屏幕记录。")
		return
	}
	fatal(errors.New("未找到该条目 ID"))
}

// ---------- 解锁与输入 ----------

// unlock 读取库文件、派生主密钥并校验主密码正确性。
func unlock(path string) (*storage.VaultFile, []byte, error) {
	v, err := storage.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	pass, err := readPassword("主密码: ")
	if err != nil {
		return nil, nil, err
	}
	mk, err := deriveAndClear(pass, v.Salt, v.Iterations)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyMasterKey(mk, v); err != nil {
		clear(mk)
		return nil, nil, err
	}
	return v, mk, nil
}

// verifyMasterKey 通过内部验证条目校验主密码：能解开任一 Internal 条目即视为正确。
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

// deriveAndClear 派生主密钥，并立即清零主密码的字节副本。
func deriveAndClear(pass string, salt []byte, iterations int) ([]byte, error) {
	passBytes := []byte(pass)
	mk, err := crypto.DeriveMasterKey(string(passBytes), salt, iterations)
	clear(passBytes)
	return mk, err
}

func readPasswordTwice() (string, error) {
	p1, err := readPassword("设置主密码: ")
	if err != nil {
		return "", err
	}
	if err := policy.CheckPassword(p1); err != nil {
		return "", err
	}
	p2, err := readPassword("再次输入主密码: ")
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", errors.New("两次输入的主密码不一致")
	}
	return p1, nil
}

// stdinReader 共享标准输入读取器，保证管道/脚本场景下多行输入按顺序消费。
var stdinReader *bufio.Reader

func stdinLine() (string, error) {
	if stdinReader == nil {
		stdinReader = bufio.NewReader(os.Stdin)
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("读取输入失败: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readPassword 读取主密码：终端环境隐藏回显；管道/脚本环境按行读取。
func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", fmt.Errorf("读取主密码失败: %w", err)
		}
		return string(b), nil
	}
	return stdinLine()
}

// readLine 读取一行普通输入（标题/账号/密码等）。
func readLine(prompt string) (string, error) {
	fmt.Print(prompt)
	return stdinLine()
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "错误: %v\n", err)
	os.Exit(1)
}
