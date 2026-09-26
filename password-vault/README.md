# password-vault

> **当前版本：v1.0.0（对外首个正式版）**

个人单机、桌面端使用的密码保险箱：可加密存储并解密取回明文密码（凭据），
加密体系全部采用国家标准商用密码算法（SM3/SM4），设计对齐金融行业
网络安全等级保护（等保 2.0）关键控制点与《中华人民共和国密码法》/
《商用密码管理条例》对商用密码应用的要求。

## 功能特性（v1.0.0）

- 主密码 ≥12 位、四类字符至少三类；连续失败指数退避；闲置 5 分钟自动锁定
- 凭据支持标题 / 账号 / 密码 / 地址（IP·域名）/ 端口 / 备注，可新建、编辑、删除
- 两级删除：移入回收站可恢复；彻底删除触发密文覆盖（防密文残留）
- 加密备份 / 恢复（SM3 完整性校验，备份不含任何明文）
- 本地审计日志（不记录密码与凭据内容）
- 修改主密码（设置入口，信封加密重封装，无需重加密数据）

## 环境要求

- Go 1.27 及以上（[go.dev/dl](https://go.dev/dl)）
- Git 2.x
- GUI 构建需要 C 编译器（MinGW-w64，如 WinLibs）与 WebView2 Runtime（Win10/11 通常已内置）
- 国内网络环境下 Go 模块代理建议设置为 `goproxy.cn`（本仓库已在 `go.mod` 中固定依赖）

## 快速开始（GUI）

```powershell
# 运行全部测试（含国标测试向量）
go test ./...

# 构建桌面程序
# 注意：必须使用 -tags native_webview2loader 固定旧版 WebView2 加载器
# （新版 loader 空闲约 60 秒会自动退出进程，不可交付）；
# 产物在 build\bin\password-vault.exe
wails build -tags native_webview2loader

# 运行
.\build\bin\password-vault.exe
```

首次启动进入「创建保险箱」：主密码 ≥12 位，且大写/小写/数字/符号至少含三类
（GUI 与 CLI 均按此策略校验）。之后启动输入主密码解锁，
左侧列表选凭据 → 右侧查看/复制密码（复制后 30 秒自动清空剪贴板）。
删除凭据为两级：「删除」移入回收站（可恢复）；回收站中「彻底删除」才触发
密文覆盖（随机覆写旧密文后原子重写库文件，防密文残留）。

备份与恢复：解锁后在顶栏点「备份」选择保存位置，库文件将整体备份为带
SM3 完整性校验的密文副本（备份内容不含任何明文）；「恢复」选择备份文件，
程序先校验完整性（魔数/版本/摘要/库格式）再原子替换，任何一步不通过都
不会改动当前库，恢复后需重新解锁。

库文件默认位置：`%USERPROFILE%\.password-vault\vault.vault`
（请定期用「备份」功能保存副本，勿手动删改）。

## 打包交付

`scripts/package.ps1` 一键生成交付包：重新 `wails build -tags native_webview2loader`
→ 生成《使用说明.txt》→ 输出 `release\password-vault-v<版本>-win64.zip`
（内含 exe 与使用说明）。

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package.ps1 -Version 1.0.0
```

交付说明：
- 产物为**单个 exe**（前端资源已嵌入），依赖系统 WebView2 Runtime（Win10/11 通常已内置），
  解压 zip 后把 exe 发给使用者即可，无需安装；
- 每台机器的库文件独立存放在各自 `%USERPROFILE%\.password-vault\`，互不影响；
- 请随包附上《使用说明.txt》（主密码不可找回、定期备份等安全须知）。

## CLI（与 GUI 共用同一库文件格式）

```powershell
go run ./cmd/vault init .\my.vault        # 创建库
go run ./cmd/vault add .\my.vault         # 新增一条凭据
go run ./cmd/vault list .\my.vault        # 列出凭据
go run ./cmd/vault get .\my.vault <ID>    # 取出一条凭据
```

加密体系：PBKDF2-HMAC-SM3 主密钥派生（迭代 60 万次）+ SM4-GCM
认证加密（每条凭据独立数据密钥的信封加密）。库文件全量密文，任何篡改都会被拒绝打开。

## 目录结构

| 路径 | 职责 |
| --- | --- |
| `main.go` | 桌面 GUI 入口（Wails v2），嵌入 frontend 静态资源 |
| `frontend/` | GUI 界面：纯 HTML/CSS/JS（解锁/主界面/弹窗），样式依据 `docs/ui-design.md` |
| `internal/gui` | GUI 后端服务层：解锁/新建/列表/取出/复制/锁定/删除/改密，复用加密核心 |
| `cmd/vault` | CLI 入口（init/add/list/get），与 GUI 共用同一库文件格式 |
| `internal/crypto` | 加密核心：PBKDF2-HMAC-SM3 密钥派生、SM4-GCM 信封加密、算法参数、国标测试向量 |
| `internal/storage` | 加密库文件二进制格式读写、版本管理、防篡改校验、删除时密文覆盖 |
| `internal/policy` | 主密码强度策略（≥12 位且四类字符至少三类），GUI 与 CLI 共用 |
| `docs/design.md` | 设计方案：合规依据、威胁模型、加密体系、等保映射 |
| `docs/ui-design.md` | 界面设计规范：设计 Token、三屏布局、组件与安全界面要求 |
| `docs/acceptance-checklist.md` | 验收清单：日常改动验收 + 等保/密评自检项 |
| `docs/compliance-report.md` | 商用密码应用安全性自查报告（GB/T 39786-2021 与等保控制点逐项核对） |

## 协作约定

- 主干分支 `main`，小步提交，一次提交对应一个可独立验收的改动。
- 提交信息格式：`<类型>: <简述>`；类型取值 `feat` / `fix` / `docs` / `test` / `refactor` / `chore`。
- 合入前必须通过：编译（`go build ./...`）、全部测试（`go test ./...`）；
  加密相关改动须通过国密标准测试向量（见 `docs/acceptance-checklist.md`）。
- 所有改动同步更新相应文档与变更记录，保证项目可被任何人接手维护。
- 真实凭据数据（`.vault` 库文件及备份）严禁进入版本库。

## 合规目标（摘要）

- 等保 2.0（GB/T 22239-2019）：身份鉴别、数据保密性、数据完整性、安全审计、
  数据备份与恢复、剩余信息保护。
- 密码法 / 商用密码应用安全性评估（GB/T 39786-2021）：只使用合规商用密码算法
  （SM3/SM4），不自行实现算法；算法实现采用经过验证的库。
- 金融数据安全分级（JR/T 0197-2020）：凭据属高敏数据，按 3 级及以上防护要求处理。

详细设计见 `docs/design.md`。
