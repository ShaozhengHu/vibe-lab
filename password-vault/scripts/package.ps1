# 一键打包交付脚本：构建 → 生成使用说明 → 输出 zip 到 release/
# 用法：powershell -ExecutionPolicy Bypass -File .\scripts\package.ps1 [-Version 1.0.0]
# 注意：脚本需为 UTF-8 with BOM（PowerShell 5.1 无 BOM 会按 ANSI 解析导致乱码）；
# 字符串统一使用单引号，文本内中文引号使用直角引号「」，避免弯引号被当作定界符。
param(
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host '[1/4] wails build ...'
# -tags native_webview2loader：固定使用旧版 WebView2 加载器。
# 新版 Go WebView2Loader 在窗口空闲约 60 秒后会自行退出进程（exit 0），不可用于交付。
wails build -tags native_webview2loader
if ($LASTEXITCODE -ne 0) { throw 'wails build 失败' }

Write-Host '[2/4] 准备 release 目录 ...'
$rel = Join-Path $root 'release'
if (Test-Path $rel) { Remove-Item $rel -Recurse -Force }
New-Item -ItemType Directory -Path $rel | Out-Null
Copy-Item (Join-Path $root 'build\bin\password-vault.exe') (Join-Path $rel 'password-vault.exe') -Force

Write-Host '[3/4] 生成使用说明 ...'
$lines = @(
    '密码保险箱 使用说明',
    '版本：' + $Version,
    '',
    '一、软件简介',
    '密码保险箱是一款本地运行的密码管理工具，采用国家标准商用密码算法',
    '（SM3/SM4）对凭据加密存储。所有数据仅保存在本机，不上传网络。',
    '',
    '二、运行环境',
    '- Windows 10 / Windows 11',
    '- 需 WebView2 运行时（Win10/11 通常已内置，无需单独安装）',
    '- 无需安装，双击 password-vault.exe 即可运行',
    '',
    '三、首次使用（创建保险箱）',
    '1. 双击运行程序，进入「设置主密码」页面；',
    '2. 主密码要求：至少 12 位，且包含大写字母、小写字母、数字、符号中的至少三类；',
    '3. 确认主密码后创建完成，自动进入主界面。',
    '',
    '四、日常使用',
    '- 解锁：启动后输入主密码进入主界面；',
    '- 添加凭据：点击「＋ 新建凭据」，填写标题、账号、密码，可选填地址（IP/域名）、端口、备注；',
    '- 编辑凭据：详情页点击「编辑凭据」可修改任意字段（含补填地址、端口、备注）；',
    '- 查看/复制：选中左侧条目，右侧可「显示」密码或「复制密码」（复制后 30 秒自动清空剪贴板）；',
    '- 删除：点击「删除凭据」进入回收站，回收站中可「恢复」或「彻底删除」。',
    '- 修改主密码：顶栏「设置」，输入当前主密码与新主密码（至少 12 位、含三类字符）即可修改；',
    '',
    '五、备份与恢复（重要）',
    '- 备份：主界面顶栏「备份」，选择保存位置，生成加密备份文件；',
    '- 恢复：顶栏「恢复」，选择备份文件，程序校验通过后覆盖当前库并重新解锁；',
    '- 建议定期备份，并将备份存放在安全位置（如加密移动硬盘）。',
    '',
    '六、安全须知',
    '1. 主密码无法找回：主密码不存储、不上传，遗忘即数据不可恢复，请务必牢记；',
    '2. 数据位置：库文件位于 C:\Users\<用户名>\.password-vault\vault.vault；',
    '3. 请勿将库文件或备份文件发送给他人或上传网盘；',
    '4. 离开电脑前请点击「锁定」；程序闲置 5 分钟也会自动锁定；',
    '5. 连续输错主密码会触发等待（最长 60 秒），属正常保护机制。',
    '',
    '七、免责说明',
    '本软件为个人单机工具，加密算法与密钥管理符合商用密码应用要求；',
    '如用于单位业务场景，请遵守所在单位信息安全管理制度。'
)
$readmeText = $lines -join [Environment]::NewLine
[System.IO.File]::WriteAllText((Join-Path $rel '使用说明.txt'), $readmeText, (New-Object System.Text.UTF8Encoding $true))

Write-Host '[4/4] 压缩打包 ...'
$zip = Join-Path $rel ('password-vault-v' + $Version + '-win64.zip')
Compress-Archive -Path (Join-Path $rel 'password-vault.exe'), (Join-Path $rel '使用说明.txt') -DestinationPath $zip -Force

Write-Host ''
Write-Host ('打包完成：' + $zip)
Write-Host '交付方式：将 zip 解压后，把 password-vault.exe 与 使用说明.txt 一起发给使用者即可。'
