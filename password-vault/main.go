// password-vault 桌面 GUI 入口（Wails v2）。
// 界面为 frontend/ 下的静态资源（纯 HTML/CSS/JS，无前端构建链），
// 通过 go:embed 嵌入；后端逻辑由 internal/gui.Service 提供并绑定到前端。
package main

import (
	"embed"
	"fmt"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/windows"

	"password-vault/internal/gui"
)

//go:embed all:frontend
var assets embed.FS

func main() {
	svc := gui.NewService()

	err := wails.Run(&options.App{
		Title:     "密码保险箱",
		Width:     920,
		Height:    620,
		MinWidth:  380, // 锁屏/创建屏会缩为小框（类似微信/飞书登录窗口），故最小值放开
		MinHeight: 540,
		// 无边框自绘窗口：标题栏由前端实现（见 frontend/index.html 的 titlebar），
		// 保留系统 Aero 阴影与 Win11 圆角（不启用 DisableFramelessWindowDecorations）。
		Frameless: true,
		// 透明背景的兜底色：Windows 11 上由 Mica 提供背景，其余系统回退到该底色。
		BackgroundColour: &options.RGBA{R: 246, G: 248, B: 251, A: 255},
		Windows: &windows.Options{
			WebviewIsTransparent: true, // 透出窗口 Mica/底色背景
			WindowIsTranslucent:  true,
			BackdropType:         windows.Mica, // Win11 22621+：云母材质背景
		},
		Assets:    assets,
		OnStartup:  svc.OnStartup,
		OnShutdown: svc.OnShutdown,
		Bind: []interface{}{
			svc,
		},
	})
	if err != nil {
		fmt.Printf("应用启动失败: %v\n", err)
	}
}
