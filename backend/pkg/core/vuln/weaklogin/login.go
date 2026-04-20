package login

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// WeakFormLoginResult 表示弱口令表单登录测试结果
type WeakFormLoginResult struct {
	Vulnerable bool   `json:"vulnerable"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Response   string `json:"response"`
	Reason     string `json:"reason"`
}

// 用户名输入框的候选选择器
var usernameCandidates = []string{
	`#username`, `input[name="username"]`, `input[name="user"]`, `input[name="email"]`,
	`input[type="email"]`, `.username`, `.user`, `#email`, `input[placeholder*="user"]`,
}

// 密码输入框的候选选择器
var passwordCandidates = []string{
	`#password`, `input[name="password"]`, `input[type="password"]`, `.password`, `.pwd`,
}

// 提交按钮的候选选择器
var submitButtonCandidates = []string{
	`button[type="submit"]`, `input[type="submit"]`, `button.login`, `.login-btn`, `button:contains("登录")`,
	`button:contains("Login")`, `button:contains("Sign in")`,
}

// TestWeakFormLogin 使用 chromedp 模拟弱表单登录漏洞检测
// 参考 capture_server.go 的 runCaptureForFormLogin 实现
func TestWeakFormLogin(targetURL string, weakCreds []string) (*WeakFormLoginResult, error) {
	// 尝试每个弱口令组合
	for _, cred := range weakCreds {
		cred := strings.Split(cred, ":")
		username := cred[0]
		password := cred[1]

		result, err := attemptLoginWithChromedp(targetURL, username, password)
		if err != nil {
			return &WeakFormLoginResult{
				Vulnerable: false,
				Username:   username,
				Password:   password,
				Response:   "",
				Reason:     fmt.Sprintf("测试异常: %v", err),
			}, nil
		}

		if result.Vulnerable {
			return result, nil
		}
	}

	return &WeakFormLoginResult{
		Vulnerable: false,
		Username:   "",
		Password:   "",
		Response:   "",
		Reason:     "未检测到弱口令表单登录漏洞",
	}, nil
}

// attemptLoginWithChromedp 使用 chromedp 尝试登录
func attemptLoginWithChromedp(targetURL, username, password string) (*WeakFormLoginResult, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", false),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-plugins", true),
		chromedp.Flag("disable-images", true),
		chromedp.Flag("disable-javascript", false), // 保持启用JS，因为可能需要
	)
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, 15*time.Second) // 减少超时时间
	defer cancel()

	// 启用网络监听
	if err := chromedp.Run(ctx, network.Enable()); err != nil {
		return nil, fmt.Errorf("network enable: %w", err)
	}

	var mu sync.Mutex
	var loginSuccess bool
	var responseBody string
	var setCookies []string

	// 监听网络请求，检测登录成功信号
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventResponseReceived:
			// 检查响应是否包含登录成功的信号
			if e.Response.Status >= 200 && e.Response.Status < 400 {
				// 检查 URL 是否包含登录相关关键词
				url := strings.ToLower(e.Response.URL)
				if strings.Contains(url, "login") || strings.Contains(url, "auth") ||
					strings.Contains(url, "signin") || strings.Contains(url, "token") {
					// 获取响应体
					go func(requestID network.RequestID, resp *network.Response) {
						chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
							body, err := network.GetResponseBody(requestID).Do(ctx)
							if err != nil {
								return err
							}
							fmt.Printf("URL: %s, len(body): %v, err: %v\n", resp.URL, len(body), err)
							if len(body) > 0 {
								bodyStr := string(body)
								bodyLower := strings.ToLower(bodyStr)

								// 检查是否包含登录成功的信号
								successSignals := []string{
									"access_token", "refresh_token", "jwt", "token", "success",
									"登录成功", "已登录", "欢迎", "登陆成功", "dashboard", "home",
								}

								// 检查是否包含登录失败的信号
								failSignals := []string{
									"invalid", "error", "failed", "failure", "unauthorized", "forbidden",
									"验证码", "错误", "失败", "账号或密码", "incorrect", "wrong",
								}

								hasSuccess := false
								hasFail := false

								for _, signal := range successSignals {
									if strings.Contains(bodyLower, signal) {
										hasSuccess = true
										break
									}
								}

								for _, signal := range failSignals {
									if strings.Contains(bodyLower, signal) {
										hasFail = true
										break
									}
								}

								// 如果包含成功信号且不包含失败信号，认为登录成功
								if hasSuccess && !hasFail {
									mu.Lock()
									loginSuccess = true
									responseBody = bodyStr
									mu.Unlock()
								}
							}
							return nil
						}))
					}(e.RequestID, e.Response)
				}
			}

			// 检查 Set-Cookie 头
			for name, value := range e.Response.Headers {
				if strings.ToLower(name) == "set-cookie" {
					if str, ok := value.(string); ok {
						cookieLower := strings.ToLower(str)
						if strings.Contains(cookieLower, "session") ||
							strings.Contains(cookieLower, "token") ||
							strings.Contains(cookieLower, "auth") {
							mu.Lock()
							setCookies = append(setCookies, str)
							mu.Unlock()
						}
					}
				}
			}
		}
	})

	// 导航到目标页面
	if err := chromedp.Run(ctx,
		chromedp.Navigate(targetURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
	); err != nil {
		return &WeakFormLoginResult{
			Vulnerable: false,
			Username:   username,
			Password:   password,
			Response:   "",
			Reason:     fmt.Sprintf("页面导航失败: %v", err),
		}, nil
	}

	// 查找并填写登录表单
	usrSel := findSelector(ctx, usernameCandidates)
	pwdSel := findSelector(ctx, passwordCandidates)
	btnSel := findSelector(ctx, submitButtonCandidates)

	var actions []chromedp.Action
	if usrSel != "" {
		actions = append(actions, chromedp.SetValue(usrSel, username, chromedp.ByQuery))
	}
	if pwdSel != "" {
		actions = append(actions, chromedp.SetValue(pwdSel, password, chromedp.ByQuery))
	}

	// 触发提交
	if btnSel != "" {
		actions = append(actions, chromedp.Click(btnSel, chromedp.ByQuery))
	} else if pwdSel != "" {
		actions = append(actions, chromedp.SendKeys(pwdSel, "\n", chromedp.ByQuery))
	} else {
		// fallback：提交第一个表单
		actions = append(actions, chromedp.Evaluate(`(function(){ if(document.forms && document.forms.length>0){ document.forms[0].submit(); return "submitted"; } else { return "no-forms"; } })()`, nil))
	}

	if len(actions) > 0 {
		_ = chromedp.Run(ctx, actions...)
	}

	// 等待登录处理完成
	time.Sleep(2 * time.Second)

	// 检查结果
	mu.Lock()
	defer mu.Unlock()

	if loginSuccess || len(setCookies) > 0 {
		return &WeakFormLoginResult{
			Vulnerable: true,
			Username:   username,
			Password:   password,
			Response:   responseBody,
			Reason:     "弱口令登录成功（通过响应内容或 Set-Cookie 判断）",
		}, nil
	}

	return &WeakFormLoginResult{
		Vulnerable: false,
		Username:   username,
		Password:   password,
		Response:   "",
		Reason:     "登录失败",
	}, nil
}

// findSelector 查找可用的选择器
func findSelector(ctx context.Context, candidates []string) string {
	for _, s := range candidates {
		if strings.Contains(s, ":contains") {
			continue
		}
		var exists bool
		checkJS := fmt.Sprintf(`(function(){ return document.querySelector(%q) != null; })()`, s)
		if err := chromedp.Run(ctx, chromedp.Evaluate(checkJS, &exists)); err == nil && exists {
			return s
		}
	}
	return ""
}
