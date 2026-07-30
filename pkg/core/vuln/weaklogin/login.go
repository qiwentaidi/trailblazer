package login

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// WeakFormLoginResult 表示弱口令表单登录测试结果
type WeakFormLoginResult struct {
	Vulnerable        bool   `json:"vulnerable"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	Response          string `json:"response"`
	Reason            string `json:"reason"`
	UsedPrefilledCred bool   `json:"usedPrefilledCred,omitempty"`
}

type loginInteractionResult struct {
	Triggered          bool   `json:"triggered"`
	Reason             string `json:"reason"`
	FieldCount         int    `json:"fieldCount"`
	ButtonText         string `json:"buttonText"`
	FormAction         string `json:"formAction"`
	PageURL            string `json:"pageURL"`
	CandidateCount     int    `json:"candidateCount"`
	RawFieldCount      int    `json:"rawFieldCount"`
	FirstCandidateTag  string `json:"firstCandidateTag"`
	FirstCandidateCls  string `json:"firstCandidateCls"`
	HasPasswordField   bool   `json:"hasPasswordField"`
	HasIdentityField   bool   `json:"hasIdentityField"`
	UsedPrefilledCreds bool   `json:"usedPrefilledCreds"`
}

type pageStateResult struct {
	URL          string `json:"url"`
	Title        string `json:"title"`
	BodyPreview  string `json:"bodyPreview"`
	StorageState string `json:"storageState"`
	HasAuthState bool   `json:"hasAuthState"`
	HasFailText  bool   `json:"hasFailText"`
	HasSuccessUI bool   `json:"hasSuccessUi"`
	HasLoginUI   bool   `json:"hasLoginUi"`
}

type loginRequestRecord struct {
	URL           string
	Method        string
	PostData      string
	Status        int64
	ResponseBody  string
	AuthCookies   []string
	Matched       bool
	Success       bool
	ResponseReady bool
}

const negativeControlReasonPrefix = "随机凭据基线"

func buildWeakLoginChromeFlags() map[string]any {
	return map[string]any{
		"headless":              true,
		"disable-gpu":           true,
		"disable-dev-shm-usage": true,
		"disable-extensions":    true,
		"disable-plugins":       true,
		"disable-images":        true,
		"disable-javascript":    false,
	}
}

func buildWeakLoginExecAllocatorOptions() []chromedp.ExecAllocatorOption {
	flags := buildWeakLoginChromeFlags()
	return append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", flags["headless"]),
		chromedp.Flag("disable-gpu", flags["disable-gpu"]),
		chromedp.Flag("disable-dev-shm-usage", flags["disable-dev-shm-usage"]),
		chromedp.Flag("disable-extensions", flags["disable-extensions"]),
		chromedp.Flag("disable-plugins", flags["disable-plugins"]),
		chromedp.Flag("disable-images", flags["disable-images"]),
		chromedp.Flag("disable-javascript", flags["disable-javascript"]),
	)
}

const weakLoginInteractionScript = `(function (username, password, preferExisting) {
  function isVisible(el) {
    if (!el) return false;
    var style = window.getComputedStyle ? window.getComputedStyle(el) : null;
    if (style && (style.display === "none" || style.visibility === "hidden" || style.opacity === "0")) return false;
    var rect = el.getBoundingClientRect ? el.getBoundingClientRect() : null;
    if (!rect) return false;
    return (rect.width > 0 && rect.height > 0) || !!(el.offsetWidth || el.offsetHeight || (el.getClientRects && el.getClientRects().length));
  }

  function dispatchInputEvents(el) {
    try {
      el.dispatchEvent(new InputEvent("input", { bubbles: true, data: String(el.value || "") }));
    } catch (err) {
      try { el.dispatchEvent(new Event("input", { bubbles: true })); } catch (err2) {}
    }
    ["change", "blur"].forEach(function (name) {
      try { el.dispatchEvent(new Event(name, { bubbles: true })); } catch (err) {}
    });
  }

  function setNativeValue(el, value) {
    var proto = el && el.tagName === "TEXTAREA" ? window.HTMLTextAreaElement && window.HTMLTextAreaElement.prototype : window.HTMLInputElement && window.HTMLInputElement.prototype;
    var descriptor = proto ? Object.getOwnPropertyDescriptor(proto, "value") : null;
    if (descriptor && typeof descriptor.set === "function") {
      descriptor.set.call(el, value);
      return;
    }
    el.value = value;
  }

  function fieldLabel(el) {
    return String(
      el.name ||
      el.id ||
      el.placeholder ||
      el.getAttribute("aria-label") ||
      el.getAttribute("autocomplete") ||
      el.type ||
      ""
    ).toLowerCase();
  }

  function candidateFields(root) {
    return Array.prototype.slice.call(root.querySelectorAll("input, textarea, select")).filter(function (el) {
      var type = String(el.type || "").toLowerCase();
      if (el.disabled || el.readOnly) return false;
      if (["hidden", "submit", "button", "reset", "file", "image"].indexOf(type) >= 0) return false;
      return isVisible(el);
    });
  }

  function hasPasswordField(fields) {
    return fields.some(function (el) {
      var type = String(el.type || "").toLowerCase();
      var label = fieldLabel(el);
      return type === "password" || label.indexOf("pass") >= 0 || label.indexOf("pwd") >= 0 || label.indexOf("密码") >= 0;
    });
  }

  function hasIdentityField(fields) {
    return fields.some(function (el) {
      var type = String(el.type || "").toLowerCase();
      var label = fieldLabel(el);
      return type === "text" || type === "email" || label.indexOf("user") >= 0 || label.indexOf("account") >= 0 || label.indexOf("mail") >= 0 || label.indexOf("phone") >= 0 || label.indexOf("邮箱") >= 0 || label.indexOf("账号") >= 0 || label.indexOf("用户名") >= 0;
    });
  }

  function chooseSubmitButton(root) {
    var candidates = Array.prototype.slice.call(root.querySelectorAll("button, input[type='submit'], input[type='button'], [role='button']")).filter(function (el) {
      if (el.disabled || el.getAttribute("aria-disabled") === "true") return false;
      if (isVisible(el)) return true;
      var wrapper = el.closest(".ant-btn, .login-form, .login, .form-item");
      return !!(wrapper && isVisible(wrapper));
    });
    if (!candidates.length) return null;
    var preferred = candidates.find(function (el) {
      var text = String(el.innerText || el.textContent || el.value || el.getAttribute("aria-label") || "").toLowerCase();
      var type = String(el.type || "").toLowerCase();
      return type === "submit" || /(login|sign in|signin|submit|next|continue|confirm|登录|登陆|提交|确定|继续)/i.test(text);
    });
    return preferred || candidates[0];
  }

  function formCandidates() {
    var preferredSelectors = [
      "form.login-form",
      "form.ant-form",
      ".login form",
      ".login-form",
      ".login-account-pwd form",
      ".ggd-gateway__login form",
      ".ggd-gateway__login",
      ".login",
      "[role='form']"
    ];
    var preferred = [];
    preferredSelectors.forEach(function (selector) {
      Array.prototype.slice.call(document.querySelectorAll(selector)).forEach(function (node) {
        if (preferred.indexOf(node) < 0) preferred.push(node);
      });
    });
    preferred = preferred.filter(function (node) {
      var fields = candidateFields(node);
      return fields.length > 0 && hasPasswordField(fields);
    });
    if (preferred.length) return preferred;

    var forms = Array.prototype.slice.call(document.querySelectorAll("form")).filter(function (node) {
      var fields = candidateFields(node);
      return fields.length > 0 && hasPasswordField(fields);
    });
    if (forms.length) return forms;

    var anchorField = Array.prototype.slice.call(document.querySelectorAll("input, textarea, select")).find(function (el) {
      var root = el.form || el.closest("form, .login-form, .login, .ant-form, [role='form']") || document.body;
      var fields = candidateFields(root);
      return fields.length > 0 && hasPasswordField(fields);
    });
    if (!anchorField) return [];
    var container = anchorField.closest("[role='form'], .ant-form, .el-form, .login, .login-form, .form") || anchorField.parentElement || document.body;
    return container ? [container] : [];
  }

  function fillField(el) {
    var tag = String(el.tagName || "").toLowerCase();
    var type = String(el.type || "").toLowerCase();
    var label = fieldLabel(el);
    if (tag === "select") {
      var option = Array.prototype.slice.call(el.options || []).find(function (item) {
        return !item.disabled && String(item.value || "").trim() !== "";
      });
      if (!option) return false;
      el.value = option.value;
      dispatchInputEvents(el);
      return true;
    }
    if (type === "checkbox" || type === "radio") {
      el.checked = true;
      dispatchInputEvents(el);
      return true;
    }
    var value = username;
    if (type === "password" || label.indexOf("pass") >= 0 || label.indexOf("pwd") >= 0 || label.indexOf("密码") >= 0) {
      value = password;
    }
    try { el.focus(); } catch (err) {}
    setNativeValue(el, value);
    dispatchInputEvents(el);
    return true;
  }

  function hasNonEmptyValue(el) {
    try {
      return String(el.value || "").trim() !== "";
    } catch (err) {
      return false;
    }
  }

  var candidates = formCandidates();
  if (!candidates.length) {
    return { triggered: false, reason: "no_visible_login_form", fieldCount: 0, candidateCount: 0, rawFieldCount: 0, pageURL: String(window.location.href || ""), hasPasswordField: false, hasIdentityField: false };
  }

  var firstCandidate = candidates[0];
  var rawFieldCount = firstCandidate ? firstCandidate.querySelectorAll("input, textarea, select").length : 0;
  var firstCandidateTag = firstCandidate && firstCandidate.tagName ? String(firstCandidate.tagName).toLowerCase() : "";
  var firstCandidateCls = firstCandidate ? String(firstCandidate.className || "") : "";

  for (var i = 0; i < candidates.length; i++) {
    var root = candidates[i];
    var fields = candidateFields(root);
    if (!fields.length || !hasPasswordField(fields)) continue;

    var passwordReady = fields.some(function (el) {
      var type = String(el.type || "").toLowerCase();
      var label = fieldLabel(el);
      return (type === "password" || label.indexOf("pass") >= 0 || label.indexOf("pwd") >= 0 || label.indexOf("密码") >= 0) && hasNonEmptyValue(el);
    });
    var identityReady = fields.some(function (el) {
      var type = String(el.type || "").toLowerCase();
      var label = fieldLabel(el);
      return (type === "text" || type === "email" || label.indexOf("user") >= 0 || label.indexOf("account") >= 0 || label.indexOf("mail") >= 0 || label.indexOf("phone") >= 0 || label.indexOf("邮箱") >= 0 || label.indexOf("账号") >= 0 || label.indexOf("用户名") >= 0) && hasNonEmptyValue(el);
    });

    var filled = 0;
    var usedPrefilledCreds = false;
    if (preferExisting && passwordReady && identityReady) {
      usedPrefilledCreds = true;
    } else {
      fields.forEach(function (el) {
        if (fillField(el)) filled += 1;
      });
    }
    var button = chooseSubmitButton(root);

    if (button && typeof button.click === "function") {
      button.click();
      return {
        triggered: true,
        reason: usedPrefilledCreds ? "clicked_submit_control_with_prefilled_credentials" : "clicked_submit_control",
        fieldCount: filled,
        buttonText: String(button.innerText || button.textContent || button.value || button.getAttribute("aria-label") || ""),
        formAction: String(root.action || ""),
        pageURL: String(window.location.href || ""),
        candidateCount: candidates.length,
        rawFieldCount: root.querySelectorAll("input, textarea, select").length,
        firstCandidateTag: firstCandidateTag,
        firstCandidateCls: firstCandidateCls,
        hasPasswordField: true,
        hasIdentityField: hasIdentityField(fields),
        usedPrefilledCreds: usedPrefilledCreds
      };
    }
    if (root.tagName && String(root.tagName).toLowerCase() === "form" && typeof root.requestSubmit === "function") {
      root.requestSubmit();
      return {
        triggered: true,
        reason: usedPrefilledCreds ? "request_submit_with_prefilled_credentials" : "request_submit",
        fieldCount: filled,
        buttonText: "",
        formAction: String(root.action || ""),
        pageURL: String(window.location.href || ""),
        candidateCount: candidates.length,
        rawFieldCount: root.querySelectorAll("input, textarea, select").length,
        firstCandidateTag: firstCandidateTag,
        firstCandidateCls: firstCandidateCls,
        hasPasswordField: true,
        hasIdentityField: hasIdentityField(fields),
        usedPrefilledCreds: usedPrefilledCreds
      };
    }
    if (fields.length > 0) {
      var passwordField = fields.find(function (el) {
        var type = String(el.type || "").toLowerCase();
        var label = fieldLabel(el);
        return type === "password" || label.indexOf("pass") >= 0 || label.indexOf("pwd") >= 0 || label.indexOf("密码") >= 0;
      });
      if (passwordField) {
        try {
          passwordField.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", code: "Enter", bubbles: true }));
          passwordField.dispatchEvent(new KeyboardEvent("keyup", { key: "Enter", code: "Enter", bubbles: true }));
        } catch (err) {}
      }
      return {
        triggered: filled > 0,
        reason: usedPrefilledCreds ? "enter_key_submit_with_prefilled_credentials" : (filled > 0 ? "enter_key_submit" : "no_fillable_fields"),
        fieldCount: filled,
        buttonText: "",
        formAction: String(root.action || ""),
        pageURL: String(window.location.href || ""),
        candidateCount: candidates.length,
        rawFieldCount: root.querySelectorAll("input, textarea, select").length,
        firstCandidateTag: firstCandidateTag,
        firstCandidateCls: firstCandidateCls,
        hasPasswordField: true,
        hasIdentityField: hasIdentityField(fields),
        usedPrefilledCreds: usedPrefilledCreds
      };
    }
  }

  return {
    triggered: false,
    reason: "no_password_form_candidate",
    fieldCount: 0,
    candidateCount: candidates.length,
    rawFieldCount: rawFieldCount,
    pageURL: String(window.location.href || ""),
    firstCandidateTag: firstCandidateTag,
    firstCandidateCls: firstCandidateCls,
    hasPasswordField: false,
    hasIdentityField: false
  };
})(%q, %q, %t)`

const weakLoginPageStateScript = `(function () {
  function safeStorage(storage) {
    var pairs = [];
    try {
      for (var i = 0; i < storage.length; i++) {
        var key = String(storage.key(i) || "");
        var value = String(storage.getItem(key) || "");
        if (/token|auth|session|user|jwt/i.test(key) || /token|jwt|bearer/i.test(value)) {
          pairs.push(key + "=" + value.slice(0, 120));
        }
      }
    } catch (err) {}
    return pairs;
  }

  var bodyText = "";
  try {
    bodyText = String(document.body && (document.body.innerText || document.body.textContent) || "").replace(/\s+/g, " ").trim();
  } catch (err) {}
  bodyText = bodyText.slice(0, 1200);

  var title = "";
  try {
    title = String(document.title || "");
  } catch (err) {}

  var storageState = safeStorage(window.localStorage).concat(safeStorage(window.sessionStorage)).join(" | ");
  var currentURL = String(window.location.href || "");
  var hasFailText = /(invalid|failed|failure|unauthorized|forbidden|incorrect|wrong|错误|失败|验证码|账号或密码)/i.test(bodyText);
  var hasSuccessUI = /(logout|sign out|dashboard|welcome|控制台|退出登录|个人中心|工作台)/i.test(bodyText + " " + title);
  var hasLoginUI = /(forgot your password|sign up|login to your|username|password|welcome back|登录|密码|用户名)/i.test(bodyText + " " + title);

  return {
    url: currentURL,
    title: title,
    bodyPreview: bodyText,
    storageState: storageState.slice(0, 400),
    hasAuthState: storageState.length > 0,
    hasFailText: hasFailText,
    hasSuccessUi: hasSuccessUI,
    hasLoginUi: hasLoginUI
  };
})()`

// TestWeakFormLogin 使用 chromedp 模拟弱表单登录漏洞检测
func TestWeakFormLogin(targetURL string, weakCreds []string) (*WeakFormLoginResult, error) {
	negativeControl := runNegativeControlLogin(targetURL)
	for _, cred := range weakCreds {
		parts := strings.SplitN(cred, ":", 2)
		if len(parts) != 2 {
			continue
		}
		username := strings.TrimSpace(parts[0])
		password := strings.TrimSpace(parts[1])
		if username == "" || password == "" {
			continue
		}

		result, err := attemptLoginWithChromedp(targetURL, username, password, false)
		if err != nil {
			return &WeakFormLoginResult{
				Vulnerable: false,
				Username:   username,
				Password:   password,
				Response:   "",
				Reason:     fmt.Sprintf("测试异常: %v", err),
			}, nil
		}

		result = assessLoginAgainstNegativeControl(result, negativeControl)
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

// TestPrefilledFormLogin 尝试直接使用页面已有的自动填充值触发登录。
func TestPrefilledFormLogin(targetURL string) (*WeakFormLoginResult, error) {
	negativeControl := runNegativeControlLogin(targetURL)
	result, err := attemptLoginWithChromedp(targetURL, "", "", true)
	if err != nil {
		return &WeakFormLoginResult{
			Vulnerable: false,
			Response:   "",
			Reason:     fmt.Sprintf("测试异常: %v", err),
		}, nil
	}
	if result == nil {
		return &WeakFormLoginResult{
			Vulnerable: false,
			Response:   "",
			Reason:     "未检测到预填充凭据登录",
		}, nil
	}
	return assessLoginAgainstNegativeControl(result, negativeControl), nil
}

func runNegativeControlLogin(targetURL string) *WeakFormLoginResult {
	username, password := buildNegativeControlCredential()
	result, err := attemptLoginWithChromedp(targetURL, username, password, false)
	if err != nil || result == nil {
		return nil
	}
	return result
}

func buildNegativeControlCredential() (string, string) {
	seed := time.Now().UnixNano()
	return fmt.Sprintf("trailblazer_negative_%d", seed), fmt.Sprintf("Tb!negative%dAa1", seed%1000000)
}

func assessLoginAgainstNegativeControl(candidate, negative *WeakFormLoginResult) *WeakFormLoginResult {
	if candidate == nil {
		return nil
	}
	if negative == nil {
		return candidate
	}

	negativeSuccess := loginResultIndicatesSuccess(negative)
	candidateSuccess := loginResultIndicatesSuccess(candidate)
	sameResponse := equivalentLoginResponses(candidate.Response, negative.Response)
	if negativeSuccess && (sameResponse || candidateSuccess) {
		return &WeakFormLoginResult{
			Vulnerable:        false,
			Username:          candidate.Username,
			Password:          candidate.Password,
			Response:          candidate.Response,
			Reason:            negativeControlReasonPrefix + "也可登录，不能判定为弱口令",
			UsedPrefilledCred: candidate.UsedPrefilledCred,
		}
	}
	if candidate.Vulnerable {
		return candidate
	}
	if !negativeSuccess && candidateSuccess && !sameResponse {
		result := *candidate
		result.Vulnerable = true
		if strings.TrimSpace(result.Reason) == "" || strings.HasPrefix(result.Reason, "登录失败") {
			result.Reason = negativeControlReasonPrefix + "失败，候选凭据响应表现为认证成功"
		}
		return &result
	}
	return candidate
}

func loginResultIndicatesSuccess(result *WeakFormLoginResult) bool {
	if result == nil {
		return false
	}
	if result.Vulnerable {
		return true
	}
	return isSuccessfulLoginResponse("", result.Response)
}

func equivalentLoginResponses(left, right string) bool {
	left = normalizeLoginComparisonBody(left)
	right = normalizeLoginComparisonBody(right)
	return left != "" && left == right
}

func normalizeLoginComparisonBody(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}

// attemptLoginWithChromedp 使用 chromedp 尝试登录
func attemptLoginWithChromedp(targetURL, username, password string, preferExisting bool) (*WeakFormLoginResult, error) {
	opts := buildWeakLoginExecAllocatorOptions()
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	if err := chromedp.Run(ctx, network.Enable()); err != nil {
		return nil, fmt.Errorf("network enable: %w", err)
	}

	var mu sync.Mutex
	loginRequests := make(map[network.RequestID]*loginRequestRecord)

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			record := &loginRequestRecord{
				URL:    e.Request.URL,
				Method: e.Request.Method,
			}
			mu.Lock()
			loginRequests[e.RequestID] = record
			mu.Unlock()
			record.PostData = readPostDataFromEntries(e.Request.PostDataEntries)
			record.Matched = isLoginRequestCandidate(record.URL, record.Method, record.PostData)
			if !record.Matched && e.Request.HasPostData {
				go func(requestID network.RequestID, url, method string) {
					_ = chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
						postDataBytes, err := network.GetRequestPostData(requestID).Do(ctx)
						if err != nil || len(postDataBytes) == 0 {
							return nil
						}
						postData := string(postDataBytes)
						mu.Lock()
						if current := loginRequests[requestID]; current != nil {
							current.PostData = postData
							current.Matched = isLoginRequestCandidate(url, method, postData)
						}
						mu.Unlock()
						return nil
					}))
				}(e.RequestID, record.URL, record.Method)
			}
		case *network.EventResponseReceived:
			mu.Lock()
			record := loginRequests[e.RequestID]
			if record != nil {
				record.Status = int64(e.Response.Status)
			}
			mu.Unlock()

			if record != nil && record.Matched && e.Response.Status >= 200 && e.Response.Status < 400 {
				go func(requestID network.RequestID, resp *network.Response) {
					_ = chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
						body, err := network.GetResponseBody(requestID).Do(ctx)
						if err != nil {
							return nil
						}
						bodyStr := string(body)
						mu.Lock()
						if current := loginRequests[requestID]; current != nil {
							current.ResponseBody = bodyStr
							current.Success = isSuccessfulLoginResponse(resp.URL, bodyStr)
							current.ResponseReady = true
						}
						mu.Unlock()
						return nil
					}))
				}(e.RequestID, e.Response)
			}

			if record == nil || !record.Matched {
				return
			}
			for name, value := range e.Response.Headers {
				if strings.ToLower(name) != "set-cookie" {
					continue
				}
				str, ok := value.(string)
				if !ok {
					continue
				}
				cookieLower := strings.ToLower(str)
				if strings.Contains(cookieLower, "session") || strings.Contains(cookieLower, "token") || strings.Contains(cookieLower, "auth") {
					mu.Lock()
					if current := loginRequests[e.RequestID]; current != nil {
						current.AuthCookies = append(current.AuthCookies, str)
					}
					mu.Unlock()
				}
			}
		}
	})

	if err := chromedp.Run(ctx,
		chromedp.Navigate(targetURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(1500*time.Millisecond),
	); err != nil {
		return &WeakFormLoginResult{
			Vulnerable: false,
			Username:   username,
			Password:   password,
			Response:   "",
			Reason:     fmt.Sprintf("页面导航失败: %v", err),
		}, nil
	}

	var initialState pageStateResult
	if err := chromedp.Run(ctx, chromedp.Evaluate(weakLoginPageStateScript, &initialState)); err != nil {
		initialState = pageStateResult{URL: targetURL}
	}

	var interaction loginInteractionResult
	script := fmt.Sprintf(weakLoginInteractionScript, username, password, preferExisting)
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, &interaction)); err != nil {
		return &WeakFormLoginResult{
			Vulnerable: false,
			Username:   username,
			Password:   password,
			Response:   "",
			Reason:     fmt.Sprintf("表单交互失败: %v", err),
		}, nil
	}

	if !interaction.Triggered {
		return &WeakFormLoginResult{
			Vulnerable: false,
			Username:   username,
			Password:   password,
			Response:   "",
			Reason:     "未找到可提交的登录表单: " + strings.TrimSpace(interaction.Reason),
		}, nil
	}

	if err := chromedp.Run(ctx, chromedp.Sleep(3500*time.Millisecond)); err != nil {
		return &WeakFormLoginResult{
			Vulnerable: false,
			Username:   username,
			Password:   password,
			Response:   "",
			Reason:     fmt.Sprintf("等待登录结果失败: %v", err),
		}, nil
	}

	var finalState pageStateResult
	if err := chromedp.Run(ctx, chromedp.Evaluate(weakLoginPageStateScript, &finalState)); err != nil {
		finalState = pageStateResult{}
	}

	mu.Lock()
	authoritativeResult := collectAuthoritativeLoginResult(loginRequests)
	mu.Unlock()

	authStateEstablished := inferAuthStateEstablished(initialState, finalState, authoritativeResult.AuthCookieCount > 0)
	pageStateSupport := inferSuccessFromPageState(initialState, finalState)
	bodyStateSuccess := isSuccessfulLoginResponse(finalState.URL, finalState.BodyPreview)
	if authoritativeResult.Success || authStateEstablished || bodyStateSuccess {
		body := authoritativeResult.ResponseBody
		if body == "" {
			body = finalState.BodyPreview
		}
		reason := "弱口令登录成功（通过认证态建立判断）"
		switch {
		case authoritativeResult.Success && authStateEstablished:
			reason = "弱口令登录成功（通过登录接口响应和认证态建立判断）"
		case authoritativeResult.Success:
			reason = "弱口令登录成功（通过登录接口响应判断）"
		case bodyStateSuccess:
			reason = "弱口令登录成功（通过页面响应内容判断）"
		case authStateEstablished && authoritativeResult.LoginRequestSeen:
			reason = "弱口令登录成功（通过登录后认证态建立判断）"
		case authStateEstablished && pageStateSupport:
			reason = "弱口令登录成功（通过认证态建立及页面状态辅助判断）"
		}
		if interaction.UsedPrefilledCreds {
			reason = "页面预填充凭据直接触发登录成功"
		}
		resultUsername := username
		resultPassword := password
		if interaction.UsedPrefilledCreds {
			resultUsername = "<prefilled>"
			resultPassword = "<prefilled>"
		}
		return &WeakFormLoginResult{
			Vulnerable:        true,
			Username:          resultUsername,
			Password:          resultPassword,
			Response:          body,
			Reason:            reason,
			UsedPrefilledCred: interaction.UsedPrefilledCreds,
		}, nil
	}

	failReason := "登录失败"
	if finalState.HasFailText {
		failReason = "登录失败（页面提示认证失败）"
	} else if pageStateSupport {
		failReason = "登录失败（仅检测到页面跳转，未检测到权威认证成功证据）"
	} else if strings.TrimSpace(interaction.Reason) != "" {
		failReason = "登录失败（" + strings.TrimSpace(interaction.Reason) + "）"
	}
	if !preferExisting {
		fallbackResult, err := attemptLoginByCommonEndpoints(targetURL, username, password)
		if err != nil {
			return nil, err
		}
		if fallbackResult != nil && fallbackResult.Vulnerable {
			return fallbackResult, nil
		}
	}
	return &WeakFormLoginResult{
		Vulnerable: false,
		Username:   username,
		Password:   password,
		Response:   finalState.BodyPreview,
		Reason:     failReason,
	}, nil
}

type authoritativeLoginResult struct {
	LoginRequestSeen bool
	Success          bool
	ResponseBody     string
	AuthCookieCount  int
}

func attemptLoginByCommonEndpoints(targetURL, username, password string) (*WeakFormLoginResult, error) {
	if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		return nil, nil
	}

	parsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, nil
	}
	base := parsed.Scheme + "://" + parsed.Host
	candidates := []string{
		base + "/login",
		base + "/api/login",
		base + "/auth/login",
	}

	payloadBytes, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	for _, endpoint := range candidates {
		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payloadBytes))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		bodyText := string(bodyBytes)

		if resp.StatusCode >= 200 && resp.StatusCode < 300 && isSuccessfulLoginResponse(endpoint, bodyText) {
			return &WeakFormLoginResult{
				Vulnerable: true,
				Username:   username,
				Password:   password,
				Response:   bodyText,
				Reason:     "弱口令登录成功（通过常见登录接口直连判断）",
			}, nil
		}
	}

	return nil, nil
}

func isSuccessfulLoginResponse(responseURL, body string) bool {
	bodyLower := strings.ToLower(body)
	urlLower := strings.ToLower(strings.TrimSpace(responseURL))
	if bodyLower == "" {
		return false
	}
	if strings.HasSuffix(urlLower, ".js") || strings.HasSuffix(urlLower, ".css") || strings.HasSuffix(urlLower, ".map") || strings.HasSuffix(urlLower, ".svg") || strings.HasSuffix(urlLower, ".png") || strings.HasSuffix(urlLower, ".jpg") || strings.HasSuffix(urlLower, ".jpeg") || strings.HasSuffix(urlLower, ".woff") || strings.HasSuffix(urlLower, ".woff2") {
		return false
	}
	if success, decisive := assessStructuredLoginResponse(body); decisive {
		return success
	}

	successSignals := []string{
		"access_token", "refresh_token", "jwt", "\"token\"", "\"accessToken\"", "\"access_token\"",
	}
	failSignals := []string{
		"invalid", "error", "failed", "failure", "unauthorized", "forbidden", "验证码", "错误", "失败", "账号或密码", "incorrect", "wrong",
	}

	hasSuccess := false
	for _, signal := range successSignals {
		if strings.Contains(bodyLower, signal) {
			hasSuccess = true
			break
		}
	}
	hasFail := false
	for _, signal := range failSignals {
		if strings.Contains(bodyLower, signal) {
			hasFail = true
			break
		}
	}
	if hasSuccess && !hasFail {
		return true
	}

	if hasFail {
		return false
	}
	if looksLikeLoginPageURL(urlLower) {
		loginSuccessSignals := []string{"success", "登录成功", "已登录", "登陆成功"}
		for _, signal := range loginSuccessSignals {
			if strings.Contains(bodyLower, strings.ToLower(signal)) {
				return true
			}
		}
	}
	if looksLikePostLoginURL(urlLower) {
		if strings.Contains(bodyLower, "\"user\"") || strings.Contains(bodyLower, "\"role\"") || strings.Contains(bodyLower, "\"menu\"") {
			return true
		}
	}
	return false
}

func assessStructuredLoginResponse(body string) (bool, bool) {
	var value any
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &value); err == nil {
		return assessLoginJSONValue(value)
	}

	compact := compactLowerASCII(body)
	switch {
	case strings.Contains(compact, `"authenticated":false`) ||
		strings.Contains(compact, `"success":false`) ||
		strings.Contains(compact, `"login":false`) ||
		strings.Contains(compact, `"loggedin":false`):
		return false, true
	case strings.Contains(compact, `"authenticated":true`) ||
		strings.Contains(compact, `"success":true`) ||
		strings.Contains(compact, `"login":true`) ||
		strings.Contains(compact, `"loggedin":true`):
		return true, true
	default:
		return false, false
	}
}

func assessLoginJSONValue(value any) (bool, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for key, raw := range typed {
			normalizedKey := normalizeLoginJSONKey(key)
			if isLoginFailureKey(normalizedKey) {
				if boolValue, ok := raw.(bool); ok && !boolValue {
					return false, true
				}
				if textValue, ok := raw.(string); ok && isFailureText(textValue) {
					return false, true
				}
			}
			if isLoginSuccessBoolKey(normalizedKey) {
				if boolValue, ok := raw.(bool); ok {
					return boolValue, true
				}
				if textValue, ok := raw.(string); ok {
					switch strings.ToLower(strings.TrimSpace(textValue)) {
					case "true", "success", "ok", "authenticated", "logged_in", "loggedin":
						return true, true
					case "false", "fail", "failed", "invalid", "unauthorized":
						return false, true
					}
				}
			}
		}
		for key, raw := range typed {
			if isLoginPrincipalKey(normalizeLoginJSONKey(key)) && hasNonEmptyJSONValue(raw) {
				return true, true
			}
		}
		for _, raw := range typed {
			if success, decisive := assessLoginJSONValue(raw); decisive {
				return success, true
			}
		}
	case []any:
		for _, item := range typed {
			if success, decisive := assessLoginJSONValue(item); decisive {
				return success, true
			}
		}
	}
	return false, false
}

func normalizeLoginJSONKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ReplaceAll(key, "-", "")
	return key
}

func isLoginSuccessBoolKey(key string) bool {
	switch key {
	case "authenticated", "auth", "success", "login", "loggedin", "ok":
		return true
	default:
		return false
	}
}

func isLoginFailureKey(key string) bool {
	switch key {
	case "authenticated", "auth", "success", "login", "loggedin", "ok", "valid":
		return true
	default:
		return false
	}
}

func isLoginPrincipalKey(key string) bool {
	switch key {
	case "principal", "user", "userid", "username", "account", "token", "accesstoken", "session", "sessionid", "role", "roles":
		return true
	default:
		return false
	}
}

func hasNonEmptyJSONValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		text := strings.TrimSpace(typed)
		return text != "" && strings.ToLower(text) != "null"
	case bool:
		return typed
	case float64:
		return typed != 0
	case []any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	default:
		return true
	}
}

func isFailureText(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.Contains(value, "invalid") ||
		strings.Contains(value, "failed") ||
		strings.Contains(value, "failure") ||
		strings.Contains(value, "unauthorized") ||
		strings.Contains(value, "forbidden") ||
		strings.Contains(value, "incorrect") ||
		strings.Contains(value, "wrong") ||
		strings.Contains(value, "错误") ||
		strings.Contains(value, "失败")
}

func compactLowerASCII(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(value) {
		switch r {
		case ' ', '\n', '\r', '\t':
			continue
		default:
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func isLoginRequestCandidate(requestURL, method, postData string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch {
		return false
	}

	urlLower := strings.ToLower(strings.TrimSpace(requestURL))
	if looksLikeLoginPageURL(urlLower) || strings.Contains(urlLower, "/oauth/token") {
		return true
	}

	postDataLower := strings.ToLower(strings.TrimSpace(postData))
	if postDataLower == "" {
		return false
	}
	identityMarkers := []string{`"username"`, `"password"`, `"account"`, `"passwd"`, `"pwd"`, "username=", "password=", "account=", "passwd=", "pwd="}
	hits := 0
	for _, marker := range identityMarkers {
		if strings.Contains(postDataLower, marker) {
			hits++
		}
	}
	return hits >= 2
}

func readPostDataFromEntries(entries []*network.PostDataEntry) string {
	if len(entries) == 0 {
		return ""
	}
	var builder strings.Builder
	for _, entry := range entries {
		if entry == nil || entry.Bytes == "" {
			continue
		}
		builder.WriteString(entry.Bytes)
	}
	return builder.String()
}

func collectAuthoritativeLoginResult(records map[network.RequestID]*loginRequestRecord) authoritativeLoginResult {
	result := authoritativeLoginResult{}
	for _, record := range records {
		if record == nil || !record.Matched {
			continue
		}
		result.LoginRequestSeen = true
		result.AuthCookieCount += len(record.AuthCookies)
		if record.Success || len(record.AuthCookies) > 0 {
			result.Success = true
			if result.ResponseBody == "" {
				result.ResponseBody = record.ResponseBody
			}
		}
	}
	return result
}

func inferAuthStateEstablished(initialState, finalState pageStateResult, hasAuthCookie bool) bool {
	if finalState.HasFailText {
		return false
	}
	if hasAuthCookie {
		return true
	}
	if !initialState.HasAuthState && finalState.HasAuthState {
		return true
	}
	initialStorage := strings.TrimSpace(initialState.StorageState)
	finalStorage := strings.TrimSpace(finalState.StorageState)
	return finalStorage != "" && finalStorage != initialStorage
}

func inferSuccessFromPageState(initialState, finalState pageStateResult) bool {
	if finalState.HasFailText {
		return false
	}
	if finalState.HasLoginUI {
		return false
	}

	initialURL := strings.TrimSpace(initialState.URL)
	finalURL := strings.TrimSpace(finalState.URL)
	if finalURL != "" && looksLikeLoginPageURL(finalURL) {
		return false
	}
	if initialURL != "" && finalURL != "" && initialURL != finalURL {
		return true
	}
	if finalURL != "" && finalURL != initialURL && looksLikePostLoginURL(finalURL) {
		return true
	}
	if finalURL != "" && !looksLikeLoginPageURL(finalURL) && (finalState.HasAuthState || finalState.HasSuccessUI) {
		return true
	}
	return false
}

func looksLikeLoginPageURL(raw string) bool {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return false
	}
	keywords := []string{"login", "signin", "sign-in", "/auth", "passport", "superadmin/login", "登录", "登陆"}
	for _, keyword := range keywords {
		if strings.Contains(raw, keyword) {
			return true
		}
	}
	return false
}

func looksLikePostLoginURL(raw string) bool {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return false
	}
	keywords := []string{"dashboard", "console", "workspace", "profile", "task", "tenant", "user", "role", "menu"}
	for _, keyword := range keywords {
		if strings.Contains(raw, keyword) {
			return true
		}
	}
	return false
}
