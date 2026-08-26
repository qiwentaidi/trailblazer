package crawl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/security"
	"github.com/chromedp/chromedp"
)

const (
	maxCapturedRequestBodySize  = 16 * 1024
	maxCapturedResponseBodySize = 128 * 1024
	defaultScanInitialWait      = 10 * time.Second
	defaultScanPostWait         = 8 * time.Second
	defaultScanTimeout          = 120 * time.Second
	defaultCaptureUserAgent     = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
	defaultCaptureLanguage      = "zh-CN,zh;q=0.9,en;q=0.8"
	defaultCapturePlatform      = "MacIntel"
)

const stealthBrowserScript = `(function () {
  try {
    var overrideGetter = function (target, key, getter) {
      try {
        Object.defineProperty(target, key, {
          configurable: true,
          enumerable: true,
          get: getter
        });
      } catch (err) {}
    };

    overrideGetter(Navigator.prototype, "webdriver", function () {
      return undefined;
    });
    overrideGetter(Navigator.prototype, "platform", function () {
      return "MacIntel";
    });
    overrideGetter(Navigator.prototype, "language", function () {
      return "zh-CN";
    });
    overrideGetter(Navigator.prototype, "languages", function () {
      return ["zh-CN", "zh", "en"];
    });
    overrideGetter(Navigator.prototype, "plugins", function () {
      return [
        { name: "Chrome PDF Plugin", filename: "internal-pdf-viewer" },
        { name: "Chrome PDF Viewer", filename: "mhjfbmdgcfjbbpaeojofohoefgiehjai" },
        { name: "Native Client", filename: "internal-nacl-plugin" },
        { name: "Microsoft Edge PDF Viewer", filename: "internal-pdf-viewer" },
        { name: "WebKit built-in PDF", filename: "internal-pdf-viewer" }
      ];
    });
    overrideGetter(Navigator.prototype, "mimeTypes", function () {
      return [
        { type: "application/pdf", suffixes: "pdf", description: "Portable Document Format" },
        { type: "text/pdf", suffixes: "pdf", description: "Portable Document Format" }
      ];
    });

    if (!window.chrome) {
      window.chrome = {};
    }
    if (!window.chrome.runtime) {
      window.chrome.runtime = {};
    }
    if (!window.chrome.app) {
      window.chrome.app = {
        isInstalled: false,
        InstallState: {
          DISABLED: "disabled",
          INSTALLED: "installed",
          NOT_INSTALLED: "not_installed"
        },
        RunningState: {
          CANNOT_RUN: "cannot_run",
          READY_TO_RUN: "ready_to_run",
          RUNNING: "running"
        }
      };
    }
    if (!window.chrome.csi) {
      window.chrome.csi = function () {
        return {
          onloadT: Date.now(),
          startE: Date.now() - 100,
          pageT: Math.max(0, Date.now() - (window.performance && performance.timing ? performance.timing.navigationStart : Date.now()))
        };
      };
    }
    if (!window.chrome.loadTimes) {
      window.chrome.loadTimes = function () {
        var now = Date.now() / 1000;
        return {
          requestTime: now - 1,
          startLoadTime: now - 1,
          commitLoadTime: now - 0.5,
          finishDocumentLoadTime: now - 0.2,
          finishLoadTime: now,
          firstPaintTime: now - 0.1
        };
      };
    }

    if (navigator.permissions && navigator.permissions.query) {
      var originalQuery = navigator.permissions.query.bind(navigator.permissions);
      navigator.permissions.query = function (parameters) {
        if (parameters && parameters.name === "notifications") {
          return Promise.resolve({ state: Notification.permission });
        }
        return originalQuery(parameters);
      };
    }

    try {
      var originalGetParameter = WebGLRenderingContext.prototype.getParameter;
      WebGLRenderingContext.prototype.getParameter = function (parameter) {
        if (parameter === 37445) {
          return "Intel Inc.";
        }
        if (parameter === 37446) {
          return "Intel Iris OpenGL Engine";
        }
        return originalGetParameter.apply(this, arguments);
      };
    } catch (err) {}

    try {
      var originalGetParameter2 = WebGL2RenderingContext.prototype.getParameter;
      WebGL2RenderingContext.prototype.getParameter = function (parameter) {
        if (parameter === 37445) {
          return "Intel Inc.";
        }
        if (parameter === 37446) {
          return "Intel Iris OpenGL Engine";
        }
        return originalGetParameter2.apply(this, arguments);
      };
    } catch (err) {}
  } catch (err) {}
})();`

// NetworkRecord 表示浏览器运行时捕获到的接口请求/响应记录
type NetworkRecord struct {
	URL              string            `json:"url"`
	Method           string            `json:"method"`
	ResourceType     string            `json:"resource_type"`
	PageURL          string            `json:"page_url,omitempty"`
	TraceID          string            `json:"trace_id,omitempty"`
	HasProtocolTrace bool              `json:"has_protocol_trace,omitempty"`
	RequestHeaders   map[string]string `json:"request_headers,omitempty"`
	RequestBody      string            `json:"request_body,omitempty"`
	ResponseHeaders  map[string]string `json:"response_headers,omitempty"`
	ResponseBody     string            `json:"response_body,omitempty"`
	ResponseCode     int               `json:"response_code"`
	MIMEType         string            `json:"mime_type,omitempty"`
	FetchedAt        time.Time         `json:"fetched_at"`
}

// FrontendRouteRecord 表示浏览器运行时捕获到的前端页面路由记录。
type FrontendRouteRecord struct {
	Path         string    `json:"path"`
	Name         string    `json:"name,omitempty"`
	SourceKind   string    `json:"source_kind,omitempty"`
	Source       string    `json:"source,omitempty"`
	PageURL      string    `json:"page_url,omitempty"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// CaptureSnapshot 表示动态采集过程中的一次增量快照。
type CaptureSnapshot struct {
	NetworkURLs    []string              `json:"network_urls"`
	APIRecords     []NetworkRecord       `json:"api_records"`
	ProtocolTraces []ProtocolTraceRecord `json:"protocol_traces"`
	FrontendRoutes []FrontendRouteRecord `json:"frontend_routes"`
	CapturedAt     time.Time             `json:"captured_at"`
}

// CaptureOptions 控制动态采集期间的页面交互行为。
type CaptureOptions struct {
	Timeout                   time.Duration
	InitialWait               time.Duration
	PostInteractionWait       time.Duration
	BrowserVisible            bool
	ProxyServer               string
	ProxyBypassList           string
	BypassFrontendRouteGuards bool
	AutoTriggerForms          bool
	AutoTriggerAttempts       int
	AutoTriggerRetryDelay     time.Duration
	AutoExploreRoutes         bool
	MaxExploreRoutes          int
	MaxRouteClicks            int
	RouteInteractionWait      time.Duration
	NativeFormTrigger         bool
	UsernameSelector          string
	PasswordSelector          string
	SubmitSelector            string
	UsernameValue             string
	PasswordValue             string
	OnUpdate                  func(CaptureSnapshot)
}

// 动态捕获网站访问时加载的所有链接
func CaptureNetworkURLs(url string) []string {
	networks, _, _, _ := CaptureNetworkActivity(url)
	return networks
}

func defaultScanCaptureOptions() CaptureOptions {
	return CaptureOptions{
		Timeout:                   defaultScanTimeout,
		InitialWait:               defaultScanInitialWait,
		PostInteractionWait:       defaultScanPostWait,
		BypassFrontendRouteGuards: true,
		AutoTriggerForms:          true,
		AutoExploreRoutes:         true,
		MaxExploreRoutes:          8,
		MaxRouteClicks:            8,
		RouteInteractionWait:      2 * time.Second,
	}
}

// CaptureNetworkActivity 捕获页面加载过程中的网络链接和接口请求/响应记录。
// 该默认入口用于常规扫描，会在有限时间内自动结束；需要手动控制会话生命周期时
// 应直接调用 CaptureNetworkActivityWithOptions 并显式传入 options。
func CaptureNetworkActivity(url string) ([]string, []NetworkRecord, []ProtocolTraceRecord, []FrontendRouteRecord) {
	return CaptureNetworkActivityWithOptions(url, defaultScanCaptureOptions())
}

// CaptureNetworkActivityWithOptions 捕获页面加载和可选交互过程中的网络链接、接口请求/响应记录。
func CaptureNetworkActivityWithOptions(url string, options CaptureOptions) ([]string, []NetworkRecord, []ProtocolTraceRecord, []FrontendRouteRecord) {
	options = normalizeCaptureOptions(options)

	var networks []string
	var apiRecords []NetworkRecord
	var protocolTraces []ProtocolTraceRecord
	var frontendRoutes []FrontendRouteRecord
	allocOpts := buildExecAllocatorOptions(options)
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), allocOpts...)
	defer allocCancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	if options.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	linkSet := make(map[string]bool)
	apiRecordSet := make(map[string]bool)
	protocolTraceIndex := make(map[string]int)
	frontendRouteIndex := make(map[string]int)
	requestMap := make(map[network.RequestID]*NetworkRecord)
	finalizedRequest := make(map[network.RequestID]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *runtime.EventBindingCalled:
			if ev.Name != protocolHookBindingName {
				return
			}

			var payload struct {
				Kind string `json:"kind"`
				ProtocolTraceRecord
				Path         string    `json:"path"`
				Name         string    `json:"name,omitempty"`
				SourceKind   string    `json:"source_kind,omitempty"`
				Source       string    `json:"source,omitempty"`
				PageURL      string    `json:"page_url,omitempty"`
				DiscoveredAt time.Time `json:"discovered_at"`
			}
			if err := json.Unmarshal([]byte(ev.Payload), &payload); err != nil {
				return
			}
			if payload.Kind != "request-trace" && payload.Kind != "response-trace" && payload.Kind != "trace-update" && payload.Kind != "frontend-route" {
				return
			}

			mu.Lock()
			if payload.Kind == "frontend-route" {
				upsertFrontendRouteRecord(frontendRouteIndex, &frontendRoutes, FrontendRouteRecord{
					Path:         payload.Path,
					Name:         payload.Name,
					SourceKind:   payload.SourceKind,
					Source:       payload.Source,
					PageURL:      payload.PageURL,
					DiscoveredAt: payload.DiscoveredAt,
				})
			} else {
				upsertProtocolTraceRecord(protocolTraceIndex, &protocolTraces, payload.ProtocolTraceRecord)
			}
			emitCaptureUpdateLocked(options.OnUpdate, networks, apiRecords, protocolTraces, frontendRoutes)
			mu.Unlock()

		case *network.EventRequestWillBeSent:
			if !isHTTPURL(ev.Request.URL) {
				return
			}

			mu.Lock()
			requestMap[ev.RequestID] = &NetworkRecord{
				URL:            ev.Request.URL,
				Method:         ev.Request.Method,
				ResourceType:   string(ev.Type),
				PageURL:        ev.DocumentURL,
				RequestHeaders: stringifyHeaders(ev.Request.Headers),
				FetchedAt:      time.Now(),
			}
			mu.Unlock()

		case *network.EventResponseReceived:
			if !isHTTPURL(ev.Response.URL) {
				return
			}

			mu.Lock()
			if !linkSet[ev.Response.URL] {
				networks = append(networks, ev.Response.URL)
				linkSet[ev.Response.URL] = true
			}

			record, ok := requestMap[ev.RequestID]
			if !ok {
				record = &NetworkRecord{
					URL:       ev.Response.URL,
					FetchedAt: time.Now(),
				}
				requestMap[ev.RequestID] = record
			}
			record.URL = ev.Response.URL
			record.ResourceType = ev.Type.String()
			if strings.TrimSpace(record.PageURL) == "" {
				record.PageURL = ev.Response.URL
			}
			record.ResponseCode = int(ev.Response.Status)
			record.ResponseHeaders = stringifyHeaders(ev.Response.Headers)
			record.MIMEType = ev.Response.MimeType
			mu.Unlock()

		case *network.EventLoadingFinished:
			wg.Add(1)
			go func(requestID network.RequestID) {
				defer wg.Done()

				var (
					requestBody  string
					responseBody []byte
				)

				_ = chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
					postData, err := network.GetRequestPostData(requestID).Do(ctx)
					if err == nil {
						requestBody = postData
					}
					return nil
				}))

				responseErr := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
					var innerErr error
					responseBody, innerErr = network.GetResponseBody(requestID).Do(ctx)
					return innerErr
				}))

				mu.Lock()
				defer mu.Unlock()

				record, ok := requestMap[requestID]
				if !ok || finalizedRequest[requestID] {
					return
				}

				if requestBody != "" {
					record.RequestBody = limitCapturedBody(requestBody, maxCapturedRequestBodySize, "请求体过长，已截断")
				}
				if responseErr == nil {
					record.ResponseBody = normalizeCapturedResponseBody(record.MIMEType, responseBody)
				} else if isAPIResource(record) {
					logResponseBodyCaptureFailure(requestID, record, responseErr)
				}
				if responseErr == nil && isAPIResource(record) && strings.TrimSpace(record.ResponseBody) == "" {
					logEmptyAPIResponseBody(requestID, record, len(responseBody))
				}

				appendAPIRecord(apiRecordSet, &apiRecords, record)
				finalizedRequest[requestID] = true
				emitCaptureUpdateLocked(options.OnUpdate, networks, apiRecords, protocolTraces, frontendRoutes)
			}(ev.RequestID)

		case *network.EventLoadingFailed:
			mu.Lock()
			defer mu.Unlock()

			record, ok := requestMap[ev.RequestID]
			if !ok || finalizedRequest[ev.RequestID] {
				return
			}

			appendAPIRecord(apiRecordSet, &apiRecords, record)
			finalizedRequest[ev.RequestID] = true
			emitCaptureUpdateLocked(options.OnUpdate, networks, apiRecords, protocolTraces, frontendRoutes)
		}
	})

	actions := []chromedp.Action{
		runtime.Enable(),
		runtime.AddBinding(protocolHookBindingName),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(stealthBrowserScript).Do(ctx)
			return err
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(buildProtocolHookScript(options)).Do(ctx)
			return err
		}),
		security.SetIgnoreCertificateErrors(true),
		network.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			return emulation.SetUserAgentOverride(defaultCaptureUserAgent).
				WithAcceptLanguage(defaultCaptureLanguage).
				WithPlatform(defaultCapturePlatform).
				Do(ctx)
		}),
		chromedp.Navigate(url),
		chromedp.Sleep(options.InitialWait),
	}
	if options.NativeFormTrigger {
		actions = append(actions, nativeFormTriggerAction(options))
	} else if options.AutoTriggerForms {
		actions = append(actions, autoTriggerFormsAction(options))
	}
	if options.AutoExploreRoutes {
		actions = append(actions, frontendRouteInteractionAction(url, options, func() []FrontendRouteRecord {
			mu.Lock()
			defer mu.Unlock()
			return cloneFrontendRouteRecords(frontendRoutes)
		}))
	}
	if options.PostInteractionWait > 0 {
		actions = append(actions, chromedp.Sleep(options.PostInteractionWait))
	} else {
		actions = append(actions, waitForBrowserSessionEndAction())
	}

	err := chromedp.Run(ctx, actions...)
	wg.Wait()
	backfillProtocolTraceResponsesFromAPIRecords(protocolTraces, apiRecords)
	linkAPIRecordsToProtocolTraces(apiRecords, protocolTraces)
	emitCaptureUpdateLocked(options.OnUpdate, networks, apiRecords, protocolTraces, frontendRoutes)

	if err != nil {
		if isExpectedCaptureCancellation(err) {
			fmt.Printf("[信息] %s 动态捕获已结束，已获取 %d 个URL、%d 条接口记录、%d 条协议轨迹、%d 条前端路由，结束原因: %v\n", url, len(networks), len(apiRecords), len(protocolTraces), len(frontendRoutes), err)
			return networks, apiRecords, protocolTraces, frontendRoutes
		}
		fmt.Printf("[错误] %s 动态捕获网络请求失败，已获取 %d 个URL、%d 条接口记录、%d 条协议轨迹、%d 条前端路由，错误原因: %v\n", url, len(networks), len(apiRecords), len(protocolTraces), len(frontendRoutes), err)
		return networks, apiRecords, protocolTraces, frontendRoutes
	}
	fmt.Printf("[信息] %s 成功捕获 %d 个网络请求，提取 %d 条接口记录、%d 条协议轨迹、%d 条前端路由\n", url, len(networks), len(apiRecords), len(protocolTraces), len(frontendRoutes))
	return networks, apiRecords, protocolTraces, frontendRoutes
}

func isExpectedCaptureCancellation(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, context.Canceled) || strings.Contains(strings.ToLower(err.Error()), "context canceled")
}

func emitCaptureUpdateLocked(callback func(CaptureSnapshot), networks []string, apiRecords []NetworkRecord, protocolTraces []ProtocolTraceRecord, frontendRoutes []FrontendRouteRecord) {
	if callback == nil {
		return
	}

	snapshot := CaptureSnapshot{
		NetworkURLs:    append([]string(nil), networks...),
		APIRecords:     cloneNetworkRecords(apiRecords),
		ProtocolTraces: cloneProtocolTraceRecords(protocolTraces),
		FrontendRoutes: cloneFrontendRouteRecords(frontendRoutes),
		CapturedAt:     time.Now(),
	}
	callback(snapshot)
}

func cloneNetworkRecords(records []NetworkRecord) []NetworkRecord {
	cloned := make([]NetworkRecord, 0, len(records))
	for _, record := range records {
		next := record
		next.RequestHeaders = cloneStringMap(record.RequestHeaders)
		next.ResponseHeaders = cloneStringMap(record.ResponseHeaders)
		cloned = append(cloned, next)
	}
	return cloned
}

func cloneProtocolTraceRecords(records []ProtocolTraceRecord) []ProtocolTraceRecord {
	cloned := make([]ProtocolTraceRecord, 0, len(records))
	for _, record := range records {
		next := record
		next.RequestHeaders = cloneStringMap(record.RequestHeaders)
		next.DynamicParams = cloneStringMap(record.DynamicParams)
		next.SessionMaterials = cloneStringMap(record.SessionMaterials)
		next.SignatureFields = append([]string(nil), record.SignatureFields...)
		next.RequestSteps = append([]ProtocolCryptoStep(nil), record.RequestSteps...)
		next.ResponseSteps = append([]ProtocolCryptoStep(nil), record.ResponseSteps...)
		next.Algorithms = append([]string(nil), record.Algorithms...)
		cloned = append(cloned, next)
	}
	return cloned
}

func cloneFrontendRouteRecords(records []FrontendRouteRecord) []FrontendRouteRecord {
	cloned := make([]FrontendRouteRecord, 0, len(records))
	for _, record := range records {
		cloned = append(cloned, record)
	}
	return cloned
}

func buildExecAllocatorOptions(options CaptureOptions) []chromedp.ExecAllocatorOption {
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", !options.BrowserVisible),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("enable-automation", false),
		chromedp.Flag("disable-infobars", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("allow-insecure-localhost", true),
		chromedp.Flag("window-size", "1440,900"),
	)

	flags := buildCaptureChromeFlags(options)
	if proxyServer, ok := flags["proxy-server"].(string); ok && proxyServer != "" {
		allocOpts = append(allocOpts, chromedp.ProxyServer(proxyServer))
	}
	if bypassList, ok := flags["proxy-bypass-list"].(string); ok && bypassList != "" {
		allocOpts = append(allocOpts, chromedp.Flag("proxy-bypass-list", bypassList))
	}

	return allocOpts
}

func buildCaptureChromeFlags(options CaptureOptions) map[string]any {
	flags := map[string]any{
		"headless":                  !options.BrowserVisible,
		"disable-blink-features":    "AutomationControlled",
		"enable-automation":         false,
		"disable-infobars":          true,
		"ignore-certificate-errors": true,
		"allow-insecure-localhost":  true,
		"window-size":               "1440,900",
	}

	if proxyServer := strings.TrimSpace(options.ProxyServer); proxyServer != "" {
		flags["proxy-server"] = proxyServer
	}
	if bypassList := strings.TrimSpace(options.ProxyBypassList); bypassList != "" {
		flags["proxy-bypass-list"] = bypassList
	}

	return flags
}

func normalizeCaptureOptions(options CaptureOptions) CaptureOptions {
	if options.Timeout < 0 {
		options.Timeout = 0
	} else if options.Timeout == 0 && options.PostInteractionWait > 0 {
		options.Timeout = 120 * time.Second
	}
	if options.NativeFormTrigger {
		if options.InitialWait <= 0 {
			options.InitialWait = 2 * time.Second
		}
		if options.PostInteractionWait <= 0 {
			options.PostInteractionWait = 8 * time.Second
		}
		return options
	}
	if options.AutoTriggerForms {
		if options.InitialWait <= 0 {
			options.InitialWait = 2 * time.Second
		}
		if options.PostInteractionWait <= 0 {
			options.PostInteractionWait = 6 * time.Second
		}
		if options.AutoTriggerAttempts <= 0 {
			options.AutoTriggerAttempts = 3
		}
		if options.AutoTriggerRetryDelay <= 0 {
			options.AutoTriggerRetryDelay = 1500 * time.Millisecond
		}
		return options
	}
	if options.MaxExploreRoutes <= 0 {
		options.MaxExploreRoutes = 8
	}
	if options.MaxRouteClicks <= 0 {
		options.MaxRouteClicks = 8
	}
	if options.RouteInteractionWait <= 0 {
		options.RouteInteractionWait = 2 * time.Second
	}

	if options.InitialWait <= 0 {
		options.InitialWait = defaultScanInitialWait
	}
	if options.PostInteractionWait < 0 {
		options.PostInteractionWait = 0
	}
	return options
}

func waitForBrowserSessionEndAction() chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
}

func nativeFormTriggerAction(options CaptureOptions) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		usernameSelector := strings.TrimSpace(options.UsernameSelector)
		passwordSelector := strings.TrimSpace(options.PasswordSelector)
		submitSelector := strings.TrimSpace(options.SubmitSelector)
		usernameValue := strings.TrimSpace(options.UsernameValue)
		passwordValue := strings.TrimSpace(options.PasswordValue)

		if usernameSelector == "" || passwordSelector == "" || submitSelector == "" {
			return fmt.Errorf("native form trigger requires username/password/submit selectors")
		}

		if err := chromedp.Run(ctx,
			chromedp.WaitVisible(usernameSelector, chromedp.ByQuery),
			chromedp.Click(usernameSelector, chromedp.ByQuery),
		); err != nil {
			return err
		}
		if usernameValue != "" {
			if err := chromedp.Run(ctx, chromedp.SendKeys(usernameSelector, usernameValue, chromedp.ByQuery)); err != nil {
				return err
			}
		}

		if err := chromedp.Run(ctx,
			chromedp.WaitVisible(passwordSelector, chromedp.ByQuery),
			chromedp.Click(passwordSelector, chromedp.ByQuery),
		); err != nil {
			return err
		}
		if passwordValue != "" {
			if err := chromedp.Run(ctx, chromedp.SendKeys(passwordSelector, passwordValue, chromedp.ByQuery)); err != nil {
				return err
			}
		}

		if err := chromedp.Run(ctx,
			chromedp.WaitVisible(submitSelector, chromedp.ByQuery),
			chromedp.Click(submitSelector, chromedp.ByQuery),
		); err != nil {
			return err
		}

		fmt.Printf(
			"[INFO] 原生表单触发已执行 user=%s pass=%s submit=%s\n",
			usernameSelector,
			passwordSelector,
			submitSelector,
		)
		return nil
	})
}

type routeInteractionResult struct {
	PageURL        string   `json:"pageURL"`
	FilledCount    int      `json:"filledCount"`
	ClickedCount   int      `json:"clickedCount"`
	SkippedCount   int      `json:"skippedCount"`
	ButtonTexts    []string `json:"buttonTexts"`
	SkippedButtons []string `json:"skippedButtons"`
}

func frontendRouteInteractionAction(entryURL string, options CaptureOptions, routeProvider func() []FrontendRouteRecord) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		if routeProvider == nil {
			return nil
		}

		routes := buildFrontendRouteExploreURLs(entryURL, routeProvider(), options.MaxExploreRoutes)
		if len(routes) == 0 {
			return nil
		}

		fmt.Printf("[信息] 前端路由动态采集开始 entry=%s routes=%d max_clicks=%d\n", entryURL, len(routes), options.MaxRouteClicks)
		for _, routeURL := range routes {
			if err := chromedp.Run(ctx, chromedp.Navigate(routeURL), chromedp.Sleep(options.RouteInteractionWait)); err != nil {
				fmt.Printf("[警告] 前端路由动态采集导航失败 route=%s err=%v\n", routeURL, err)
				continue
			}

			var result routeInteractionResult
			if err := chromedp.Evaluate(fmt.Sprintf(routeInteractionScript, options.MaxRouteClicks), &result).Do(ctx); err != nil {
				fmt.Printf("[警告] 前端路由动态采集交互失败 route=%s err=%v\n", routeURL, err)
				continue
			}
			if result.PageURL == "" {
				result.PageURL = routeURL
			}
			fmt.Printf(
				"[INFO] 前端路由动态采集 route=%s page=%s filled=%d clicked=%d skipped=%d buttons=%s skipped_buttons=%s\n",
				routeURL,
				result.PageURL,
				result.FilledCount,
				result.ClickedCount,
				result.SkippedCount,
				strings.Join(result.ButtonTexts, "|"),
				strings.Join(result.SkippedButtons, "|"),
			)

			if options.RouteInteractionWait > 0 {
				if err := chromedp.Run(ctx, chromedp.Sleep(options.RouteInteractionWait)); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func buildFrontendRouteExploreURLs(entryURL string, records []FrontendRouteRecord, maxRoutes int) []string {
	if maxRoutes <= 0 {
		maxRoutes = 8
	}
	base := stripURLFragment(strings.TrimSpace(entryURL))
	if base == "" {
		return nil
	}
	hashBase := deriveFrontendRouteHashBase(entryURL)
	if hashBase == "" {
		hashBase = base
	}

	prefixes := deriveFrontendRouteBasePrefixes(entryURL, records)
	seen := map[string]bool{entryURL: true, base: true}
	var routes []string
	for _, record := range records {
		if shouldSkipFrontendRouteExploration(record.Path) {
			continue
		}
		for _, candidate := range frontendRouteURLCandidates(base, hashBase, record.Path, prefixes) {
			if seen[candidate] {
				continue
			}
			seen[candidate] = true
			routes = append(routes, candidate)
			if len(routes) >= maxRoutes {
				return routes
			}
		}
	}
	return routes
}

func deriveFrontendRouteHashBase(entryURL string) string {
	value := strings.TrimSpace(entryURL)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "#") {
		return stripURLFragment(value)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return stripURLFragment(value)
	}
	parsed.Path = "/"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func deriveFrontendRouteBasePrefixes(entryURL string, records []FrontendRouteRecord) []string {
	parsedEntry, err := url.Parse(strings.TrimSpace(entryURL))
	if err != nil {
		return nil
	}

	seen := map[string]bool{}
	var prefixes []string
	appendPrefix := func(value string) {
		value = normalizeFrontendRoutePrefix(value)
		if value == "" || value == "/" || seen[value] {
			return
		}
		seen[value] = true
		prefixes = append(prefixes, value)
	}

	entryPath := strings.TrimSpace(parsedEntry.Path)
	if entryPath != "" && entryPath != "/" {
		if dir := path.Dir(entryPath); dir != "." && dir != "/" {
			appendPrefix(dir)
		}
	}

	normalizedPaths := make([]string, 0, len(records))
	for _, record := range records {
		normalized := normalizeFrontendRouteCandidatePath(record.Path)
		if normalized != "" {
			normalizedPaths = append(normalizedPaths, normalized)
		}
	}
	if current := normalizeFrontendRouteCandidatePath(entryURL); current != "" {
		normalizedPaths = append(normalizedPaths, current)
	}

	for _, current := range normalizedPaths {
		for _, routePath := range normalizedPaths {
			if current == "" || routePath == "" || current == routePath {
				continue
			}
			if !strings.HasSuffix(current, routePath) {
				continue
			}
			prefix := strings.TrimSuffix(current, routePath)
			appendPrefix(prefix)
		}
	}

	return prefixes
}

func shouldSkipFrontendRouteExploration(rawPath string) bool {
	path := strings.TrimSpace(rawPath)
	if path == "" {
		return true
	}
	if parsed, err := url.Parse(path); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		path = parsed.Path
	}
	return strings.Contains(path, ":")
}

func normalizeFrontendRouteCandidatePath(rawPath string) string {
	path := strings.TrimSpace(rawPath)
	if path == "" {
		return ""
	}
	if parsed, err := url.Parse(path); err == nil {
		switch {
		case parsed.Fragment != "" && strings.HasPrefix(parsed.Fragment, "/"):
			path = parsed.Fragment
		case parsed.Path != "":
			path = parsed.Path
		}
	}
	if strings.HasPrefix(path, "#") {
		path = strings.TrimPrefix(path, "#")
	}
	if strings.HasPrefix(path, "/#") {
		path = strings.TrimPrefix(path, "/")
	}
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return normalizeFrontendRoutePrefix(path)
}

func normalizeFrontendRoutePrefix(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	value = strings.ReplaceAll(value, "//", "/")
	value = strings.TrimRight(value, "/")
	if value == "" {
		return "/"
	}
	return value
}

func frontendRouteURLCandidates(base, hashBase, rawPath string, prefixes []string) []string {
	path := strings.TrimSpace(rawPath)
	if path == "" {
		return nil
	}
	if parsed, err := url.Parse(path); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return []string{path}
	}

	if strings.HasPrefix(path, "#") {
		return []string{hashBase + path}
	}

	if strings.HasPrefix(path, "/#") {
		return []string{hashBase + strings.TrimPrefix(path, "/")}
	}

	if strings.HasPrefix(path, "/") {
		candidates := []string{hashBase + "#" + path}
		if parsedBase, err := url.Parse(base); err == nil && parsedBase.Scheme != "" && parsedBase.Host != "" {
			seen := map[string]bool{}
			appendCandidate := func(candidatePath string) {
				candidatePath = normalizeFrontendRoutePrefix(candidatePath)
				if candidatePath == "" {
					return
				}
				next := *parsedBase
				next.Path = candidatePath
				next.RawQuery = ""
				next.Fragment = ""
				candidate := next.String()
				if candidate == "" || seen[candidate] {
					return
				}
				seen[candidate] = true
				candidates = append(candidates, candidate)
			}
			appendCandidate(path)
			for _, prefix := range prefixes {
				if strings.HasPrefix(path, prefix+"/") || path == prefix {
					continue
				}
				appendCandidate(prefix + path)
			}
		}
		return candidates
	}

	return []string{base + "#/" + strings.TrimLeft(path, "/")}
}

func stripURLFragment(value string) string {
	if idx := strings.Index(value, "#"); idx >= 0 {
		return value[:idx]
	}
	return value
}

type autoTriggerResult struct {
	Triggered         bool   `json:"triggered"`
	Reason            string `json:"reason"`
	FormAction        string `json:"formAction"`
	FieldCount        int    `json:"fieldCount"`
	ButtonText        string `json:"buttonText"`
	CandidateCount    int    `json:"candidateCount"`
	RawFieldCount     int    `json:"rawFieldCount"`
	FirstCandidateTag string `json:"firstCandidateTag"`
	FirstCandidateCls string `json:"firstCandidateCls"`
}

func autoTriggerFormsAction(options CaptureOptions) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		for attempt := 0; attempt < options.AutoTriggerAttempts; attempt++ {
			var result autoTriggerResult
			if err := chromedp.Evaluate(autoTriggerFormsScript, &result).Do(ctx); err != nil {
				return err
			}
			if result.Triggered {
				fmt.Printf(
					"[INFO] 自动表单触发成功 attempt=%d fields=%d candidates=%d raw_fields=%d action=%s button=%s reason=%s\n",
					attempt+1,
					result.FieldCount,
					result.CandidateCount,
					result.RawFieldCount,
					strings.TrimSpace(result.FormAction),
					strings.TrimSpace(result.ButtonText),
					strings.TrimSpace(result.Reason),
				)
				return nil
			}
			if attempt == options.AutoTriggerAttempts-1 {
				fmt.Printf(
					"[INFO] 自动表单触发未命中 attempt=%d reason=%s candidates=%d raw_fields=%d first=%s.%s\n",
					attempt+1,
					strings.TrimSpace(result.Reason),
					result.CandidateCount,
					result.RawFieldCount,
					strings.TrimSpace(result.FirstCandidateTag),
					strings.TrimSpace(result.FirstCandidateCls),
				)
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(options.AutoTriggerRetryDelay):
			}
		}
		return nil
	})
}

const autoTriggerFormsScript = `(function () {
  function isVisible(el) {
    if (!el) {
      return false;
    }
    var style = window.getComputedStyle ? window.getComputedStyle(el) : null;
    if (style && (style.display === "none" || style.visibility === "hidden")) {
      return false;
    }
    var rect = el.getBoundingClientRect ? el.getBoundingClientRect() : null;
    if (!rect) {
      return false;
    }
    if (rect.width > 0 && rect.height > 0) {
      return true;
    }
    return !!(el.offsetWidth || el.offsetHeight || (el.getClientRects && el.getClientRects().length));
  }

  function dispatchInputEvents(el) {
    ["input", "change", "blur"].forEach(function (name) {
      try {
        if (name === "input" && typeof InputEvent === "function") {
          el.dispatchEvent(new InputEvent(name, { bubbles: true, inputType: "insertText", data: String(el.value || "") }));
        } else {
          el.dispatchEvent(new Event(name, { bubbles: true }));
        }
      } catch (err) {}
    });
  }

  function setNativeValue(el, value) {
    var proto = el && el.constructor && el.constructor.prototype;
    var descriptor = proto ? Object.getOwnPropertyDescriptor(proto, "value") : null;
    if (descriptor && descriptor.set) {
      descriptor.set.call(el, value);
    } else {
      el.value = value;
    }
  }

  function textFromAssociatedLabel(el) {
    if (!el) {
      return "";
    }
    var parts = [];
    var id = String(el.id || "").trim();
    if (id) {
      var direct = document.querySelector("label[for='" + id.replace(/'/g, "\\'") + "']");
      if (direct) {
        parts.push(direct.innerText || direct.textContent || "");
      }
    }
    var wrapper = el.closest ? el.closest("label, .ant-form-item, .el-form-item, .ivu-form-item, .n-form-item, .van-field, .form-item") : null;
    if (wrapper) {
      var label = wrapper.querySelector ? wrapper.querySelector("label, .ant-form-item-label, .el-form-item__label, .ivu-form-item-label, .n-form-item-label, .van-field__label") : null;
      if (label) {
        parts.push(label.innerText || label.textContent || "");
      }
    }
    return parts.join(" ");
  }

  function deriveFieldLabel(el) {
    return [
      el.name,
      el.id,
      el.placeholder,
      el.getAttribute && el.getAttribute("aria-label"),
      el.getAttribute && el.getAttribute("title"),
      el.getAttribute && el.getAttribute("data-testid"),
      el.getAttribute && el.getAttribute("data-field"),
      el.getAttribute && el.getAttribute("autocomplete"),
      textFromAssociatedLabel(el),
      el.className,
      el.type
    ].map(function (value) {
      return String(value || "");
    }).join(" ").toLowerCase();
  }

  function buildValue(el, index) {
    var label = deriveFieldLabel(el);
    var type = String(el.type || "").toLowerCase();
    var seed = Date.now().toString(36).slice(-6) + String(index || 0);
    if (type === "url" || label.indexOf("url") >= 0 || label.indexOf("endpoint") >= 0 || label.indexOf("link") >= 0 || label.indexOf("地址") >= 0) {
      return "https://example.com";
    }
    if (label.indexOf("target") >= 0 || label.indexOf("host") >= 0 || label.indexOf("domain") >= 0 || label.indexOf("ip") >= 0 || label.indexOf("目标") >= 0 || label.indexOf("主机") >= 0 || label.indexOf("域名") >= 0) {
      return "127.0.0.1";
    }
    if (type === "email" || label.indexOf("mail") >= 0 || label.indexOf("邮箱") >= 0) {
      return "trailblazer+" + seed + "@example.com";
    }
    if (label.indexOf("user") >= 0 || label.indexOf("account") >= 0 || label.indexOf("login") >= 0 || label.indexOf("用户名") >= 0 || label.indexOf("账号") >= 0 || label.indexOf("账户") >= 0) {
      return "trailblazer_user";
    }
    if (type === "password" || label.indexOf("pass") >= 0 || label.indexOf("pwd") >= 0 || label.indexOf("密码") >= 0) {
      return "Tb!" + seed + "Aa1";
    }
    if (type === "tel" || label.indexOf("phone") >= 0 || label.indexOf("mobile") >= 0 || label.indexOf("tel") >= 0 || label.indexOf("手机") >= 0) {
      return "13800138" + String((10 + index) % 90).padStart(2, "0");
    }
    if (type === "number" || /\b(id|count|page|size|num|limit|offset)\b/.test(label) || label.indexOf("页码") >= 0 || label.indexOf("数量") >= 0) {
      var min = Number(el.getAttribute && el.getAttribute("min"));
      var max = Number(el.getAttribute && el.getAttribute("max"));
      var numeric = isFinite(min) ? Math.max(min, 1) : (label.indexOf("page") >= 0 || label.indexOf("页码") >= 0 ? 1 : 10);
      if (isFinite(max)) {
        numeric = Math.min(numeric, max);
      }
      return String(numeric);
    }
    if (type === "date") {
      return "2026-01-01";
    }
    if (type === "datetime-local") {
      return "2026-01-01T00:00";
    }
    if (type === "time") {
      return "00:00";
    }
    if (type === "month") {
      return "2026-01";
    }
    if (label.indexOf("keyword") >= 0 || label.indexOf("search") >= 0 || label.indexOf("query") >= 0 || label.indexOf("filter") >= 0 || label.indexOf("关键词") >= 0 || label.indexOf("搜索") >= 0 || label.indexOf("查询") >= 0 || label.indexOf("筛选") >= 0) {
      return "test";
    }
    if (label.indexOf("code") >= 0 || label.indexOf("captcha") >= 0 || label.indexOf("verify") >= 0 || label.indexOf("验证码") >= 0 || label.indexOf("校验") >= 0) {
      return "1234";
    }
    if (label.indexOf("city") >= 0 || label.indexOf("城市") >= 0) {
      return "Hangzhou";
    }
    if (label.indexOf("province") >= 0 || label.indexOf("省份") >= 0) {
      return "Zhejiang";
    }
    if (label.indexOf("name") >= 0 || label.indexOf("名称") >= 0 || label.indexOf("姓名") >= 0) {
      return "trailblazer";
    }
    return "trailblazer_" + seed;
  }

  function candidateFields(root) {
    return Array.prototype.slice.call(root.querySelectorAll("input, textarea, select, [contenteditable='true'], [role='textbox']")).filter(function (el) {
      if (el.disabled || el.readOnly) {
        return false;
      }
      var type = String(el.type || "").toLowerCase();
      if (["hidden", "submit", "button", "reset", "file", "image"].indexOf(type) >= 0) {
        return false;
      }
      if (isVisible(el)) {
        return true;
      }
      var wrapper = el.closest(".ant-form-item, .ant-input-affix-wrapper, .ant-input, .el-form-item, .el-input, .ivu-form-item, .n-form-item, .van-field, .login-form, .query-form, .search-form, .filter-form, .login, .search, .query, .filter, .form-item");
      return !!(wrapper && isVisible(wrapper));
    });
  }

  function fillFields(fields) {
    var filled = 0;
    fields.forEach(function (el, index) {
      var tag = String(el.tagName || "").toLowerCase();
      var type = String(el.type || "").toLowerCase();
      if (tag === "select") {
        if (String(el.value || "").trim() !== "") {
          dispatchInputEvents(el);
          filled += 1;
          return;
        }
        var nextOption = Array.prototype.slice.call(el.options || []).find(function (option) {
          return !option.disabled && String(option.value || "").trim() !== "";
        });
        if (nextOption) {
          el.value = nextOption.value;
          dispatchInputEvents(el);
          filled += 1;
        }
        return;
      }
      if (type === "checkbox" || type === "radio") {
        el.checked = true;
        dispatchInputEvents(el);
        filled += 1;
        return;
      }
      var value = buildValue(el, index + 1);
      try {
        el.focus();
      } catch (err) {}
      if (el.isContentEditable) {
        if (String(el.innerText || el.textContent || "").trim() === "") {
          el.textContent = value;
        }
        dispatchInputEvents(el);
        filled += 1;
        return;
      }
      if (String(el.value || "").trim() === "") {
        setNativeValue(el, value);
      }
      dispatchInputEvents(el);
      filled += 1;
    });
    return filled;
  }

  function buttonText(el) {
    return String(el.innerText || el.textContent || el.value || el.getAttribute("aria-label") || el.title || "").replace(/\s+/g, " ").trim();
  }

  function isDangerousButton(el) {
    var text = buttonText(el);
    var cls = String((el && el.className) || "").toLowerCase();
    return /(delete|remove|clear|drop|disable|shutdown|logout|log out|run|execute|exec|poc|attack|exploit|删除|移除|清空|禁用|退出|运行|执行|攻击|利用)/i.test(text + " " + cls);
  }

  function chooseSubmitButton(root) {
    var candidates = Array.prototype.slice.call(root.querySelectorAll("button, input[type='submit'], input[type='button'], [role='button']"))
      .filter(function (el) {
        if (el.disabled) {
          return false;
        }
        if (isDangerousButton(el)) {
          return false;
        }
        if (isVisible(el)) {
          return true;
        }
        var wrapper = el.closest(".ant-btn, .el-button, .ivu-btn, .n-button, .van-button, .login-form, .query-form, .search-form, .filter-form, .login, .search, .query, .filter, .form-item");
        return !!(wrapper && isVisible(wrapper));
      });
    if (!candidates.length) {
      return null;
    }
    var preferred = candidates.find(function (el) {
      var text = buttonText(el).toLowerCase();
      var type = String(el.type || "").toLowerCase();
      return type === "submit" || /(login|sign in|signin|submit|next|continue|confirm|query|search|filter|find|refresh|登录|提交|确定|继续|查询|搜索|筛选|查找|刷新)/i.test(text);
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
      "form.search-form",
      "form.query-form",
      "form.filter-form",
      ".search-form",
      ".query-form",
      ".filter-form",
      ".search form",
      ".query form",
      ".filter form",
      ".el-form",
      ".ivu-form",
      ".n-form",
      ".van-form",
      ".login",
      "[role='form']"
    ];
    var preferred = [];
    preferredSelectors.forEach(function (selector) {
      Array.prototype.slice.call(document.querySelectorAll(selector)).forEach(function (node) {
        if (preferred.indexOf(node) < 0) {
          preferred.push(node);
        }
      });
    });
    preferred = preferred.filter(function (node) {
      return isVisible(node) || candidateFields(node).length > 0;
    });
    if (preferred.length) {
      return preferred;
    }

    var forms = Array.prototype.slice.call(document.querySelectorAll("form")).filter(function (node) {
      return isVisible(node) || candidateFields(node).length > 0;
    });
    if (forms.length) {
      return forms;
    }
    var anchorField = Array.prototype.slice.call(document.querySelectorAll("input, textarea, select"))
      .find(function (el) {
        return !el.disabled && candidateFields(el.form || el.closest("form, .login-form, .query-form, .search-form, .filter-form, .login, .query, .search, .filter, .ant-form, .el-form, .ivu-form, .n-form, .van-form, [role='form']") || document.body).length > 0;
      });
    if (!anchorField) {
      return [];
    }
    var container = anchorField.closest("[role='form'], .ant-form, .el-form, .ivu-form, .n-form, .van-form, .login, .query, .search, .filter, .login-form, .query-form, .search-form, .filter-form, .form") ||
      anchorField.parentElement || document.body;
    return container ? [container] : [];
  }

  var candidates = formCandidates();
  if (!candidates.length) {
    return { triggered: false, reason: "no_visible_form", candidateCount: 0, rawFieldCount: 0 };
  }

  var firstCandidate = candidates[0];
  var rawFieldCount = firstCandidate ? firstCandidate.querySelectorAll("input, textarea, select").length : 0;
  var firstCandidateTag = firstCandidate && firstCandidate.tagName ? String(firstCandidate.tagName).toLowerCase() : "";
  var firstCandidateCls = firstCandidate ? String(firstCandidate.className || "") : "";

  for (var i = 0; i < candidates.length; i++) {
    var root = candidates[i];
    if (root.__trailblazerAutoTriggered) {
      continue;
    }
    var fields = candidateFields(root);
    if (!fields.length) {
      continue;
    }
    var button = chooseSubmitButton(root);
    var filled = fillFields(fields);
    root.__trailblazerAutoTriggered = true;
    if (button && typeof button.click === "function") {
      button.click();
      return {
        triggered: true,
        reason: "clicked_submit_control",
        formAction: String(root.action || ""),
        fieldCount: filled,
        buttonText: String(button.innerText || button.textContent || button.value || ""),
        candidateCount: candidates.length,
        rawFieldCount: root.querySelectorAll("input, textarea, select").length,
        firstCandidateTag: firstCandidateTag,
        firstCandidateCls: firstCandidateCls
      };
    }
    if (root.tagName && String(root.tagName).toLowerCase() === "form" && typeof root.requestSubmit === "function") {
      root.requestSubmit();
      return {
        triggered: true,
        reason: "request_submit",
        formAction: String(root.action || ""),
        fieldCount: filled,
        buttonText: "",
        candidateCount: candidates.length,
        rawFieldCount: root.querySelectorAll("input, textarea, select").length,
        firstCandidateTag: firstCandidateTag,
        firstCandidateCls: firstCandidateCls
      };
    }
    if (root.tagName && String(root.tagName).toLowerCase() === "form" && typeof root.submit === "function") {
      root.submit();
      return {
        triggered: true,
        reason: "submit",
        formAction: String(root.action || ""),
        fieldCount: filled,
        buttonText: "",
        candidateCount: candidates.length,
        rawFieldCount: root.querySelectorAll("input, textarea, select").length,
        firstCandidateTag: firstCandidateTag,
        firstCandidateCls: firstCandidateCls
      };
    }
    return {
      triggered: filled > 0,
      reason: filled > 0 ? "filled_only" : "no_fillable_fields",
      formAction: String(root.action || ""),
      fieldCount: filled,
      buttonText: "",
      candidateCount: candidates.length,
      rawFieldCount: root.querySelectorAll("input, textarea, select").length,
      firstCandidateTag: firstCandidateTag,
      firstCandidateCls: firstCandidateCls
    };
  }

  return {
    triggered: false,
    reason: "no_fillable_form",
    candidateCount: candidates.length,
    rawFieldCount: rawFieldCount,
    firstCandidateTag: firstCandidateTag,
    firstCandidateCls: firstCandidateCls
  };
})()`

const routeInteractionScript = `(function () {
  var maxClicks = %d;
  function isVisible(el) {
    if (!el) return false;
    var style = window.getComputedStyle ? window.getComputedStyle(el) : null;
    if (style && (style.display === "none" || style.visibility === "hidden" || style.opacity === "0")) return false;
    var rect = el.getBoundingClientRect ? el.getBoundingClientRect() : null;
    if (!rect) return false;
    return (rect.width > 0 && rect.height > 0) || !!(el.offsetWidth || el.offsetHeight || (el.getClientRects && el.getClientRects().length));
  }
  function dispatchInputEvents(el) {
    ["input", "change", "blur"].forEach(function (name) {
      try { el.dispatchEvent(new Event(name, { bubbles: true })); } catch (err) {}
    });
  }
  function fieldLabel(el) {
    return String(el.name || el.id || el.placeholder || el.getAttribute("aria-label") || el.type || "").toLowerCase();
  }
  function buildValue(el, index) {
    var label = fieldLabel(el);
    var type = String(el.type || "").toLowerCase();
    if (type === "url" || label.indexOf("url") >= 0 || label.indexOf("endpoint") >= 0 || label.indexOf("link") >= 0 || label.indexOf("地址") >= 0) return "http://example.com";
    if (label.indexOf("target") >= 0 || label.indexOf("host") >= 0 || label.indexOf("ip") >= 0 || label.indexOf("目标") >= 0) return "127.0.0.1";
    if (type === "email" || label.indexOf("mail") >= 0 || label.indexOf("邮箱") >= 0) return "test@example.com";
    if (type === "password" || label.indexOf("pass") >= 0 || label.indexOf("pwd") >= 0 || label.indexOf("密码") >= 0) return "Test@123456";
    if (type === "tel" || label.indexOf("phone") >= 0 || label.indexOf("mobile") >= 0 || label.indexOf("手机") >= 0) return "13800138000";
    if (type === "number" || /\b(id|count|page|size|num)\b/.test(label)) return String(index || 1);
    if (type === "date") return "2026-01-01";
    if (label.indexOf("keyword") >= 0 || label.indexOf("search") >= 0 || label.indexOf("query") >= 0 || label.indexOf("关键词") >= 0) return "test";
    return "trailblazer_test_" + String(index || 1);
  }
  function fillFields() {
    var fields = Array.prototype.slice.call(document.querySelectorAll("input, textarea, select")).filter(function (el) {
      var type = String(el.type || "").toLowerCase();
      return !el.disabled && !el.readOnly && ["hidden", "submit", "button", "reset", "file", "image"].indexOf(type) < 0 && isVisible(el);
    });
    var filled = 0;
    fields.forEach(function (el, index) {
      var tag = String(el.tagName || "").toLowerCase();
      var type = String(el.type || "").toLowerCase();
      if (tag === "select") {
        var option = Array.prototype.slice.call(el.options || []).find(function (item) {
          return !item.disabled && String(item.value || "").trim() !== "";
        });
        if (option) {
          el.value = option.value;
          dispatchInputEvents(el);
          filled += 1;
        }
        return;
      }
      if (type === "checkbox" || type === "radio") {
        el.checked = true;
        dispatchInputEvents(el);
        filled += 1;
        return;
      }
      try { el.focus(); } catch (err) {}
      el.value = buildValue(el, index + 1);
      dispatchInputEvents(el);
      filled += 1;
    });
    return filled;
  }
  function buttonText(el) {
    var direct = String(el.innerText || el.textContent || el.value || el.getAttribute("aria-label") || el.title || "").replace(/\s+/g, " ").trim();
    if (direct) return direct;
    var field = el.querySelector ? el.querySelector("input, textarea") : null;
    if (!field) return "";
    return String(field.value || field.getAttribute("placeholder") || field.getAttribute("aria-label") || field.title || "").replace(/\s+/g, " ").trim();
  }
  function className(el) {
    return String((el && el.className) || "").toLowerCase();
  }
  function isDangerousButton(text) {
    return /(delete|remove|clear|drop|disable|shutdown|logout|log out|run|execute|exec|poc|attack|exploit|删除|移除|清空|禁用|退出|运行|执行|攻击|利用)/i.test(text);
  }
  function isNativeFormField(el) {
    if (!el || !el.tagName) return false;
    var tag = String(el.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select" || tag === "option") return true;
    if (el.isContentEditable) return true;
    return false;
  }
  function hasFrameworkClickableClass(el) {
    var cls = className(el);
    return /(^|\s)(el-button|el-link|el-dropdown-link|el-select|el-cascader|el-date-editor|el-upload|el-pagination__sizes|ant-btn|ant-select-selector|ant-picker|ant-dropdown-trigger|ant-pagination-item-link|ivu-btn|ivu-select-selection|ivu-page-item|ivu-page-next|ivu-page-prev|n-button|n-base-selection|my_export)(\s|$)/.test(cls);
  }
  function hasInteractiveDescendant(el) {
    if (!el || !el.querySelector) return false;
    return !!el.querySelector([
      "button",
      "a[href]",
      "[role='button']",
      "[role='link']",
      "[onclick]",
      "[tabindex]",
      "[aria-haspopup]",
      "[aria-expanded]",
      "[aria-controls]",
      "[data-target]",
      "[data-toggle]",
      "[data-action]",
      "[data-click]",
      "[data-testid]",
      "i[class*='icon']",
      "svg",
      ".el-icon-upload",
      ".el-icon-download"
    ].join(", "));
  }
  function isLikelyActionText(text) {
    return !!(text && text.length <= 24 && /(query|search|filter|submit|confirm|next|refresh|import|export|download|upload|select|choose|open|more|查询|搜索|筛选|提交|确定|继续|刷新|导入|导出|下载|上传|选择|打开|更多)/i.test(text));
  }
  function hasClickSignal(el) {
    if (!el || !el.tagName) return false;
    var tag = String(el.tagName || "").toLowerCase();
    var role = String(el.getAttribute("role") || "").toLowerCase();
    var href = String(el.getAttribute("href") || "").trim();
    var tabIndex = String(el.getAttribute("tabindex") || "").trim();
    var style = window.getComputedStyle ? window.getComputedStyle(el) : null;
    var ariaHaspopup = String(el.getAttribute("aria-haspopup") || "").toLowerCase();
    var ariaExpanded = el.getAttribute("aria-expanded");
    var ariaControls = String(el.getAttribute("aria-controls") || "").trim();
    var dataTarget = String(el.getAttribute("data-target") || el.getAttribute("data-toggle") || "").trim();
    if (tag === "button" || tag === "summary") return true;
    if (tag === "a" && href && href !== "#" && !/^javascript:/i.test(href)) return true;
    if (tag === "label" && String(el.getAttribute("for") || "").trim()) return true;
    if (role === "button" || role === "link" || role === "menuitem" || role === "tab") return true;
    if (typeof el.onclick === "function" || el.hasAttribute("onclick")) return true;
    if (tabIndex && tabIndex !== "-1") return true;
    if (ariaHaspopup === "true" || ariaHaspopup === "menu" || ariaHaspopup === "listbox" || ariaExpanded === "true" || ariaExpanded === "false") return true;
    if (ariaControls || dataTarget) return true;
    if (style && style.cursor === "pointer") return true;
    if (el.hasAttribute("data-action") || el.hasAttribute("data-click") || el.hasAttribute("data-testid")) return true;
    var text = buttonText(el);
    if (text && text.length <= 16 && /(import|export|download|upload|导入|导出|下载|上传)/i.test(text)) return true;
    if (isLikelyActionText(text) && hasInteractiveDescendant(el)) return true;
    if (isLikelyActionText(text) && /action|operate|toolbar|tools|op|btn|button|link|export|import|download|upload|search|query|filter|page|pager|select|choice|my_export|操作|工具|按钮|链接|导出|导入|下载|上传|查询|筛选|分页|下拉/.test(className(el))) return true;
    if (hasFrameworkClickableClass(el)) return true;
    return false;
  }
  function normalizeClickableTarget(el) {
    if (!el || !el.closest) return el;
    return el.closest([
      "button",
      "a[href]",
      "label[for]",
      "input[type='submit']",
      "input[type='button']",
      "[role='button']",
      "[role='link']",
      "[role='menuitem']",
      "[role='tab']",
      ".el-button",
      ".el-link",
      ".el-dropdown-link",
      ".el-select",
      ".el-cascader",
      ".el-date-editor",
      ".el-upload",
      ".my_export",
      "[class*='export']",
      "[class*='import']",
      "[class*='download']",
      "[class*='upload']",
      "[class*='action']",
      "[class*='operate']",
      "[class*='toolbar']",
      "[class*='tools']",
      "[class*='btn']",
      "[class*='button']",
      "[class*='link']",
      "[class*='search']",
      "[class*='query']",
      "[class*='filter']",
      "[class*='page']",
      "[class*='pager']",
      "[class*='select']",
      ".el-pagination .btn-prev",
      ".el-pagination .btn-next",
      ".el-pagination__sizes",
      ".ant-btn",
      ".ant-select-selector",
      ".ant-picker",
      ".ant-dropdown-trigger",
      ".ant-pagination-prev",
      ".ant-pagination-next",
      ".ant-pagination-item",
      ".ivu-btn",
      ".ivu-select-selection",
      ".ivu-page-prev",
      ".ivu-page-next",
      ".ivu-page-item",
      ".n-button",
      ".n-base-selection"
    ].join(", ")) || el;
  }
  function isOversizedContainer(el) {
    if (!el || !el.getBoundingClientRect) return false;
    var rect = el.getBoundingClientRect();
    var viewportW = window.innerWidth || document.documentElement.clientWidth || 0;
    var viewportH = window.innerHeight || document.documentElement.clientHeight || 0;
    if (!viewportW || !viewportH) return false;
    return rect.width >= viewportW * 0.8 && rect.height >= viewportH * 0.25;
  }
  function collectClickableTargets() {
    var selector = [
      "button",
      "a[href]",
      "label[for]",
      "input[type='submit']",
      "input[type='button']",
      "[role='button']",
      "[role='link']",
      "[role='menuitem']",
      "[role='tab']",
      "[aria-haspopup]",
      "[aria-expanded]",
      "[aria-controls]",
      "[onclick]",
      "[tabindex]",
      "[data-target]",
      "[data-toggle]",
      "[data-action]",
      "[data-click]",
      "[data-testid]",
      ".el-button",
      ".el-link",
      ".el-dropdown-link",
      ".el-select",
      ".el-cascader",
      ".el-date-editor",
      ".el-upload",
      ".my_export",
      "[class*='export']",
      "[class*='import']",
      "[class*='download']",
      "[class*='upload']",
      "[class*='action']",
      "[class*='operate']",
      "[class*='toolbar']",
      "[class*='tools']",
      "[class*='btn']",
      "[class*='button']",
      "[class*='link']",
      "[class*='search']",
      "[class*='query']",
      "[class*='filter']",
      "[class*='page']",
      "[class*='pager']",
      "[class*='select']",
      ".el-pagination .btn-prev",
      ".el-pagination .btn-next",
      ".el-pagination__sizes",
      ".ant-btn",
      ".ant-select-selector",
      ".ant-picker",
      ".ant-dropdown-trigger",
      ".ant-pagination-prev",
      ".ant-pagination-next",
      ".ant-pagination-item",
      ".ivu-btn",
      ".ivu-select-selection",
      ".ivu-page-prev",
      ".ivu-page-next",
      ".ivu-page-item",
      ".n-button",
      ".n-base-selection"
    ].join(", ");
    var seen = [];
    return Array.prototype.slice.call(document.querySelectorAll(selector)).map(function (el) {
      return normalizeClickableTarget(el);
    }).filter(function (target) {
      if (!target || seen.indexOf(target) >= 0) return false;
      seen.push(target);
      if (target.disabled || target.getAttribute("aria-disabled") === "true") return false;
      if (!isVisible(target)) return false;
      if (isNativeFormField(target)) return false;
      if (!hasClickSignal(target)) return false;
      if (isOversizedContainer(target)) return false;
      return true;
    });
  }
  var filled = fillFields();
  var buttons = collectClickableTargets();
  var clicked = [];
  var skipped = [];
  buttons.forEach(function (el) {
    var text = buttonText(el);
    if (clicked.length >= maxClicks) return;
    if (isDangerousButton(text)) {
      if (text) skipped.push(text);
      return;
    }
    try {
      el.click();
      clicked.push(text || String(el.className || "button"));
    } catch (err) {
      if (text) skipped.push(text);
    }
  });
  return {
    pageURL: String(window.location.href || ""),
    filledCount: filled,
    clickedCount: clicked.length,
    skippedCount: skipped.length,
    buttonTexts: clicked.slice(0, 20),
    skippedButtons: skipped.slice(0, 20)
  };
})()`

func appendAPIRecord(apiRecordSet map[string]bool, apiRecords *[]NetworkRecord, record *NetworkRecord) {
	if record == nil || !isAPIResource(record) {
		return
	}

	key := record.Method + "|" + record.URL + "|" + record.RequestBody
	if apiRecordSet[key] {
		return
	}
	apiRecordSet[key] = true
	*apiRecords = append(*apiRecords, *record)
	logRouteCapturedAPIRecord(record)
}

func logRouteCapturedAPIRecord(record *NetworkRecord) {
	if record == nil {
		return
	}
	pageURL := strings.TrimSpace(record.PageURL)
	if pageURL == "" || !looksLikeFrontendRoutePage(pageURL) {
		return
	}

	fmt.Printf(
		"[INFO] 前端路由接口采集 route=%s method=%s api=%s params=%s body=%s\n",
		pageURL,
		strings.TrimSpace(record.Method),
		strings.TrimSpace(record.URL),
		formatCapturedQueryParams(record.URL),
		formatCapturedBodyPreview(record.RequestBody),
	)
}

func looksLikeFrontendRoutePage(pageURL string) bool {
	if strings.Contains(pageURL, "#/") || strings.Contains(pageURL, "#!") {
		return true
	}
	parsed, err := url.Parse(pageURL)
	if err != nil {
		return false
	}
	path := strings.Trim(parsed.Path, "/")
	return path != "" && !strings.Contains(path, ".")
}

func formatCapturedQueryParams(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.RawQuery == "" {
		return "-"
	}
	return limitCapturedBody(parsed.RawQuery, 512, "查询参数过长，已截断")
}

func formatCapturedBodyPreview(body string) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return "-"
	}
	return limitCapturedBody(body, 1024, "请求体过长，已截断")
}

func upsertProtocolTraceRecord(traceIndex map[string]int, traces *[]ProtocolTraceRecord, record ProtocolTraceRecord) {
	record.normalize()
	traceKey := protocolTraceKey(record)
	if idx, ok := traceIndex[traceKey]; ok {
		mergeProtocolTraceRecord(&(*traces)[idx], record)
		return
	}
	if !shouldOutputProtocolTraceRecord(record) {
		return
	}

	traceIndex[traceKey] = len(*traces)
	*traces = append(*traces, record)
}

func shouldOutputProtocolTraceRecord(record ProtocolTraceRecord) bool {
	if hasMeaningfulCapturedProtocolSignal(&record) {
		return true
	}
	return hasCapturedProtocolCryptoMaterial(&record)
}

func hasCapturedProtocolCryptoMaterial(record *ProtocolTraceRecord) bool {
	if record == nil {
		return false
	}

	hasKeyMaterial := false
	for _, key := range []string{"sm4_key_hex", "crypto_key_raw", "key_exchange_public_key"} {
		if strings.TrimSpace(record.SessionMaterials[key]) != "" {
			hasKeyMaterial = true
			break
		}
	}

	requestCiphertext := firstNonEmptyCapturedProtocolString(
		record.SessionMaterials["latest_ciphertext"],
		record.FinalRequestBody,
	)
	requestPlaintext := firstNonEmptyCapturedProtocolString(
		record.SessionMaterials["latest_plaintext"],
		record.RequestBeforeTransform,
	)
	responseCiphertext := strings.TrimSpace(record.SessionMaterials["latest_response_ciphertext"])
	responsePlaintext := strings.TrimSpace(record.SessionMaterials["latest_response_plaintext"])

	if hasKeyMaterial && (requestCiphertext != "" || responseCiphertext != "" || requestPlaintext != "" || responsePlaintext != "") {
		return true
	}
	if responseCiphertext != "" && responsePlaintext != "" && responseCiphertext != responsePlaintext {
		return true
	}
	return requestCiphertext != "" && requestPlaintext != "" && requestCiphertext != requestPlaintext && isLikelyCapturedCiphertext(requestCiphertext)
}

func upsertFrontendRouteRecord(routeIndex map[string]int, routes *[]FrontendRouteRecord, record FrontendRouteRecord) {
	record.Path = strings.TrimSpace(record.Path)
	record.Name = strings.TrimSpace(record.Name)
	record.SourceKind = strings.TrimSpace(record.SourceKind)
	record.Source = strings.TrimSpace(record.Source)
	record.PageURL = strings.TrimSpace(record.PageURL)
	if record.Path == "" {
		return
	}
	if record.DiscoveredAt.IsZero() {
		record.DiscoveredAt = time.Now()
	}

	key := frontendRouteKey(record)
	if idx, ok := routeIndex[key]; ok {
		existing := &(*routes)[idx]
		if existing.Name == "" {
			existing.Name = record.Name
		}
		if existing.SourceKind == "" {
			existing.SourceKind = record.SourceKind
		}
		if existing.Source == "" {
			existing.Source = record.Source
		}
		if existing.PageURL == "" {
			existing.PageURL = record.PageURL
		}
		if record.DiscoveredAt.After(existing.DiscoveredAt) {
			existing.DiscoveredAt = record.DiscoveredAt
		}
		return
	}

	routeIndex[key] = len(*routes)
	*routes = append(*routes, record)
}

func frontendRouteKey(record FrontendRouteRecord) string {
	return record.Path + "|" + record.Name + "|" + record.SourceKind
}

func protocolTraceKey(record ProtocolTraceRecord) string {
	if record.TraceID != "" {
		return record.TraceID
	}
	return record.Method + "|" + record.RequestURL + "|" + record.FinalRequestBody
}

func mergeProtocolTraceRecord(dst *ProtocolTraceRecord, src ProtocolTraceRecord) {
	if dst == nil {
		return
	}

	if dst.TaskID == "" {
		dst.TaskID = src.TaskID
	}
	if dst.TraceID == "" {
		dst.TraceID = src.TraceID
	}
	if dst.Transport == "" {
		dst.Transport = src.Transport
	}
	if dst.PageURL == "" {
		dst.PageURL = src.PageURL
	}
	if dst.RequestURL == "" {
		dst.RequestURL = src.RequestURL
	}
	if dst.Method == "" {
		dst.Method = src.Method
	}
	if dst.RequestBeforeTransform == "" {
		dst.RequestBeforeTransform = src.RequestBeforeTransform
	}
	if dst.FinalRequestBody == "" {
		dst.FinalRequestBody = src.FinalRequestBody
	}
	if dst.Stack == "" {
		dst.Stack = src.Stack
	}
	if src.CapturedAtMS > dst.CapturedAtMS {
		dst.CapturedAtMS = src.CapturedAtMS
	}
	if dst.CreatedAt.IsZero() || (!src.CreatedAt.IsZero() && src.CreatedAt.After(dst.CreatedAt)) {
		dst.CreatedAt = src.CreatedAt
	}

	dst.RequestHeaders = mergeStringMaps(dst.RequestHeaders, src.RequestHeaders)
	dst.DynamicParams = mergeStringMaps(dst.DynamicParams, src.DynamicParams)
	dst.SessionMaterials = mergeStringMaps(dst.SessionMaterials, src.SessionMaterials)
	dst.SignatureFields = mergeUniqueStrings(dst.SignatureFields, src.SignatureFields)
	dst.RequestSteps = mergeCryptoSteps(dst.RequestSteps, src.RequestSteps)
	dst.ResponseSteps = mergeCryptoSteps(dst.ResponseSteps, src.ResponseSteps)
	dst.normalize()
}

func mergeStringMaps(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]string, len(src))
	}
	for key, value := range src {
		if value == "" {
			continue
		}
		dst[key] = value
	}
	return dst
}

func mergeUniqueStrings(dst, src []string) []string {
	if len(src) == 0 {
		return dst
	}
	seen := make(map[string]bool, len(dst))
	for _, item := range dst {
		seen[item] = true
	}
	for _, item := range src {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		dst = append(dst, item)
	}
	return dst
}

func mergeCryptoSteps(dst, src []ProtocolCryptoStep) []ProtocolCryptoStep {
	if len(src) == 0 {
		return dst
	}
	seen := make(map[string]bool, len(dst))
	for _, step := range dst {
		seen[protocolCryptoStepKey(step)] = true
	}
	for _, step := range src {
		key := protocolCryptoStepKey(step)
		if seen[key] {
			continue
		}
		seen[key] = true
		dst = append(dst, step)
	}
	return dst
}

func protocolCryptoStepKey(step ProtocolCryptoStep) string {
	return step.Source + "|" + step.Algorithm + "|" + step.InputPreview + "|" + step.OutputPreview + "|" + step.CallID + "|" + step.ParentCallID + "|" + step.FunctionPath + "|" + step.ModuleID + "|" + step.Stack
}

func backfillProtocolTraceResponsesFromAPIRecords(traces []ProtocolTraceRecord, apiRecords []NetworkRecord) {
	if len(traces) == 0 || len(apiRecords) == 0 {
		return
	}

	traceIndicesByKey := make(map[string][]int)
	traceCursorByKey := make(map[string]int)
	for idx := range traces {
		key := protocolTraceResponseKey(traces[idx].Method, traces[idx].RequestURL)
		traceIndicesByKey[key] = append(traceIndicesByKey[key], idx)
	}

	for _, record := range apiRecords {
		if strings.TrimSpace(record.ResponseBody) == "" {
			continue
		}

		key := protocolTraceResponseKey(record.Method, record.URL)
		indices := traceIndicesByKey[key]
		if len(indices) == 0 {
			logUnmatchedAPIResponseForTrace(record)
			continue
		}

		cursor := traceCursorByKey[key]
		matched := false
		for ; cursor < len(indices); cursor++ {
			trace := &traces[indices[cursor]]
			if trace.SessionMaterials == nil {
				trace.SessionMaterials = make(map[string]string)
			}

			if isLikelyPlaintextResponse(record) {
				if trace.SessionMaterials["latest_response_plaintext"] == "" {
					trace.SessionMaterials["latest_response_plaintext"] = record.ResponseBody
				}
			} else {
				if trace.SessionMaterials["latest_response_ciphertext"] == "" {
					trace.SessionMaterials["latest_response_ciphertext"] = record.ResponseBody
				}
			}
			trace.normalize()
			traceCursorByKey[key] = cursor + 1
			matched = true
			break
		}
		if !matched {
			logTraceResponseBackfillExhausted(record, len(indices))
		}
	}
}

func protocolTraceResponseKey(method, requestURL string) string {
	return normalizeProtocolMethod(method) + "|" + strings.TrimSpace(requestURL)
}

func linkAPIRecordsToProtocolTraces(apiRecords []NetworkRecord, traces []ProtocolTraceRecord) {
	if len(apiRecords) == 0 || len(traces) == 0 {
		return
	}

	traceIndexByRequest := make(map[string][]int)
	traceCursorByRequest := make(map[string]int)
	for idx := range traces {
		key := protocolTraceRequestKey(traces[idx].Method, traces[idx].RequestURL, traces[idx].FinalRequestBody)
		traceIndexByRequest[key] = append(traceIndexByRequest[key], idx)
	}

	for idx := range apiRecords {
		key := protocolTraceRequestKey(apiRecords[idx].Method, apiRecords[idx].URL, apiRecords[idx].RequestBody)
		indices := traceIndexByRequest[key]
		if len(indices) == 0 {
			apiRecords[idx].HasProtocolTrace = false
			logAPIRecordTraceLinkMiss(apiRecords[idx], "no-request-match")
			continue
		}

		cursor := traceCursorByRequest[key]
		if cursor >= len(indices) {
			cursor = len(indices) - 1
		}
		if cursor < 0 {
			apiRecords[idx].HasProtocolTrace = false
			logAPIRecordTraceLinkMiss(apiRecords[idx], "invalid-cursor")
			continue
		}

		trace := traces[indices[cursor]]
		if strings.TrimSpace(trace.TraceID) == "" {
			apiRecords[idx].HasProtocolTrace = false
			logAPIRecordTraceLinkMiss(apiRecords[idx], "empty-trace-id")
			continue
		}

		apiRecords[idx].TraceID = trace.TraceID
		apiRecords[idx].HasProtocolTrace = true
		traceCursorByRequest[key] = cursor + 1
	}
}

func protocolTraceRequestKey(method, requestURL, requestBody string) string {
	return normalizeProtocolMethod(method) + "|" + strings.TrimSpace(requestURL) + "|" + strings.TrimSpace(requestBody)
}

func isLikelyPlaintextResponse(record NetworkRecord) bool {
	body := strings.TrimSpace(record.ResponseBody)
	if isLikelyEncodedPayloadResponse(body) {
		return false
	}

	mimeType := strings.ToLower(strings.TrimSpace(record.MIMEType))
	if strings.Contains(mimeType, "json") || strings.Contains(mimeType, "text") || strings.Contains(mimeType, "javascript") || strings.Contains(mimeType, "xml") {
		return true
	}

	return strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[")
}

func isLikelyEncodedPayloadResponse(body string) bool {
	trimmed := strings.TrimSpace(body)
	if len(trimmed) >= 2 && strings.HasPrefix(trimmed, `"`) && strings.HasSuffix(trimmed, `"`) {
		trimmed = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	}
	if len(trimmed) < 48 {
		return false
	}
	if !strings.ContainsAny(trimmed, "{[") {
		if isHexString(trimmed) && len(trimmed)%2 == 0 {
			return true
		}
		if isBase64Like(trimmed) {
			return true
		}
	}
	return false
}

func logResponseBodyCaptureFailure(requestID network.RequestID, record *NetworkRecord, err error) {
	if record == nil || err == nil {
		return
	}
	fmt.Printf(
		"[WARN] chromedp 响应体抓取失败 request_id=%s method=%s url=%s status=%d type=%s mime=%s err=%v\n",
		requestID,
		strings.TrimSpace(record.Method),
		strings.TrimSpace(record.URL),
		record.ResponseCode,
		strings.TrimSpace(record.ResourceType),
		strings.TrimSpace(record.MIMEType),
		err,
	)
}

func logEmptyAPIResponseBody(requestID network.RequestID, record *NetworkRecord, rawBodySize int) {
	if record == nil {
		return
	}
	fmt.Printf(
		"[WARN] API 响应完成但 body 为空 request_id=%s method=%s url=%s status=%d type=%s mime=%s raw_body_size=%d\n",
		requestID,
		strings.TrimSpace(record.Method),
		strings.TrimSpace(record.URL),
		record.ResponseCode,
		strings.TrimSpace(record.ResourceType),
		strings.TrimSpace(record.MIMEType),
		rawBodySize,
	)
}

func logUnmatchedAPIResponseForTrace(record NetworkRecord) {
	fmt.Printf(
		"[WARN] API 响应未找到可回填的协议轨迹 method=%s url=%s status=%d mime=%s response_len=%d\n",
		strings.TrimSpace(record.Method),
		strings.TrimSpace(record.URL),
		record.ResponseCode,
		strings.TrimSpace(record.MIMEType),
		len(record.ResponseBody),
	)
}

func logTraceResponseBackfillExhausted(record NetworkRecord, candidateCount int) {
	fmt.Printf(
		"[WARN] API 响应存在候选协议轨迹但未完成回填 method=%s url=%s candidates=%d status=%d response_len=%d\n",
		strings.TrimSpace(record.Method),
		strings.TrimSpace(record.URL),
		candidateCount,
		record.ResponseCode,
		len(record.ResponseBody),
	)
}

func logAPIRecordTraceLinkMiss(record NetworkRecord, reason string) {
	fmt.Printf(
		"[WARN] API 记录未关联到协议轨迹 reason=%s method=%s url=%s request_len=%d response_len=%d\n",
		reason,
		strings.TrimSpace(record.Method),
		strings.TrimSpace(record.URL),
		len(record.RequestBody),
		len(record.ResponseBody),
	)
}

func isHexString(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
			return false
		}
	}
	return true
}

func isBase64Like(value string) bool {
	if value == "" || len(value)%4 != 0 {
		return false
	}
	for _, ch := range value {
		if (ch < 'A' || ch > 'Z') &&
			(ch < 'a' || ch > 'z') &&
			(ch < '0' || ch > '9') &&
			ch != '+' && ch != '/' && ch != '-' && ch != '_' && ch != '=' {
			return false
		}
	}
	return true
}

func normalizeCapturedResponseBody(mimeType string, responseBody []byte) string {
	if len(responseBody) == 0 {
		return ""
	}
	if shouldStoreCapturedBodyAsText(mimeType, responseBody) {
		return limitCapturedBody(string(responseBody), maxCapturedResponseBodySize, "响应体过长，已截断")
	}
	return limitCapturedBody(base64.StdEncoding.EncodeToString(responseBody), maxCapturedResponseBodySize, "响应体过长，已截断")
}

func shouldStoreCapturedBodyAsText(mimeType string, responseBody []byte) bool {
	if len(responseBody) == 0 || !utf8.Valid(responseBody) {
		return false
	}

	body := strings.TrimSpace(string(responseBody))
	if strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[") {
		return true
	}

	mimeType = strings.ToLower(strings.TrimSpace(mimeType))
	if strings.Contains(mimeType, "json") || strings.Contains(mimeType, "javascript") || strings.Contains(mimeType, "xml") || strings.Contains(mimeType, "html") {
		return true
	}

	printable := 0
	for _, r := range body {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r < 127) {
			printable++
		}
	}
	return printable >= len(body)*9/10
}

func isHTTPURL(rawURL string) bool {
	return strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://")
}

func isAPIResource(record *NetworkRecord) bool {
	if record == nil {
		return false
	}

	switch strings.ToLower(record.ResourceType) {
	case "xhr", "fetch":
		return true
	default:
		return false
	}
}

func stringifyHeaders(headers network.Headers) map[string]string {
	if len(headers) == 0 {
		return nil
	}

	result := make(map[string]string, len(headers))
	for key, value := range headers {
		result[key] = fmt.Sprint(value)
	}
	return result
}

func limitCapturedBody(body string, maxSize int, message string) string {
	if body == "" || len(body) <= maxSize {
		return body
	}
	return body[:maxSize] + "\n...[内容过长，" + message + "]"
}
