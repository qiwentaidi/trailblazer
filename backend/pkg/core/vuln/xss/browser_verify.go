package xss

import (
	"context"
	"encoding/json"
	"time"
	"trailblazer/pkg/core/structs"
	"trailblazer/pkg/core/vuln"

	cdruntime "github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

func verifyReflectedXSSExecutionInBrowser(apiReq structs.APIRequest, payload, responseBody string) bool {
	if !shouldAttemptBrowserVerification(apiReq, responseBody) {
		return false
	}

	marker := extractExecutionMarker(payload)
	if marker == "" {
		return false
	}

	pageURL, _ := vuln.ResolveAPIRequestTransport(apiReq)
	if pageURL == "" {
		return false
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	tabCtx, tabCancel := chromedp.NewContext(allocCtx)
	defer tabCancel()

	ctx, cancel := context.WithTimeout(tabCtx, 12*time.Second)
	defer cancel()

	var evalResult string
	err := chromedp.Run(ctx,
		chromedp.Navigate(pageURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(1200*time.Millisecond),
		chromedp.ActionFunc(func(ctx context.Context) error {
			result, _, err := cdruntime.Evaluate(`(function() {
				var hit = window.__TB_XSS_HIT__;
				if (typeof hit === 'string') {
					return hit;
				}
				var attr = document.documentElement && document.documentElement.getAttribute('data-tb-xss-hit');
				return attr || '';
			})()`).
				WithReturnByValue(true).
				Do(ctx)
			if err != nil {
				return err
			}
			if result != nil && len(result.Value) > 0 {
				if err := json.Unmarshal(result.Value, &evalResult); err != nil {
					return err
				}
			}
			return nil
		}),
	)
	if err != nil {
		return false
	}

	return evalResult == marker
}
