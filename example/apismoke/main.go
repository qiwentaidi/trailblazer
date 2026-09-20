// apismoke 是 trailblazer SDK 接口资产能力的端到端冒烟程序：
// 起一个会发起 XHR 的本地站点，用 sdk.CrawlAPIContexts 采集，
// 然后验证 OpenAPI 导出与授权对照实验。
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/qiwentaidi/trailblazer/pkg/sdk"
)

func main() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/index.html":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><html><body><h1>smoke</h1><script>
fetch('/api/users/123?page=1', {headers: {'Authorization': 'Bearer smoke-token'}})
  .then(r => r.json()).then(d => console.log(d));
fetch('/api/orders', {method: 'POST',
  headers: {'Content-Type': 'application/json', 'X-Session-Token': 'tok-abc'},
  body: JSON.stringify({item: 'book', count: 2, password: 'p@ss'})});
</script></body></html>`)
		case "/api/users/123":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":123,"name":"alice","email":"alice@example.com"}`)
		case "/api/orders":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"orderId":"o-1","status":"created"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	fmt.Println("== target:", srv.URL)
	store, err := sdk.CrawlAPIContexts(srv.URL, &sdk.APICrawlOptions{
		MaxDepth:    1,
		Timeout:     10,
		Concurrency: 2,
		RateLimit:   50,
	})
	if err != nil {
		fmt.Println("crawl error:", err)
	}
	fmt.Printf("== captured %d operations\n", store.Len())
	for _, ctx := range store.List() {
		fmt.Printf("   %s %s auth=%s params=%d resp=%d\n",
			ctx.Method, ctx.PathTemplate, ctx.Auth.Mode, len(ctx.Parameters), ctx.Response.Status)
	}

	if store.Len() == 0 {
		fmt.Println("SMOKE FAIL: no API contexts captured")
		os.Exit(1)
	}

	doc, err := sdk.ExportOpenAPI(store, "Smoke API")
	if err != nil {
		fmt.Println("SMOKE FAIL: export:", err)
		os.Exit(1)
	}
	fmt.Println("== OpenAPI export OK,", len(doc), "bytes")

	// 授权对照实验：对带凭据观测到的接口跑匿名变体
	checked := 0
	for _, ctx := range store.List() {
		if !ctx.Auth.Present {
			continue
		}
		verdict := sdk.RunAuthorizationCheck(ctx, nil)
		fmt.Printf("   authz %s %s -> vulnerable=%v confidence=%s reasons=%v\n",
			ctx.Method, ctx.PathTemplate, verdict.Vulnerable, verdict.Confidence, verdict.Reasons)
		checked++
	}
	if checked == 0 {
		fmt.Println("SMOKE FAIL: no authenticated context to check")
		os.Exit(1)
	}
	fmt.Println("SMOKE OK")
}
