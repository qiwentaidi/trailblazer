package unauth

import "testing"

func TestAssessConfidenceLowersRepeatedGenericErrors(t *testing.T) {
	seenHTMLHashes.Lock()
	seenHTMLHashes.items = make(map[string]struct{})
	seenHTMLHashes.Unlock()

	responseSignatureTracker.Lock()
	responseSignatureTracker.counts = make(map[string]int)
	responseSignatureTracker.Unlock()

	body := `{"code":"err.common.system.error","msg":"系统错误","success":false}`
	for i := 0; i < 5; i++ {
		confidence, reason := assessConfidence(200, body, "https://example.com/api/message/query")
		if confidence != "low" {
			t.Fatalf("confidence = %q, want low; reason=%q", confidence, reason)
		}
		if i == 4 {
			if reason == "" {
				t.Fatal("expected non-empty confidence reason")
			}
		}
	}
}

func TestAssessConfidenceKeepsStructuredDataHigher(t *testing.T) {
	seenHTMLHashes.Lock()
	seenHTMLHashes.items = make(map[string]struct{})
	seenHTMLHashes.Unlock()

	responseSignatureTracker.Lock()
	responseSignatureTracker.counts = make(map[string]int)
	responseSignatureTracker.Unlock()

	body := `{"code":200,"data":{"list":[{"id":1,"name":"alice"},{"id":2,"name":"bob"}],"total":2},"success":true}`
	confidence, reason := assessConfidence(200, body, "https://example.com/api/orders/query")
	if confidence != "high" {
		t.Fatalf("confidence = %q, want high; reason=%q", confidence, reason)
	}
}

func TestShouldTreatHTMLAsUnauthorizedRejectsLoginPage(t *testing.T) {
	body := `<!doctype html><html><body><h1>用户登录</h1><form><input name="username"/><input name="password"/></form><div>请先登录后访问</div></body></html>`
	if shouldTreatHTMLAsUnauthorized(body, "https://example.com/admin/login") {
		t.Fatal("expected login html to be rejected")
	}
}

func TestShouldTreatHTMLAsUnauthorizedRejectsGenericErrorPage(t *testing.T) {
	body := `<!doctype html><html><body><h1>403 Forbidden</h1><p>访问受限</p><p>系统错误</p></body></html>`
	if shouldTreatHTMLAsUnauthorized(body, "https://example.com/admin/orders") {
		t.Fatal("expected generic error html to be rejected")
	}
}

func TestShouldTreatHTMLAsUnauthorizedRejectsSPAShell(t *testing.T) {
	body := `<!doctype html><html><body><div id="app"></div><script src="/static/js/app.js"></script></body></html>`
	if shouldTreatHTMLAsUnauthorized(body, "https://example.com/dashboard") {
		t.Fatal("expected spa shell html to be rejected")
	}
}

func TestShouldTreatHTMLAsUnauthorizedAcceptsBusinessTablePage(t *testing.T) {
	body := `<!doctype html><html><body><h1>用户管理后台</h1><table><tr><th>姓名</th><th>邮箱</th><th>手机号</th></tr><tr><td>Alice</td><td>alice@example.com</td><td>13800138000</td></tr></table></body></html>`
	if !shouldTreatHTMLAsUnauthorized(body, "https://example.com/admin/users") {
		t.Fatal("expected business html with sensitive data to be accepted")
	}
}
