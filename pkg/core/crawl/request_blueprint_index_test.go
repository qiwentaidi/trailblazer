package crawl

import (
	"strings"
	"testing"
)

const indexEquivalenceSample = `
const config = { baseURL: "/api", timeout: 3000 };
let token = "abc";
function buildQuery(id, type) {
	return { reportId: id, kind: type, nested: { deep: [1, 2, { x: "y" }] } };
}
var loadReport = function(id) {
	return service.post("/api/reports/load", buildQuery(id, "full"));
};
loadReport(42);
service.get("/api/list", { params: { page: 1 } });
obj.name = "member assignment must not index";
if (token == "abc") { console.log("eq must not index"); }
const arrow = (a) => ({ value: a });
fetch("/api/direct", { method: "POST", body: JSON.stringify(config) });
`

func TestJSSourceIndexCallExpressionsMatchLegacyScanner(t *testing.T) {
	index := buildJSSourceIndex(indexEquivalenceSample)
	if index.truncated {
		t.Fatal("index unexpectedly truncated on small sample")
	}
	for _, callee := range []string{"buildQuery", "loadReport", "fetch", "missing"} {
		legacy := findCallExpressions(indexEquivalenceSample, callee)
		indexed := findCallExpressionsWithIndex(index, indexEquivalenceSample, callee)
		if len(legacy) != len(indexed) {
			t.Fatalf("callee %q: legacy=%d indexed=%d", callee, len(legacy), len(indexed))
		}
		for i := range legacy {
			if legacy[i].Index != indexed[i].Index || legacy[i].Args != indexed[i].Args || legacy[i].CallText != indexed[i].CallText {
				t.Fatalf("callee %q call %d mismatch:\nlegacy=%#v\nindexed=%#v", callee, i, legacy[i], indexed[i])
			}
		}
	}
}

func TestJSSourceIndexAssignmentExpressionsMatchLegacyScanner(t *testing.T) {
	index := buildJSSourceIndex(indexEquivalenceSample)
	for _, name := range []string{"config", "token", "loadReport", "arrow", "missing"} {
		legacyExpr, legacyOK := findJSAssignmentExpression(indexEquivalenceSample, name)
		indexedExpr, indexedOK := findJSAssignmentExpressionWithIndex(index, indexEquivalenceSample, name)
		if legacyOK != indexedOK {
			t.Fatalf("name %q: legacy ok=%v indexed ok=%v", name, legacyOK, indexedOK)
		}
		if legacyOK && strings.TrimSpace(legacyExpr) != strings.TrimSpace(indexedExpr) {
			t.Fatalf("name %q: legacy=%q indexed=%q", name, legacyExpr, indexedExpr)
		}
	}
	// Member assignment `obj.name = ...` must not register `name`.
	if _, ok := findJSAssignmentExpressionWithIndex(index, indexEquivalenceSample, "name"); ok {
		t.Fatal("member assignment must not be indexed as a symbol definition")
	}
}

func TestJSSourceIndexBalancedMatchesLegacyScanner(t *testing.T) {
	index := buildJSSourceIndex(indexEquivalenceSample)
	for openIndex, ch := range []byte(indexEquivalenceSample) {
		if ch != '(' && ch != '{' && ch != '[' {
			continue
		}
		closeChar := map[byte]byte{'(': ')', '{': '}', '[': ']'}[ch]
		legacyArgs, legacyEnd, legacyOK := extractBalancedJS(indexEquivalenceSample, openIndex, ch, closeChar)
		indexedArgs, indexedEnd, indexedOK := index.balanced(openIndex, ch, closeChar)
		if legacyOK != indexedOK {
			t.Fatalf("open %d (%c): legacy ok=%v indexed ok=%v", openIndex, ch, legacyOK, indexedOK)
		}
		if legacyOK && (legacyArgs != indexedArgs || legacyEnd != indexedEnd) {
			t.Fatalf("open %d (%c): legacy end=%d indexed end=%d", openIndex, ch, legacyEnd, indexedEnd)
		}
	}
}

func TestJSSourceIndexEnclosingFunction(t *testing.T) {
	index := buildJSSourceIndex(indexEquivalenceSample)
	postPos := strings.Index(indexEquivalenceSample, `service.post("/api/reports/load"`)
	if postPos < 0 {
		t.Fatal("sample missing call")
	}
	span, ok := index.enclosingFunction(postPos)
	if !ok {
		t.Fatal("expected enclosing function for service.post call")
	}
	text := indexEquivalenceSample[span.Start:span.End]
	if !strings.HasPrefix(text, "function(id)") || !strings.Contains(text, "service.post") {
		t.Fatalf("unexpected enclosing span: %q", text)
	}
	// A position outside any function must not match.
	if _, ok := index.enclosingFunction(strings.Index(indexEquivalenceSample, "const config")); ok {
		t.Fatal("top-level statement must not have an enclosing function")
	}
}

func TestJSSourceIndexTruncatedFallsBackToLegacy(t *testing.T) {
	index := &jsSourceIndex{content: indexEquivalenceSample, truncated: true}
	legacy := findCallExpressions(indexEquivalenceSample, "loadReport")
	indexed := findCallExpressionsWithIndex(index, indexEquivalenceSample, "loadReport")
	if len(legacy) != len(indexed) {
		t.Fatalf("truncated index must fall back to legacy scanner: legacy=%d indexed=%d", len(legacy), len(indexed))
	}
	legacyExpr, legacyOK := findJSAssignmentExpression(indexEquivalenceSample, "config")
	indexedExpr, indexedOK := findJSAssignmentExpressionWithIndex(index, indexEquivalenceSample, "config")
	if legacyOK != indexedOK || strings.TrimSpace(legacyExpr) != strings.TrimSpace(indexedExpr) {
		t.Fatal("truncated index must fall back to legacy assignment scanner")
	}
}

func TestResolveStaticArgumentExpressionDepthBudget(t *testing.T) {
	// Direct calls beyond the depth budget return empty.
	if got := resolveStaticArgumentExpressionDepth("const value = {a:1};", "value", maxStaticArgumentResolveDepth+1); got != "" {
		t.Fatalf("expected depth budget to stop resolution, got %q", got)
	}
	// Nested JSON.stringify beyond the budget terminates quickly instead of
	// recursing without bound; the partially unwrapped raw expression is an
	// acceptable bounded result.
	expr := "value"
	for i := 0; i < maxStaticArgumentResolveDepth+4; i++ {
		expr = "JSON.stringify(" + expr + ")"
	}
	got := resolveStaticArgumentExpression("const value = {a:1};", expr)
	if strings.Count(got, "JSON.stringify(") >= maxStaticArgumentResolveDepth+4 {
		t.Fatalf("expected bounded unwrapping, got %q", got)
	}
	// Shallow nesting still resolves.
	shallow := "JSON.stringify(JSON.stringify(value))"
	if got := resolveStaticArgumentExpression("const value = {a:1};", shallow); got == "" {
		t.Fatal("expected shallow nesting to resolve")
	}
}
