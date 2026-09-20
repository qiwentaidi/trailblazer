package crawl

import (
	"strings"
	"testing"
	"time"
)

func TestParseJSExpressionNestedObject(t *testing.T) {
	expr := parseJSExpression(`{ accountId: user.id, includeInactive: false, filter: { page: 1, size: 20, tags: ["a", "b"] } }`)
	if expr == nil || expr.Kind != jsExprObject {
		t.Fatalf("expected object, got %#v", expr)
	}
	fields := jsFieldsFromExpression(expr, nil, 0)
	got := map[string]string{}
	for _, field := range fields {
		got[field.Name] = field.Value
	}
	if got["includeInactive"] != "false" {
		t.Fatalf("expected static boolean field, got %#v", fields)
	}
	if _, ok := got["accountId"]; !ok {
		t.Fatalf("expected accountId field, got %#v", fields)
	}
	if _, ok := got["filter"]; !ok {
		t.Fatalf("expected nested filter field, got %#v", fields)
	}
	// Nested object node must retain its own structure.
	for _, field := range fields {
		if field.Name == "filter" && (field.Expr == nil || field.Expr.Kind != jsExprObject || len(field.Expr.Fields) != 3) {
			t.Fatalf("expected nested object node with 3 fields, got %#v", field.Expr)
		}
	}
}

func TestParseJSExpressionTemplateAndConcat(t *testing.T) {
	expr := parseJSExpression("`/api/reports/${id}/detail`")
	if expr == nil || expr.Kind != jsExprTemplate {
		t.Fatalf("expected template, got %#v", expr)
	}
	if value, ok := evalJSExprStatic(expr, func(name string) (string, bool) {
		if name == "id" {
			return "42", true
		}
		return "", false
	}); !ok || value != "/api/reports/42/detail" {
		t.Fatalf("expected resolved template, got %q ok=%v", value, ok)
	}
	// Unresolvable interpolation must stay dynamic.
	if _, ok := evalJSExprStatic(expr, nil); ok {
		t.Fatal("dynamic template must not statically resolve")
	}

	concat := parseJSExpression(`"/api/" + tenant + "/list"`)
	value, ok := evalJSExprStatic(concat, func(name string) (string, bool) {
		return "acme", name == "tenant"
	})
	if !ok || value != "/api/acme/list" {
		t.Fatalf("expected concat resolution, got %q ok=%v", value, ok)
	}
}

func TestParseJSExpressionSpreadAndJSONStringify(t *testing.T) {
	expr := parseJSExpression(`JSON.stringify({ ...base, extra: 1 })`)
	if expr == nil || expr.Kind != jsExprCall || expr.Callee != "JSON.stringify" {
		t.Fatalf("expected JSON.stringify call, got %#v", expr)
	}
	spreadResolve := func(name string) (*jsExpr, bool) {
		if name == "base" {
			return parseJSExpression(`{ reportId: 7, kind: "full" }`), true
		}
		return nil, false
	}
	fields := jsFieldsFromExpression(expr, spreadResolve, 0)
	got := map[string]string{}
	for _, field := range fields {
		got[field.Name] = field.Value
	}
	if got["reportId"] != "7" || got["kind"] != "full" || got["extra"] != "1" {
		t.Fatalf("expected spread-merged fields, got %#v", got)
	}
}

func TestParseJSExpressionURLSearchParamsAndAxiosConfig(t *testing.T) {
	params := parseJSExpression(`new URLSearchParams({ page: 1, keyword: "tax" })`)
	if params == nil || params.Kind != jsExprCall {
		t.Fatalf("expected call, got %#v", params)
	}
	fields := jsFieldsFromExpression(params, nil, 0)
	got := map[string]string{}
	for _, field := range fields {
		got[field.Name] = field.Value
	}
	if got["page"] != "1" || got["keyword"] != "tax" {
		t.Fatalf("expected URLSearchParams fields, got %#v", got)
	}

	config := parseJSExpression(`{ baseURL: "/api", headers: { "X-App": "trail" }, timeout: 3000, withCredentials: true }`)
	fields = jsFieldsFromExpression(config, nil, 0)
	got = map[string]string{}
	for _, field := range fields {
		got[field.Name] = field.Value
	}
	if got["baseURL"] != "/api" || got["timeout"] != "3000" || got["withCredentials"] != "true" {
		t.Fatalf("expected axios config fields, got %#v", got)
	}
}

func TestParseJSExpressionFaultTolerance(t *testing.T) {
	// Broken / foreign syntax must degrade to raw nodes, never panic.
	for _, broken := range []string{
		`{ a: 1, b: `,
		`foo(bar(1, {x: [2, 3]}`,
		"if (x) { y() } else { z() }",
		`a => {`,
		strings.Repeat("{ a: ", 64) + "1",
	} {
		expr := parseJSExpression(broken)
		if expr == nil {
			t.Fatalf("parser must always return a node for %q", broken)
		}
	}
}

func TestParseJSExpressionBudgets(t *testing.T) {
	// Very long input is capped, and deep nesting terminates quickly.
	long := `{ items: [` + strings.Repeat(`"x",`, 200000) + `] }`
	start := time.Now()
	expr := parseJSExpression(long)
	if expr == nil {
		t.Fatal("expected node for long input")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("parse exceeded budget: %s", elapsed)
	}
}

func TestRequestBlueprintParamResolvesTemplateWithSymbols(t *testing.T) {
	symbols := jsRequestSymbolIndex{
		content: "const tenant = \"acme\";",
		definitions: map[string]jsRequestSymbolDefinition{
			"tenant": {Name: "tenant", Kind: "constant", Value: "acme"},
		},
	}
	param := resolveRequestBlueprintParam(RequestBlueprintParam{
		Name: "path", Source: "path", ValueExpr: "`/api/${tenant}/reports`",
	}, nil, symbols)
	if !param.Resolved || param.Value != "/api/acme/reports" {
		t.Fatalf("expected template resolution via symbols, got %#v", param)
	}

	dynamic := resolveRequestBlueprintParam(RequestBlueprintParam{
		Name: "path", Source: "path", ValueExpr: "`/api/${user.id}/reports`",
	}, nil, symbols)
	if dynamic.Resolved && strings.Contains(dynamic.Value, "${") {
		t.Fatalf("dynamic template must not resolve with placeholders: %#v", dynamic)
	}
}
