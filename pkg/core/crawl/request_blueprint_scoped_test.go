package crawl

import (
	"strings"
	"testing"

	"github.com/qiwentaidi/trailblazer/pkg/core/database"
)

func TestScopedResolverContentIncludesOnlyLinkedMaterial(t *testing.T) {
	resources := []database.JSResource{
		{URL: "https://example.com/main.js", Content: `
function request(e){return e}
webpackJsonp.push({"9h9Y":function(e,t,r){r.d(t,{a:function(){return u}});var u="/taxi-saas";}});
`},
		{URL: "https://example.com/chunk.js", Content: `
var m=r("9h9Y");
function addResource(e){return Object(f.d)({url:"".concat(m.a,"/resource/add"),type:"get"});}
`},
		{URL: "https://example.com/inline-vars.js", Content: `var _LoginUrl = 'https://example.com/api/login';`},
		{URL: "https://example.com/unrelated.js", Content: `
webpackJsonp.push({"zz11":function(e,t,r){var secret="/internal-only-path";}});
`},
	}
	resolver := newJSModuleResolver(resources)

	scope := resolver.scopedResolverContent("https://example.com/chunk.js", maxScopedResolverBytes)
	if !strings.Contains(scope, "/taxi-saas") {
		t.Fatalf("webpack-edged module fragment must be in scope, got %q", scope)
	}
	if !strings.Contains(scope, "function request(e)") {
		t.Fatalf("edged file head (wrapper helpers) must be in scope, got %q", scope)
	}
	if !strings.Contains(scope, "_LoginUrl") {
		t.Fatalf("global script must be in scope, got %q", scope)
	}
	if strings.Contains(scope, "/internal-only-path") {
		t.Fatalf("unlinked bundle module must not leak into scope, got %q", scope)
	}

	// The file itself is excluded; callers prepend their own content.
	if strings.Contains(scope, "addResource") {
		t.Fatalf("own content must not be duplicated in scope, got %q", scope)
	}
}

func TestScopedResolverContentRespectsBudget(t *testing.T) {
	var big strings.Builder
	for big.Len() < 500*1024 {
		big.WriteString("var g" + strings.Repeat("1", 60) + "=1;")
	}
	resources := []database.JSResource{
		{URL: "https://example.com/page.js", Content: `fetch("/api/x");`},
		{URL: "https://example.com/globals.js", Content: big.String()},
	}
	resolver := newJSModuleResolver(resources)
	scope := resolver.scopedResolverContent("https://example.com/page.js", 8*1024)
	if len(scope) > 8*1024 {
		t.Fatalf("scoped corpus exceeded budget: %d", len(scope))
	}
}
