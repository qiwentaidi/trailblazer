package crawl

import (
	"strings"
	"testing"

	"github.com/qiwentaidi/trailblazer/pkg/core/database"
)

const webpackResolverBundle = `!function(e){var t={};function n(r){if(t[r])return t[r].exports;var o=t[r]={exports:{}};return e[r].call(o.exports,o,o.exports,n),o.exports}n.d=function(e,t){for(var r in t)n.o(t,r)&&!n.o(e,r)&&Object.defineProperty(e,r,{enumerable:!0,get:t[r]})};n(456)}({
123:function(e,t,n){"use strict";var api=n(456);api.get("/api/users/list",{params:{page:1}});},
456:function(e,t,n){"use strict";n.d(t,{default:function(){return api}});var baseURL="/api/v2";var api={get:function(u,c){return u}};}
});`

func TestJSModuleResolverWebpackBoundaries(t *testing.T) {
	resolver := newJSModuleResolver([]database.JSResource{{
		URL:     "https://example.com/assets/app.js",
		Content: webpackResolverBundle,
	}})
	if len(resolver.modules) != 2 {
		t.Fatalf("expected 2 webpack modules, got %#v", resolver.modules)
	}
	var exporting *jsModuleInfo
	for i := range resolver.modules {
		if resolver.modules[i].ID == "456" {
			exporting = &resolver.modules[i]
		}
	}
	if exporting == nil {
		t.Fatal("module 456 not detected")
	}
	if _, ok := exporting.Exported["default"]; !ok {
		t.Fatalf("expected default export detected, got %#v", exporting.Exported)
	}
}

func TestJSModuleResolverSameFileLookup(t *testing.T) {
	resolver := newJSModuleResolver([]database.JSResource{{
		URL:     "https://example.com/assets/app.js",
		Content: webpackResolverBundle,
	}})
	// From module 123 (the caller), resolve baseURL defined in module 456.
	callerOffset := strings.Index(webpackResolverBundle, `api.get("/api/users/list"`)
	hits := resolver.lookupSymbol("baseURL", "https://example.com/assets/app.js", callerOffset, 2)
	if len(hits) == 0 {
		t.Fatal("expected same-file module lookup to resolve baseURL")
	}
	if hits[0].Value != "/api/v2" || hits[0].Kind != "constant" {
		t.Fatalf("unexpected resolution: %#v", hits[0])
	}
}

func TestJSModuleResolverESMCrossFileLink(t *testing.T) {
	resources := []database.JSResource{
		{URL: "https://example.com/assets/page.js", Content: `
import { buildQuery } from "./util.js";
fetch("/api/reports", { method: "POST", body: JSON.stringify(buildQuery(1)) });
`},
		{URL: "https://example.com/assets/util.js", Content: `
export function buildQuery(id) { return { reportId: id }; }
export const pageSize = 20;
const internalOnly = "secret-local";
`},
	}
	resolver := newJSModuleResolver(resources)
	hits := resolver.lookupSymbol("pageSize", "https://example.com/assets/page.js", 0, 2)
	// pageSize is not imported by page.js, so no cross-file association.
	if len(hits) != 0 {
		t.Fatalf("unimported symbol must not cross files, got %#v", hits)
	}
	hits = resolver.lookupSymbol("buildQuery", "https://example.com/assets/page.js", 0, 2)
	if len(hits) == 0 {
		t.Fatal("imported symbol must resolve via the ESM edge")
	}
	if hits[0].File != "https://example.com/assets/util.js" {
		t.Fatalf("expected resolution from util.js, got %#v", hits[0])
	}
}

func TestJSModuleResolverSourceMapCorpus(t *testing.T) {
	sourceMap := `{"version":3,"sources":["webpack:///src/api/config.js"],"sourcesContent":["export const apiRoot = \"/api/v3\";"],"mappings":"AAAA"}`
	resources := []database.JSResource{
		{URL: "https://example.com/assets/app.js", Content: `var x=1;fetch("/api/ping");
//# sourceMappingURL=app.js.map`},
		{URL: "https://example.com/assets/app.js.map", Content: sourceMap},
	}
	resolver := newJSModuleResolver(resources)
	hits := resolver.lookupSymbol("apiRoot", "https://example.com/assets/app.js", 0, 2)
	if len(hits) == 0 {
		t.Fatal("expected source-map-restored module to resolve apiRoot")
	}
	if hits[0].ModulePath != "webpack:///src/api/config.js" || hits[0].Value != "/api/v3" {
		t.Fatalf("unexpected source map resolution: %#v", hits[0])
	}
}

func TestEnrichRequestBlueprintSymbolsFromModules(t *testing.T) {
	resolver := newJSModuleResolver([]database.JSResource{{
		URL:     "https://example.com/assets/app.js",
		Content: webpackResolverBundle,
	}})
	index := jsRequestSymbolIndex{
		content:     `api.get("/api/users/list",{params:{page:1}})`,
		definitions: map[string]jsRequestSymbolDefinition{},
		callsites:   map[string][]callExpression{},
	}
	callerOffset := strings.Index(webpackResolverBundle, `api.get("/api/users/list"`)
	enrichRequestBlueprintSymbolsFromModules(&index, resolver, "https://example.com/assets/app.js", callerOffset, []string{"baseURL"})
	definition, ok := index.definitions["baseURL"]
	if !ok {
		t.Fatal("expected baseURL to be enriched from the module resolver")
	}
	if definition.Value != "/api/v2" || definition.Kind != "constant" {
		t.Fatalf("unexpected enriched definition: %#v", definition)
	}
}

func TestJSModuleResolverNoFalseCrossFileAssociation(t *testing.T) {
	// Two unrelated files both define `config`; a lookup from file A must
	// prefer file A's own definition and never silently borrow file B's.
	resources := []database.JSResource{
		{URL: "https://example.com/a.js", Content: `var config={timeout:1};service.post("/api/a",config);`},
		{URL: "https://example.com/b.js", Content: `var config={timeout:9999};service.post("/api/b",config);`},
	}
	resolver := newJSModuleResolver(resources)
	hits := resolver.lookupSymbol("config", "https://example.com/a.js", 5, 2)
	if len(hits) != 1 {
		t.Fatalf("expected exactly the local definition, got %#v", hits)
	}
	if hits[0].File != "https://example.com/a.js" || !strings.Contains(hits[0].ValueExpr, "timeout:1") {
		t.Fatalf("cross-file false association detected: %#v", hits[0])
	}
}
