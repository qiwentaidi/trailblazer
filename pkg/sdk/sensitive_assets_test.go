package sdk

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/qiwentaidi/trailblazer/pkg/core/database"
)

func TestAnalyzeSensitiveAssetsIsStaticAndPreservesValuesByDefault(t *testing.T) {
	assets := &APIAssetResult{JSResources: []database.JSResource{{
		URL:     "https://example.test/assets/app.js",
		Content: `const password="hunter2"; const mail="alice@example.test"; const phone="13800138000"; const endpoint="10.0.0.8:8080";`,
	}}}
	result, err := AnalyzeSensitiveAssets(assets, nil)
	if err != nil {
		t.Fatalf("AnalyzeSensitiveAssets: %v", err)
	}
	if result.ResourcesAnalyzed != 1 || len(result.Items) < 4 {
		t.Fatalf("unexpected analysis result: %+v", result)
	}
	for _, item := range result.Items {
		if item.Value == "" || item.MaskedValue != item.Value {
			t.Fatalf("raw value and compatibility alias must be preserved: %+v", item)
		}
		if !strings.Contains(item.Evidence, item.Value) {
			t.Fatalf("evidence must preserve original value: %+v", item)
		}
	}
}

func TestAnalyzeSensitiveAssetsCanIncludeRawValueWhenExplicit(t *testing.T) {
	assets := &APIAssetResult{JSResources: []database.JSResource{{
		URL:     "https://example.test/assets/app.js",
		Content: `const password="hunter2";`,
	}}}
	result, err := AnalyzeSensitiveAssets(assets, &SensitiveAssetOptions{IncludeRawValue: true})
	if err != nil {
		t.Fatalf("AnalyzeSensitiveAssets: %v", err)
	}
	if len(result.Items) != 1 || !strings.Contains(result.Items[0].Value, "hunter2") {
		t.Fatalf("explicit raw-value option was not honored: %+v", result.Items)
	}
}

func TestAnalyzeSensitiveAssetsFindsAIAndCloudKeyCandidates(t *testing.T) {
	assets := &APIAssetResult{JSResources: []database.JSResource{{
		URL: "https://example.test/assets/config.js",
		// Construct representative values at runtime so fixture data cannot be
		// mistaken for real credentials by source-control secret scanners.
		Content: strings.Join([]string{
			`const openai = "` + "sk-proj-" + strings.Repeat("a", 32) + `";`,
			`const google = "` + "AIza" + strings.Repeat("a", 35) + `";`,
			`const aws = "` + "AKIA" + strings.Repeat("A", 16) + `";`,
			`const tencent = "` + "AKID" + strings.Repeat("a", 32) + `";`,
		}, "\n"),
	}}}
	result, err := AnalyzeSensitiveAssets(assets, nil)
	if err != nil {
		t.Fatalf("AnalyzeSensitiveAssets: %v", err)
	}
	rules := make(map[string]bool)
	for _, item := range result.Items {
		rules[item.Rule] = true
		if item.Rule == "openai-compatible-api-key" || item.Rule == "google-ai-api-key" || item.Rule == "aws-access-key-id" || item.Rule == "tencent-cloud-secret-id" {
			if item.Type != "ai_api_key" && item.Type != "cloud_key" {
				t.Errorf("unexpected type for %s: %+v", item.Rule, item)
			}
			if item.Value == "" || item.MaskedValue != item.Value {
				t.Errorf("raw key must be preserved: %+v", item)
			}
		}
	}
	for _, rule := range []string{"openai-compatible-api-key", "google-ai-api-key", "aws-access-key-id", "tencent-cloud-secret-id"} {
		if !rules[rule] {
			t.Errorf("missing key rule %q in %+v", rule, result.Items)
		}
	}
}

func TestSensitiveAssetOptionsNeverHideValues(t *testing.T) {
	for _, opts := range []*SensitiveAssetOptions{nil, {}, {IncludeRawValue: false}, {IncludeRawValue: true}} {
		assets := &APIAssetResult{JSResources: []database.JSResource{{URL: "https://example.test/app.js", Content: `"alice@example.test" "annie@example.test"`}, {URL: "https://example.test/other.js", Content: `"alice@example.test"`}}}
		result, err := AnalyzeSensitiveAssets(assets, opts)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Items) != 2 {
			t.Fatalf("distinct emails must not merge: %+v", result.Items)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{"alice@example.test", "annie@example.test"} {
			if !strings.Contains(string(encoded), `"value":"`+value+`"`) || !strings.Contains(string(encoded), `"maskedValue":"`+value+`"`) {
				t.Fatalf("JSON must contain original values: %s", encoded)
			}
		}
		for _, item := range result.Items {
			if item.Value == "alice@example.test" && len(item.Sources) != 2 {
				t.Fatalf("duplicate sources must still merge: %+v", item)
			}
		}
	}
}
