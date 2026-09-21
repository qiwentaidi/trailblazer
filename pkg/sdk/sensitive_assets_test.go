package sdk

import (
	"strings"
	"testing"

	"github.com/qiwentaidi/trailblazer/pkg/core/database"
)

func TestAnalyzeSensitiveAssetsIsStaticAndRedactsByDefault(t *testing.T) {
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
		if item.Value != "" {
			t.Fatalf("raw value must be omitted by default: %+v", item)
		}
		if strings.Contains(item.Evidence, "hunter2") || strings.Contains(item.Evidence, "13800138000") {
			t.Fatalf("evidence must redact sensitive values: %+v", item)
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
			if item.Value != "" {
				t.Errorf("raw key must remain omitted: %+v", item)
			}
		}
	}
	for _, rule := range []string{"openai-compatible-api-key", "google-ai-api-key", "aws-access-key-id", "tencent-cloud-secret-id"} {
		if !rules[rule] {
			t.Errorf("missing key rule %q in %+v", rule, result.Items)
		}
	}
}
