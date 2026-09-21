package sdk

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
)

// SensitiveAssetOptions is retained for compatibility with existing callers.
type SensitiveAssetOptions struct {
	// Deprecated: raw values are always included, regardless of this option.
	IncludeRawValue bool
}

// SensitiveAsset is one rule-based sensitive-data lead from a collected JS
// resource. It is evidence, not a verified exposure: minified bundles can
// contain examples, dead code, or build-time placeholders.
type SensitiveAsset struct {
	Type string `json:"type"`
	// MaskedValue is a legacy alias of Value and contains the original value.
	MaskedValue string   `json:"maskedValue"`
	Value       string   `json:"value,omitempty"`
	Source      string   `json:"source"`
	Sources     []string `json:"sources,omitempty"`
	Offset      int      `json:"offset"`
	Rule        string   `json:"rule"`
	Evidence    string   `json:"evidence,omitempty"`
}

// SensitiveAssetResult is the output of AnalyzeSensitiveAssets. Analysis only
// reads assets.JSResources; it never fetches JS, performs browser actions, or
// sends requests to the target.
type SensitiveAssetResult struct {
	Items             []SensitiveAsset `json:"items"`
	ResourcesAnalyzed int              `json:"resourcesAnalyzed"`
}

// sensitiveKeyRules are deterministic format rules for commonly embedded AI
// and cloud credentials. They intentionally identify candidates only: a
// format match cannot establish that a credential is live or authorized.
var sensitiveKeyRules = []struct {
	kind    string
	rule    string
	pattern *regexp.Regexp
}{
	{"ai_api_key", "openai-compatible-api-key", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`)},
	{"ai_api_key", "anthropic-api-key", regexp.MustCompile(`\bsk-ant-api\d{2}-[A-Za-z0-9_-]{20,}\b`)},
	{"ai_api_key", "google-ai-api-key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"ai_api_key", "hugging-face-token", regexp.MustCompile(`\bhf_[A-Za-z0-9]{20,}\b`)},
	{"ai_api_key", "replicate-api-token", regexp.MustCompile(`\br8_[A-Za-z0-9]{20,}\b`)},
	{"cloud_key", "aws-access-key-id", regexp.MustCompile(`\b(?:AKIA|ASIA|A3T)[A-Z0-9]{16}\b`)},
	{"cloud_key", "tencent-cloud-secret-id", regexp.MustCompile(`\bAKID[A-Za-z0-9]{32,}\b`)},
	{"cloud_key", "alibaba-cloud-access-key-id", regexp.MustCompile(`\bLTAI[A-Za-z0-9]{12,}\b`)},
	{"cloud_key", "aws-secret-access-key", regexp.MustCompile(`(?i)\baws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b`)},
	{"cloud_key", "azure-storage-connection-string", regexp.MustCompile(`(?i)\bDefaultEndpointsProtocol=https?;AccountName=[^;\s"']+;AccountKey=[A-Za-z0-9+/=]{20,}`)},
}

// AnalyzeSensitiveAssets runs the legacy rule families against JS resources
// already collected by CrawlAPIAssets. It intentionally remains separate from
// DetectOperationVulns because sensitive-data leads are asset evidence, not
// vulnerability verdicts.
func AnalyzeSensitiveAssets(assets *APIAssetResult, _ *SensitiveAssetOptions) (*SensitiveAssetResult, error) {
	if assets == nil {
		return nil, errSensitiveAssetsNil
	}
	result := &SensitiveAssetResult{ResourcesAnalyzed: len(assets.JSResources)}
	for _, resource := range assets.JSResources {
		content := resource.Content
		if content == "" {
			continue
		}
		result.Items = append(result.Items, findSensitiveAssets(content, resource.URL, crawl.Sensitive.FindAllStringIndex(content, -1), "sensitive_configuration", "legacy-sensitive")...)
		result.Items = append(result.Items, findSensitiveAssets(content, resource.URL, crawl.Email.FindAllStringIndex(content, -1), "email", "legacy-email")...)
		result.Items = append(result.Items, findSensitiveAssets(content, resource.URL, crawl.Phone.FindAllStringIndex(content, -1), "phone", "legacy-phone")...)
		result.Items = append(result.Items, findSensitiveAssets(content, resource.URL, crawl.IDCard.FindAllStringIndex(content, -1), "id_card", "legacy-id-card")...)
		result.Items = append(result.Items, findSensitiveAssets(content, resource.URL, crawl.IP_PORT.FindAllStringIndex(content, -1), "ip_url", "legacy-ip-port")...)
		for _, keyRule := range sensitiveKeyRules {
			result.Items = append(result.Items, findSensitiveAssets(content, resource.URL, keyRule.pattern.FindAllStringIndex(content, -1), keyRule.kind, keyRule.rule)...)
		}
	}
	result.Items = dedupeSensitiveAssets(result.Items)
	return result, nil
}

var errSensitiveAssetsNil = &sensitiveAssetsError{"assets cannot be nil"}

type sensitiveAssetsError struct{ message string }

func (e *sensitiveAssetsError) Error() string { return "sensitive-assets: " + e.message }

func findSensitiveAssets(content, source string, matches [][]int, kind, rule string) []SensitiveAsset {
	items := make([]SensitiveAsset, 0, len(matches))
	for _, match := range matches {
		if len(match) != 2 || match[0] < 0 || match[1] <= match[0] {
			continue
		}
		value := strings.TrimSpace(content[match[0]:match[1]])
		if value == "" {
			continue
		}
		item := SensitiveAsset{
			Type:        kind,
			MaskedValue: value,
			Value:       value,
			Source:      source,
			Sources:     []string{source},
			Offset:      match[0],
			Rule:        rule,
			Evidence:    fmt.Sprintf("Matched by %s at byte offset %d; value %s.", rule, match[0], value),
		}
		items = append(items, item)
	}
	return items
}

func dedupeSensitiveAssets(items []SensitiveAsset) []SensitiveAsset {
	byKey := make(map[string]int, len(items))
	result := make([]SensitiveAsset, 0, len(items))
	for _, item := range items {
		key := item.Type + "\x00" + item.Value
		if index, exists := byKey[key]; exists {
			result[index].Sources = appendUniqueSensitiveSource(result[index].Sources, item.Source)
			continue
		}
		item.Sources = appendUniqueSensitiveSource(nil, item.Sources...)
		byKey[key] = len(result)
		result = append(result, item)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Source == result[j].Source {
			return result[i].Offset < result[j].Offset
		}
		return result[i].Source < result[j].Source
	})
	return result
}

func appendUniqueSensitiveSource(sources []string, additions ...string) []string {
	seen := make(map[string]struct{}, len(sources)+len(additions))
	for _, source := range sources {
		seen[source] = struct{}{}
	}
	for _, source := range additions {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}
		if _, exists := seen[source]; exists {
			continue
		}
		seen[source] = struct{}{}
		sources = append(sources, source)
	}
	return sources
}
