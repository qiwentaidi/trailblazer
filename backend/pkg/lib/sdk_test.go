package lib

import (
	"os"
	"testing"
	"time"
	"trailblazer/pkg/config"
	"trailblazer/pkg/core/crawl"
	"trailblazer/pkg/core/database"
	"trailblazer/pkg/core/protocoltool"
	"trailblazer/pkg/core/structs"
)

func TestNewScanOptionsEnablesVulnDetectionByDefault(t *testing.T) {
	options := NewScanOptions()

	if !options.VulnDetection.Enabled {
		t.Fatalf("expected vuln detection to be enabled by default")
	}
}

func TestResolveSDKVulnDetectionOptionsDisablesAllModulesWhenGlobalSwitchOff(t *testing.T) {
	resolved := resolveSDKVulnDetectionOptions(VulnDetectionOptions{
		Enabled:      false,
		SQLInjection: config.SQLInjectionConfig{Enabled: true},
		LFI:          config.LFIConfig{Enabled: true},
		SSRF:         config.SSRFConfig{Enabled: true},
		Redirect:     config.RedirectConfig{Enabled: true},
		XSS:          config.XSSConfig{Enabled: true},
		Upload:       config.UploadConfig{Enabled: true},
	})

	if resolved.SQLInjection.Enabled || resolved.LFI.Enabled || resolved.SSRF.Enabled ||
		resolved.Redirect.Enabled || resolved.XSS.Enabled || resolved.Upload.Enabled {
		t.Fatalf("expected all vuln modules to be disabled when global switch is off: %+v", resolved)
	}
}

func TestBuildSDKJSFindOptionsSkipsAllVulnScanningWhenGlobalSwitchOff(t *testing.T) {
	options := NewScanOptions()
	options.VulnDetection.Enabled = false

	jsFindOptions := buildSDKJSFindOptions("cli-mode", "https://example.com", []string{"/api"}, "/api", crawl.StaticEndpointHintBundle{}, options, nil)

	if !jsFindOptions.SkipVulnScan {
		t.Fatalf("expected SkipVulnScan to be true when sdk vuln detection is disabled")
	}
	if jsFindOptions.Authentication == nil {
		t.Fatalf("expected authentication rules to still be passed through")
	}
	if cfg, ok := jsFindOptions.SQLInjConfig.(config.SQLInjectionConfig); !ok || cfg.Enabled {
		t.Fatalf("expected SQL injection config to be disabled, got %#v", jsFindOptions.SQLInjConfig)
	}
	if cfg, ok := jsFindOptions.UploadConfig.(config.UploadConfig); !ok || cfg.Enabled {
		t.Fatalf("expected upload config to be disabled, got %#v", jsFindOptions.UploadConfig)
	}
}

func TestBuildSDKJSFindOptionsCarriesStaticHints(t *testing.T) {
	options := NewScanOptions()
	options.DataStore = database.NewMemoryScanDataStore()
	hints := crawl.StaticEndpointHintBundle{
		Methods: map[string]string{
			"/ccat/api/getApisGroupByApp": "GET",
		},
		RequestPayload: map[string]structs.StaticRequestPayloadHint{
			"GET\x00/ccat/api/getApisGroupByApp": {
				Carrier: "body",
				Format:  "json",
				Preview: `{app:e}`,
			},
		},
	}

	jsFindOptions := buildSDKJSFindOptions("cli-mode", "https://example.com", []string{"/ccat/api/getApisGroupByApp"}, "/api", hints, options, nil)
	if got := jsFindOptions.StaticMethodHints["/ccat/api/getApisGroupByApp"]; got != "GET" {
		t.Fatalf("expected static method hint to be propagated, got %q", got)
	}
	if got := jsFindOptions.StaticRequestPayloadHints["GET\x00/ccat/api/getApisGroupByApp"].Preview; got != `{app:e}` {
		t.Fatalf("expected static payload hint to be propagated, got %q", got)
	}
	if jsFindOptions.DataStore != options.DataStore {
		t.Fatal("expected custom scan data store to be propagated")
	}
}

func TestBuildSDKStaticHintBundleWithFetcherAndTempDir(t *testing.T) {
	parentDir := t.TempDir()
	fetcher := func(jsURL string) ([]byte, error) {
		switch jsURL {
		case "https://example.com/static/main.js":
			return []byte(`
const nn="https://api.example.com";
dn({type:"get",url:"".concat(nn,"/ccat/api/getApisGroupByApp"),body:{app:e},showErrorModal:!0});
`), nil
		case "https://example.com/static/vendor.js":
			return []byte(`
const client=axios.create({baseURL:"https://api.example.com"});
client.post("/ccat/testcases/getCaseList",{pageNum:1,pageSize:10});
`), nil
		default:
			return nil, os.ErrNotExist
		}
	}

	bundle := buildSDKStaticHintBundleWithFetcherAndTempDir(
		"https://example.com/index",
		[]string{"/static/main.js", "https://example.com/static/vendor.js"},
		fetcher,
		parentDir,
	)

	if got := bundle.Methods["/ccat/api/getApisGroupByApp"]; got != "GET" {
		t.Fatalf("expected GET method hint, got %#v", bundle.Methods)
	}
	if got := bundle.Methods["/ccat/testcases/getCaseList"]; got != "POST" {
		t.Fatalf("expected POST method hint, got %#v", bundle.Methods)
	}
	payloadHint, ok := bundle.RequestPayload["GET\x00/ccat/api/getApisGroupByApp"]
	if !ok {
		t.Fatalf("expected wrapper-config payload hint, got %#v", bundle.RequestPayload)
	}
	if payloadHint.Carrier != "body" || payloadHint.Format != "json" || payloadHint.Preview != "{app:e}" {
		t.Fatalf("unexpected wrapper-config payload hint: %#v", payloadHint)
	}

	entries, err := os.ReadDir(parentDir)
	if err != nil {
		t.Fatalf("expected temp parent dir to be readable, got error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected temp parent dir to be cleaned, found %d entries", len(entries))
	}
}

func TestLoadScanOptionsFromFileDefaultsGlobalVulnSwitchToEnabled(t *testing.T) {
	configPath := t.TempDir() + "/config.yaml"
	content := []byte("vuln-detection:\n  sql-injection:\n    enabled: false\n")
	if err := os.WriteFile(configPath, content, 0o644); err != nil {
		t.Fatalf("expected temp config to be written, got error: %v", err)
	}

	options, err := LoadScanOptionsFromFile(configPath)
	if err != nil {
		t.Fatalf("expected config to load, got error: %v", err)
	}
	if !options.VulnDetection.Enabled {
		t.Fatalf("expected global vuln switch to default to enabled when field is missing")
	}
}

func TestLoadScanOptionsFromFileReadsGlobalVulnSwitch(t *testing.T) {
	configPath := t.TempDir() + "/config.yaml"
	content := []byte("vuln-detection:\n  enabled: false\n  sql-injection:\n    enabled: true\n")
	if err := os.WriteFile(configPath, content, 0o644); err != nil {
		t.Fatalf("expected temp config to be written, got error: %v", err)
	}

	options, err := LoadScanOptionsFromFile(configPath)
	if err != nil {
		t.Fatalf("expected config to load, got error: %v", err)
	}
	if options.VulnDetection.Enabled {
		t.Fatalf("expected global vuln switch to load as disabled")
	}
}

func TestNewTargetResultFromCapturedActivityIncludesCapturedRecords(t *testing.T) {
	timestamp := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	apiRecords := []crawl.NetworkRecord{
		{
			URL:              "https://example.com/api/music",
			Method:           "POST",
			TraceID:          "trace-1",
			HasProtocolTrace: true,
			RequestBody:      "{\"page\":1}",
			ResponseBody:     "\"abcdef\"",
			ResponseCode:     200,
			FetchedAt:        timestamp,
		},
	}
	protocolTraces := []crawl.ProtocolTraceRecord{
		{
			TaskID:                 "cli-mode",
			TraceID:                "trace-1",
			RequestURL:             "https://example.com/api/music",
			Method:                 "POST",
			RequestBeforeTransform: "{\"page\":1}",
			FinalRequestBody:       "abcdef",
			SessionMaterials: map[string]string{
				"latest_response_ciphertext": "abcdef",
				"latest_response_plaintext":  "{\"code\":0}",
				"sm4_key_hex":                "0123456789abcdeffedcba9876543210",
			},
			CreatedAt: timestamp,
		},
	}
	result := newTargetResultFromCapturedActivity(
		"https://example.com",
		[]string{"https://example.com/api/music"},
		apiRecords,
		protocolTraces,
		nil,
	)

	if len(result.APIRecords) != 1 {
		t.Fatalf("expected 1 api record, got %d", len(result.APIRecords))
	}
	if result.APIRecords[0].ResponseBody != "\"abcdef\"" {
		t.Fatalf("expected captured response body to be preserved, got %q", result.APIRecords[0].ResponseBody)
	}
	if got := result.APIRecords[0].TraceID; got != "trace-1" {
		t.Fatalf("expected api record trace id to be preserved, got %q", got)
	}
	if !result.APIRecords[0].HasProtocolTrace {
		t.Fatal("expected api record to preserve protocol trace flag")
	}
	if len(result.ProtocolTraces) != 1 {
		t.Fatalf("expected 1 protocol trace, got %d", len(result.ProtocolTraces))
	}
	if got := result.ProtocolTraces[0].SessionMaterials["latest_response_plaintext"]; got != "{\"code\":0}" {
		t.Fatalf("expected latest_response_plaintext to be preserved, got %q", got)
	}
	if got := result.ProtocolTraces[0].TaskID; got != "cli-mode" {
		t.Fatalf("expected task id to be preserved, got %q", got)
	}
}

func TestBuildSDKTargetOverviewFocusesOnVulnerabilities(t *testing.T) {
	target := TargetResult{
		APIRecords: []APIRecord{
			{URL: "https://example.com/api/orders", Method: "GET"},
			{URL: "https://example.com/api/orders", Method: "POST"},
		},
		ProtocolTraces: []ProtocolTrace{{TraceID: "trace-1"}},
		Assets: AssetInfo{
			APIRoutes: []string{"/api/orders", "/api/profile"},
			APIRoots:  []string{"/api"},
		},
		Vulnerabilities: []VulnerabilityItem{
			{
				Title:            "未授权访问漏洞",
				Level:            "high",
				Type:             "unauthorized",
				URL:              "https://example.com/api/orders?id=1",
				Method:           "GET",
				Confidence:       "high",
				DataExposure:     "internal_business",
				HasProtocolTrace: true,
			},
			{
				Title:      "SQL注入漏洞",
				Level:      "medium",
				Type:       "sql_injection",
				URL:        "https://example.com/api/orders?id=2",
				Method:     "GET",
				Confidence: "medium",
			},
		},
	}

	overview := buildSDKTargetOverview(target)
	if overview.VulnerabilityCount != 2 {
		t.Fatalf("expected vulnerability count 2, got %d", overview.VulnerabilityCount)
	}
	if overview.VulnerableEndpoints != 1 {
		t.Fatalf("expected deduped vulnerable endpoints 1, got %d", overview.VulnerableEndpoints)
	}
	if overview.Severity.High != 1 || overview.Severity.Medium != 1 {
		t.Fatalf("unexpected severity summary: %+v", overview.Severity)
	}
	if overview.VulnerabilityTypes["unauthorized"] != 1 || overview.VulnerabilityTypes["sql_injection"] != 1 {
		t.Fatalf("unexpected vulnerability types: %+v", overview.VulnerabilityTypes)
	}
	if overview.Auxiliary.APIRecords != 2 || overview.Auxiliary.ProtocolTraces != 1 {
		t.Fatalf("unexpected auxiliary counts: %+v", overview.Auxiliary)
	}
	if len(overview.KeyFindings) != 2 {
		t.Fatalf("expected 2 key findings, got %d", len(overview.KeyFindings))
	}
}

func TestNewTargetResultFromCapturedActivityNormalizesProtocolTraceForView(t *testing.T) {
	timestamp := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)

	result := newTargetResultFromCapturedActivity(
		"https://example.com",
		[]string{"https://example.com/api/music"},
		nil,
		[]crawl.ProtocolTraceRecord{
			{
				TaskID:     "cli-mode",
				TraceID:    "trace-2",
				RequestURL: "https://example.com/api/music",
				Method:     "POST",
				RequestSteps: []crawl.ProtocolCryptoStep{
					{
						Source:        "JSON.stringify",
						Algorithm:     "json.stringify",
						InputPreview:  `{"page":1}`,
						OutputPreview: `{"page":1}`,
					},
					{
						Source:        "module.se",
						Algorithm:     "sm4.encrypt",
						InputPreview:  `{"page":1}`,
						OutputPreview: "abcdef",
					},
				},
				ResponseSteps: []crawl.ProtocolCryptoStep{
					{
						Source:        "JSON.parse",
						Algorithm:     "json.parse",
						InputPreview:  `{"code":0,"data":[1]}`,
						OutputPreview: `{"code":0,"data":[1]}`,
					},
					{
						Source:        "module.sd",
						Algorithm:     "sm4.decrypt",
						InputPreview:  "abcdef",
						OutputPreview: `{"code":0,"data":[1]}`,
					},
				},
				SessionMaterials: map[string]string{
					"latest_response_plaintext": "{}",
				},
				CreatedAt: timestamp,
			},
		},
		nil,
	)

	if len(result.ProtocolTraces) != 1 {
		t.Fatalf("expected 1 protocol trace, got %d", len(result.ProtocolTraces))
	}

	trace := result.ProtocolTraces[0]
	if got := trace.SessionMaterials["latest_response_plaintext"]; got != `{"code":0,"data":[1]}` {
		t.Fatalf("expected normalized response plaintext to prefer response step output, got %q", got)
	}
	if len(trace.ResponseSteps) == 0 {
		t.Fatal("expected meaningful response steps to be preserved")
	}
	if trace.ResponseSteps[0].Algorithm != "sm4.decrypt" {
		t.Fatalf("expected response step algorithm to be preserved, got %#v", trace.ResponseSteps)
	}
	if len(trace.RequestSteps) != 1 || trace.RequestSteps[0].Algorithm != "sm4.encrypt" {
		t.Fatalf("expected request steps to filter json.stringify and preserve sm4.encrypt, got %#v", trace.RequestSteps)
	}
	if got := trace.Algorithms; len(got) != 2 || got[0] != "sm4.encrypt" || got[1] != "sm4.decrypt" {
		t.Fatalf("expected algorithms to exclude json.parse/json.stringify and preserve crypto steps, got %#v", got)
	}
}

func TestMergeCapturedAPIRecordsWithProtocolTracesSynthesizesMissingRuntimeRecord(t *testing.T) {
	timestamp := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)

	merged := mergeCapturedAPIRecordsWithProtocolTraces(
		[]crawl.NetworkRecord{
			{
				URL:          "https://cas.example.com/auth/token",
				Method:       "GET",
				ResourceType: "xhr",
				FetchedAt:    timestamp,
			},
		},
		[]crawl.ProtocolTraceRecord{
			{
				TraceID:          "trace-ccat",
				Transport:        "fetch",
				RequestURL:       "https://example.com/ccat/testcases/getCaseList",
				Method:           "POST",
				FinalRequestBody: `{"pageNum":1,"pageSize":10}`,
				SessionMaterials: map[string]string{
					"latest_response_plaintext": `{"code":0,"data":[]}`,
				},
				CreatedAt: timestamp,
			},
		},
	)

	if len(merged) != 2 {
		t.Fatalf("expected 2 merged runtime records, got %d", len(merged))
	}

	var synthesized *crawl.NetworkRecord
	for i := range merged {
		if merged[i].URL == "https://example.com/ccat/testcases/getCaseList" {
			synthesized = &merged[i]
			break
		}
	}
	if synthesized == nil {
		t.Fatal("expected missing protocol trace request to be synthesized as api record")
	}
	if synthesized.TraceID != "trace-ccat" || !synthesized.HasProtocolTrace {
		t.Fatalf("expected synthesized record to keep trace linkage, got %+v", *synthesized)
	}
	if synthesized.RequestBody != `{"pageNum":1,"pageSize":10}` {
		t.Fatalf("expected synthesized request body, got %q", synthesized.RequestBody)
	}
	if synthesized.ResponseBody != `{"code":0,"data":[]}` {
		t.Fatalf("expected synthesized response plaintext, got %q", synthesized.ResponseBody)
	}
}

func TestMergeRuntimeAPIRoutesIncludesRuntimeTraceURLs(t *testing.T) {
	routes := mergeRuntimeAPIRoutes(
		[]string{"/api/common/getCitys"},
		nil,
		[]crawl.ProtocolTraceRecord{
			{RequestURL: "https://example.com/ccat/testcases/getCaseList"},
		},
	)

	found := false
	for _, route := range routes {
		if route == "https://example.com/ccat/testcases/getCaseList" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected runtime trace url to be merged into api routes, got %#v", routes)
	}
}

func TestPreferAbsoluteRuntimeRoutesDropsRelativeDuplicate(t *testing.T) {
	routes := preferAbsoluteRuntimeRoutes([]string{
		"/api/common/getCitys",
		"https://example.com/api/common/getCitys",
		"/ccat/testcases/getCaseList",
	})

	if len(routes) != 2 {
		t.Fatalf("expected relative duplicate to be removed, got %#v", routes)
	}
	for _, route := range routes {
		if route == "/api/common/getCitys" {
			t.Fatalf("expected relative route duplicate to be removed, got %#v", routes)
		}
	}
}

func TestPreferAbsoluteAPIRootsDropsRelativeDuplicate(t *testing.T) {
	roots := preferAbsoluteAPIRoots([]string{
		"https://example.com/api/",
		"/api/",
		"https://example.com/api/common/",
	})

	if len(roots) != 2 {
		t.Fatalf("expected relative api root duplicate to be removed, got %#v", roots)
	}
	for _, root := range roots {
		if root == "/api/" {
			t.Fatalf("expected relative api root duplicate to be removed, got %#v", roots)
		}
	}
}

func TestDecryptProtocolTraceUsesStoredResponsePlaintext(t *testing.T) {
	trace := ProtocolTrace{
		TraceID: "trace-1",
		SessionMaterials: map[string]string{
			"sm4_key_hex":                "0123456789abcdeffedcba9876543210",
			"latest_response_ciphertext": "abcdef",
			"latest_response_plaintext":  "{\"code\":0,\"message\":\"ok\"}",
		},
	}

	result, err := DecryptProtocolTrace(trace, "", "abcdef")
	if err != nil {
		t.Fatalf("expected decrypt to succeed, got error: %v", err)
	}
	if result.Plaintext != "{\"code\":0,\"message\":\"ok\"}" {
		t.Fatalf("expected plaintext to come from stored response plaintext, got %q", result.Plaintext)
	}
}

func TestDecryptProtocolTraceFallsBackToSM4(t *testing.T) {
	keyHex := "0123456789abcdeffedcba9876543210"
	plaintext := "{\"title\":\"song\"}"
	ciphertext, err := protocoltool.EncryptSM4Hex(plaintext, keyHex)
	if err != nil {
		t.Fatalf("expected test ciphertext to be created, got error: %v", err)
	}

	trace := ProtocolTrace{
		TraceID: "trace-2",
		SessionMaterials: map[string]string{
			"sm4_key_hex": keyHex,
		},
	}

	result, err := DecryptProtocolTrace(trace, "", ciphertext)
	if err != nil {
		t.Fatalf("expected decrypt to succeed, got error: %v", err)
	}
	if result.Plaintext != plaintext {
		t.Fatalf("expected plaintext %q, got %q", plaintext, result.Plaintext)
	}
}

func TestAnalyzeProtocolTraceClassifiesMissingResponseDecryptPath(t *testing.T) {
	trace := ProtocolTrace{
		TraceID:    "trace-3",
		RequestURL: "https://example.com/api/music",
		Algorithms: []string{"aes-gcm", "text.decode"},
		ResponseSteps: []ProtocolCryptoStep{
			{Source: "TextDecoder.decode", Algorithm: "text.decode"},
		},
		SessionMaterials: map[string]string{
			"latest_response_ciphertext": "abcdef",
		},
	}

	analysis := AnalyzeProtocolTrace(trace)

	if analysis.Status != TraceEvidenceResponsePathNotCaptured {
		t.Fatalf("expected status %q, got %q", TraceEvidenceResponsePathNotCaptured, analysis.Status)
	}
	if analysis.HasResponseCiphertext != true {
		t.Fatalf("expected response ciphertext to be detected")
	}
	if analysis.HasResponsePlaintext {
		t.Fatalf("expected response plaintext to be absent")
	}
}

func TestAnalyzeProtocolTraceClassifiesCapturedResponsePlaintext(t *testing.T) {
	trace := ProtocolTrace{
		TraceID:    "trace-4",
		RequestURL: "https://example.com/api/music",
		SessionMaterials: map[string]string{
			"latest_response_ciphertext": "abcdef",
			"latest_response_plaintext":  "{\"code\":0}",
		},
	}

	analysis := AnalyzeProtocolTrace(trace)

	if analysis.Status != TraceEvidenceResponsePlaintextCaptured {
		t.Fatalf("expected status %q, got %q", TraceEvidenceResponsePlaintextCaptured, analysis.Status)
	}
	if !analysis.HasResponsePlaintext {
		t.Fatalf("expected response plaintext to be detected")
	}
}

func TestAnalyzeProtocolTraceClassifiesEncodingVariantSuspected(t *testing.T) {
	trace := ProtocolTrace{
		TraceID:    "trace-5",
		RequestURL: "https://example.com/api/music?encoding=ag-1&sign=abc123",
		Algorithms: []string{"aes-gcm", "text.decode"},
		ResponseSteps: []ProtocolCryptoStep{
			{Source: "TextDecoder.decode", Algorithm: "text.decode"},
		},
		SessionMaterials: map[string]string{
			"latest_response_ciphertext": "abcdef",
		},
	}

	analysis := AnalyzeProtocolTrace(trace)

	if analysis.Status != TraceEvidenceEncodingVariantSuspected {
		t.Fatalf("expected status %q, got %q", TraceEvidenceEncodingVariantSuspected, analysis.Status)
	}
	if len(analysis.VariantSuggestions) != 2 {
		t.Fatalf("expected 2 variant suggestions, got %d", len(analysis.VariantSuggestions))
	}
	if analysis.VariantSuggestions[0].Parameter != "encoding" {
		t.Fatalf("expected first suggestion to target encoding, got %q", analysis.VariantSuggestions[0].Parameter)
	}
	if analysis.VariantSuggestions[0].Action != "remove" {
		t.Fatalf("expected first suggestion to remove encoding, got %q", analysis.VariantSuggestions[0].Action)
	}
	if analysis.VariantSuggestions[1].CandidateValue != "utf-8" {
		t.Fatalf("expected second suggestion to set utf-8, got %q", analysis.VariantSuggestions[1].CandidateValue)
	}
}

func TestAnalyzeProtocolTraceDoesNotFlagStandardEncodingAsVariant(t *testing.T) {
	trace := ProtocolTrace{
		TraceID:    "trace-6",
		RequestURL: "https://example.com/api/music?encoding=utf-8&sign=abc123",
		Algorithms: []string{"aes-gcm", "text.decode"},
		ResponseSteps: []ProtocolCryptoStep{
			{Source: "TextDecoder.decode", Algorithm: "text.decode"},
		},
		SessionMaterials: map[string]string{
			"latest_response_ciphertext": "abcdef",
		},
	}

	analysis := AnalyzeProtocolTrace(trace)

	if analysis.Status != TraceEvidenceResponsePathNotCaptured {
		t.Fatalf("expected status %q, got %q", TraceEvidenceResponsePathNotCaptured, analysis.Status)
	}
	if len(analysis.VariantSuggestions) != 0 {
		t.Fatalf("expected no variant suggestions, got %d", len(analysis.VariantSuggestions))
	}
}

func TestDedupeSDKVulnerabilitiesPrefersHTTPSVariant(t *testing.T) {
	vulns := dedupeSDKVulnerabilities([]VulnRecord{
		{
			Title:          "未授权访问",
			Type:           "未授权访问",
			Method:         "GET",
			URL:            "http://example.com/api/common/getCitys",
			ResponseLength: 100,
		},
		{
			Title:          "未授权访问",
			Type:           "未授权访问",
			Method:         "GET",
			URL:            "https://example.com/api/common/getCitys",
			ResponseLength: 100,
		},
	})

	if len(vulns) != 1 {
		t.Fatalf("expected duplicate vulnerabilities to be merged, got %#v", vulns)
	}
	if vulns[0].URL != "https://example.com/api/common/getCitys" {
		t.Fatalf("expected https variant to be preferred, got %#v", vulns[0])
	}
}
