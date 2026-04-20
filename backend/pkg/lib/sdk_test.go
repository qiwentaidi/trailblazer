package lib

import (
	"os"
	"testing"
	"time"
	"trailblazer/pkg/config"
	"trailblazer/pkg/core/crawl"
	"trailblazer/pkg/core/protocoltool"
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

	jsFindOptions := buildSDKJSFindOptions("cli-mode", "https://example.com", []string{"/api"}, "/api", options, nil)

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
