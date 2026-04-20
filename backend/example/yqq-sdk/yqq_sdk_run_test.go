package main

import (
	"testing"
	"trailblazer/pkg/lib"
)

func TestBuildTraceSummaryEntrySkipsDecryptWhenResponsePlaintextCaptured(t *testing.T) {
	trace := lib.ProtocolTrace{
		TraceID:    "trace-1",
		RequestURL: "https://y.qq.com/api/test",
		Method:     "GET",
		SessionMaterials: map[string]string{
			"latest_response_ciphertext": "abcdef",
			"latest_response_plaintext":  "{\"code\":0,\"message\":\"ok\"}",
			"crypto_key_base64":          "vQNYcNWvpBM0VK8INvXhzw==",
		},
	}

	entry := buildTraceSummaryEntry(trace)

	if got := entry["decryptStatus"]; got != "not_needed" {
		t.Fatalf("expected decryptStatus=not_needed when response plaintext exists, got %v", got)
	}
	if _, exists := entry["decryptError"]; exists {
		t.Fatalf("expected decryptError to be omitted when response plaintext exists")
	}
	if _, exists := entry["materialSummary"]; exists {
		t.Fatalf("expected materialSummary to be omitted when response plaintext exists")
	}
	if got := entry["decryptPreview"]; got != "{\"code\":0,\"message\":\"ok\"}" {
		t.Fatalf("expected decrypt preview to reuse captured plaintext, got %v", got)
	}
}

func TestBuildTraceSummaryEntryKeepsMaterialSummaryWhenPlaintextMissing(t *testing.T) {
	trace := lib.ProtocolTrace{
		TraceID:    "trace-2",
		RequestURL: "https://y.qq.com/api/test",
		Method:     "GET",
		SessionMaterials: map[string]string{
			"crypto_key_base64": "vQNYcNWvpBM0VK8INvXhzw==",
		},
	}

	entry := buildTraceSummaryEntry(trace)

	if got := entry["decryptStatus"]; got != "skipped" {
		t.Fatalf("expected decryptStatus=skipped when ciphertext is missing, got %v", got)
	}
	if _, exists := entry["materialSummary"]; !exists {
		t.Fatalf("expected materialSummary to remain available when plaintext is missing")
	}
}
