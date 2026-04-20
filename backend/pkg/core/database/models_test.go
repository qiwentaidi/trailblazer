package database

import "testing"

func TestCompactProtocolCryptoStepsPreservesResponseDecryptStep(t *testing.T) {
	steps := []ProtocolCryptoStep{
		{Source: "window.mod.sd", Algorithm: "sm4", InputPreview: "cipher", OutputPreview: "{\"code\":200}"},
	}
	for i := 0; i < 20; i++ {
		steps = append(steps, ProtocolCryptoStep{
			Source:        "JSON.parse",
			Algorithm:     "json.parse",
			InputPreview:  "{\"code\":200}",
			OutputPreview: "{\"code\":200}",
		})
	}

	compacted := compactProtocolCryptoSteps(steps, "")

	foundDecrypt := false
	for _, step := range compacted {
		if step.Source == "window.mod.sd" {
			foundDecrypt = true
			break
		}
	}
	if !foundDecrypt {
		t.Fatalf("expected compacted steps to preserve response decrypt step, got %#v", compacted)
	}
}

func TestNormalizeForViewDoesNotBackfillLatestPlaintextFromResponseJSONStringify(t *testing.T) {
	trace := ProtocolTraceRecord{
		TraceID: "trace-response-json",
		ResponseSteps: []ProtocolCryptoStep{
			{
				Source:        "JSON.stringify",
				Algorithm:     "json.stringify",
				InputPreview:  "{\"code\":200}",
				OutputPreview: "{\"code\":200}",
			},
			{
				Source:        "JSON.parse",
				Algorithm:     "json.parse",
				InputPreview:  "{\"code\":200}",
				OutputPreview: "{\"code\":200}",
			},
		},
		SessionMaterials: map[string]string{
			"latest_response_plaintext": "{\"code\":200}",
		},
	}

	trace.NormalizeForView()

	if got := trace.SessionMaterials["latest_plaintext"]; got != "" {
		t.Fatalf("expected latest_plaintext to stay empty for response-side JSON stringify, got %q", got)
	}
	if got := trace.RequestBeforeTransform; got != "" {
		t.Fatalf("expected request_before_transform to stay empty, got %q", got)
	}
}

func TestNormalizeForViewSuppressesMirroredRequestPlaintextWithoutRequestEvidence(t *testing.T) {
	trace := ProtocolTraceRecord{
		TraceID:                "trace-mirrored-request",
		RequestBeforeTransform: "{\"code\":200}",
		SessionMaterials: map[string]string{
			"latest_response_plaintext":  "{\"code\":200}",
			"latest_response_ciphertext": "cipher-response",
		},
		ResponseSteps: []ProtocolCryptoStep{
			{
				Source:        "crypto.decrypt",
				Algorithm:     "aes-cbc",
				InputPreview:  "cipher-response",
				OutputPreview: "{\"code\":200}",
			},
		},
	}

	trace.NormalizeForView()

	if got := trace.RequestBeforeTransform; got != "" {
		t.Fatalf("expected mirrored request_before_transform to be cleared, got %q", got)
	}
}

func TestNormalizeForViewDropsOpaqueResponsePlaintextArtifacts(t *testing.T) {
	trace := ProtocolTraceRecord{
		TraceID: "trace-opaque-response",
		SessionMaterials: map[string]string{
			"latest_response_plaintext": `"4869f146b63d96e8d1c886ae2105fb6dbbf56673503fc8c2d783bd4ef2005e76a572037243afcd80639bcabba46fd2155a555e80ef831a7f807536e6ddc23ac2052f592d0551ff6792b1d8ab8d945cb5"`,
		},
	}

	trace.NormalizeForView()

	if got := trace.SessionMaterials["latest_response_plaintext"]; got != "" {
		t.Fatalf("expected opaque latest_response_plaintext to be cleared, got %q", got)
	}
}

func TestNormalizeForViewDoesNotBackfillLatestResponseCiphertextFromRequestSideHelpers(t *testing.T) {
	trace := ProtocolTraceRecord{
		TraceID: "trace-response-ciphertext-no-backfill",
		RequestSteps: []ProtocolCryptoStep{
			{
				Source:        "window.atob",
				Algorithm:     "base64.decode",
				InputPreview:  "TVRSRFJUTFZORUU1TkVaR01EQkZSVExFTjBSQ05FVTVSRQ==",
				OutputPreview: "04CE9E4A94FF00EE9D7DB4E9DFA01FFA1E6E146630B760142CAE625B163AF9A85AE63480E9DE9E1A76D1BD88C8B21C75E7325932C66A5C028DB5CB3966C4B4B7D7",
			},
			{
				Source:        "crypto.decrypt",
				Algorithm:     "aes-cbc",
				InputPreview:  "04CE9E4A94FF00EE9D7DB4E9DFA01FFA1E6E146630B760142CAE625B163AF9A85AE63480E9DE9E1A76D1BD88C8B21C75E7325932C66A5C028DB5CB3966C4B4B7D7",
				OutputPreview: "{\"code\":200}",
			},
		},
	}

	trace.NormalizeForView()

	if got := trace.SessionMaterials["latest_response_ciphertext"]; got != "" {
		t.Fatalf("expected latest_response_ciphertext to stay empty for request-side helper chain, got %q", got)
	}
}

func TestNormalizeForViewPrefersRicherResponseStepPlaintext(t *testing.T) {
	trace := ProtocolTraceRecord{
		TraceID: "trace-response-preferred-step",
		ResponseSteps: []ProtocolCryptoStep{
			{
				Source:        "JSON.stringify",
				Algorithm:     "json.stringify",
				InputPreview:  `{"code":"err.common.system.error","msg":"系统错误","success":false}`,
				OutputPreview: `{"code":"err.common.system.error","msg":"系统错误","success":false}`,
			},
			{
				Source:        "JSON.stringify",
				Algorithm:     "json.stringify",
				InputPreview:  `{}`,
				OutputPreview: `{}`,
			},
		},
		SessionMaterials: map[string]string{
			"latest_response_plaintext": `{}`,
		},
	}

	trace.NormalizeForView()

	if got := trace.SessionMaterials["latest_response_plaintext"]; got != `{"code":"err.common.system.error","msg":"系统错误","success":false}` {
		t.Fatalf("expected richer response step plaintext to win, got %q", got)
	}
}

func TestNormalizeForViewBackfillsSyntheticRuntimeStepsFromSessionMaterials(t *testing.T) {
	trace := ProtocolTraceRecord{
		TraceID:                "trace-runtime-backfill",
		RequestBeforeTransform: `{}`,
		FinalRequestBody:       `c4e860c7fe76e44c9d0dda90a71770dc`,
		SessionMaterials: map[string]string{
			"sm4_key_hex":                    "30303438313833303239313330303839",
			"latest_plaintext":               `{}`,
			"latest_ciphertext":              `c4e860c7fe76e44c9d0dda90a71770dc`,
			"latest_response_ciphertext":     `2bbae1443373f169fb5756dda09db56e`,
			"latest_response_plaintext":      `{"code":0}`,
			"request_runtime_function_path":  "__webpack_require__(2076).se",
			"request_runtime_module_id":      "2076",
			"response_runtime_function_path": "__webpack_require__(2076).sd",
			"response_runtime_module_id":     "2076",
		},
	}

	trace.NormalizeForView()

	if len(trace.RequestSteps) == 0 {
		t.Fatalf("expected request steps to be backfilled")
	}
	if got := trace.RequestSteps[0].Source; got != "__webpack_require__(2076).se" {
		t.Fatalf("expected synthetic request step source, got %q", got)
	}
	if got := trace.RequestSteps[0].ModuleID; got != "2076" {
		t.Fatalf("expected synthetic request module id, got %q", got)
	}
	if got := trace.RequestSteps[0].Algorithm; got != "sm4.encrypt" {
		t.Fatalf("expected synthetic request algorithm, got %q", got)
	}

	if len(trace.ResponseSteps) == 0 {
		t.Fatalf("expected response steps to be backfilled")
	}
	if got := trace.ResponseSteps[0].Source; got != "__webpack_require__(2076).sd" {
		t.Fatalf("expected synthetic response step source, got %q", got)
	}
	if got := trace.ResponseSteps[0].ModuleID; got != "2076" {
		t.Fatalf("expected synthetic response module id, got %q", got)
	}
	if got := trace.ResponseSteps[0].Algorithm; got != "sm4.decrypt" {
		t.Fatalf("expected synthetic response algorithm, got %q", got)
	}
}
