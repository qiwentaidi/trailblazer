package crawl

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestUpsertProtocolTraceRecordMergesLateResponseMaterials(t *testing.T) {
	traces := []ProtocolTraceRecord{{
		TraceID:          "trace-1",
		RequestURL:       "https://u6.y.qq.com/cgi-bin/musics.fcg",
		Method:           "POST",
		FinalRequestBody: "request-ciphertext",
		SessionMaterials: map[string]string{
			"latest_plaintext": "request-plaintext",
		},
		RequestSteps: []ProtocolCryptoStep{{
			Source:    "webcrypto.encrypt",
			Algorithm: "AES-GCM",
		}},
	}}
	traceIndex := map[string]int{"trace-1": 0}

	update := ProtocolTraceRecord{
		TraceID:    "trace-1",
		RequestURL: "https://u6.y.qq.com/cgi-bin/musics.fcg",
		Method:     "POST",
		SessionMaterials: map[string]string{
			"latest_response_ciphertext": "response-ciphertext",
			"latest_response_plaintext":  "{\"code\":0}",
		},
		ResponseSteps: []ProtocolCryptoStep{{
			Source:        "webcrypto.decrypt",
			Algorithm:     "AES-GCM",
			InputPreview:  "[ArrayBuffer 1528 bytes]",
			OutputPreview: "{\"code\":0}",
		}},
	}

	upsertProtocolTraceRecord(traceIndex, &traces, update)

	if got := len(traces); got != 1 {
		t.Fatalf("expected a single merged trace, got %d", got)
	}

	merged := traces[0]
	if got := merged.SessionMaterials["latest_response_ciphertext"]; got != "response-ciphertext" {
		t.Fatalf("expected response ciphertext to be merged, got %q", got)
	}
	if got := merged.SessionMaterials["latest_response_plaintext"]; got != "{\"code\":0}" {
		t.Fatalf("expected response plaintext to be merged, got %q", got)
	}
	if got := len(merged.RequestSteps); got != 1 {
		t.Fatalf("expected request steps to be preserved, got %d", got)
	}
	if got := len(merged.ResponseSteps); got != 1 {
		t.Fatalf("expected response steps to be merged, got %d", got)
	}
	if got := strings.Join(merged.Algorithms, ","); got != "AES-GCM" {
		t.Fatalf("expected merged algorithms to dedupe to AES-GCM, got %q", got)
	}
}

func TestProtocolTraceNormalizePreservesLargeResponseCiphertext(t *testing.T) {
	largeCiphertext := strings.Repeat("A", 1024)
	trace := ProtocolTraceRecord{
		TraceID: "trace-2",
		SessionMaterials: map[string]string{
			"latest_response_ciphertext": largeCiphertext,
		},
	}

	trace.normalize()

	if got := trace.SessionMaterials["latest_response_ciphertext"]; got != largeCiphertext {
		t.Fatalf("expected response ciphertext to survive normalization, got length %d want %d", len(got), len(largeCiphertext))
	}
}

func TestBackfillProtocolTraceResponsesFromAPIRecords(t *testing.T) {
	traces := []ProtocolTraceRecord{{
		TraceID:    "trace-3",
		RequestURL: "https://u6.y.qq.com/cgi-bin/musics.fcg?encoding=ag-1",
		Method:     "POST",
	}}
	apiRecords := []NetworkRecord{{
		URL:          "https://u6.y.qq.com/cgi-bin/musics.fcg?encoding=ag-1",
		Method:       "POST",
		ResponseBody: "binary-response-ciphertext",
		MIMEType:     "application/octet-stream",
	}}

	backfillProtocolTraceResponsesFromAPIRecords(traces, apiRecords)

	if got := traces[0].SessionMaterials["latest_response_ciphertext"]; got != "binary-response-ciphertext" {
		t.Fatalf("expected response ciphertext to backfill from api record, got %q", got)
	}
}

func TestBackfillProtocolTraceResponsesFromPlaintextAPIRecords(t *testing.T) {
	traces := []ProtocolTraceRecord{{
		TraceID:    "trace-4",
		RequestURL: "https://c6.y.qq.com/tips/fcgi-bin/fcg_music_red_dota.fcg?format=json",
		Method:     "GET",
	}}
	apiRecords := []NetworkRecord{{
		URL:          "https://c6.y.qq.com/tips/fcgi-bin/fcg_music_red_dota.fcg?format=json",
		Method:       "GET",
		ResponseBody: "{\"code\":1,\"subcode\":1,\"msg\":\"\",\"data\":{}}",
		MIMEType:     "text/html",
	}}

	backfillProtocolTraceResponsesFromAPIRecords(traces, apiRecords)

	if got := traces[0].SessionMaterials["latest_response_plaintext"]; got != "{\"code\":1,\"subcode\":1,\"msg\":\"\",\"data\":{}}" {
		t.Fatalf("expected plaintext response to backfill as latest_response_plaintext, got %q", got)
	}
	if got := traces[0].SessionMaterials["latest_response_ciphertext"]; got != "" {
		t.Fatalf("expected plaintext response not to backfill as latest_response_ciphertext, got %q", got)
	}
}

func TestBackfillProtocolTraceResponsesCompletesMissingCiphertext(t *testing.T) {
	traces := []ProtocolTraceRecord{{
		TraceID:    "trace-5",
		RequestURL: "https://szpz.wsjkw.hangzhou.gov.cn/api/sysChannel/query/info",
		Method:     "POST",
		SessionMaterials: map[string]string{
			"latest_response_plaintext": `{"code":"err.common.system.error","msg":"系统错误","success":false}`,
		},
	}}
	apiRecords := []NetworkRecord{{
		URL:          "https://szpz.wsjkw.hangzhou.gov.cn/api/sysChannel/query/info",
		Method:       "POST",
		ResponseBody: `"d21ce8aaf550b5d24da7ecf1dcd13a191a2eae9440b303ddbcfce489aeb295d2cbed01853b6639dc6078a9b7780ec9815220c287069683913e6816f248d2173683970571fc18cff33cc0ebd268393f68"`,
		MIMEType:     "text/plain",
	}}

	backfillProtocolTraceResponsesFromAPIRecords(traces, apiRecords)

	if got := traces[0].SessionMaterials["latest_response_ciphertext"]; got != `"d21ce8aaf550b5d24da7ecf1dcd13a191a2eae9440b303ddbcfce489aeb295d2cbed01853b6639dc6078a9b7780ec9815220c287069683913e6816f248d2173683970571fc18cff33cc0ebd268393f68"` {
		t.Fatalf("expected missing response ciphertext to backfill from api record, got %q", got)
	}
	if got := traces[0].SessionMaterials["latest_response_plaintext"]; got != `{"code":"err.common.system.error","msg":"系统错误","success":false}` {
		t.Fatalf("expected existing response plaintext to stay unchanged, got %q", got)
	}
}

func TestIsLikelyPlaintextResponseDoesNotMisclassifyQuotedCiphertext(t *testing.T) {
	record := NetworkRecord{
		ResponseBody: `"d21ce8aaf550b5d24da7ecf1dcd13a191a2eae9440b303ddbcfce489aeb295d2cbed01853b6639dc6078a9b7780ec9815220c287069683913e6816f248d2173683970571fc18cff33cc0ebd268393f68"`,
		MIMEType:     "text/plain",
	}

	if isLikelyPlaintextResponse(record) {
		t.Fatal("expected quoted hex ciphertext response not to be treated as plaintext")
	}
}

func TestLinkAPIRecordsToProtocolTracesMarksMatchedAPIRecord(t *testing.T) {
	apiRecords := []NetworkRecord{{
		URL:         "https://example.com/api/list?page=1",
		Method:      "GET",
		RequestBody: "",
	}}
	traces := []ProtocolTraceRecord{{
		TraceID:          "trace-api-1",
		RequestURL:       "https://example.com/api/list?page=1",
		Method:           "GET",
		FinalRequestBody: "",
	}}

	linkAPIRecordsToProtocolTraces(apiRecords, traces)

	if got := apiRecords[0].TraceID; got != "trace-api-1" {
		t.Fatalf("expected api record trace id to be linked, got %q", got)
	}
	if !apiRecords[0].HasProtocolTrace {
		t.Fatal("expected api record to be marked with protocol trace")
	}
}

func TestLinkAPIRecordsToProtocolTracesLeavesUnmatchedAPIRecordUnmarked(t *testing.T) {
	apiRecords := []NetworkRecord{{
		URL:         "https://example.com/api/list?page=1",
		Method:      "GET",
		RequestBody: "",
	}}
	traces := []ProtocolTraceRecord{{
		TraceID:          "trace-api-1",
		RequestURL:       "https://example.com/api/other?page=1",
		Method:           "GET",
		FinalRequestBody: "",
	}}

	linkAPIRecordsToProtocolTraces(apiRecords, traces)

	if got := apiRecords[0].TraceID; got != "" {
		t.Fatalf("expected unmatched api record trace id to stay empty, got %q", got)
	}
	if apiRecords[0].HasProtocolTrace {
		t.Fatal("expected unmatched api record not to be marked with protocol trace")
	}
}

func TestNormalizeCapturedResponseBodyEncodesBinaryAsBase64(t *testing.T) {
	raw := []byte{0x01, 0x1d, 0x8f, 0x72, 0x3a, 0xc5}
	got := normalizeCapturedResponseBody("text/plain; charset=utf-8", raw)
	want := base64.StdEncoding.EncodeToString(raw)
	if got != want {
		t.Fatalf("expected binary body to be base64 encoded, got %q want %q", got, want)
	}
}

func TestProtocolHookScriptIncludesWorkerAndWasmHooks(t *testing.T) {
	requiredSnippets := []string{
		"function hookWorkers()",
		"function wrapWorkerInstance(",
		"recordWorkerMessageStep(",
		"sharedworker.construct",
		"webassembly.instantiate",
		"webassembly.instantiateStreaming",
		"wasm_runtime_present",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(protocolHookScript, snippet) {
			t.Fatalf("expected protocol hook script to include %q", snippet)
		}
	}
}

func TestProtocolHookScriptCapturesWebCryptoDecryptResults(t *testing.T) {
	requiredSnippets := []string{
		"captureWebCryptoDecryptResult",
		"latest_response_plaintext",
		"latest_response_ciphertext",
		"webcrypto.decrypt",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(protocolHookScript, snippet) {
			t.Fatalf("expected protocol hook script to include %q", snippet)
		}
	}
}

func TestProtocolHookScriptClassifiesPlaintextResponsesSeparately(t *testing.T) {
	requiredSnippets := []string{
		"function rememberResponseBodyForTrace(trace, responseBody, contentType)",
		"function isLikelyEncodedPayload(text)",
		"var treatAsPlaintext = !isLikelyEncodedPayload(ciphertext) && (shouldTreatResponseAsText(contentType) || isLikelyReadableText(ciphertext));",
		"if (treatAsPlaintext) {",
		"latest_response_plaintext: ciphertext",
		"latest_response_ciphertext: ciphertext",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(protocolHookScript, snippet) {
			t.Fatalf("expected protocol hook script to include %q", snippet)
		}
	}
}

func TestProtocolHookScriptDoesNotTreatGlobalJSONStringifyAsLatestPlaintext(t *testing.T) {
	unexpectedSnippet := `        if (isLikelyJSONText(result)) {
          setSessionMaterial("latest_plaintext", result);
        }`

	if strings.Contains(protocolHookScript, unexpectedSnippet) {
		t.Fatalf("expected protocol hook script not to assign latest_plaintext from global JSON.stringify")
	}
}

func TestProtocolHookScriptCapturesJSONParseResults(t *testing.T) {
	requiredSnippets := []string{
		`typeof JSON.parse === "function"`,
		`recordCryptoStep("JSON.parse", "json.parse", value, result)`,
		`captureResponsePlaintextCandidate(value, "JSON.parse")`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(protocolHookScript, snippet) {
			t.Fatalf("expected protocol hook script to include %q", snippet)
		}
	}
}
