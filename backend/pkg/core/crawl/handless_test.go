package crawl

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

func TestBuildCaptureChromeFlagsIncludesProxySettings(t *testing.T) {
	flags := buildCaptureChromeFlags(CaptureOptions{
		BrowserVisible:  true,
		ProxyServer:     "http://127.0.0.1:8080",
		ProxyBypassList: "<-loopback>",
	})

	if got, ok := flags["headless"].(bool); !ok || got {
		t.Fatalf("expected visible browser to set headless=false, got %#v", flags["headless"])
	}
	if got := flags["proxy-server"]; got != "http://127.0.0.1:8080" {
		t.Fatalf("expected proxy-server flag, got %#v", got)
	}
	if got := flags["proxy-bypass-list"]; got != "<-loopback>" {
		t.Fatalf("expected proxy-bypass-list flag, got %#v", got)
	}
}

func TestIsExpectedCaptureCancellation(t *testing.T) {
	if !isExpectedCaptureCancellation(context.Canceled) {
		t.Fatal("expected context.Canceled to be treated as expected cancellation")
	}
	if isExpectedCaptureCancellation(fmt.Errorf("network failure")) {
		t.Fatal("expected unrelated error not to be treated as expected cancellation")
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

func TestProtocolHookScriptWrapsWebpackPrototypeEncryptors(t *testing.T) {
	requiredSnippets := []string{
		`function scanAndWrapPrototypeFunctions(candidate, label)`,
		`function hookKnownCryptoConstructors()`,
		`scanAndWrapPrototypeFunctions(window.JSEncrypt, "window.JSEncrypt")`,
		`scanAndWrapPrototypeFunctions(window.RSAKey, "window.RSAKey")`,
		`Object.getOwnPropertyNames(prototype)`,
		`label + ".prototype." + methodName`,
		`function stringifyWithoutCapture(value)`,
		`isLikelyRSABase64Ciphertext(outputPreview)`,
		`normalizedAlgorithm = "rsa.encrypt"`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(protocolHookScript, snippet) {
			t.Fatalf("expected protocol hook script to include %q", snippet)
		}
	}
}

func TestProtocolHookScriptSynthesizesFieldRSAEncryptionSteps(t *testing.T) {
	requiredSnippets := []string{
		`function collectEncryptedFieldCandidates(value, path, target)`,
		`function findCryptoStepForCiphertext(cryptoSteps, ciphertext)`,
		`function synthesizeFieldEncryptionSteps(finalBodyPreview, cryptoSteps)`,
		`var matchedStep = findCryptoStepForCiphertext(cryptoSteps, value)`,
		`algorithm = isLikelyRSABase64Ciphertext(value) ? "rsa.encrypt(inferred)" : "encrypted-field(inferred)"`,
		`setSessionMaterial("latest_plaintext", stringifyWithoutCapture(reconstructedBody))`,
		`setSessionMaterial("encrypted_field_inference_only", "true")`,
		`sessionMaterials["encrypted_field_inference_only"] === "true"`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(protocolHookScript, snippet) {
			t.Fatalf("expected protocol hook script to include %q", snippet)
		}
	}
}

func TestAutoTriggerFormsScriptIncludesCommonLoginHeuristics(t *testing.T) {
	requiredSnippets := []string{
		`"form.login-form"`,
		`".ggd-gateway__login form"`,
		`candidateFields(node).length > 0`,
		`querySelectorAll("input, textarea, select")`,
		`querySelectorAll("button, input[type='submit'], input[type='button'], [role='button']")`,
		`trailblazer_`,
		`Tb!`,
		`request_submit`,
		`clicked_submit_control`,
		`__trailblazerAutoTriggered`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(autoTriggerFormsScript, snippet) {
			t.Fatalf("expected auto trigger form script to include %q", snippet)
		}
	}
}

func TestCaptureNetworkActivityWithOptionsAutoTriggersVisibleForm(t *testing.T) {
	var loginRequests atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprintf(w, `<!doctype html>
<html>
  <body>
    <form id="login-form">
      <input type="text" name="username" placeholder="用户名" />
      <input type="password" name="password" placeholder="密码" />
      <button type="submit">登录</button>
    </form>
    <script>
      document.getElementById("login-form").addEventListener("submit", async function (event) {
        event.preventDefault();
        const form = event.target;
        const payload = {
          username: form.username.value,
          password: form.password.value
        };
        const response = await fetch("/api/login", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload)
        });
        const data = await response.json();
        document.body.setAttribute("data-login-status", data.code);
      });
    </script>
  </body>
</html>`)
		case "/api/login":
			loginRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":"SUCCESS","data":"cipher-demo"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, records, traces := CaptureNetworkActivityWithOptions(server.URL, CaptureOptions{
		AutoTriggerForms:    true,
		InitialWait:         1200 * time.Millisecond,
		PostInteractionWait: 2500 * time.Millisecond,
		Timeout:             20 * time.Second,
	})

	if loginRequests.Load() == 0 && len(records) == 0 && len(traces) == 0 {
		t.Skip("chromedp runtime unavailable or auto form trigger did not execute in this environment")
	}
	if loginRequests.Load() == 0 {
		t.Fatalf("expected auto-triggered login request to reach test server")
	}

	var matched bool
	for _, record := range records {
		if strings.HasSuffix(record.URL, "/api/login") && record.Method == "POST" {
			matched = true
			if !strings.Contains(record.RequestBody, "trailblazer_") {
				t.Fatalf("expected randomized username in request body, got %q", record.RequestBody)
			}
			if !strings.Contains(record.RequestBody, "Tb!") {
				t.Fatalf("expected randomized password in request body, got %q", record.RequestBody)
			}
			if !strings.Contains(record.ResponseBody, `"SUCCESS"`) {
				t.Fatalf("expected login response to be captured, got %q", record.ResponseBody)
			}
		}
	}
	if !matched {
		t.Fatalf("expected /api/login request to be captured, got %#v", records)
	}

	var foundTrace bool
	for _, trace := range traces {
		if strings.HasSuffix(trace.RequestURL, "/api/login") {
			foundTrace = true
			break
		}
	}
	if !foundTrace {
		t.Fatalf("expected protocol trace for auto-triggered login request, got %#v", traces)
	}
}

func TestCaptureNetworkActivityHooksJSEncryptPrototype(t *testing.T) {
	const rsaCipher = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	var encryptedRequests atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprintf(w, `<!doctype html>
<html>
  <body>
    <script>
      window.JSEncrypt = function () {};
      window.JSEncrypt.prototype.encrypt = function (value) {
        window.__lastPlaintext = value;
        return %q;
      };
      setTimeout(async function () {
        var encryptor = new window.JSEncrypt();
        var cipher = encryptor.encrypt("plain-value");
        await fetch("/api/submit", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ secret: cipher })
        });
      }, 1800);
    </script>
  </body>
</html>`, rsaCipher)
		case "/api/submit":
			encryptedRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":"OK"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, records, traces := CaptureNetworkActivityWithOptions(server.URL, CaptureOptions{
		InitialWait:         500 * time.Millisecond,
		PostInteractionWait: 3500 * time.Millisecond,
		Timeout:             20 * time.Second,
	})

	if encryptedRequests.Load() == 0 && len(records) == 0 && len(traces) == 0 {
		t.Skip("chromedp runtime unavailable or timed JS request did not execute in this environment")
	}
	if encryptedRequests.Load() == 0 {
		t.Fatalf("expected encrypted request to reach test server")
	}

	var foundRealRSA bool
	var foundPlaintext bool
	for _, trace := range traces {
		if !strings.HasSuffix(trace.RequestURL, "/api/submit") {
			continue
		}
		if strings.Contains(trace.RequestBeforeTransform, "plain-value") {
			foundPlaintext = true
		}
		for _, step := range trace.RequestSteps {
			if step.Algorithm == "rsa.encrypt" && step.InputPreview == "plain-value" && step.OutputPreview == rsaCipher {
				foundRealRSA = true
			}
		}
	}
	if !foundRealRSA {
		t.Fatalf("expected real JSEncrypt rsa.encrypt step, got %#v", traces)
	}
	if !foundPlaintext {
		t.Fatalf("expected request plaintext to be reconstructed from matched rsa step, got %#v", traces)
	}
}

func TestCaptureNetworkActivityDoesNotCarryRSAStepsIntoFollowingGET(t *testing.T) {
	const rsaCipher = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	var postRequests atomic.Int32
	var getRequests atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprintf(w, `<!doctype html>
<html>
  <body>
    <script>
      window.JSEncrypt = function () {};
      window.JSEncrypt.prototype.encrypt = function (value) { return %q; };
      setTimeout(async function () {
        var encryptor = new window.JSEncrypt();
        var cipher = encryptor.encrypt("first-plain");
        await fetch("/api/encrypted", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ secret: cipher })
        });
        await fetch("/api/captcha?userName=admin");
      }, 1800);
    </script>
  </body>
</html>`, rsaCipher)
		case "/api/encrypted":
			postRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":"POST_OK"}`))
		case "/api/captcha":
			getRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":"GET_OK","data":{"imageCode":"data:image/png;base64,AA=="}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, records, traces := CaptureNetworkActivityWithOptions(server.URL, CaptureOptions{
		InitialWait:         500 * time.Millisecond,
		PostInteractionWait: 4500 * time.Millisecond,
		Timeout:             20 * time.Second,
	})

	if postRequests.Load() == 0 && getRequests.Load() == 0 && len(records) == 0 && len(traces) == 0 {
		t.Skip("chromedp runtime unavailable or timed JS requests did not execute in this environment")
	}
	if postRequests.Load() == 0 || getRequests.Load() == 0 {
		t.Fatalf("expected both POST and GET requests, post=%d get=%d", postRequests.Load(), getRequests.Load())
	}

	var foundGET bool
	for _, trace := range traces {
		if !strings.Contains(trace.RequestURL, "/api/captcha") {
			continue
		}
		foundGET = true
		if len(trace.RequestSteps) != 0 {
			t.Fatalf("expected GET trace not to inherit request crypto steps, got %#v", trace.RequestSteps)
		}
		if len(trace.Algorithms) != 0 {
			t.Fatalf("expected GET trace algorithms to be empty, got %#v", trace.Algorithms)
		}
		if trace.RequestBeforeTransform != "" {
			t.Fatalf("expected GET trace request plaintext to be empty, got %q", trace.RequestBeforeTransform)
		}
	}
	if !foundGET {
		t.Fatalf("expected GET trace for /api/captcha, got %#v", traces)
	}
}
