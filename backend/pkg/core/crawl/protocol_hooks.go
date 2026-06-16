package crawl

import (
	"fmt"
	"strings"
	"time"
)

const protocolHookBindingName = "__trailblazerHookSink"

// ProtocolCryptoStep 表示一次前端加密/签名相关调用
type ProtocolCryptoStep struct {
	Source        string `json:"source"`
	Algorithm     string `json:"algorithm,omitempty"`
	InputPreview  string `json:"input_preview,omitempty"`
	OutputPreview string `json:"output_preview,omitempty"`
	CallID        string `json:"call_id,omitempty"`
	ParentCallID  string `json:"parent_call_id,omitempty"`
	FunctionPath  string `json:"function_path,omitempty"`
	ModuleID      string `json:"module_id,omitempty"`
	Stack         string `json:"stack,omitempty"`
	CapturedAtMS  int64  `json:"captured_at_ms,omitempty"`
}

// ProtocolTraceRecord 表示一次接口发包时关联到的协议轨迹
type ProtocolTraceRecord struct {
	TaskID                 string               `json:"task_id,omitempty"`
	TraceID                string               `json:"trace_id"`
	Transport              string               `json:"transport"`
	PageURL                string               `json:"page_url"`
	RequestURL             string               `json:"request_url"`
	Method                 string               `json:"method"`
	RequestHeaders         map[string]string    `json:"request_headers,omitempty"`
	RequestBeforeTransform string               `json:"request_before_transform,omitempty"`
	FinalRequestBody       string               `json:"final_request_body,omitempty"`
	RequestSteps           []ProtocolCryptoStep `json:"request_steps,omitempty"`
	ResponseSteps          []ProtocolCryptoStep `json:"response_steps,omitempty"`
	SignatureFields        []string             `json:"signature_fields,omitempty"`
	DynamicParams          map[string]string    `json:"dynamic_params,omitempty"`
	SessionMaterials       map[string]string    `json:"session_materials,omitempty"`
	Algorithms             []string             `json:"algorithms,omitempty"`
	Stack                  string               `json:"stack,omitempty"`
	CapturedAtMS           int64                `json:"captured_at_ms,omitempty"`
	CreatedAt              time.Time            `json:"created_at"`
}

func (r *ProtocolTraceRecord) normalize() {
	if r == nil {
		return
	}

	r.Method = normalizeProtocolMethod(r.Method)
	r.RequestBeforeTransform = limitCapturedBody(r.RequestBeforeTransform, maxCapturedRequestBodySize, "明文内容过长，已截断")
	r.FinalRequestBody = limitCapturedBody(r.FinalRequestBody, maxCapturedRequestBodySize, "请求体过长，已截断")
	r.Stack = limitCapturedBody(r.Stack, 2048, "调用栈过长，已截断")
	if len(r.RequestHeaders) > 0 {
		for key, value := range r.RequestHeaders {
			r.RequestHeaders[key] = limitCapturedBody(value, 512, "请求头过长，已截断")
		}
	}
	if len(r.SessionMaterials) > 0 {
		for key, value := range r.SessionMaterials {
			r.SessionMaterials[key] = limitCapturedBody(value, protocolSessionMaterialLimit(key), "会话材料过长，已截断")
		}
	}

	allSteps := append(append([]ProtocolCryptoStep{}, r.RequestSteps...), r.ResponseSteps...)

	if len(allSteps) > 0 {
		algorithms := make([]string, 0, len(allSteps))
		seen := make(map[string]bool)
		for i := range r.RequestSteps {
			r.RequestSteps[i].InputPreview = limitCapturedBody(r.RequestSteps[i].InputPreview, 1024, "输入内容过长，已截断")
			r.RequestSteps[i].OutputPreview = limitCapturedBody(r.RequestSteps[i].OutputPreview, 1024, "输出内容过长，已截断")
			r.RequestSteps[i].CallID = limitCapturedBody(r.RequestSteps[i].CallID, 128, "调用 ID 过长，已截断")
			r.RequestSteps[i].ParentCallID = limitCapturedBody(r.RequestSteps[i].ParentCallID, 128, "父调用 ID 过长，已截断")
			r.RequestSteps[i].FunctionPath = limitCapturedBody(r.RequestSteps[i].FunctionPath, 256, "函数路径过长，已截断")
			r.RequestSteps[i].ModuleID = limitCapturedBody(r.RequestSteps[i].ModuleID, 128, "模块 ID 过长，已截断")
			r.RequestSteps[i].Stack = limitCapturedBody(r.RequestSteps[i].Stack, 1024, "调用栈过长，已截断")
			if r.RequestSteps[i].Algorithm != "" && !seen[r.RequestSteps[i].Algorithm] {
				seen[r.RequestSteps[i].Algorithm] = true
				algorithms = append(algorithms, r.RequestSteps[i].Algorithm)
			}
		}
		for i := range r.ResponseSteps {
			r.ResponseSteps[i].InputPreview = limitCapturedBody(r.ResponseSteps[i].InputPreview, 1024, "输入内容过长，已截断")
			r.ResponseSteps[i].OutputPreview = limitCapturedBody(r.ResponseSteps[i].OutputPreview, 1024, "输出内容过长，已截断")
			r.ResponseSteps[i].CallID = limitCapturedBody(r.ResponseSteps[i].CallID, 128, "调用 ID 过长，已截断")
			r.ResponseSteps[i].ParentCallID = limitCapturedBody(r.ResponseSteps[i].ParentCallID, 128, "父调用 ID 过长，已截断")
			r.ResponseSteps[i].FunctionPath = limitCapturedBody(r.ResponseSteps[i].FunctionPath, 256, "函数路径过长，已截断")
			r.ResponseSteps[i].ModuleID = limitCapturedBody(r.ResponseSteps[i].ModuleID, 128, "模块 ID 过长，已截断")
			r.ResponseSteps[i].Stack = limitCapturedBody(r.ResponseSteps[i].Stack, 1024, "调用栈过长，已截断")
			if r.ResponseSteps[i].Algorithm != "" && !seen[r.ResponseSteps[i].Algorithm] {
				seen[r.ResponseSteps[i].Algorithm] = true
				algorithms = append(algorithms, r.ResponseSteps[i].Algorithm)
			}
		}
		r.Algorithms = normalizeCapturedProtocolAlgorithms(algorithms)
	} else {
		r.Algorithms = normalizeCapturedProtocolAlgorithms(r.Algorithms)
	}

	if hasPlaintextOnlyCapturedProtocolEvidence(r) || !hasMeaningfulCapturedProtocolSignal(r) {
		r.RequestSteps = nil
		r.ResponseSteps = nil
	}

	if r.CreatedAt.IsZero() {
		if r.CapturedAtMS > 0 {
			r.CreatedAt = time.UnixMilli(r.CapturedAtMS)
		} else {
			r.CreatedAt = time.Now()
		}
	}
}

func normalizeCapturedProtocolAlgorithms(algorithms []string) []string {
	filtered := make([]string, 0, len(algorithms))
	seen := make(map[string]bool, len(algorithms))
	for _, algorithm := range algorithms {
		trimmed := strings.TrimSpace(algorithm)
		normalized := strings.ToLower(trimmed)
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		filtered = append(filtered, trimmed)
	}
	return filtered
}

func filterMeaningfulCapturedProtocolAlgorithms(algorithms []string) []string {
	filtered := make([]string, 0, len(algorithms))
	for _, algorithm := range normalizeCapturedProtocolAlgorithms(algorithms) {
		if isIgnorableCapturedProtocolAlgorithm(strings.ToLower(strings.TrimSpace(algorithm))) {
			continue
		}
		filtered = append(filtered, algorithm)
	}
	return filtered
}

func isIgnorableCapturedProtocolAlgorithm(value string) bool {
	switch strings.TrimSpace(value) {
	case "",
		"json.parse",
		"json.stringify",
		"json.parse(inferred)",
		"json.stringify(inferred)",
		"json.parse()",
		"json.stringify()",
		"base64-encoded-payload",
		"hex-encoded-payload",
		"encrypted-field(inferred)":
		return true
	default:
		return false
	}
}

func hasMeaningfulCapturedProtocolSignal(trace *ProtocolTraceRecord) bool {
	if trace == nil {
		return false
	}
	if len(filterMeaningfulCapturedProtocolAlgorithms(trace.Algorithms)) > 0 {
		return true
	}
	for _, step := range append(append([]ProtocolCryptoStep{}, trace.RequestSteps...), trace.ResponseSteps...) {
		if isMeaningfulCapturedProtocolStep(step) {
			return true
		}
	}
	return false
}

func isMeaningfulCapturedProtocolStep(step ProtocolCryptoStep) bool {
	source := strings.ToLower(strings.TrimSpace(step.Source))
	algorithm := strings.ToLower(strings.TrimSpace(step.Algorithm))
	if isIgnorableCapturedProtocolAlgorithm(source) && isIgnorableCapturedProtocolAlgorithm(algorithm) {
		return false
	}
	if strings.Contains(source, "encrypt") || strings.Contains(source, "decrypt") || strings.Contains(source, "sign") {
		return true
	}
	if strings.Contains(algorithm, "encrypt") || strings.Contains(algorithm, "decrypt") || strings.Contains(algorithm, "sign") {
		return true
	}
	for _, token := range []string{"rsa", "sm2", "sm3", "sm4", "aes", "des", "tripledes", "rc4", "rabbit", "hmac", "sha", "md5"} {
		if strings.Contains(source, token) || strings.Contains(algorithm, token) {
			return true
		}
	}
	return false
}

func hasPlaintextOnlyCapturedProtocolEvidence(trace *ProtocolTraceRecord) bool {
	if trace == nil || len(trace.SessionMaterials) == 0 {
		return false
	}

	hasPlaintext := false
	for key, value := range trace.SessionMaterials {
		normalizedKey := strings.TrimSpace(key)
		normalizedValue := strings.TrimSpace(value)
		if normalizedValue == "" {
			continue
		}
		switch normalizedKey {
		case "latest_response_plaintext":
			hasPlaintext = true
		default:
			return false
		}
	}

	if !hasPlaintext {
		return false
	}
	if len(filterMeaningfulCapturedProtocolAlgorithms(trace.Algorithms)) > 0 {
		return false
	}
	for _, step := range append(append([]ProtocolCryptoStep{}, trace.RequestSteps...), trace.ResponseSteps...) {
		if isMeaningfulCapturedProtocolStep(step) {
			return false
		}
	}
	return true
}

func protocolSessionMaterialLimit(key string) int {
	switch key {
	case "latest_response_ciphertext", "latest_response_plaintext":
		return maxCapturedResponseBodySize
	case "latest_ciphertext", "latest_plaintext", "request_before_transform", "final_request_body":
		return maxCapturedRequestBodySize
	default:
		return 512
	}
}

func normalizeProtocolMethod(method string) string {
	if method == "" {
		return "GET"
	}
	return method
}

const protocolHookScriptTemplate = `(function () {
  if (window.__trailblazerProtocolHookInstalled) {
    return;
  }
  window.__trailblazerProtocolHookInstalled = true;

  var bindingName = "__trailblazerHookSink";
  var recentCryptoSteps = [];
  var nextCryptoStepSeq = 0;
  var nextFunctionCallSeq = 0;
  var recentSessionMaterials = {};
  var recentWindowMs = 15000;
  var maxCryptoSteps = 40;
  var maxPreviewLength = 4096;
  var dynamicKeyPattern = /^(sign|signature|timestamp|nonce|token|access_token|auth|authorization|deviceid|device_id|ts|t)$/i;
  var suspiciousFuncPattern = /(encrypt|decrypt|sign|signature|sm2|sm3|sm4|aes|des|rsa|md5|sha1|sha256|sha512|hmac|base64|hex)/i;
  var helperFuncPattern = /^(rn|randomstring|sth|st|sa|sb|sc|sd|se)$/i;
  var maxWrappedFunctions = 300;
  var wrappedFunctionCount = 0;
  var suppressJSONStringifyCapture = false;
  var recentResponseContexts = [];
  var maxResponseContexts = 16;
  var activeFunctionCallStack = [];
  var lastRequestStepSeq = 0;
  var recentSensitiveInputs = [];
  var maxSensitiveInputs = 20;
  var bypassFrontendRouteGuards = __TRAILBLAZER_BYPASS_FRONTEND_ROUTE_GUARDS__;
  var maxBypassedLoginRedirects = 12;
  var bypassedLoginRedirectCount = 0;

  function nowMs() {
    return Date.now();
  }

  function makeId() {
    return "trace-" + nowMs().toString(36) + "-" + Math.random().toString(36).slice(2, 10);
  }

  function makeCallId() {
    nextFunctionCallSeq += 1;
    return "call-" + nowMs().toString(36) + "-" + nextFunctionCallSeq.toString(36);
  }

  function inferModuleId(functionPath) {
    var value = String(functionPath || "");
    var webpackMatch = value.match(/__webpack_require__\((\d+)\)/);
    if (webpackMatch && webpackMatch[1]) {
      return webpackMatch[1];
    }
    var cacheMatch = value.match(/\.c(?:ache)?\.(\d+)\.exports/);
    if (cacheMatch && cacheMatch[1]) {
      return cacheMatch[1];
    }
    return "";
  }

  function currentFunctionCall() {
    if (!activeFunctionCallStack.length) {
      return null;
    }
    return activeFunctionCallStack[activeFunctionCallStack.length - 1];
  }

  function enterFunctionCall(functionPath) {
    var parent = currentFunctionCall();
    var call = {
      call_id: makeCallId(),
      parent_call_id: parent && parent.call_id ? parent.call_id : "",
      function_path: String(functionPath || ""),
      module_id: inferModuleId(functionPath)
    };
    activeFunctionCallStack.push(call);
    return call;
  }

  function leaveFunctionCall(call) {
    if (!call) {
      return;
    }
    for (var index = activeFunctionCallStack.length - 1; index >= 0; index--) {
      if (activeFunctionCallStack[index] === call) {
        activeFunctionCallStack.splice(index, 1);
        return;
      }
    }
  }

  function limitText(text) {
    if (text == null) {
      return "";
    }
    var str = String(text);
    if (str.length <= maxPreviewLength) {
      return str;
    }
    return str.slice(0, maxPreviewLength) + "\n...[内容过长，已截断]";
  }

  function stringifyWithoutCapture(value) {
    var previous = suppressJSONStringifyCapture;
    suppressJSONStringifyCapture = true;
    try {
      return JSON.stringify(value);
    } finally {
      suppressJSONStringifyCapture = previous;
    }
  }

  function normalizeAlgorithm(algorithm) {
    if (!algorithm) {
      return "";
    }
    if (typeof algorithm === "string") {
      return algorithm;
    }
    if (typeof algorithm === "object" && algorithm.name) {
      return String(algorithm.name);
    }
    try {
      return limitText(stringifyWithoutCapture(algorithm));
    } catch (err) {
      return limitText(String(algorithm));
    }
  }

  function captureStack() {
    try {
      var stack = new Error().stack || "";
      return limitText(stack.split("\n").slice(2, 8).join("\n"));
    } catch (err) {
      return "";
    }
  }

  function toPreview(value) {
    if (value == null) {
      return "";
    }
    if (typeof value === "string") {
      return limitText(value);
    }
    if (typeof URLSearchParams !== "undefined" && value instanceof URLSearchParams) {
      return limitText(value.toString());
    }
    if (typeof FormData !== "undefined" && value instanceof FormData) {
      var formObj = {};
      value.forEach(function (entryValue, entryKey) {
        if (typeof entryValue === "string") {
          formObj[entryKey] = entryValue;
        } else {
          formObj[entryKey] = "[binary]";
        }
      });
      try {
        return limitText(stringifyWithoutCapture(formObj));
      } catch (err) {
        return "[FormData]";
      }
    }
    if (typeof Blob !== "undefined" && value instanceof Blob) {
      return "[Blob " + value.size + " bytes]";
    }
    if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) {
      return "[ArrayBuffer " + value.byteLength + " bytes]";
    }
    if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
      return "[TypedArray " + value.byteLength + " bytes]";
    }
    if (typeof value === "object") {
      try {
        if (typeof value.toString === "function") {
          var maybe = value.toString();
          if (maybe && maybe !== "[object Object]") {
            return limitText(maybe);
          }
        }
      } catch (err) {}
      try {
        return limitText(stringifyWithoutCapture(value));
      } catch (err) {
        return limitText(String(value));
      }
    }
    return limitText(String(value));
  }

  function pruneRecentCryptoSteps() {
    var cutoff = nowMs() - recentWindowMs;
    recentCryptoSteps = recentCryptoSteps.filter(function (step) {
      return step.captured_at_ms >= cutoff;
    });
    if (recentCryptoSteps.length > maxCryptoSteps) {
      recentCryptoSteps = recentCryptoSteps.slice(recentCryptoSteps.length - maxCryptoSteps);
    }
  }

  function currentCryptoStepSeq() {
    return nextCryptoStepSeq;
  }

  function snapshotRecentCryptoSteps(sinceSeq) {
    pruneRecentCryptoSteps();
    return recentCryptoSteps.map(function (step) {
      if (sinceSeq && step.seq <= sinceSeq) {
        return null;
      }
      return {
        source: step.source,
        algorithm: step.algorithm,
        input_preview: step.input_preview,
        output_preview: step.output_preview,
        call_id: step.call_id,
        parent_call_id: step.parent_call_id,
        function_path: step.function_path,
        module_id: step.module_id,
        stack: step.stack,
        captured_at_ms: step.captured_at_ms
      };
    }).filter(Boolean);
  }

  function markTraceStepCursor(trace, fieldName, value) {
    if (!trace) {
      return;
    }
    try {
      Object.defineProperty(trace, fieldName, {
        value: value,
        writable: true,
        configurable: true,
        enumerable: false
      });
    } catch (err) {
      trace[fieldName] = value;
    }
  }

  function setSessionMaterial(key, value) {
    var preview = toPreview(value);
    if (!preview) {
      return;
    }
    if (!shouldReplaceSessionMaterial(key, preview)) {
      return;
    }
    recentSessionMaterials[key] = {
      value: preview,
      captured_at_ms: nowMs()
    };
  }

  function scoreResponsePlaintextCandidate(text) {
    var normalized = String(text || "").trim();
    if (!normalized) {
      return -1;
    }
    if (!isLikelyJSONText(normalized) && !isLikelyReadableText(normalized)) {
      return -1;
    }
    if (normalized === "{}" || normalized === "[]" || normalized === "null" || normalized === '""') {
      return 1;
    }
    var score = normalized.length;
    if (normalized.charAt(0) === "{" || normalized.charAt(0) === "[") {
      score += 20;
    }
    if (normalized.indexOf(":") >= 0) {
      score += 20;
    }
    return score;
  }

  function shouldReplaceSessionMaterial(key, nextValue) {
    pruneSessionMaterials();
    var current = recentSessionMaterials[key] && recentSessionMaterials[key].value;
    if (!current) {
      return true;
    }
    if (key === "latest_response_plaintext") {
      return scoreResponsePlaintextCandidate(nextValue) >= scoreResponsePlaintextCandidate(current);
    }
    return true;
  }

  function setSessionMaterialIfMissing(key, value) {
    pruneSessionMaterials();
    if (recentSessionMaterials[key] && recentSessionMaterials[key].value) {
      return;
    }
    setSessionMaterial(key, value);
  }

  function pruneSessionMaterials() {
    var cutoff = nowMs() - recentWindowMs;
    Object.keys(recentSessionMaterials).forEach(function (key) {
      if (!recentSessionMaterials[key] || recentSessionMaterials[key].captured_at_ms < cutoff) {
        delete recentSessionMaterials[key];
      }
    });
  }

  function snapshotSessionMaterials() {
    pruneSessionMaterials();
    var materials = {};
    Object.keys(recentSessionMaterials).forEach(function (key) {
      materials[key] = recentSessionMaterials[key].value;
    });
    return materials;
  }

  function isLikelyJSONText(text) {
    if (!text) {
      return false;
    }
    return /^[\[{]/.test(String(text).trim());
  }

  function isHexString(text) {
    return !!text && /^[a-f0-9]+$/i.test(String(text)) && String(text).length % 2 === 0;
  }

  function decodeHexAscii(hexText) {
    if (!isHexString(hexText)) {
      return "";
    }
    var out = "";
    for (var i = 0; i < hexText.length; i += 2) {
      var code = parseInt(hexText.slice(i, i + 2), 16);
      if (!(code >= 32 && code <= 126)) {
        return "";
      }
      out += String.fromCharCode(code);
    }
    return out;
  }

  function captureSessionMaterialFromStep(step) {
    if (!step) {
      return;
    }
    var source = String(step.source || "").toLowerCase();
    var input = String(step.input_preview || "");
    var output = String(step.output_preview || "");

    if (/(^|\.)(rn)$/.test(source) && /^\d{16}$/.test(output)) {
      setSessionMaterial("session_seed_b", output);
    }

    if (/(^|\.)(randomstring)$/.test(source) && /^[A-Za-z0-9]{8}$/.test(output)) {
      setSessionMaterial("nonce", output);
    }

    if (/(^|\.)(sth)$/.test(source) && /^\d{16}$/.test(input) && /^[a-f0-9]{32}$/i.test(output)) {
      setSessionMaterial("session_seed_b", input);
      setSessionMaterial("sm4_key_hex", output.toLowerCase());
    }

    if (/(^|\.)(st)$/.test(source) && input && output) {
      setSessionMaterial("key_exchange_header", output);
    }

    if (source === "window.atob" || source === "window.btoa") {
      if (isLikelyRawAESKey(output)) {
        setSessionMaterialIfMissing("crypto_key_raw", output);
        var keyBase64 = binaryStringToBase64(output);
        if (keyBase64) {
          setSessionMaterialIfMissing("crypto_key_base64", keyBase64);
        }
      }
      if (/^[a-f0-9]{32}$/i.test(output)) {
        setSessionMaterial("sm4_key_hex", output.toLowerCase());
        var maybeSeed = decodeHexAscii(output);
        if (/^\d{16}$/.test(maybeSeed)) {
          setSessionMaterial("session_seed_b", maybeSeed);
        }
      }
      if (/^[a-f0-9]{128,}$/i.test(output) && output.indexOf("04") === 0) {
        setSessionMaterial("key_exchange_public_key", output);
      }
    }

    if (/(^|\.)(se)$/.test(source) && input && /^[a-f0-9]{32,}$/i.test(output)) {
      setSessionMaterial("latest_plaintext", input);
      setSessionMaterial("latest_ciphertext", output.toLowerCase());
      if (step.function_path) {
        setSessionMaterialIfMissing("request_runtime_function_path", step.function_path);
      }
      if (step.module_id) {
        setSessionMaterialIfMissing("request_runtime_module_id", step.module_id);
      }
    }

    if (source.indexOf("encrypt") >= 0 && input && /^[a-f0-9]{32,}$/i.test(output)) {
      if (step.function_path) {
        setSessionMaterialIfMissing("request_runtime_function_path", step.function_path);
      }
      if (step.module_id) {
        setSessionMaterialIfMissing("request_runtime_module_id", step.module_id);
      }
    }

    if (source.indexOf("encrypt") >= 0 && input && isLikelyRSABase64Ciphertext(output)) {
      setSessionMaterial("latest_plaintext", input);
      setSessionMaterial("latest_ciphertext", output);
      if (step.function_path) {
        setSessionMaterialIfMissing("request_runtime_function_path", step.function_path);
      }
      if (step.module_id) {
        setSessionMaterialIfMissing("request_runtime_module_id", step.module_id);
      }
    }

    if (/(^|\.)(sd)$/.test(source) && /^[a-f0-9]{32,}$/i.test(input) && output) {
      setSessionMaterial("latest_response_ciphertext", input.toLowerCase());
      setSessionMaterial("latest_response_plaintext", output);
      if (step.function_path) {
        setSessionMaterialIfMissing("response_runtime_function_path", step.function_path);
      }
      if (step.module_id) {
        setSessionMaterialIfMissing("response_runtime_module_id", step.module_id);
      }
      emitTraceUpdateForLatestResponse({
        latest_response_ciphertext: input.toLowerCase(),
        latest_response_plaintext: output
      });
    }

    if (source.indexOf("decrypt") >= 0 && /^[a-f0-9]{32,}$/i.test(input) && output) {
      if (step.function_path) {
        setSessionMaterialIfMissing("response_runtime_function_path", step.function_path);
      }
      if (step.module_id) {
        setSessionMaterialIfMissing("response_runtime_module_id", step.module_id);
      }
    }

    if (source === "webcrypto.decrypt") {
      emitTraceUpdateForLatestResponse(null);
    }

    if (source === "TextDecoder.decode" && output && isLikelyJSONText(output)) {
      setSessionMaterial("latest_response_plaintext", output);
      emitTraceUpdateForLatestResponse({
        latest_response_plaintext: output
      });
    }
  }

  function emitPayload(payload) {
    try {
      if (typeof window[bindingName] === "function") {
        suppressJSONStringifyCapture = true;
        window[bindingName](JSON.stringify(payload));
      }
    } catch (err) {}
    suppressJSONStringifyCapture = false;
  }

  function pruneRecentResponseContexts() {
    var cutoff = nowMs() - recentWindowMs;
    recentResponseContexts = recentResponseContexts.filter(function (context) {
      return context && context.trace_id && context.captured_at_ms >= cutoff;
    });
    if (recentResponseContexts.length > maxResponseContexts) {
      recentResponseContexts = recentResponseContexts.slice(recentResponseContexts.length - maxResponseContexts);
    }
  }

  function rememberResponseContext(trace, responseBody, responseKind) {
    if (!trace || !trace.trace_id) {
      return null;
    }
    var context = {
      trace_id: trace.trace_id,
      transport: trace.transport,
      page_url: trace.page_url || window.location.href,
      request_url: trace.request_url,
      method: trace.method || "GET",
      request_step_seq: trace.__request_step_seq || 0,
      response_ciphertext: responseKind === "ciphertext" ? (responseBody || "") : "",
      response_plaintext: responseKind === "plaintext" ? (responseBody || "") : "",
      captured_at_ms: nowMs()
    };
    recentResponseContexts.push(context);
    pruneRecentResponseContexts();
    return context;
  }

  function latestResponseContext() {
    pruneRecentResponseContexts();
    if (!recentResponseContexts.length) {
      return null;
    }
    return recentResponseContexts[recentResponseContexts.length - 1];
  }

  function emitTraceUpdateForContext(context, extraSessionMaterials) {
    if (!context || !context.trace_id) {
      return;
    }
    var responseSteps = snapshotRecentCryptoSteps(context.request_step_seq || 0);
    var sessionMaterials = snapshotSessionMaterials();
    if (context.response_ciphertext && !sessionMaterials["latest_response_ciphertext"]) {
      sessionMaterials["latest_response_ciphertext"] = context.response_ciphertext;
    }
    if (context.response_plaintext && !sessionMaterials["latest_response_plaintext"]) {
      sessionMaterials["latest_response_plaintext"] = context.response_plaintext;
    }
    if (extraSessionMaterials) {
      Object.keys(extraSessionMaterials).forEach(function (key) {
        if (extraSessionMaterials[key]) {
          sessionMaterials[key] = extraSessionMaterials[key];
        }
      });
    }
    emitPayload({
      kind: "trace-update",
      trace_id: context.trace_id,
      transport: context.transport || "",
      page_url: context.page_url || window.location.href,
      request_url: context.request_url || window.location.href,
      method: (context.method || "GET").toUpperCase(),
      response_steps: responseSteps,
      session_materials: sessionMaterials,
      algorithms: inferAlgorithms("", responseSteps),
      captured_at_ms: nowMs()
    });
  }

  function emitTraceUpdateForLatestResponse(extraSessionMaterials) {
    emitTraceUpdateForContext(latestResponseContext(), extraSessionMaterials);
  }

  function arrayBufferToBinaryString(buffer) {
    if (!buffer || typeof Uint8Array === "undefined") {
      return "";
    }
    var bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    var chunkSize = 0x8000;
    var out = "";
    for (var i = 0; i < bytes.length; i += chunkSize) {
      var chunk = bytes.subarray(i, i + chunkSize);
      out += String.fromCharCode.apply(null, chunk);
    }
    return out;
  }

  function binaryStringToBase64(value) {
    if (!value) {
      return "";
    }
    try {
      return window.btoa(value);
    } catch (err) {
      return "";
    }
  }

  function arrayBufferToBase64(buffer) {
    return binaryStringToBase64(arrayBufferToBinaryString(buffer));
  }

  function bytesLikeToUint8Array(value) {
    if (!value || typeof Uint8Array === "undefined" || typeof ArrayBuffer === "undefined") {
      return null;
    }
    if (value instanceof Uint8Array) {
      return value;
    }
    if (value instanceof ArrayBuffer) {
      return new Uint8Array(value);
    }
    if (ArrayBuffer.isView && ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    }
    if (typeof value === "string") {
      var out = new Uint8Array(value.length);
      for (var i = 0; i < value.length; i++) {
        out[i] = value.charCodeAt(i) & 0xff;
      }
      return out;
    }
    return null;
  }

  function decodeBytesLikeToText(value) {
    var bytes = bytesLikeToUint8Array(value);
    if (!bytes || !bytes.length) {
      return "";
    }
    if (typeof TextDecoder !== "undefined") {
      try {
        return new TextDecoder("utf-8").decode(bytes);
      } catch (err) {}
    }
    return arrayBufferToBinaryString(bytes);
  }

  function isLikelyReadableText(text) {
    if (!text) {
      return false;
    }
    var trimmed = String(text).trim();
    if (!trimmed) {
      return false;
    }
    var printable = 0;
    for (var i = 0; i < trimmed.length; i++) {
      var code = trimmed.charCodeAt(i);
      if ((code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13 || code >= 0x4e00) {
        printable += 1;
      }
    }
    return printable / Math.max(trimmed.length, 1) > 0.85;
  }

  function isLikelyEncodedPayload(text) {
    if (!text) {
      return false;
    }
    var trimmed = String(text).trim();
    if (trimmed.length < 48) {
      return false;
    }
    if (/^[A-Za-z0-9+/=]+$/.test(trimmed) && trimmed.indexOf("{") < 0 && trimmed.indexOf("[") < 0) {
      return true;
    }
    if (/^[a-f0-9]+$/i.test(trimmed) && trimmed.length % 2 === 0) {
      return true;
    }
    return false;
  }

  function isLikelyRSABase64Ciphertext(text) {
    if (!text) {
      return false;
    }
    var trimmed = String(text).trim();
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed) || trimmed.length % 4 !== 0) {
      return false;
    }
    return trimmed.length === 172 || trimmed.length === 344 || trimmed.length === 684;
  }

  function isSensitiveInputElement(element) {
    if (!element) {
      return false;
    }
    var tagName = String(element.tagName || "").toLowerCase();
    if (tagName !== "input" && tagName !== "textarea") {
      return false;
    }
    var type = String(element.type || "").toLowerCase();
    var hint = [
      element.name,
      element.id,
      element.className,
      element.placeholder,
      element.autocomplete,
      type
    ].join(" ").toLowerCase();
    return type === "password" || /password|passwd|pwd|pass|mm|kl|密码|口令/.test(hint);
  }

  function rememberSensitiveInput(element) {
    if (!isSensitiveInputElement(element)) {
      return;
    }
    var value = "";
    try {
      value = String(element.value || "");
    } catch (err) {}
    if (!value) {
      return;
    }
    recentSensitiveInputs.push({
      value: limitText(value),
      hint: limitText([element.name, element.id, element.placeholder, element.type].join("|")),
      captured_at_ms: nowMs()
    });
    if (recentSensitiveInputs.length > maxSensitiveInputs) {
      recentSensitiveInputs = recentSensitiveInputs.slice(recentSensitiveInputs.length - maxSensitiveInputs);
    }
  }

  function scanSensitiveInputsFromDOM() {
    if (!document || typeof document.querySelectorAll !== "function") {
      return;
    }
    try {
      var nodes = document.querySelectorAll("input, textarea");
      Array.prototype.slice.call(nodes).forEach(function (node) {
        rememberSensitiveInput(node);
      });
    } catch (err) {}
  }

  function latestSensitiveInputValue() {
    try {
      rememberSensitiveInput(document.activeElement);
    } catch (err) {}
    scanSensitiveInputsFromDOM();
    var cutoff = nowMs() - recentWindowMs;
    recentSensitiveInputs = recentSensitiveInputs.filter(function (entry) {
      return entry && entry.captured_at_ms >= cutoff;
    });
    if (!recentSensitiveInputs.length) {
      return "";
    }
    return recentSensitiveInputs[recentSensitiveInputs.length - 1].value || "";
  }

  function hookSensitiveInputCapture() {
    if (!document || document.__trailblazerSensitiveInputHooked) {
      return;
    }
    var handler = function (event) {
      rememberSensitiveInput(event && event.target);
    };
    try {
      document.addEventListener("input", handler, true);
      document.addEventListener("change", handler, true);
      document.addEventListener("keyup", handler, true);
      document.__trailblazerSensitiveInputHooked = true;
    } catch (err) {}
  }

  function isLikelyRawAESKey(value) {
    if (!value || (value.length !== 16 && value.length !== 24 && value.length !== 32)) {
      return false;
    }
    for (var i = 0; i < value.length; i++) {
      var code = value.charCodeAt(i);
      if (code < 32 || code > 126) {
        return false;
      }
    }
    return true;
  }

  function bytesLikeToBinaryString(value) {
    if (!value) {
      return "";
    }
    if (typeof value === "string") {
      return value;
    }
    if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) {
      return arrayBufferToBinaryString(value);
    }
    if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
      return arrayBufferToBinaryString(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    }
    return "";
  }

  function captureResponsePlaintextCandidate(value, sourceLabel) {
    if (value == null) {
      return;
    }
    var preview = toPreview(value);
    if (isLikelyJSONText(preview) || isLikelyReadableText(preview)) {
      setSessionMaterial("latest_response_plaintext", preview);
      emitTraceUpdateForLatestResponse({
        latest_response_plaintext: preview
      });
      return;
    }

    var decoded = decodeBytesLikeToText(value);
    if (decoded && (isLikelyJSONText(decoded) || isLikelyReadableText(decoded))) {
      setSessionMaterial("latest_response_plaintext", decoded);
      emitTraceUpdateForLatestResponse({
        latest_response_plaintext: decoded
      });
      return;
    }

    if (sourceLabel) {
      setSessionMaterialIfMissing("response_processing_source", sourceLabel);
    }
  }

  function captureResponseCiphertextCandidate(value) {
    if (value == null) {
      return;
    }
    var ciphertext = "";
    if (typeof value === "string") {
      ciphertext = value;
    } else if (typeof ArrayBuffer !== "undefined" && (value instanceof ArrayBuffer || (ArrayBuffer.isView && ArrayBuffer.isView(value)))) {
      ciphertext = arrayBufferToBase64(value instanceof ArrayBuffer ? value : value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    }
    ciphertext = String(ciphertext || "").trim();
    if (!ciphertext) {
      return;
    }
    setSessionMaterial("latest_response_ciphertext", ciphertext);
    emitTraceUpdateForLatestResponse({
      latest_response_ciphertext: ciphertext
    });
  }

  function captureWebCryptoDecryptResult(input, output) {
    captureResponseCiphertextCandidate(input);
    captureResponsePlaintextCandidate(output, "webcrypto.decrypt");
  }

  function recordWorkerMessageStep(source, value) {
    recordCryptoStep(source, source, value, value);
    captureResponsePlaintextCandidate(value, source);
  }

  function captureWebCryptoAlgorithmMaterials(algorithm) {
    if (!algorithm || typeof algorithm !== "object") {
      return;
    }
    if (algorithm.iv) {
      var ivBinary = bytesLikeToBinaryString(algorithm.iv);
      if (ivBinary) {
        setSessionMaterial("crypto_iv_base64", binaryStringToBase64(ivBinary));
      }
    }
    if (algorithm.additionalData) {
      var aadBinary = bytesLikeToBinaryString(algorithm.additionalData);
      if (aadBinary) {
        setSessionMaterial("crypto_aad_base64", binaryStringToBase64(aadBinary));
      }
    }
    if (algorithm.tagLength) {
      setSessionMaterial("crypto_tag_length", String(algorithm.tagLength));
    }
  }

  function captureWebCryptoKeyMaterial(format, keyData, algorithm) {
    if (String(format || "").toLowerCase() !== "raw") {
      return;
    }
    var algorithmName = normalizeAlgorithm(algorithm).toLowerCase();
    if (algorithmName.indexOf("aes") < 0) {
      return;
    }
    var raw = bytesLikeToBinaryString(keyData);
    if (!raw) {
      return;
    }
    var keyBase64 = binaryStringToBase64(raw);
    if (keyBase64) {
      setSessionMaterial("crypto_key_base64", keyBase64);
    }
    if (isLikelyRawAESKey(raw)) {
      setSessionMaterial("crypto_key_raw", raw);
    }
  }

  function normalizeDiscoveredRoutePath(value) {
    if (value == null) {
      return "";
    }
    var raw = String(value || "").trim();
    if (!raw) {
      return "";
    }
    if (raw === "*" || raw === "/*") {
      return raw;
    }
    if (raw.charAt(0) === "#") {
      raw = raw.slice(1);
    }
    if (raw.indexOf("/#/") >= 0) {
      raw = raw.slice(raw.indexOf("/#/") + 2);
    }
    if (/^https?:\/\//i.test(raw)) {
      try {
        var parsed = new URL(raw, window.location.href);
        if (parsed.hash && parsed.hash.indexOf("#/") === 0) {
          raw = parsed.hash.slice(1);
        } else {
          raw = parsed.pathname || "";
        }
      } catch (err) {
        return "";
      }
    } else if (raw.indexOf("#/") >= 0) {
      raw = raw.slice(raw.indexOf("#/") + 1);
    }
    if (!raw) {
      return "";
    }
    if (raw.charAt(0) !== "/") {
      raw = "/" + raw;
    }
    raw = raw.split("?")[0].split("#")[0].trim();
    if (!raw) {
      return "";
    }
    return raw.replace(/\/{2,}/g, "/");
  }

  function decodeRedirectTarget(raw) {
    if (typeof raw !== "string") {
      return "";
    }
    var value = raw.trim();
    if (!value) {
      return "";
    }
    for (var i = 0; i < 2; i += 1) {
      try {
        value = decodeURIComponent(value);
      } catch (err) {
        break;
      }
    }
    return normalizeDiscoveredRoutePath(value);
  }

  function extractRedirectTarget(candidate) {
    if (candidate == null) {
      return "";
    }
    if (typeof candidate === "object") {
      try {
        if (candidate.query && typeof candidate.query.redirect === "string") {
          return decodeRedirectTarget(candidate.query.redirect);
        }
      } catch (err) {}
      try {
        if (typeof candidate.redirect === "string") {
          return decodeRedirectTarget(candidate.redirect);
        }
      } catch (err) {}
      try {
        if (typeof candidate.fullPath === "string") {
          return extractRedirectTarget(candidate.fullPath);
        }
      } catch (err) {}
      try {
        if (typeof candidate.path === "string" && typeof candidate.search === "string") {
          return extractRedirectTarget(candidate.path + candidate.search);
        }
      } catch (err) {}
      return "";
    }
    var text = String(candidate || "");
    if (!text) {
      return "";
    }
    var match = text.match(/(?:[?#&]|^)redirect=([^&#]+)/i);
    if (match && match[1]) {
      return decodeRedirectTarget(match[1]);
    }
    if (text.indexOf("#") >= 0) {
      var hashPart = text.slice(text.indexOf("#") + 1);
      match = hashPart.match(/(?:[?&]|^)redirect=([^&#]+)/i);
      if (match && match[1]) {
        return decodeRedirectTarget(match[1]);
      }
    }
    return "";
  }

  function cloneNavigationLocation(location) {
    if (!location || typeof location !== "object") {
      return location;
    }
    var cloned = Array.isArray(location) ? location.slice() : {};
    Object.keys(location).forEach(function (key) {
      if (key === "query" && location.query && typeof location.query === "object") {
        var nextQuery = {};
        Object.keys(location.query).forEach(function (queryKey) {
          nextQuery[queryKey] = location.query[queryKey];
        });
        cloned.query = nextQuery;
        return;
      }
      cloned[key] = location[key];
    });
    return cloned;
  }

  function rewriteGuardedNavigationTarget(location, sourceKind, source) {
    if (!bypassFrontendRouteGuards || bypassedLoginRedirectCount >= maxBypassedLoginRedirects) {
      return location;
    }
    var redirectTarget = extractRedirectTarget(location);
    if (!redirectTarget) {
      return location;
    }
    bypassedLoginRedirectCount += 1;
    emitFrontendRoute(redirectTarget, "", sourceKind || "guard-bypass", source || "guard.redirect");
    if (typeof location === "string") {
      return redirectTarget;
    }
    if (location && typeof location === "object") {
      var cloned = cloneNavigationLocation(location);
      cloned.path = redirectTarget;
      cloned.fullPath = redirectTarget;
      if (cloned.query && typeof cloned.query === "object") {
        delete cloned.query.redirect;
      }
      if (typeof cloned.hash === "string" && cloned.hash.indexOf("?redirect=") >= 0) {
        cloned.hash = "#" + redirectTarget.replace(/^#/, "");
      }
      return cloned;
    }
    return location;
  }

  function routeNameOf(candidate) {
    if (!candidate || typeof candidate !== "object") {
      return "";
    }
    if (typeof candidate.name === "string") {
      return candidate.name.trim();
    }
    return "";
  }

  function emitRouteFromNavigationTarget(candidate, sourceKind, source) {
    var routePath = "";
    if (candidate && typeof candidate === "object") {
      if (typeof candidate.fullPath === "string" && candidate.fullPath) {
        routePath = candidate.fullPath;
      } else if (typeof candidate.path === "string" && candidate.path) {
        routePath = candidate.path;
      } else if (typeof candidate.hash === "string" && candidate.hash) {
        routePath = candidate.hash;
      }
    } else if (typeof candidate === "string") {
      routePath = candidate;
    }
    if (routePath) {
      emitFrontendRoute(routePath, routeNameOf(candidate), sourceKind, source);
    }
  }

  function emitFrontendRoute(path, name, sourceKind, source) {
    var normalizedPath = normalizeDiscoveredRoutePath(path);
    var normalizedName = String(name || "").trim();
    if (!normalizedPath) {
      return;
    }
    emitPayload({
      kind: "frontend-route",
      path: normalizedPath,
      name: normalizedName,
      source_kind: String(sourceKind || ""),
      source: limitText(String(source || "")),
      page_url: window.location.href,
      captured_at_ms: nowMs()
    });
  }

  function joinRoutePath(basePath, routePath) {
    var base = String(basePath || "").trim();
    var path = String(routePath || "").trim();
    if (!path) {
      return base;
    }
    if (path === "*") {
      return path;
    }
    if (path.charAt(0) === "/") {
      return path;
    }
    if (!base || base === "/") {
      return "/" + path.replace(/^\/+/, "");
    }
    return base.replace(/\/+$/, "") + "/" + path.replace(/^\/+/, "");
  }

  function looksLikeOfficialRouteRecord(candidate) {
    if (!candidate || typeof candidate !== "object") {
      return false;
    }
    if (typeof candidate.path === "string" && candidate.path.trim()) {
      return true;
    }
    if (typeof candidate.name === "string" && candidate.name.trim() && Array.isArray(candidate.children)) {
      return true;
    }
    return false;
  }

  function emitRouteRecord(candidate, sourceKind, source, parentPath) {
    if (!candidate || typeof candidate !== "object") {
      return "";
    }
    var routePath = "";
    if (typeof candidate.path === "string" && candidate.path.trim()) {
      routePath = joinRoutePath(parentPath, candidate.path);
    } else if (typeof candidate.alias === "string" && candidate.alias.trim()) {
      routePath = joinRoutePath(parentPath, candidate.alias);
    }
    if (!routePath) {
      return "";
    }
    emitFrontendRoute(routePath, routeNameOf(candidate), sourceKind, source);
    if (candidate.alias) {
      if (Array.isArray(candidate.alias)) {
        candidate.alias.forEach(function (aliasValue) {
          emitFrontendRoute(joinRoutePath(parentPath, aliasValue), routeNameOf(candidate), sourceKind, source + ".alias");
        });
      } else if (typeof candidate.alias === "string") {
        emitFrontendRoute(joinRoutePath(parentPath, candidate.alias), routeNameOf(candidate), sourceKind, source + ".alias");
      }
    }
    return routePath;
  }

  function readRoutesFromCollection(routes, sourceKind, source, parentPath, depth) {
    if (depth > 6 || !routes || typeof routes.length !== "number") {
      return;
    }
    try {
      Array.prototype.slice.call(routes, 0, 512).forEach(function (route, index) {
        if (!looksLikeOfficialRouteRecord(route)) {
          return;
        }
        var fullPath = emitRouteRecord(route, sourceKind, source + "[" + index + "]", parentPath);
        if (Array.isArray(route.children) && route.children.length) {
          readRoutesFromCollection(route.children, sourceKind, source + "[" + index + "].children", fullPath, depth + 1);
        }
      });
    } catch (err) {}
  }

  function emitRoutesFromRouter(router, source) {
    if (!router || typeof router !== "object") {
      return;
    }
    try {
      if (typeof router.getRoutes === "function") {
        readRoutesFromCollection(router.getRoutes(), "router-get-routes", source + ".getRoutes()", "", 0);
      }
    } catch (err) {}
    try {
      if (router.options && Array.isArray(router.options.routes)) {
        readRoutesFromCollection(router.options.routes, "router-options", source + ".options.routes", "", 0);
      }
    } catch (err) {}
    try {
      if (router.matcher && typeof router.matcher.getRoutes === "function") {
        readRoutesFromCollection(router.matcher.getRoutes(), "router-matcher", source + ".matcher.getRoutes()", "", 0);
      }
    } catch (err) {}
    try {
      if (router.history && router.history.current && Array.isArray(router.history.current.matched)) {
        readRoutesFromCollection(router.history.current.matched, "router-current-matched", source + ".history.current.matched", "", 0);
      }
    } catch (err) {}
  }

  function looksLikeReactRouteRecord(route) {
    if (!route || typeof route !== "object") {
      return false;
    }
    if (typeof route.path === "string") {
      return true;
    }
    if (route.index === true) {
      return true;
    }
    if (typeof route.id === "string" && Array.isArray(route.children)) {
      return true;
    }
    if (typeof route.name === "string" && (Array.isArray(route.childRoutes) || Array.isArray(route.routes))) {
      return true;
    }
    return false;
  }

  function routeNameFromReactRoute(route) {
    if (!route || typeof route !== "object") {
      return "";
    }
    if (typeof route.name === "string" && route.name.trim()) {
      return route.name.trim();
    }
    if (typeof route.id === "string" && route.id.trim()) {
      return route.id.trim();
    }
    return "";
  }

  function joinReactRoutePath(basePath, route) {
    if (!route || typeof route !== "object") {
      return "";
    }
    if (route.index === true) {
      return basePath || "/";
    }
    if (typeof route.path === "string") {
      return joinRoutePath(basePath, route.path);
    }
    if (typeof route.to === "string") {
      return joinRoutePath(basePath, route.to);
    }
    if (typeof route.from === "string") {
      return joinRoutePath(basePath, route.from);
    }
    return "";
  }

  function readReactRoutes(routes, sourceKind, source, parentPath, depth) {
    if (depth > 8 || !Array.isArray(routes)) {
      return;
    }
    routes.slice(0, 512).forEach(function (route, index) {
      if (!looksLikeReactRouteRecord(route)) {
        return;
      }
      var fullPath = joinReactRoutePath(parentPath, route);
      if (fullPath) {
        emitFrontendRoute(fullPath, routeNameFromReactRoute(route), sourceKind, source + "[" + index + "]");
      }
      var nextBase = fullPath || parentPath;
      if (Array.isArray(route.children) && route.children.length) {
        readReactRoutes(route.children, sourceKind, source + "[" + index + "].children", nextBase, depth + 1);
      }
      if (Array.isArray(route.childRoutes) && route.childRoutes.length) {
        readReactRoutes(route.childRoutes, sourceKind, source + "[" + index + "].childRoutes", nextBase, depth + 1);
      }
      if (Array.isArray(route.routes) && route.routes.length) {
        readReactRoutes(route.routes, sourceKind, source + "[" + index + "].routes", nextBase, depth + 1);
      }
    });
  }

  function getReactElementProps(value) {
    if (!value || typeof value !== "object") {
      return null;
    }
    if (value.props && typeof value.props === "object") {
      return value.props;
    }
    return value;
  }

  function readReactJSXRoutes(value, sourceKind, source, parentPath, depth) {
    if (depth > 8 || value == null) {
      return;
    }
    if (Array.isArray(value)) {
      value.slice(0, 256).forEach(function (item, index) {
        readReactJSXRoutes(item, sourceKind, source + "[" + index + "]", parentPath, depth + 1);
      });
      return;
    }
    if (typeof value !== "object") {
      return;
    }
    var props = getReactElementProps(value);
    if (!props || typeof props !== "object") {
      return;
    }
    var nextBase = parentPath;
    if (typeof props.path === "string") {
      nextBase = joinRoutePath(parentPath, props.path);
      emitFrontendRoute(nextBase, "", sourceKind, source + ".props.path");
    } else if (props.index === true) {
      nextBase = parentPath || "/";
      emitFrontendRoute(nextBase, "", sourceKind, source + ".props.index");
    } else if (typeof props.to === "string" && /^\/|^#\//.test(props.to)) {
      nextBase = joinRoutePath(parentPath, props.to);
      emitFrontendRoute(nextBase, "", sourceKind, source + ".props.to");
    }
    if (props.children != null) {
      readReactJSXRoutes(props.children, sourceKind, source + ".props.children", nextBase, depth + 1);
    }
  }

  function reactFiberTagName(tag) {
    switch (tag) {
      case 0: return "FunctionComponent";
      case 1: return "ClassComponent";
      case 3: return "HostRoot";
      case 5: return "HostComponent";
      case 10: return "ContextProvider";
      case 11: return "ForwardRef";
      case 14: return "MemoComponent";
      case 15: return "SimpleMemoComponent";
      default: return "";
    }
  }

  function getReactFiberProp(node) {
    if (!node || typeof node !== "object") {
      return "";
    }
    try {
      var keys = Object.getOwnPropertyNames(node);
      for (var i = 0; i < keys.length; i += 1) {
        if (keys[i].indexOf("__reactFiber$") === 0 || keys[i].indexOf("__reactInternalInstance$") === 0) {
          return keys[i];
        }
      }
    } catch (err) {}
    return "";
  }

  function findReactHostFibers() {
    if (!document || (!document.body && !document.documentElement)) {
      return [];
    }
    var roots = [];
    var queue = [];
    var visited = [];
    var seenFibers = [];
    if (document.body) {
      queue.push(document.body);
    }
    if (document.documentElement && document.documentElement !== document.body) {
      queue.push(document.documentElement);
    }
    while (queue.length) {
      var node = queue.shift();
      if (!node) {
        continue;
      }
      if (visited.indexOf(node) >= 0) {
        continue;
      }
      visited.push(node);
      if (node.nodeType === 1) {
        var fiberProp = getReactFiberProp(node);
        if (fiberProp && node[fiberProp] && typeof node[fiberProp] === "object" && seenFibers.indexOf(node[fiberProp]) < 0) {
          seenFibers.push(node[fiberProp]);
          roots.push(node[fiberProp]);
        }
      }
      try {
        var childNodes = node.childNodes || [];
        for (var i = 0; i < childNodes.length; i += 1) {
          queue.push(childNodes[i]);
        }
      } catch (err) {}
    }
    return roots;
  }

  function findReactFiberRoot(fiber) {
    if (!fiber || typeof fiber !== "object") {
      return null;
    }
    var current = fiber;
    var depth = 0;
    while (current && depth < 10000) {
      if (current.tag === 3) {
        if (current.stateNode && current.stateNode.current && current.stateNode.current.child) {
          return current.stateNode.current.child;
        }
        if (current.child) {
          return current.child;
        }
        return current;
      }
      current = current.return;
      depth += 1;
    }
    return fiber;
  }

  function inspectReactFiberRoutes(startFiber, source) {
    if (!startFiber || typeof startFiber !== "object") {
      return;
    }
    var stack = [startFiber];
    var seen = [];
    var steps = 0;
    while (stack.length && steps < 4096) {
      var fiber = stack.pop();
      steps += 1;
      if (!fiber || typeof fiber !== "object") {
        continue;
      }
      if (seen.indexOf(fiber) >= 0) {
        continue;
      }
      seen.push(fiber);
      try {
        var props = fiber.memoizedProps || fiber.pendingProps || null;
        var tagName = reactFiberTagName(fiber.tag);
        var fiberSource = source + "." + (tagName || "fiber");
        if (props && typeof props === "object") {
          if (props.router && props.router.routes && Array.isArray(props.router.routes)) {
            readReactRoutes(props.router.routes, "react-router-provider", fiberSource + ".props.router.routes", "", 0);
          }
          if (Array.isArray(props.routes)) {
            readReactRoutes(props.routes, "react-routes-props", fiberSource + ".props.routes", "", 0);
          }
          if (props.children != null) {
            readReactJSXRoutes(props.children, "react-jsx-routes", fiberSource + ".props.children", "", 0);
          }
        }
      } catch (err) {}
      if (fiber.child) {
        stack.push(fiber.child);
      }
      if (fiber.sibling) {
        stack.push(fiber.sibling);
      }
    }
  }

  function scanReactRouters() {
    var hostFibers = findReactHostFibers();
    if (!hostFibers || !hostFibers.length) {
      return;
    }
    hostFibers.forEach(function (fiber, index) {
      var rootFiber = findReactFiberRoot(fiber);
      inspectReactFiberRoutes(rootFiber, "react-root[" + index + "]");
    });
  }

  function looksLikeRouterInstance(candidate) {
    if (!candidate || typeof candidate !== "object") {
      return false;
    }
    try {
      var hasNavigation = typeof candidate.push === "function" || typeof candidate.replace === "function" || typeof candidate.resolve === "function";
      var hasRouteStore = typeof candidate.getRoutes === "function" ||
        (candidate.options && Array.isArray(candidate.options.routes)) ||
        (candidate.matcher && typeof candidate.matcher.getRoutes === "function") ||
        (candidate.history && candidate.history.current && Array.isArray(candidate.history.current.matched));
      if (hasNavigation && hasRouteStore) {
        return true;
      }
    } catch (err) {}
    return false;
  }

  function findVueRoots() {
    if (!document || !document.body) {
      return [];
    }
    var roots = [];
    var queue = [document.body];
    var seen = [];
    while (queue.length) {
      var node = queue.shift();
      if (!node || node.nodeType !== 1) {
        continue;
      }
      try {
        if (seen.indexOf(node) >= 0) {
          continue;
        }
        seen.push(node);
      } catch (err) {}
      if (node.__vue_app__ || node.__vue__) {
        roots.push(node);
      }
      try {
        var children = node.childNodes || [];
        for (var i = 0; i < children.length; i += 1) {
          queue.push(children[i]);
        }
      } catch (err) {}
    }
    return roots;
  }

  function findVueRouterFromRoot(root) {
    if (!root || typeof root !== "object") {
      return null;
    }
    try {
      if (root.__vue_app__) {
        var app = root.__vue_app__;
        if (app.config && app.config.globalProperties && looksLikeRouterInstance(app.config.globalProperties.$router)) {
          return app.config.globalProperties.$router;
        }
        var instance = app._instance;
        if (instance && instance.appContext && instance.appContext.config && instance.appContext.config.globalProperties && looksLikeRouterInstance(instance.appContext.config.globalProperties.$router)) {
          return instance.appContext.config.globalProperties.$router;
        }
        if (instance && instance.ctx && looksLikeRouterInstance(instance.ctx.$router)) {
          return instance.ctx.$router;
        }
      }
      if (root.__vue__) {
        var vue = root.__vue__;
        if (looksLikeRouterInstance(vue.$router)) {
          return vue.$router;
        }
        if (vue.$root && looksLikeRouterInstance(vue.$root.$router)) {
          return vue.$root.$router;
        }
        if (vue.$root && vue.$root.$options && looksLikeRouterInstance(vue.$root.$options.router)) {
          return vue.$root.$options.router;
        }
        if (looksLikeRouterInstance(vue._router)) {
          return vue._router;
        }
      }
    } catch (err) {}
    return null;
  }

  function tryPatchVueRouterCandidate(candidate, source) {
    if (!candidate || typeof candidate !== "object") {
      return false;
    }
    if (looksLikeRouterInstance(candidate)) {
      patchRouterInstance(candidate, source);
      return true;
    }
    return false;
  }

  function tryPatchVueOwnerCandidate(candidate, source) {
    if (!candidate || typeof candidate !== "object") {
      return false;
    }
    try {
      if (tryPatchVueRouterCandidate(candidate.$router, source + ".$router")) {
        return true;
      }
    } catch (err) {}
    try {
      if (tryPatchVueRouterCandidate(candidate.router, source + ".router")) {
        return true;
      }
    } catch (err) {}
    try {
      if (tryPatchVueRouterCandidate(candidate._router, source + "._router")) {
        return true;
      }
    } catch (err) {}
    try {
      if (candidate.$root && tryPatchVueRouterCandidate(candidate.$root.$router, source + ".$root.$router")) {
        return true;
      }
    } catch (err) {}
    try {
      if (candidate.$root && candidate.$root.$options && tryPatchVueRouterCandidate(candidate.$root.$options.router, source + ".$root.$options.router")) {
        return true;
      }
    } catch (err) {}
    try {
      if (candidate.$options && tryPatchVueRouterCandidate(candidate.$options.router, source + ".$options.router")) {
        return true;
      }
    } catch (err) {}
    try {
      if (candidate._routerRoot && tryPatchVueRouterCandidate(candidate._routerRoot._router, source + "._routerRoot._router")) {
        return true;
      }
    } catch (err) {}
    try {
      if (candidate.config && candidate.config.globalProperties && tryPatchVueRouterCandidate(candidate.config.globalProperties.$router, source + ".config.globalProperties.$router")) {
        return true;
      }
    } catch (err) {}
    try {
      if (candidate._instance && candidate._instance.appContext && candidate._instance.appContext.config && candidate._instance.appContext.config.globalProperties &&
          tryPatchVueRouterCandidate(candidate._instance.appContext.config.globalProperties.$router, source + "._instance.appContext.config.globalProperties.$router")) {
        return true;
      }
    } catch (err) {}
    try {
      if (candidate._instance && candidate._instance.ctx && tryPatchVueRouterCandidate(candidate._instance.ctx.$router, source + "._instance.ctx.$router")) {
        return true;
      }
    } catch (err) {}
    return false;
  }

  function scanVueDevtoolsHook() {
    var hook = null;
    try {
      hook = window.__VUE_DEVTOOLS_GLOBAL_HOOK__;
    } catch (err) {}
    if (!hook || typeof hook !== "object") {
      return;
    }

    tryPatchVueOwnerCandidate(hook, "vue-devtools-hook");

    try {
      if (Array.isArray(hook.apps)) {
        hook.apps.slice(0, 128).forEach(function (app, index) {
          tryPatchVueOwnerCandidate(app, "vue-devtools-hook.apps[" + index + "]");
        });
      } else if (hook.apps && typeof hook.apps.forEach === "function") {
        var appIndex = 0;
        hook.apps.forEach(function (app) {
          tryPatchVueOwnerCandidate(app, "vue-devtools-hook.apps[" + appIndex + "]");
          appIndex += 1;
        });
      }
    } catch (err) {}

    try {
      if (hook.store && Array.isArray(hook.store.apps)) {
        hook.store.apps.slice(0, 128).forEach(function (app, index) {
          tryPatchVueOwnerCandidate(app, "vue-devtools-hook.store.apps[" + index + "]");
        });
      }
    } catch (err) {}
  }

  function scanVueWindowCandidates() {
    var keys = [];
    try {
      keys = Object.getOwnPropertyNames(window);
    } catch (err) {
      return;
    }
    keys.slice(0, 2048).forEach(function (key) {
      var candidate = null;
      try {
        candidate = window[key];
      } catch (err) {
        return;
      }
      if (!candidate || (typeof candidate !== "object" && typeof candidate !== "function")) {
        return;
      }
      tryPatchVueRouterCandidate(candidate, "window." + key);
      tryPatchVueOwnerCandidate(candidate, "window." + key);
      try {
        if (candidate.default) {
          tryPatchVueRouterCandidate(candidate.default, "window." + key + ".default");
          tryPatchVueOwnerCandidate(candidate.default, "window." + key + ".default");
        }
      } catch (err) {}
    });
  }

  function clearRouterGuardCollection(value) {
    if (!value) {
      return;
    }
    try {
      if (Array.isArray(value)) {
        value.length = 0;
        return;
      }
      if (typeof value.clear === "function") {
        value.clear();
      }
    } catch (err) {}
  }

  function scrubExistingRouterGuards(router) {
    if (!router || typeof router !== "object" || !bypassFrontendRouteGuards) {
      return;
    }
    ["beforeHooks", "resolveHooks", "afterHooks", "beforeGuards", "resolveGuards", "afterGuards"].forEach(function (key) {
      try {
        clearRouterGuardCollection(router[key]);
      } catch (err) {}
      try {
        if (router.options && router.options[key]) {
          clearRouterGuardCollection(router.options[key]);
        }
      } catch (err) {}
    });
  }

  function wrapRouteGuard(methodName, guard, source) {
    if (typeof guard !== "function" || guard.__trailblazerGuardWrapped) {
      return guard;
    }
    var wrapped = function (to, from, next) {
      emitRouteFromNavigationTarget(to, "guard-target", source + "." + methodName);
      if (!bypassFrontendRouteGuards) {
        return guard.apply(this, arguments);
      }
      if (typeof next === "function") {
        try {
          next();
        } catch (err) {}
        return;
      }
      return true;
    };
    wrapped.__trailblazerGuardWrapped = true;
    wrapped.__trailblazerOriginalGuard = guard;
    return wrapped;
  }

  function patchRouterMethod(router, methodName, source, wrapperFactory) {
    if (!router || typeof router[methodName] !== "function" || router[methodName].__trailblazerWrapped) {
      return;
    }
    var original = router[methodName];
    var wrapped = wrapperFactory(original);
    if (typeof wrapped !== "function") {
      return;
    }
    wrapped.__trailblazerWrapped = true;
    wrapped.__trailblazerOriginal = original;
    router[methodName] = wrapped;
  }

  function patchRouterInstance(router, source) {
    if (!looksLikeRouterInstance(router) || router.__trailblazerRouterPatched) {
      return;
    }
    router.__trailblazerRouterPatched = true;
    scrubExistingRouterGuards(router);

    patchRouterMethod(router, "beforeEach", source, function (original) {
      return function (guard) {
        return original.call(this, wrapRouteGuard("beforeEach", guard, source));
      };
    });
    patchRouterMethod(router, "beforeResolve", source, function (original) {
      return function (guard) {
        return original.call(this, wrapRouteGuard("beforeResolve", guard, source));
      };
    });
    patchRouterMethod(router, "push", source, function (original) {
      return function (location) {
        var rewritten = rewriteGuardedNavigationTarget(location, "guard-bypass", source + ".push");
        emitRouteFromNavigationTarget(rewritten, "router-push", source + ".push");
        arguments[0] = rewritten;
        return original.apply(this, arguments);
      };
    });
    patchRouterMethod(router, "replace", source, function (original) {
      return function (location) {
        var rewritten = rewriteGuardedNavigationTarget(location, "guard-bypass", source + ".replace");
        emitRouteFromNavigationTarget(rewritten, "router-replace", source + ".replace");
        arguments[0] = rewritten;
        return original.apply(this, arguments);
      };
    });
    patchRouterMethod(router, "addRoutes", source, function (original) {
      return function (routes) {
        if (Array.isArray(routes)) {
          readRoutesFromCollection(routes, "router-add-routes", source + ".addRoutes", "", 0);
        }
        return original.apply(this, arguments);
      };
    });
    patchRouterMethod(router, "addRoute", source, function (original) {
      return function (route) {
        if (looksLikeOfficialRouteRecord(route)) {
          var parentPath = "";
          if (arguments.length > 1 && typeof arguments[0] === "string" && route && typeof route.path === "string") {
            parentPath = arguments[0];
          }
          emitRouteRecord(route, "router-add-route", source + ".addRoute", parentPath);
          if (Array.isArray(route.children) && route.children.length) {
            readRoutesFromCollection(route.children, "router-add-route", source + ".addRoute.children", joinRoutePath(parentPath, route.path), 0);
          }
        }
        return original.apply(this, arguments);
      };
    });
    emitRoutesFromRouter(router, source);
  }

  function hookHistoryRoutes() {
    if (window.history && typeof window.history.pushState === "function" && !window.history.pushState.__trailblazerWrapped) {
      var originalPushState = window.history.pushState;
      window.history.pushState = function (state, title, url) {
        url = rewriteGuardedNavigationTarget(url || window.location.href, "guard-bypass", "history.pushState");
        var result = originalPushState.apply(this, arguments);
        emitFrontendRoute(url || window.location.href, "", "history-push", "history.pushState");
        return result;
      };
      window.history.pushState.__trailblazerWrapped = true;
    }
    if (window.history && typeof window.history.replaceState === "function" && !window.history.replaceState.__trailblazerWrapped) {
      var originalReplaceState = window.history.replaceState;
      window.history.replaceState = function (state, title, url) {
        url = rewriteGuardedNavigationTarget(url || window.location.href, "guard-bypass", "history.replaceState");
        var result = originalReplaceState.apply(this, arguments);
        emitFrontendRoute(url || window.location.href, "", "history-replace", "history.replaceState");
        return result;
      };
      window.history.replaceState.__trailblazerWrapped = true;
    }
    try {
      window.addEventListener("hashchange", function () {
        emitFrontendRoute(window.location.href, "", "hashchange", "window.location.hash");
      }, true);
      window.addEventListener("popstate", function () {
        emitFrontendRoute(window.location.href, "", "popstate", "window.location");
      }, true);
    } catch (err) {}
  }

  function scanVueRouters() {
    var roots = findVueRoots();
    if (!roots || !roots.length) {
      scanVueDevtoolsHook();
      scanVueWindowCandidates();
      return;
    }
    roots.forEach(function (root, index) {
      var router = findVueRouterFromRoot(root);
      if (router) {
        patchRouterInstance(router, "vue-root[" + index + "]");
      }
    });
    scanVueDevtoolsHook();
    scanVueWindowCandidates();
  }

  function watchFrontendRouteMounts() {
    if (typeof MutationObserver !== "function" || !document || !document.documentElement) {
      return;
    }
    try {
      var observer = new MutationObserver(function (mutations) {
        for (var i = 0; i < mutations.length; i += 1) {
          if (mutations[i] && mutations[i].addedNodes && mutations[i].addedNodes.length) {
            scanVueRouters();
            scanReactRouters();
            return;
          }
        }
      });
      observer.observe(document.documentElement, {
        childList: true,
        subtree: true
      });
    } catch (err) {}
  }

  function hookFrontendRoutes() {
    hookHistoryRoutes();
    scanVueRouters();
    scanReactRouters();
    watchFrontendRouteMounts();
    window.setTimeout(scanVueRouters, 1200);
    window.setTimeout(scanVueRouters, 2600);
    window.setTimeout(scanReactRouters, 1200);
    window.setTimeout(scanReactRouters, 2600);
  }

  function shouldTreatResponseAsText(contentType) {
    var normalized = String(contentType || "").toLowerCase();
    return normalized.indexOf("json") >= 0 || normalized.indexOf("javascript") >= 0 || normalized.indexOf("xml") >= 0 || normalized.indexOf("html") >= 0;
  }

  function rememberResponseBodyForTrace(trace, responseBody, contentType) {
    var ciphertext = responseBody == null ? "" : String(responseBody);
    if (!trace || !trace.trace_id || !ciphertext) {
      return;
    }
    var treatAsPlaintext = !isLikelyEncodedPayload(ciphertext) && (shouldTreatResponseAsText(contentType) || isLikelyReadableText(ciphertext));
    if (treatAsPlaintext) {
      var plaintextContext = rememberResponseContext(trace, ciphertext, "plaintext");
      emitTraceUpdateForContext(plaintextContext, {
        latest_response_plaintext: ciphertext
      });
      return;
    }
    var context = rememberResponseContext(trace, ciphertext, "ciphertext");
    emitTraceUpdateForContext(context, {
      latest_response_ciphertext: ciphertext
    });
  }

  function captureFetchResponse(trace, response) {
    if (!trace || !trace.trace_id || !response || typeof response.clone !== "function") {
      return;
    }
    try {
      var cloned = response.clone();
      var contentType = "";
      try {
        if (cloned.headers && typeof cloned.headers.get === "function") {
          contentType = cloned.headers.get("content-type") || "";
        }
      } catch (err) {}

      if (shouldTreatResponseAsText(contentType) && typeof cloned.text === "function") {
        cloned.text().then(function (text) {
          rememberResponseBodyForTrace(trace, text, contentType);
        }).catch(function () {});
        return;
      }

      if (typeof cloned.arrayBuffer === "function") {
        cloned.arrayBuffer().then(function (buffer) {
          rememberResponseBodyForTrace(trace, arrayBufferToBase64(buffer), contentType);
        }).catch(function () {});
      }
    } catch (err) {}
  }

  function captureXHRResponse(xhr) {
    if (!xhr || !xhr.__trailblazerMeta || !xhr.__trailblazerMeta.trace) {
      return;
    }
    try {
      var responseBody = "";
      if (xhr.responseType === "" || xhr.responseType === "text") {
        responseBody = xhr.responseText || "";
      } else if (xhr.responseType === "json") {
        if (xhr.response != null) {
          responseBody = stringifyWithoutCapture(xhr.response);
        }
      } else if (typeof ArrayBuffer !== "undefined" && xhr.response instanceof ArrayBuffer) {
        responseBody = arrayBufferToBase64(xhr.response);
      } else if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(xhr.response)) {
        responseBody = arrayBufferToBase64(xhr.response.buffer);
      } else if (typeof xhr.response === "string") {
        responseBody = xhr.response;
      }
      if (responseBody) {
        var contentType = "";
        try {
          contentType = xhr.getResponseHeader("content-type") || "";
        } catch (err) {}
        rememberResponseBodyForTrace(xhr.__trailblazerMeta.trace, responseBody, contentType);
      }
    } catch (err) {}
  }

  function recordCryptoStep(source, algorithm, input, output, meta) {
    var activeCall = currentFunctionCall();
    meta = meta || {};
    var inputPreview = toPreview(input);
    var outputPreview = toPreview(output);
    var normalizedAlgorithm = normalizeAlgorithm(algorithm);
    if (String(source || "").toLowerCase().indexOf("encrypt") >= 0 && isLikelyRSABase64Ciphertext(outputPreview)) {
      normalizedAlgorithm = "rsa.encrypt";
    }
    var step = {
      seq: ++nextCryptoStepSeq,
      source: source,
      algorithm: normalizedAlgorithm,
      input_preview: inputPreview,
      output_preview: outputPreview,
      call_id: String(meta.call_id || (activeCall && activeCall.call_id) || ""),
      parent_call_id: String(meta.parent_call_id || (activeCall && activeCall.parent_call_id) || ""),
      function_path: String(meta.function_path || (activeCall && activeCall.function_path) || ""),
      module_id: String(meta.module_id || (activeCall && activeCall.module_id) || ""),
      stack: captureStack(),
      captured_at_ms: nowMs()
    };
    recentCryptoSteps.push(step);
    pruneRecentCryptoSteps();
    captureSessionMaterialFromStep(step);
    return step;
  }

  function resolveRequestUrl(input) {
    try {
      if (typeof input === "string") {
        return new URL(input, window.location.href).href;
      }
      if (input && typeof input.url === "string") {
        return new URL(input.url, window.location.href).href;
      }
    } catch (err) {}
    try {
      return String(input || window.location.href);
    } catch (err) {
      return window.location.href;
    }
  }

  function normalizeHeaderName(name) {
    return String(name || "").trim().toLowerCase();
  }

  function normalizeHeadersInput(headersInput) {
    var headers = {};
    if (!headersInput) {
      return headers;
    }

    try {
      if (typeof Headers !== "undefined" && headersInput instanceof Headers) {
        headersInput.forEach(function (value, key) {
          headers[normalizeHeaderName(key)] = toPreview(value);
        });
        return headers;
      }
    } catch (err) {}

    if (Array.isArray(headersInput)) {
      headersInput.forEach(function (entry) {
        if (Array.isArray(entry) && entry.length >= 2) {
          headers[normalizeHeaderName(entry[0])] = toPreview(entry[1]);
        }
      });
      return headers;
    }

    if (typeof headersInput === "object") {
      Object.keys(headersInput).forEach(function (key) {
        headers[normalizeHeaderName(key)] = toPreview(headersInput[key]);
      });
    }
    return headers;
  }

  function putDynamicParam(target, key, value) {
    var normalizedKey = String(key || "");
    var shortKey = normalizedKey.split(".").pop();
    if (!dynamicKeyPattern.test(normalizedKey) && !dynamicKeyPattern.test(shortKey)) {
      return;
    }
    var preview = toPreview(value);
    if (!preview) {
      return;
    }
    target[key] = preview;
  }

  function addHeaderDynamicParams(dynamicParams, headers) {
    if (!headers || typeof headers !== "object") {
      return;
    }
    Object.keys(headers).forEach(function (key) {
      putDynamicParam(dynamicParams, "header." + normalizeHeaderName(key), headers[key]);
    });
  }

  function collectDynamicParamsFromObject(target, value, prefix) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return;
    }
    Object.keys(value).slice(0, 40).forEach(function (key) {
      var nextPrefix = prefix ? prefix + "." + key : key;
      var nextValue = value[key];
      putDynamicParam(target, nextPrefix, nextValue);
      if (nextValue && typeof nextValue === "object" && !Array.isArray(nextValue)) {
        collectDynamicParamsFromObject(target, nextValue, nextPrefix);
      }
    });
  }

  function collectDynamicParams(requestURL, finalBodyPreview, requestHeaders) {
    var dynamicParams = {};
    try {
      var parsedURL = new URL(requestURL, window.location.href);
      parsedURL.searchParams.forEach(function (value, key) {
        putDynamicParam(dynamicParams, key, value);
      });
    } catch (err) {}

    addHeaderDynamicParams(dynamicParams, requestHeaders);

    if (!finalBodyPreview) {
      return dynamicParams;
    }

    try {
      var jsonBody = JSON.parse(finalBodyPreview);
      collectDynamicParamsFromObject(dynamicParams, jsonBody, "");
      return dynamicParams;
    } catch (err) {}

    try {
      var params = new URLSearchParams(finalBodyPreview);
      params.forEach(function (value, key) {
        putDynamicParam(dynamicParams, key, value);
      });
    } catch (err) {}

    return dynamicParams;
  }

  function collectSignatureFields(dynamicParams) {
    return Object.keys(dynamicParams).filter(function (key) {
      return /sign|signature|authorization|token|auth/i.test(key);
    });
  }

  function collectEncryptedFieldCandidates(value, path, target) {
    if (!value || typeof value !== "object") {
      return;
    }
    if (Array.isArray(value)) {
      value.slice(0, 80).forEach(function (entry, index) {
        collectEncryptedFieldCandidates(entry, path.concat(String(index)), target);
      });
      return;
    }
    Object.keys(value).slice(0, 80).forEach(function (key) {
      var nextPath = path.concat(key);
      var entry = value[key];
      if (typeof entry === "string" && isLikelyEncodedPayload(entry)) {
        target.push({ path: nextPath, key: key, value: entry });
        return;
      }
      collectEncryptedFieldCandidates(entry, nextPath, target);
    });
  }

  function setPathValue(root, path, value) {
    var cursor = root;
    for (var i = 0; i < path.length - 1; i++) {
      if (!cursor || typeof cursor !== "object") {
        return;
      }
      cursor = cursor[path[i]];
    }
    if (cursor && typeof cursor === "object" && path.length) {
      cursor[path[path.length - 1]] = value;
    }
  }

  function normalizeCiphertextForCompare(value) {
    var normalized = String(value || "").trim();
    if (normalized.length >= 2 && normalized.charAt(0) === '"' && normalized.charAt(normalized.length - 1) === '"') {
      normalized = normalized.slice(1, normalized.length - 1);
    }
    return normalized;
  }

  function findCryptoStepForCiphertext(cryptoSteps, ciphertext) {
    var expected = normalizeCiphertextForCompare(ciphertext);
    if (!expected) {
      return null;
    }
    for (var i = (cryptoSteps || []).length - 1; i >= 0; i--) {
      var step = cryptoSteps[i] || {};
      if (normalizeCiphertextForCompare(step.output_preview) === expected) {
        return step;
      }
    }
    return null;
  }

  function synthesizeFieldEncryptionSteps(finalBodyPreview, cryptoSteps) {
    var steps = [];
    if (!finalBodyPreview || !isLikelyJSONText(finalBodyPreview)) {
      return steps;
    }
    var body;
    try {
      body = JSON.parse(finalBodyPreview);
    } catch (err) {
      return steps;
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return steps;
    }

    var candidates = [];
    var reconstructedBody = null;
    var hasReconstructedPlaintext = false;
    collectEncryptedFieldCandidates(body, [], candidates);
    candidates.forEach(function (candidate) {
      var key = candidate.key;
      var value = candidate.value;
      var matchedStep = findCryptoStepForCiphertext(cryptoSteps, value);
      var plaintext = "";
      var algorithm = "";
      var functionPath = "";
      var source = "request-field." + candidate.path.join(".");
      if (matchedStep) {
        plaintext = matchedStep.input_preview || "";
        algorithm = matchedStep.algorithm || matchedStep.source || "field.encrypt";
        functionPath = matchedStep.function_path || "matched runtime crypto output";
        if (!reconstructedBody) {
          try {
            reconstructedBody = JSON.parse(stringifyWithoutCapture(body));
          } catch (err) {
            reconstructedBody = null;
          }
        }
        if (reconstructedBody) {
          setPathValue(reconstructedBody, candidate.path, plaintext || "[captured-empty-input]");
          hasReconstructedPlaintext = true;
        }
      } else {
        algorithm = isLikelyRSABase64Ciphertext(value) ? "rsa.encrypt(inferred)" : "encrypted-field(inferred)";
        plaintext = "[unknown-plaintext]";
        functionPath = "request body field inference (no matching runtime step)";
      }
      steps.push({
        source: source,
        algorithm: algorithm,
        input_preview: limitText(plaintext || "[sensitive-input-unavailable]"),
        output_preview: limitText(value),
        call_id: "",
        parent_call_id: "",
        function_path: functionPath,
        module_id: "",
        stack: "",
        captured_at_ms: nowMs()
      });
      setSessionMaterial("latest_ciphertext", value);
    });
    if (hasReconstructedPlaintext && reconstructedBody) {
      try {
        setSessionMaterial("latest_plaintext", stringifyWithoutCapture(reconstructedBody));
      } catch (err) {}
    } else if (candidates.length) {
      setSessionMaterial("encrypted_field_inference_only", "true");
    }
    return steps;
  }

  function inferAlgorithms(finalBodyPreview, cryptoSteps) {
    var algorithms = [];
    var seen = {};

    function push(value) {
      if (!value || seen[value]) {
        return;
      }
      seen[value] = true;
      algorithms.push(value);
    }

    (cryptoSteps || []).forEach(function (step) {
      push(step.algorithm || step.source);
    });

    if (!finalBodyPreview) {
      return algorithms;
    }

    if (/^[a-f0-9]{32,}$/i.test(finalBodyPreview) && finalBodyPreview.length % 2 === 0) {
      push("hex-encoded-payload");
    } else if (/^[A-Za-z0-9+/=]{24,}$/.test(finalBodyPreview) && finalBodyPreview.length % 4 === 0) {
      push("base64-encoded-payload");
    }

    return algorithms;
  }

  function pickRequestBeforeTransformCandidate(finalBodyPreview, cryptoSteps, sessionMaterials) {
    if (sessionMaterials && isLikelyJSONText(sessionMaterials["latest_plaintext"])) {
      return sessionMaterials["latest_plaintext"];
    }
    if (sessionMaterials && sessionMaterials["encrypted_field_inference_only"] === "true") {
      return "";
    }

    for (var i = cryptoSteps.length - 1; i >= 0; i--) {
      var step = cryptoSteps[i];
      if (step.source === "JSON.stringify" && isLikelyJSONText(step.output_preview)) {
        return step.output_preview;
      }
    }

    for (var j = cryptoSteps.length - 1; j >= 0; j--) {
      var candidate = cryptoSteps[j];
      if ((/(^|\.)(se)$/).test(String(candidate.source || "").toLowerCase()) && isLikelyJSONText(candidate.input_preview)) {
        return candidate.input_preview;
      }
    }

    for (var k = cryptoSteps.length - 1; k >= 0; k--) {
      var generic = cryptoSteps[k];
      if (isLikelyJSONText(generic.input_preview)) {
        return generic.input_preview;
      }
      if (isLikelyJSONText(generic.output_preview)) {
        return generic.output_preview;
      }
    }

    if (isLikelyJSONText(finalBodyPreview)) {
      return finalBodyPreview;
    }
    return "";
  }

  function buildRequestTrace(transport, requestURL, method, requestBody, requestHeaders) {
    var finalBodyPreview = toPreview(requestBody);
    var normalizedMethod = String(method || "GET").toUpperCase();
    var hasRequestBody = !!finalBodyPreview && normalizedMethod !== "GET" && normalizedMethod !== "HEAD" && normalizedMethod !== "OPTIONS";
    var requestStepStartSeq = lastRequestStepSeq;
    var requestSteps = hasRequestBody ? snapshotRecentCryptoSteps(requestStepStartSeq) : [];
    var inferredFieldSteps = synthesizeFieldEncryptionSteps(finalBodyPreview, requestSteps);
    if (inferredFieldSteps.length) {
      requestSteps = requestSteps.concat(inferredFieldSteps);
    }
    var normalizedHeaders = normalizeHeadersInput(requestHeaders);
    var dynamicParams = collectDynamicParams(requestURL, finalBodyPreview, normalizedHeaders);
    var sessionMaterials = snapshotSessionMaterials();
    delete sessionMaterials["latest_response_ciphertext"];
    delete sessionMaterials["latest_response_plaintext"];
    delete sessionMaterials["response_runtime_function_path"];
    delete sessionMaterials["response_runtime_module_id"];
    delete sessionMaterials["response_processing_source"];
    if (normalizedHeaders["gv59jppeesnw"]) {
      sessionMaterials["nonce"] = normalizedHeaders["gv59jppeesnw"];
    }
    if (normalizedHeaders["kqn29pkxstkn"]) {
      sessionMaterials["timestamp"] = normalizedHeaders["kqn29pkxstkn"];
    }
    if (normalizedHeaders["bpzhepzrvcjy"]) {
      sessionMaterials["signature"] = normalizedHeaders["bpzhepzrvcjy"];
    }
    if (normalizedHeaders["6zzbinypyphq"]) {
      sessionMaterials["key_exchange_header"] = normalizedHeaders["6zzbinypyphq"];
    }
    if (normalizedHeaders["x-access-token"]) {
      sessionMaterials["x_access_token"] = normalizedHeaders["x-access-token"];
    }
    if (normalizedHeaders["channel-code"]) {
      sessionMaterials["channel_code"] = normalizedHeaders["channel-code"];
    }
    if (finalBodyPreview) {
      sessionMaterials["latest_ciphertext"] = finalBodyPreview;
    }
    var requestBeforeTransform = "";
    if (!hasRequestBody) {
      requestSteps = [];
    } else if (finalBodyPreview || (requestSteps && requestSteps.length > 0)) {
      requestBeforeTransform = pickRequestBeforeTransformCandidate(finalBodyPreview, requestSteps, sessionMaterials);
    }
    if (requestBeforeTransform) {
      sessionMaterials["latest_plaintext"] = requestBeforeTransform;
    } else {
      delete sessionMaterials["latest_plaintext"];
    }
    var trace = {
      kind: "request-trace",
      trace_id: makeId(),
      transport: transport,
      page_url: window.location.href,
      request_url: requestURL,
      method: normalizedMethod,
      request_headers: normalizedHeaders,
      request_before_transform: requestBeforeTransform,
      final_request_body: finalBodyPreview,
      request_steps: requestSteps,
      signature_fields: collectSignatureFields(dynamicParams),
      dynamic_params: dynamicParams,
      session_materials: sessionMaterials,
      algorithms: inferAlgorithms(finalBodyPreview, requestSteps),
      stack: captureStack(),
      captured_at_ms: nowMs()
    };
    markTraceStepCursor(trace, "__request_step_seq", currentCryptoStepSeq());
    lastRequestStepSeq = currentCryptoStepSeq();
    return trace;
  }

  function wrapNamedFunction(container, methodName, label) {
    if (!container || typeof container[methodName] !== "function") {
      return false;
    }
    if (container[methodName].__trailblazerWrapped || wrappedFunctionCount >= maxWrappedFunctions) {
      return false;
    }

    var originalMethod = container[methodName];
    var wrappedMethod = function () {
      var args = Array.prototype.slice.call(arguments);
      var call = enterFunctionCall(label);
      var result;
      var isAsync = false;
      try {
        result = originalMethod.apply(this, args);
        isAsync = !!(result && typeof result.then === "function");
      } catch (err) {
        leaveFunctionCall(call);
        throw err;
      }
      if (result && typeof result.then === "function") {
        return result.then(function (output) {
          recordCryptoStep(label, label, args[0], output, call);
          leaveFunctionCall(call);
          return output;
        }, function (err) {
          leaveFunctionCall(call);
          throw err;
        });
      }
      try {
        recordCryptoStep(label, label, args[0], result, call);
        return result;
      } finally {
        if (!isAsync) {
          leaveFunctionCall(call);
        }
      }
    };
    wrappedMethod.__trailblazerWrapped = true;
    container[methodName] = wrappedMethod;
    wrappedFunctionCount += 1;
    return true;
  }

  function scanAndWrapPrototypeFunctions(candidate, label) {
    if (!candidate || typeof candidate !== "function" || !candidate.prototype || wrappedFunctionCount >= maxWrappedFunctions) {
      return;
    }
    var prototype = candidate.prototype;
    try {
      Object.getOwnPropertyNames(prototype).slice(0, 80).forEach(function (methodName) {
        if (methodName === "constructor" || wrappedFunctionCount >= maxWrappedFunctions) {
          return;
        }
        if (!suspiciousFuncPattern.test(methodName) && !helperFuncPattern.test(methodName)) {
          return;
        }
        wrapNamedFunction(prototype, methodName, label + ".prototype." + methodName);
      });
    } catch (err) {}
  }

  function scanAndWrapSuspiciousFunctions(root, rootName, depth) {
    if (!root || (typeof root !== "object" && typeof root !== "function") || depth < 0 || wrappedFunctionCount >= maxWrappedFunctions) {
      return;
    }

    if (typeof root === "function") {
      scanAndWrapPrototypeFunctions(root, rootName);
    }

    Object.keys(root).slice(0, 120).forEach(function (key) {
      if (wrappedFunctionCount >= maxWrappedFunctions) {
        return;
      }

      var value;
      try {
        value = root[key];
      } catch (err) {
        return;
      }

      if (typeof value === "function") {
        scanAndWrapPrototypeFunctions(value, rootName + "." + key);
      }

      if (!suspiciousFuncPattern.test(key) && !helperFuncPattern.test(key)) {
        if (depth > 0 && value && typeof value === "object" && !Array.isArray(value)) {
          scanAndWrapSuspiciousFunctions(value, rootName + "." + key, depth - 1);
        }
        return;
      }

      if (typeof value === "function") {
        scanAndWrapPrototypeFunctions(value, rootName + "." + key);
        wrapNamedFunction(root, key, rootName + "." + key);
        return;
      }

      if (depth > 0 && value && typeof value === "object" && !Array.isArray(value)) {
        scanAndWrapSuspiciousFunctions(value, rootName + "." + key, depth - 1);
      }
    });
  }

  function scanWebpackModuleCache(cacheRoot, runtimeLabel) {
    if (!cacheRoot || typeof cacheRoot !== "object" || wrappedFunctionCount >= maxWrappedFunctions) {
      return;
    }
    Object.keys(cacheRoot).slice(0, 120).forEach(function (moduleID) {
      if (wrappedFunctionCount >= maxWrappedFunctions) {
        return;
      }
      var cacheEntry;
      try {
        cacheEntry = cacheRoot[moduleID];
      } catch (err) {
        return;
      }
      if (!cacheEntry) {
        return;
      }
      var exportsRoot = cacheEntry.exports || cacheEntry;
      if (!exportsRoot || (typeof exportsRoot !== "object" && typeof exportsRoot !== "function")) {
        return;
      }
      if (typeof exportsRoot === "function") {
        scanAndWrapPrototypeFunctions(exportsRoot, runtimeLabel + "(" + moduleID + ").exports");
      }
      scanAndWrapSuspiciousFunctions(exportsRoot, runtimeLabel + "(" + moduleID + ").exports", 2);
    });
  }

  function hookKnownCryptoConstructors() {
    try {
      if (typeof window.JSEncrypt === "function") {
        scanAndWrapPrototypeFunctions(window.JSEncrypt, "window.JSEncrypt");
      }
    } catch (err) {}
    try {
      if (typeof window.RSAKey === "function") {
        scanAndWrapPrototypeFunctions(window.RSAKey, "window.RSAKey");
      }
    } catch (err) {}
    try {
      if (window.KJUR && window.KJUR.crypto && typeof window.KJUR.crypto.Cipher === "object") {
        scanAndWrapSuspiciousFunctions(window.KJUR.crypto.Cipher, "window.KJUR.crypto.Cipher", 1);
      }
    } catch (err) {}
    try {
      if (window.sm2 && typeof window.sm2 === "object") {
        scanAndWrapSuspiciousFunctions(window.sm2, "window.sm2", 1);
      }
    } catch (err) {}
    try {
      if (window.sm4 && typeof window.sm4 === "object") {
        scanAndWrapSuspiciousFunctions(window.sm4, "window.sm4", 1);
      }
    } catch (err) {}
  }

  function scanWebpackRuntimeCandidates() {
    if (wrappedFunctionCount >= maxWrappedFunctions) {
      return;
    }
    try {
      if (typeof window.__webpack_require__ === "function" && window.__webpack_require__.c) {
        scanWebpackModuleCache(window.__webpack_require__.c, "__webpack_require__");
      }
    } catch (err) {}

    Object.keys(window).slice(0, 200).forEach(function (key) {
      if (wrappedFunctionCount >= maxWrappedFunctions) {
        return;
      }
      var value;
      try {
        value = window[key];
      } catch (err) {
        return;
      }
      if (!value) {
        return;
      }

      try {
        if (typeof value === "function" && value.c && typeof value.c === "object") {
          scanWebpackModuleCache(value.c, "window." + key);
          return;
        }
      } catch (err) {}

      try {
        if (typeof value === "object" && value.c && typeof value.c === "object") {
          scanWebpackModuleCache(value.c, "window." + key);
        }
      } catch (err) {}
    });
  }

  function hookCommonEncodingHelpers() {
    if (typeof JSON !== "undefined" && typeof JSON.stringify === "function" && !JSON.stringify.__trailblazerWrapped) {
      var originalJSONStringify = JSON.stringify;
      var wrappedJSONStringify = function (value) {
        var result = originalJSONStringify.apply(this, arguments);
        if (suppressJSONStringifyCapture || (value && typeof value === "object" && value.kind === "request-trace")) {
          return result;
        }
        recordCryptoStep("JSON.stringify", "json.stringify", value, result);
        return result;
      };
      wrappedJSONStringify.__trailblazerWrapped = true;
      JSON.stringify = wrappedJSONStringify;
    }

    if (typeof JSON !== "undefined" && typeof JSON.parse === "function" && !JSON.parse.__trailblazerWrapped) {
      var originalJSONParse = JSON.parse;
      var wrappedJSONParse = function (value) {
        var result = originalJSONParse.apply(this, arguments);
        recordCryptoStep("JSON.parse", "json.parse", value, result);
        captureResponsePlaintextCandidate(value, "JSON.parse");
        captureResponsePlaintextCandidate(result, "JSON.parse");
        return result;
      };
      wrappedJSONParse.__trailblazerWrapped = true;
      JSON.parse = wrappedJSONParse;
    }

    if (typeof window.btoa === "function" && !window.btoa.__trailblazerWrapped) {
      var originalBtoa = window.btoa;
      var wrappedBtoa = function (value) {
        var result = originalBtoa.apply(this, arguments);
        recordCryptoStep("window.btoa", "base64.encode", value, result);
        return result;
      };
      wrappedBtoa.__trailblazerWrapped = true;
      window.btoa = wrappedBtoa;
    }

    if (typeof window.atob === "function" && !window.atob.__trailblazerWrapped) {
      var originalAtob = window.atob;
      var wrappedAtob = function (value) {
        var result = originalAtob.apply(this, arguments);
        recordCryptoStep("window.atob", "base64.decode", value, result);
        return result;
      };
      wrappedAtob.__trailblazerWrapped = true;
      window.atob = wrappedAtob;
    }

    if (typeof TextEncoder !== "undefined" && TextEncoder.prototype && typeof TextEncoder.prototype.encode === "function" && !TextEncoder.prototype.encode.__trailblazerWrapped) {
      var originalEncode = TextEncoder.prototype.encode;
      var wrappedEncode = function (value) {
        var result = originalEncode.apply(this, arguments);
        recordCryptoStep("TextEncoder.encode", "text.encode", value, result);
        return result;
      };
      wrappedEncode.__trailblazerWrapped = true;
      TextEncoder.prototype.encode = wrappedEncode;
    }

    if (typeof TextDecoder !== "undefined" && TextDecoder.prototype && typeof TextDecoder.prototype.decode === "function" && !TextDecoder.prototype.decode.__trailblazerWrapped) {
      var originalDecode = TextDecoder.prototype.decode;
      var wrappedDecode = function (value) {
        var result = originalDecode.apply(this, arguments);
        recordCryptoStep("TextDecoder.decode", "text.decode", value, result);
        return result;
      };
      wrappedDecode.__trailblazerWrapped = true;
      TextDecoder.prototype.decode = wrappedDecode;
    }
  }

  function hookFetch() {
    if (typeof window.fetch !== "function" || window.fetch.__trailblazerWrapped) {
      return;
    }
    var originalFetch = window.fetch;
    var wrappedFetch = function (input, init) {
      var trace = null;
      try {
        var method = (init && init.method) || (input && input.method) || "GET";
        var body = (init && Object.prototype.hasOwnProperty.call(init, "body")) ? init.body : (input && input.body);
        var headers = (init && init.headers) || (input && input.headers);
        trace = buildRequestTrace("fetch", resolveRequestUrl(input), method, body, headers);
        emitPayload(trace);
      } catch (err) {}
      var result = originalFetch.apply(this, arguments);
      if (trace && result && typeof result.then === "function") {
        return result.then(function (response) {
          captureFetchResponse(trace, response);
          return response;
        });
      }
      return result;
    };
    wrappedFetch.__trailblazerWrapped = true;
    window.fetch = wrappedFetch;
  }

  function hookXHR() {
    if (!window.XMLHttpRequest || window.XMLHttpRequest.__trailblazerWrapped) {
      return;
    }
    var originalOpen = window.XMLHttpRequest.prototype.open;
    var originalSend = window.XMLHttpRequest.prototype.send;
    var originalSetRequestHeader = window.XMLHttpRequest.prototype.setRequestHeader;

    window.XMLHttpRequest.prototype.open = function (method, requestURL) {
      this.__trailblazerMeta = {
        method: method || "GET",
        requestURL: resolveRequestUrl(requestURL),
        headers: {}
      };
      if (!this.__trailblazerResponseHookInstalled && typeof this.addEventListener === "function") {
        var xhr = this;
        this.addEventListener("loadend", function () {
          captureXHRResponse(xhr);
        });
        this.__trailblazerResponseHookInstalled = true;
      }
      return originalOpen.apply(this, arguments);
    };

    window.XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
      try {
        this.__trailblazerMeta = this.__trailblazerMeta || { headers: {} };
        this.__trailblazerMeta.headers = this.__trailblazerMeta.headers || {};
        this.__trailblazerMeta.headers[normalizeHeaderName(name)] = toPreview(value);
      } catch (err) {}
      return originalSetRequestHeader.apply(this, arguments);
    };

    window.XMLHttpRequest.prototype.send = function (body) {
      try {
        var meta = this.__trailblazerMeta || {};
        meta.trace = buildRequestTrace("xhr", meta.requestURL || window.location.href, meta.method || "GET", body, meta.headers || {});
        this.__trailblazerMeta = meta;
        emitPayload(meta.trace);
      } catch (err) {}
      return originalSend.apply(this, arguments);
    };

    window.XMLHttpRequest.__trailblazerWrapped = true;
  }

  function wrapWebCryptoMethod(target, methodName) {
    if (!target || typeof target[methodName] !== "function" || target[methodName].__trailblazerWrapped) {
      return;
    }
    var originalMethod = target[methodName];
    var wrappedMethod = function () {
      var args = Array.prototype.slice.call(arguments);
      var algorithm = args[0];
      var input = args[args.length - 1];
      captureWebCryptoAlgorithmMaterials(algorithm);
      var label = "webcrypto." + methodName;
      var call = enterFunctionCall(label);
      var result;
      try {
        result = originalMethod.apply(this, args);
      } catch (err) {
        leaveFunctionCall(call);
        throw err;
      }
      if (result && typeof result.then === "function") {
        return result.then(function (output) {
          recordCryptoStep(label, algorithm, input, output, call);
          if (methodName === "decrypt") {
            captureWebCryptoDecryptResult(input, output);
          }
          leaveFunctionCall(call);
          return output;
        }, function (err) {
          leaveFunctionCall(call);
          throw err;
        });
      }
      try {
        recordCryptoStep(label, algorithm, input, result, call);
        if (methodName === "decrypt") {
          captureWebCryptoDecryptResult(input, result);
        }
        return result;
      } finally {
        leaveFunctionCall(call);
      }
    };
    wrappedMethod.__trailblazerWrapped = true;
    target[methodName] = wrappedMethod;
  }

  function wrapWebCryptoImportKey(target) {
    if (!target || typeof target.importKey !== "function" || target.importKey.__trailblazerWrapped) {
      return;
    }
    var originalMethod = target.importKey;
    var wrappedMethod = function () {
      var args = Array.prototype.slice.call(arguments);
      var format = args[0];
      var keyData = args[1];
      var algorithm = args[2];
      captureWebCryptoKeyMaterial(format, keyData, algorithm);
      var call = enterFunctionCall("webcrypto.importKey");
      var result;
      try {
        result = originalMethod.apply(this, args);
      } catch (err) {
        leaveFunctionCall(call);
        throw err;
      }
      if (result && typeof result.then === "function") {
        return result.then(function (output) {
          recordCryptoStep("webcrypto.importKey", algorithm, keyData, output, call);
          leaveFunctionCall(call);
          return output;
        }, function (err) {
          leaveFunctionCall(call);
          throw err;
        });
      }
      try {
        recordCryptoStep("webcrypto.importKey", algorithm, keyData, result, call);
        return result;
      } finally {
        leaveFunctionCall(call);
      }
    };
    wrappedMethod.__trailblazerWrapped = true;
    target.importKey = wrappedMethod;
  }

  function hookWebCrypto() {
    if (!window.crypto || !window.crypto.subtle) {
      return;
    }
    wrapWebCryptoImportKey(window.crypto.subtle);
    wrapWebCryptoMethod(window.crypto.subtle, "encrypt");
    wrapWebCryptoMethod(window.crypto.subtle, "decrypt");
    wrapWebCryptoMethod(window.crypto.subtle, "sign");
    wrapWebCryptoMethod(window.crypto.subtle, "digest");
  }

  function wrapMessagePort(port, label) {
    if (!port || port.__trailblazerWrapped) {
      return;
    }
    if (typeof port.postMessage === "function" && !port.postMessage.__trailblazerWrapped) {
      var originalPostMessage = port.postMessage;
      var wrappedPostMessage = function (value) {
        recordCryptoStep(label + ".postMessage", label + ".postMessage", value, value);
        return originalPostMessage.apply(this, arguments);
      };
      wrappedPostMessage.__trailblazerWrapped = true;
      port.postMessage = wrappedPostMessage;
    }
    if (typeof port.addEventListener === "function") {
      port.addEventListener("message", function (event) {
        recordWorkerMessageStep(label + ".message", event && event.data);
      });
      try {
        if (typeof port.start === "function") {
          port.start();
        }
      } catch (err) {}
    }
    port.__trailblazerWrapped = true;
  }

  function wrapWorkerInstance(worker, label) {
    if (!worker || worker.__trailblazerWrapped) {
      return worker;
    }
    if (typeof worker.postMessage === "function" && !worker.postMessage.__trailblazerWrapped) {
      var originalPostMessage = worker.postMessage;
      var wrappedPostMessage = function (value) {
        recordCryptoStep(label + ".postMessage", label + ".postMessage", value, value);
        return originalPostMessage.apply(this, arguments);
      };
      wrappedPostMessage.__trailblazerWrapped = true;
      worker.postMessage = wrappedPostMessage;
    }
    if (typeof worker.addEventListener === "function") {
      worker.addEventListener("message", function (event) {
        recordWorkerMessageStep(label + ".message", event && event.data);
      });
    }
    if (worker.port) {
      wrapMessagePort(worker.port, label + ".port");
    }
    worker.__trailblazerWrapped = true;
    return worker;
  }

  function hookWorkers() {
    if (typeof window.Worker === "function" && !window.Worker.__trailblazerWrapped) {
      var OriginalWorker = window.Worker;
      var WrappedWorker = function (scriptURL, options) {
        var worker = arguments.length > 1 ? new OriginalWorker(scriptURL, options) : new OriginalWorker(scriptURL);
        recordCryptoStep("worker.construct", "worker.construct", scriptURL, "[Worker]");
        return wrapWorkerInstance(worker, "worker");
      };
      WrappedWorker.prototype = OriginalWorker.prototype;
      WrappedWorker.__trailblazerWrapped = true;
      window.Worker = WrappedWorker;
    }

    if (typeof window.SharedWorker === "function" && !window.SharedWorker.__trailblazerWrapped) {
      var OriginalSharedWorker = window.SharedWorker;
      var WrappedSharedWorker = function (scriptURL, options) {
        var worker = arguments.length > 1 ? new OriginalSharedWorker(scriptURL, options) : new OriginalSharedWorker(scriptURL);
        recordCryptoStep("sharedworker.construct", "sharedworker.construct", scriptURL, "[SharedWorker]");
        return wrapWorkerInstance(worker, "sharedworker");
      };
      WrappedSharedWorker.prototype = OriginalSharedWorker.prototype;
      WrappedSharedWorker.__trailblazerWrapped = true;
      window.SharedWorker = WrappedSharedWorker;
    }
  }

  function summarizeWasmResult(result) {
    try {
      if (result && result.instance && result.instance.exports) {
        return Object.keys(result.instance.exports).slice(0, 16).join(",");
      }
      if (result && result.exports) {
        return Object.keys(result.exports).slice(0, 16).join(",");
      }
    } catch (err) {}
    return "[WebAssembly]";
  }

  function hookWebAssembly() {
    if (!window.WebAssembly) {
      return;
    }

    if (typeof window.WebAssembly.instantiate === "function" && !window.WebAssembly.instantiate.__trailblazerWrapped) {
      var originalInstantiate = window.WebAssembly.instantiate;
      window.WebAssembly.instantiate = function () {
        var args = Array.prototype.slice.call(arguments);
        var result = originalInstantiate.apply(this, args);
        if (result && typeof result.then === "function") {
          return result.then(function (output) {
            recordCryptoStep("webassembly.instantiate", "webassembly.instantiate", args[0], summarizeWasmResult(output));
            setSessionMaterialIfMissing("wasm_runtime_present", "true");
            return output;
          });
        }
        recordCryptoStep("webassembly.instantiate", "webassembly.instantiate", args[0], summarizeWasmResult(result));
        setSessionMaterialIfMissing("wasm_runtime_present", "true");
        return result;
      };
      window.WebAssembly.instantiate.__trailblazerWrapped = true;
    }

    if (typeof window.WebAssembly.instantiateStreaming === "function" && !window.WebAssembly.instantiateStreaming.__trailblazerWrapped) {
      var originalInstantiateStreaming = window.WebAssembly.instantiateStreaming;
      window.WebAssembly.instantiateStreaming = function () {
        var args = Array.prototype.slice.call(arguments);
        var result = originalInstantiateStreaming.apply(this, args);
        if (result && typeof result.then === "function") {
          return result.then(function (output) {
            recordCryptoStep("webassembly.instantiateStreaming", "webassembly.instantiateStreaming", args[0], summarizeWasmResult(output));
            setSessionMaterialIfMissing("wasm_runtime_present", "true");
            return output;
          });
        }
        recordCryptoStep("webassembly.instantiateStreaming", "webassembly.instantiateStreaming", args[0], summarizeWasmResult(result));
        setSessionMaterialIfMissing("wasm_runtime_present", "true");
        return result;
      };
      window.WebAssembly.instantiateStreaming.__trailblazerWrapped = true;
    }
  }

  function wrapCryptoJSMethod(container, methodName, label) {
    if (!container || typeof container[methodName] !== "function" || container[methodName].__trailblazerWrapped) {
      return;
    }
    var originalMethod = container[methodName];
    var wrappedMethod = function () {
      var call = enterFunctionCall(label);
      var result;
      try {
        result = originalMethod.apply(this, arguments);
      } catch (err) {
        leaveFunctionCall(call);
        throw err;
      }
      var output = result;
      try {
        if (result && typeof result.toString === "function") {
          output = result.toString();
        }
      } catch (err) {}
      try {
        recordCryptoStep(label, label, arguments[0], output, call);
        return result;
      } finally {
        leaveFunctionCall(call);
      }
    };
    wrappedMethod.__trailblazerWrapped = true;
    container[methodName] = wrappedMethod;
  }

  function hookCryptoJS() {
    var root = window.CryptoJS;
    if (!root || root.__trailblazerHooked) {
      return !!root;
    }

    [["AES", ["encrypt", "decrypt"]], ["DES", ["encrypt", "decrypt"]], ["TripleDES", ["encrypt", "decrypt"]], ["RC4", ["encrypt", "decrypt"]], ["Rabbit", ["encrypt", "decrypt"]]].forEach(function (entry) {
      var namespace = entry[0];
      var methods = entry[1];
      if (!root[namespace]) {
        return;
      }
      methods.forEach(function (methodName) {
        wrapCryptoJSMethod(root[namespace], methodName, "cryptojs." + namespace + "." + methodName);
      });
    });

    ["MD5", "SHA1", "SHA256", "SHA512", "HmacSHA1", "HmacSHA256", "HmacSHA512"].forEach(function (methodName) {
      wrapCryptoJSMethod(root, methodName, "cryptojs." + methodName);
    });

    if (root.enc) {
      ["Hex", "Base64", "Utf8"].forEach(function (namespace) {
        if (!root.enc[namespace]) {
          return;
        }
        ["stringify", "parse"].forEach(function (methodName) {
          wrapCryptoJSMethod(root.enc[namespace], methodName, "cryptojs.enc." + namespace + "." + methodName);
        });
      });
    }

    root.__trailblazerHooked = true;
    return true;
  }

  hookFetch();
  hookXHR();
  hookWebCrypto();
  hookWorkers();
  hookWebAssembly();
  hookCommonEncodingHelpers();
  hookSensitiveInputCapture();
  hookFrontendRoutes();
  hookKnownCryptoConstructors();
  scanAndWrapSuspiciousFunctions(window, "window", 2);
  scanWebpackRuntimeCandidates();
  hookCryptoJS();
  var attempts = 0;
  var timer = window.setInterval(function () {
    attempts += 1;
    hookCryptoJS();
    hookSensitiveInputCapture();
    scanVueRouters();
    hookKnownCryptoConstructors();
    scanAndWrapSuspiciousFunctions(window, "window", 2);
    scanWebpackRuntimeCandidates();
    if (attempts > 20) {
      window.clearInterval(timer);
    }
  }, 1000);
})();`

var protocolHookScript = buildProtocolHookScript(CaptureOptions{
	BypassFrontendRouteGuards: true,
})

func buildProtocolHookScript(options CaptureOptions) string {
	flag := "false"
	if options.BypassFrontendRouteGuards {
		flag = "true"
	}
	return strings.ReplaceAll(
		protocolHookScriptTemplate,
		"__TRAILBLAZER_BYPASS_FRONTEND_ROUTE_GUARDS__",
		fmt.Sprintf("%s", flag),
	)
}
