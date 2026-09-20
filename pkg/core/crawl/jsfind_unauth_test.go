package crawl

import (
	"encoding/json"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestResolveUnauthorizedProtocolContextUsesMatchedTraceAndCiphertext(t *testing.T) {
	index := buildUnauthorizedAPIResourceIndex([]database.APIResource{
		{
			Method:           "POST",
			URL:              "https://example.com/api/orders/query?id=1&b=2",
			TraceID:          "trace-unauth-1",
			HasProtocolTrace: true,
			ResponseBody:     `"4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c"`,
			FetchedAt:        time.Now(),
		},
	})

	context := resolveUnauthorizedProtocolContext(structs.APIRequest{
		Method: "POST",
		URL:    "https://example.com/api/orders/query?b=2&id=1",
	}, `{"data":"5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d","useGlobalEnc":true,"enc":"rsa"}`, index, nil)

	if context.TraceID != "trace-unauth-1" {
		t.Fatalf("expected trace id to be matched, got %q", context.TraceID)
	}
	if !context.HasProtocolTrace {
		t.Fatal("expected unauthorized result to inherit protocol trace association")
	}
	if context.ResponseCiphertext != "5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d" {
		t.Fatalf("expected ciphertext to be normalized, got %q", context.ResponseCiphertext)
	}
	if context.DecryptionStatus != "not_tried" {
		t.Fatalf("expected decryption status to be not_tried, got %q", context.DecryptionStatus)
	}
	if context.DecryptionDetail == "" || context.DecryptionDetail == "已关联协议轨迹，可先尝试离线解密，失败后可继续尝试在线 runtime 解密" {
		t.Fatalf("expected decryption detail to include match strategy, got %q", context.DecryptionDetail)
	}
	if !strings.Contains(context.DecryptionDetail, "密文来源: 当前未授权探测响应") {
		t.Fatalf("expected decryption detail to include probe ciphertext source, got %q", context.DecryptionDetail)
	}
}

func TestNormalizeUnauthorizedCiphertextSkipsRandomBusinessField(t *testing.T) {
	body := `{"msg":"处理成功","data":{"card_id":"b0KV0u3Ixdb-81MXvTHaHQXC0Vd1RyVgznzb0T3eZNWpu3PIQ72ASh3IvGTAW_FHS56SvRvCPuMjLK20Pv762Dtm"}}`
	if ciphertext := normalizeUnauthorizedCiphertext(body); ciphertext != "" {
		t.Fatalf("expected random card_id not to be treated as response ciphertext, got %q", ciphertext)
	}
	if isLikelyEncryptedResponseEnvelope(body) {
		t.Fatalf("expected plaintext business response not to be treated as an encryption envelope")
	}
}

func TestNormalizeUnauthorizedCiphertextSkipsUnstructuredPayloadField(t *testing.T) {
	body := `{"payload":"b0KV0u3Ixdb-81MXvTHaHQXC0Vd1RyVgznzb0T3eZNWpu3PIQ72ASh3IvGTAW_FHS56SvRvCPuMjLK20Pv762Dtm"}`
	if ciphertext := normalizeUnauthorizedCiphertext(body); ciphertext != "" {
		t.Fatalf("expected unstructured payload field not to be treated as response ciphertext, got %q", ciphertext)
	}
}

func TestNormalizeUnauthorizedCiphertextRecognizesGlobalEncryptionEnvelope(t *testing.T) {
	body := `{"msg":"处理成功","data":"ET1zUF_0fPUJoGNjK-Ba9DLNyf0yppLFKPd8tSrAbKznLH7TdHZ4CVlDCj1OmXwU8FoaE-Wx3HLLqhMFVHd_j1V7BBL2XLEwE7rfTN7UHSPGhq9llewYcF37kNahCzq5eRv57wOj60Y4Gkxi3fa4ep-7e6F-07vz3IMCyNThiPR8BpSCFYmT37n_zCdNL06TUCECLUS0Eee4mn0Cb8_et-DsATaE9ahWyAyiCty3MYRHOV61byzQ1aPh2UJy_MyaJndd1SN0D03NtSWp7Bhur6NI5RcSc8_hZbzNM5XY2ViZPQOrprMIf0tSAxKsQkNODdtIvewMrgWl1d8HXSGJDQ==","useGlobalEnc":true,"digest":"DdbgIS6gsggzfAb3PtZzDYBCkvzs6tmYBtEY9w-lWsMVBOOz0CsHI5cku4EbPT2vjIXuCB1F6U-Xy3GqmJN4O50bJP1422lhjdtlOphnxRRg8zChuu5ih0TWil7ybvFzXWaexDs2jZJ4j_y00NgMw3Do07E2OvOaNC8rxjGC84NnDCEfkm0YtyH87zf1hUGO_yCofkhc79p_hLg9LPVksMiD6fJDh12AHU8Fc70HfnG_QLaCdtiWomVenfLlG7XURdi6VQtOAlqSZu0Jtu_zByp690OMv3YsG36iGb5f8C6TxpVumFlebbxiBFlNb4TD9k4gKD_o0xE8GVGC9FvUnQ==","state":"ok","enc":"rsa"}`
	if !isLikelyEncryptedResponseEnvelope(body) {
		t.Fatal("expected useGlobalEnc + enc + encrypted data response to be recognized as an envelope")
	}
	if ciphertext := normalizeUnauthorizedCiphertext(body); !strings.HasPrefix(ciphertext, "ET1zUF_0fPUJoGNj") {
		t.Fatalf("expected encrypted data payload, got %q", ciphertext)
	}
}

func TestApplyStaticRequestPayloadHintSetsJSONHeadersAndMetadata(t *testing.T) {
	apiReq := structs.APIRequest{
		URL:     "https://example.com/api/orders/query",
		Method:  "POST",
		Headers: map[string]string{},
		Params: url.Values{
			"id": []string{"1"},
		},
	}

	applyStaticRequestPayloadHint(&apiReq, map[string]structs.StaticRequestPayloadHint{
		"POST\x00/api/orders/query": {
			Carrier: "body",
			Format:  "json",
			Preview: `{"id":"1"}`,
		},
	}, nil)

	if apiReq.PayloadCarrier != "body" {
		t.Fatalf("expected payload carrier body, got %q", apiReq.PayloadCarrier)
	}
	if apiReq.PayloadFormat != "json" {
		t.Fatalf("expected payload format json, got %q", apiReq.PayloadFormat)
	}
	if apiReq.Headers["Content-Type"] != "application/json" {
		t.Fatalf("expected application/json header, got %#v", apiReq.Headers)
	}
}

func TestApplyStaticRequestPayloadHintPrefersQueryCarrier(t *testing.T) {
	apiReq := structs.APIRequest{
		URL:     "https://example.com/api/orders/list",
		Method:  "POST",
		Headers: map[string]string{},
		Params: url.Values{
			"tenant": []string{"a"},
		},
	}

	applyStaticRequestPayloadHint(&apiReq, map[string]structs.StaticRequestPayloadHint{
		"POST\x00/api/orders/list": {
			Carrier: "params",
			Format:  "query",
		},
	}, nil)

	if apiReq.PayloadCarrier != "params" {
		t.Fatalf("expected payload carrier params, got %q", apiReq.PayloadCarrier)
	}
	if apiReq.PayloadFormat != "query" {
		t.Fatalf("expected payload format query, got %q", apiReq.PayloadFormat)
	}
}

func TestApplyStaticRequestPayloadHintBuildsUsableJSONBodyFromVariablePreview(t *testing.T) {
	apiReq := structs.APIRequest{
		URL:     "https://example.com/ccat/step/getSteps",
		Method:  "GET",
		Headers: map[string]string{},
	}

	applyStaticRequestPayloadHint(&apiReq, map[string]structs.StaticRequestPayloadHint{
		"GET\x00/ccat/step/getSteps": {
			Carrier: "body",
			Format:  "json",
			Preview: `{caseId:t}`,
		},
	}, nil)

	if apiReq.Body == `{caseId:t}` {
		t.Fatalf("expected preview variables to be normalized, got raw body %q", apiReq.Body)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(apiReq.Body), &payload); err != nil {
		t.Fatalf("expected valid json body, got %q: %v", apiReq.Body, err)
	}
	if payload["caseId"] != "" {
		t.Fatalf("expected caseId without placeholder rule to prefer empty value, got %#v", payload["caseId"])
	}
}

func TestApplyStaticRequestPayloadHintUsesCompletedParamsInsideJSONPreview(t *testing.T) {
	apiReq := structs.APIRequest{
		URL:     "https://example.com/ccat/step/getStepParamsByStepId",
		Method:  "GET",
		Headers: map[string]string{},
		Params: url.Values{
			"stepId": []string{"6238"},
		},
	}

	applyStaticRequestPayloadHint(&apiReq, map[string]structs.StaticRequestPayloadHint{
		"GET\x00/ccat/step/getStepParamsByStepId": {
			Carrier: "body",
			Format:  "json",
			Preview: `{stepId:e}`,
		},
	}, nil)

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(apiReq.Body), &payload); err != nil {
		t.Fatalf("expected valid json body, got %q: %v", apiReq.Body, err)
	}
	if payload["stepId"] != "6238" {
		t.Fatalf("expected completed param to be reused in body, got %#v", payload["stepId"])
	}
}

func TestVerifyAndFixStaticGETPayloadHintKeepsQueryAndJSONBody(t *testing.T) {
	apiReq := structs.APIRequest{
		URL:     "https://example.com/api/refreshApiInfoByInterfaceName",
		Method:  "GET",
		Headers: map[string]string{"Content-Type": "application/json"},
		Params: url.Values{
			"env":           []string{"TEST33"},
			"interfaceName": []string{"test"},
		},
		Body:           `{"env":"TEST33","interfaceName":"test"}`,
		PayloadCarrier: "body",
		PayloadFormat:  "json",
	}

	verifyAndFixStaticGETPayloadHint(&apiReq)

	if apiReq.PayloadCarrier != "params" {
		t.Fatalf("expected query carrier after normalization, got %q", apiReq.PayloadCarrier)
	}
	if apiReq.PayloadFormat != "query" {
		t.Fatalf("expected query format after normalization, got %q", apiReq.PayloadFormat)
	}
	if strings.TrimSpace(apiReq.Body) != `{"env":"TEST33","interfaceName":"test"}` {
		t.Fatalf("expected json body to be preserved for compatibility, got %q", apiReq.Body)
	}
	if got := apiReq.Params.Get("interfaceName"); got != "test" {
		t.Fatalf("expected body field to be backfilled into query params, got %q", got)
	}
}

func TestApplyStaticRequestPayloadHintBuildsGETBodyAndQueryFromVariablePreview(t *testing.T) {
	apiReq := structs.APIRequest{
		URL:     "https://example.com/ccat/api/getApisGroupByApp",
		Method:  "GET",
		Headers: map[string]string{},
	}

	applyStaticRequestPayloadHint(&apiReq, map[string]structs.StaticRequestPayloadHint{
		"GET\x00/ccat/api/getApisGroupByApp": {
			Carrier: "body",
			Format:  "json",
			Preview: `{app:t}`,
		},
	}, map[string]string{
		"default": "test",
	})
	verifyAndFixStaticGETPayloadHint(&apiReq)

	if apiReq.Body != `{"app":"test"}` {
		t.Fatalf("expected GET body to be normalized from preview, got %q", apiReq.Body)
	}
	if got := apiReq.Params.Get("app"); got != "test" {
		t.Fatalf("expected GET query params to be backfilled from body, got %q", got)
	}
	if apiReq.PayloadCarrier != "params" || apiReq.PayloadFormat != "query" {
		t.Fatalf("expected GET request to normalize to query transport, got carrier=%q format=%q", apiReq.PayloadCarrier, apiReq.PayloadFormat)
	}
}

func TestApplyStaticRequestPayloadHintUsesPlaceholderRuleBeforeEmptyFallback(t *testing.T) {
	apiReq := structs.APIRequest{
		URL:     "https://example.com/ccat/step/getStepParams",
		Method:  "POST",
		Headers: map[string]string{},
	}

	applyStaticRequestPayloadHint(&apiReq, map[string]structs.StaticRequestPayloadHint{
		"POST\x00/ccat/step/getStepParams": {
			Carrier: "body",
			Format:  "json",
			Preview: `{"caseId":t,"httpReqType":"query","stepId":e}`,
		},
	}, map[string]string{
		"default": "test",
		"id":      "1",
	})

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(apiReq.Body), &payload); err != nil {
		t.Fatalf("expected valid json body, got %q: %v", apiReq.Body, err)
	}
	if payload["caseId"] != "1" {
		t.Fatalf("expected caseId to reuse placeholder rule, got %#v", payload["caseId"])
	}
	if payload["stepId"] != "1" {
		t.Fatalf("expected stepId to reuse placeholder rule, got %#v", payload["stepId"])
	}
	if payload["httpReqType"] != "query" {
		t.Fatalf("expected literal field to be preserved, got %#v", payload["httpReqType"])
	}
}

func TestApplyStaticHeaderHintsSetsReusableHeadersOnly(t *testing.T) {
	headers := map[string]string{}

	applyStaticHeaderHints("/api/orders", headers, map[string]map[string]string{
		"POST\x00/api/orders": {
			"channel-code":   "miniapp",
			"Authorization":  "Bearer token",
			"X-Request-From": "console",
		},
	})

	if headers["channel-code"] != "miniapp" {
		t.Fatalf("expected channel-code to be applied, got %#v", headers)
	}
	if headers["X-Request-From"] != "console" {
		t.Fatalf("expected X-Request-From to be applied, got %#v", headers)
	}
	if got := headers["Authorization"]; got != "" {
		t.Fatalf("expected Authorization to be filtered, got %q", got)
	}
}

func TestResolveStaticProbeMethodUsesPathLevelPOSTHint(t *testing.T) {
	method, matched := resolveStaticProbeMethod(
		"https://example.com/api/orders/query?id=1",
		map[string]string{
			"/api/orders/query": "POST",
		},
	)

	if !matched {
		t.Fatal("expected static method hint to match path")
	}
	if method != "POST" {
		t.Fatalf("expected POST method, got %q", method)
	}
}

func TestResolveStaticProbeMethodRejectsUnsupportedMethodHint(t *testing.T) {
	method, matched := resolveStaticProbeMethod(
		"/api/orders/query",
		map[string]string{
			"/api/orders/query": "DELETE",
		},
	)

	if matched {
		t.Fatalf("expected DELETE hint to be ignored, got method %q", method)
	}
	if method != "" {
		t.Fatalf("expected empty method when hint ignored, got %q", method)
	}
}

func TestResolveUnauthorizedProtocolContextSkipsPlaintextResponse(t *testing.T) {
	context := resolveUnauthorizedProtocolContext(structs.APIRequest{
		Method: "GET",
		URL:    "https://example.com/api/orders/list",
	}, `{"code":401,"message":"forbidden"}`, nil, nil)

	if context.ResponseCiphertext != "" {
		t.Fatalf("expected plaintext response not to be treated as ciphertext, got %q", context.ResponseCiphertext)
	}
	if context.DecryptionStatus != "" {
		t.Fatalf("expected decryption status to remain empty, got %q", context.DecryptionStatus)
	}
}

func TestResolveUnauthorizedProtocolContextMatchesByRouteTemplate(t *testing.T) {
	index := buildUnauthorizedAPIResourceIndex([]database.APIResource{
		{
			Method:           "GET",
			URL:              "https://example.com/api/orders/123456/detail?view=full",
			TraceID:          "trace-template-1",
			HasProtocolTrace: true,
			FetchedAt:        time.Now(),
		},
	})

	context := resolveUnauthorizedProtocolContext(structs.APIRequest{
		Method: "GET",
		URL:    "https://example.com/api/orders/987654/detail?view=compact",
	}, `"4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c"`, index, nil)

	if context.TraceID != "trace-template-1" {
		t.Fatalf("expected route-template match trace id, got %q", context.TraceID)
	}
	if !context.HasProtocolTrace {
		t.Fatal("expected route-template match to preserve protocol trace flag")
	}
	if context.DecryptionDetail == "" || context.DecryptionDetail == "已关联协议轨迹，可先尝试离线解密，失败后可继续尝试在线 runtime 解密" {
		t.Fatalf("expected route-template detail to include match reason, got %q", context.DecryptionDetail)
	}
}

func TestResolveUnauthorizedProtocolContextFallsBackToProbeCiphertext(t *testing.T) {
	index := buildUnauthorizedAPIResourceIndex([]database.APIResource{
		{
			Method:           "GET",
			URL:              "https://example.com/api/orders/list",
			TraceID:          "trace-fallback-1",
			HasProtocolTrace: true,
			ResponseBody:     `{"code":401,"message":"forbidden"}`,
			FetchedAt:        time.Now(),
		},
	})

	context := resolveUnauthorizedProtocolContext(structs.APIRequest{
		Method: "GET",
		URL:    "https://example.com/api/orders/list",
	}, `"4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c"`, index, nil)

	if context.ResponseCiphertext != "4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c" {
		t.Fatalf("expected probe ciphertext fallback, got %q", context.ResponseCiphertext)
	}
	if !strings.Contains(context.DecryptionDetail, "密文来源: 当前未授权探测响应") {
		t.Fatalf("expected decryption detail to include probe ciphertext source, got %q", context.DecryptionDetail)
	}
}

func TestResolveUnauthorizedProtocolContextFallsBackToMatchedAPIRecordCiphertext(t *testing.T) {
	index := buildUnauthorizedAPIResourceIndex([]database.APIResource{
		{
			Method:           "GET",
			URL:              "https://example.com/api/orders/list",
			TraceID:          "trace-api-record-1",
			HasProtocolTrace: true,
			ResponseBody:     `{"useGlobalEnc":true,"enc":"sm4","data":"4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c"}`,
			FetchedAt:        time.Now(),
		},
	})

	context := resolveUnauthorizedProtocolContext(structs.APIRequest{
		Method: "GET",
		URL:    "https://example.com/api/orders/list",
	}, `{"code":401,"message":"forbidden"}`, index, nil)

	if context.ResponseCiphertext != "4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c" {
		t.Fatalf("expected api record ciphertext fallback, got %q", context.ResponseCiphertext)
	}
	if !strings.Contains(context.DecryptionDetail, "密文来源: 已匹配 API 记录响应") {
		t.Fatalf("expected decryption detail to include api-record ciphertext source, got %q", context.DecryptionDetail)
	}
}

func TestResolveUnauthorizedProtocolContextFallsBackToSiteLevelTraceForDecrypt(t *testing.T) {
	traceIndex := &unauthorizedProtocolTraceIndex{
		byTraceID: map[string]database.ProtocolTraceRecord{
			"trace-site-decrypt-1": {
				TraceID:                "trace-site-decrypt-1",
				Method:                 "POST",
				RequestURL:             "https://example.com/api/orders/query",
				RequestBeforeTransform: `{"id":1}`,
				RequestHeaders: map[string]string{
					"6zzbinypyphq": "exchange-site",
				},
				SessionMaterials: map[string]string{
					"sm4_key_hex":         "31393435323038373838333136383734",
					"key_exchange_header": "exchange-site",
				},
				CreatedAt: time.Now(),
			},
		},
		traces: []database.ProtocolTraceRecord{
			{
				TraceID:                "trace-site-decrypt-1",
				Method:                 "POST",
				RequestURL:             "https://example.com/api/orders/query",
				RequestBeforeTransform: `{"id":1}`,
				RequestHeaders: map[string]string{
					"6zzbinypyphq": "exchange-site",
				},
				SessionMaterials: map[string]string{
					"sm4_key_hex":         "31393435323038373838333136383734",
					"key_exchange_header": "exchange-site",
				},
				CreatedAt: time.Now(),
			},
		},
	}

	context := resolveUnauthorizedProtocolContext(structs.APIRequest{
		Method: "POST",
		URL:    "https://example.com/api/new/endpoint",
	}, `"4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c"`, nil, traceIndex)

	if context.TraceID != "trace-site-decrypt-1" {
		t.Fatalf("expected same-host fallback trace id, got %q", context.TraceID)
	}
	if !context.HasProtocolTrace {
		t.Fatal("expected same-host fallback to preserve decryptability")
	}
	if context.DecryptionStatus != "not_tried" {
		t.Fatalf("expected decryption status not_tried, got %q", context.DecryptionStatus)
	}
	if !strings.Contains(context.DecryptionDetail, "同站点协议轨迹") {
		t.Fatalf("expected site-level decrypt detail, got %q", context.DecryptionDetail)
	}
}

func TestResolveUnauthorizedProtocolContextFallsBackToAPIBaseTraceForDecrypt(t *testing.T) {
	traceIndex := &unauthorizedProtocolTraceIndex{
		byTraceID: map[string]database.ProtocolTraceRecord{
			"trace-api-base-decrypt-1": {
				TraceID:                "trace-api-base-decrypt-1",
				Method:                 "POST",
				RequestURL:             "https://saas-api.diandianys.com/api/orders/query",
				RequestBeforeTransform: `{"id":1}`,
				RequestHeaders: map[string]string{
					"6zzbinypyphq": "exchange-api-base",
				},
				SessionMaterials: map[string]string{
					"sm4_key_hex":         "31393435323038373838333136383734",
					"key_exchange_header": "exchange-api-base",
				},
				CreatedAt: time.Now(),
			},
		},
		traces: []database.ProtocolTraceRecord{
			{
				TraceID:                "trace-api-base-decrypt-1",
				Method:                 "POST",
				RequestURL:             "https://saas-api.diandianys.com/api/orders/query",
				RequestBeforeTransform: `{"id":1}`,
				RequestHeaders: map[string]string{
					"6zzbinypyphq": "exchange-api-base",
				},
				SessionMaterials: map[string]string{
					"sm4_key_hex":         "31393435323038373838333136383734",
					"key_exchange_header": "exchange-api-base",
				},
				CreatedAt: time.Now(),
			},
		},
	}

	context := resolveUnauthorizedProtocolContext(structs.APIRequest{
		Method: "POST",
		URL:    "https://test-dl-api.diandianys.com/api/new/endpoint",
	}, `"4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c4f2a6b8c"`, nil, traceIndex)

	if context.TraceID != "trace-api-base-decrypt-1" {
		t.Fatalf("expected api-base fallback trace id, got %q", context.TraceID)
	}
	if !context.HasProtocolTrace {
		t.Fatal("expected api-base fallback to preserve decryptability")
	}
	if !strings.Contains(context.DecryptionDetail, "同 API Base") {
		t.Fatalf("expected api-base decrypt detail, got %q", context.DecryptionDetail)
	}
}

func TestApplyStaticConstantParamsAddsMissingConstantParams(t *testing.T) {
	params := applyStaticConstantParams(
		"POST",
		"https://example.com/ccat/step/getStepParams",
		nil,
		map[string]url.Values{
			"POST\x00/ccat/step/getStepParams": {
				"httpReqType": {"query"},
			},
		},
	)

	if got := params.Get("httpReqType"); got != "query" {
		t.Fatalf("expected static constant param to be injected, got %q", got)
	}
}

func TestApplyStaticConstantParamsDoesNotOverrideExistingParams(t *testing.T) {
	params := applyStaticConstantParams(
		"POST",
		"https://example.com/ccat/step/getStepParams",
		url.Values{
			"httpReqType": {"body"},
		},
		map[string]url.Values{
			"POST\x00/ccat/step/getStepParams": {
				"httpReqType": {"query"},
			},
		},
	)

	if got := params.Get("httpReqType"); got != "body" {
		t.Fatalf("expected existing param to win, got %q", got)
	}
}

func TestLookupUnauthorizedAPIResourcePrefersTraceAwarePathMatch(t *testing.T) {
	index := buildUnauthorizedAPIResourceIndex([]database.APIResource{
		{
			Method:           "POST",
			URL:              "https://example.com/api/orders/query?id=1&tenant=a",
			HasProtocolTrace: false,
			FetchedAt:        time.Now().Add(-time.Minute),
		},
		{
			Method:           "POST",
			URL:              "https://example.com/api/orders/query?id=2&tenant=a",
			TraceID:          "trace-path-1",
			HasProtocolTrace: true,
			FetchedAt:        time.Now(),
		},
	})

	resource, strategy, matched := lookupUnauthorizedAPIResource("POST", "https://example.com/api/orders/query?tenant=a", index)
	if !matched {
		t.Fatal("expected path-only lookup to match api resource")
	}
	if strategy != "same_path" {
		t.Fatalf("expected same_path strategy, got %q", strategy)
	}
	if resource.TraceID != "trace-path-1" {
		t.Fatalf("expected trace-aware candidate to win, got trace id %q", resource.TraceID)
	}
}

func TestBuildUnauthorizedProtocolReplayRequestUsesTraceEncryptionAndRemovesToken(t *testing.T) {
	trace := &database.ProtocolTraceRecord{
		TraceID:                "trace-replay-1",
		Method:                 "POST",
		RequestBeforeTransform: `{"id":1}`,
		RequestHeaders: map[string]string{
			"x-access-token": "secret-token",
			"channel-code":   "miniapp",
			"6zzbinypyphq":   "captured-exchange",
			"Content-Type":   "application/json",
		},
		SessionMaterials: map[string]string{
			"sm4_key_hex":         "31393435323038373838333136383734",
			"key_exchange_header": "captured-exchange",
			"x_access_token":      "secret-token",
			"channel_code":        "miniapp",
		},
	}

	req, detail, err := buildUnauthorizedProtocolReplayRequest(structs.APIRequest{
		URL:    "https://example.com/api/orders/query",
		Method: "POST",
		Headers: map[string]string{
			"Accept":         "application/json",
			"x-access-token": "secret-token",
		},
		Body: "{}",
	}, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Body == "" || req.Body == `{"id":1}` || req.Body == "{}" {
		t.Fatalf("expected encrypted request body, got %q", req.Body)
	}
	if got := req.Headers["x-access-token"]; got != "" {
		t.Fatalf("expected x-access-token to be removed, got %q", got)
	}
	if req.Headers["6zzbinypyphq"] != "captured-exchange" {
		t.Fatalf("expected key exchange header to be reused, got %q", req.Headers["6zzbinypyphq"])
	}
	if req.Headers["channel-code"] != "miniapp" {
		t.Fatalf("expected channel-code to be preserved, got %q", req.Headers["channel-code"])
	}
	if req.Headers["gv59JPPEesNW"] == "" || req.Headers["KQN29pKXsTKN"] == "" || req.Headers["BpzHepzRVcJy"] == "" {
		t.Fatalf("expected nonce/timestamp/signature headers to be generated, got %#v", req.Headers)
	}
	if !strings.Contains(detail, "移除 x-access-token") {
		t.Fatalf("expected replay detail to mention token removal, got %q", detail)
	}
}

func TestBuildUnauthorizedProtocolReplayRequestFallsBackToFormURLEncodedContentType(t *testing.T) {
	trace := &database.ProtocolTraceRecord{
		TraceID:                "trace-replay-form-fallback",
		Method:                 "POST",
		RequestBeforeTransform: `areaCode=0&mobile=test`,
		RequestHeaders: map[string]string{
			"x-access-token": "secret-token",
			"channel-code":   "miniapp",
			"6zzbinypyphq":   "captured-exchange",
		},
		SessionMaterials: map[string]string{
			"sm4_key_hex":         "31393435323038373838333136383734",
			"key_exchange_header": "captured-exchange",
			"x_access_token":      "secret-token",
			"channel_code":        "miniapp",
		},
	}

	req, _, err := buildUnauthorizedProtocolReplayRequest(structs.APIRequest{
		URL:    "https://example.com/api/ada/sendMessageToMobile",
		Method: "POST",
		Headers: map[string]string{
			"Accept":         "application/json",
			"x-access-token": "secret-token",
		},
		Body: "",
	}, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := req.Headers["Content-Type"]; got != "application/x-www-form-urlencoded" {
		t.Fatalf("expected form-urlencoded content-type fallback, got %q", got)
	}
}

func TestFindReusableUnauthorizedProtocolTraceFallsBackToSameHost(t *testing.T) {
	now := time.Now()
	trace, strategy, ok := findReusableUnauthorizedProtocolTrace(structs.APIRequest{
		Method: "POST",
		URL:    "https://example.com/api/other/endpoint?id=2",
		Body:   "{}",
	}, &unauthorizedProtocolTraceIndex{
		byTraceID: map[string]database.ProtocolTraceRecord{},
		traces: []database.ProtocolTraceRecord{
			{
				TraceID:                "trace-other-host",
				Method:                 "POST",
				RequestURL:             "https://other.example.org/api/orders/query",
				RequestBeforeTransform: `{"id":1}`,
				SessionMaterials: map[string]string{
					"sm4_key_hex":         "31393435323038373838333136383734",
					"key_exchange_header": "exchange-1",
				},
				RequestHeaders: map[string]string{
					"6zzbinypyphq": "exchange-1",
				},
				CreatedAt: now.Add(-time.Hour),
			},
			{
				TraceID:                "trace-same-host",
				Method:                 "POST",
				RequestURL:             "https://example.com/api/orders/query?id=1",
				RequestBeforeTransform: `{"id":1}`,
				SessionMaterials: map[string]string{
					"sm4_key_hex":         "31393435323038373838333136383734",
					"key_exchange_header": "exchange-2",
				},
				RequestHeaders: map[string]string{
					"6zzbinypyphq": "exchange-2",
				},
				CreatedAt: now,
			},
		},
	})
	if !ok {
		t.Fatal("expected same-host reusable protocol trace to be found")
	}
	if trace.TraceID != "trace-same-host" {
		t.Fatalf("expected same-host trace to be selected, got %q", trace.TraceID)
	}
	if strategy != "same_host_protocol" {
		t.Fatalf("expected same_host_protocol strategy, got %q", strategy)
	}
}

func TestFindReusableUnauthorizedProtocolTraceFallsBackToSameAPIBaseAcrossHosts(t *testing.T) {
	now := time.Now()
	trace, strategy, ok := findReusableUnauthorizedProtocolTrace(structs.APIRequest{
		Method: "POST",
		URL:    "https://test-dl-api.diandianys.com/api/notificationsSettings/query",
		Body:   "{}",
	}, &unauthorizedProtocolTraceIndex{
		byTraceID: map[string]database.ProtocolTraceRecord{},
		traces: []database.ProtocolTraceRecord{
			{
				TraceID:                "trace-other-base",
				Method:                 "POST",
				RequestURL:             "https://other.example.org/gateway/notificationsSettings/query",
				RequestBeforeTransform: `{"id":1}`,
				SessionMaterials: map[string]string{
					"sm4_key_hex":         "31393435323038373838333136383734",
					"key_exchange_header": "exchange-1",
				},
				RequestHeaders: map[string]string{
					"6zzbinypyphq": "exchange-1",
				},
				CreatedAt: now.Add(-time.Hour),
			},
			{
				TraceID:                "trace-same-api-base",
				Method:                 "POST",
				RequestURL:             "https://saas-api.diandianys.com/api/sysMessageBox/readAll",
				RequestBeforeTransform: `{"id":1}`,
				SessionMaterials: map[string]string{
					"sm4_key_hex":         "31393435323038373838333136383734",
					"key_exchange_header": "exchange-2",
				},
				RequestHeaders: map[string]string{
					"6zzbinypyphq": "exchange-2",
				},
				CreatedAt: now,
			},
		},
	})
	if !ok {
		t.Fatal("expected same-api-base reusable protocol trace to be found")
	}
	if trace.TraceID != "trace-same-api-base" {
		t.Fatalf("expected same-api-base trace to be selected, got %q", trace.TraceID)
	}
	if strategy != "same_api_base_protocol" {
		t.Fatalf("expected same_api_base_protocol strategy, got %q", strategy)
	}
}

func TestPrepareUnauthorizedProbeRequestFallsBackToSiteLevelProtocolTrace(t *testing.T) {
	req, detail := prepareUnauthorizedProbeRequest(structs.APIRequest{
		Method: "POST",
		URL:    "https://example.com/api/new/endpoint",
		Body:   "{}",
		Headers: map[string]string{
			"x-access-token": "secret-token",
		},
	}, &unauthorizedAPIResourceIndex{}, &unauthorizedProtocolTraceIndex{
		byTraceID: map[string]database.ProtocolTraceRecord{
			"trace-site-1": {
				TraceID:                "trace-site-1",
				Method:                 "POST",
				RequestURL:             "https://example.com/api/orders/query",
				RequestBeforeTransform: `{"id":1}`,
				RequestHeaders: map[string]string{
					"6zzbinypyphq": "exchange-site",
					"channel-code": "miniapp",
				},
				SessionMaterials: map[string]string{
					"sm4_key_hex":         "31393435323038373838333136383734",
					"key_exchange_header": "exchange-site",
					"channel_code":        "miniapp",
				},
				CreatedAt: time.Now(),
			},
		},
		traces: []database.ProtocolTraceRecord{
			{
				TraceID:                "trace-site-1",
				Method:                 "POST",
				RequestURL:             "https://example.com/api/orders/query",
				RequestBeforeTransform: `{"id":1}`,
				RequestHeaders: map[string]string{
					"6zzbinypyphq": "exchange-site",
					"channel-code": "miniapp",
				},
				SessionMaterials: map[string]string{
					"sm4_key_hex":         "31393435323038373838333136383734",
					"key_exchange_header": "exchange-site",
					"channel_code":        "miniapp",
				},
				CreatedAt: time.Now(),
			},
		},
	})
	if req.Body == "" || req.Body == "{}" {
		t.Fatalf("expected site-level fallback to encrypt request body, got %q", req.Body)
	}
	if !strings.Contains(detail, "同站点协议轨迹") {
		t.Fatalf("expected site-level replay detail, got %q", detail)
	}
}

func TestPrepareUnauthorizedProbeRequestFallsBackToAPIBaseProtocolTrace(t *testing.T) {
	req, detail := prepareUnauthorizedProbeRequest(structs.APIRequest{
		Method: "POST",
		URL:    "https://test-dl-api.diandianys.com/api/new/endpoint",
		Body:   "{}",
	}, &unauthorizedAPIResourceIndex{}, &unauthorizedProtocolTraceIndex{
		byTraceID: map[string]database.ProtocolTraceRecord{
			"trace-api-base-1": {
				TraceID:                "trace-api-base-1",
				Method:                 "POST",
				RequestURL:             "https://saas-api.diandianys.com/api/orders/query",
				RequestBeforeTransform: `{"id":1}`,
				RequestHeaders: map[string]string{
					"6zzbinypyphq": "exchange-api-base",
					"channel-code": "miniapp",
				},
				SessionMaterials: map[string]string{
					"sm4_key_hex":         "31393435323038373838333136383734",
					"key_exchange_header": "exchange-api-base",
					"channel_code":        "miniapp",
				},
				CreatedAt: time.Now(),
			},
		},
		traces: []database.ProtocolTraceRecord{
			{
				TraceID:                "trace-api-base-1",
				Method:                 "POST",
				RequestURL:             "https://saas-api.diandianys.com/api/orders/query",
				RequestBeforeTransform: `{"id":1}`,
				RequestHeaders: map[string]string{
					"6zzbinypyphq": "exchange-api-base",
					"channel-code": "miniapp",
				},
				SessionMaterials: map[string]string{
					"sm4_key_hex":         "31393435323038373838333136383734",
					"key_exchange_header": "exchange-api-base",
					"channel_code":        "miniapp",
				},
				CreatedAt: time.Now(),
			},
		},
	})
	if req.Body == "" || req.Body == "{}" {
		t.Fatalf("expected api-base fallback to encrypt request body, got %q", req.Body)
	}
	if !strings.Contains(detail, "同 API Base") {
		t.Fatalf("expected api-base replay detail, got %q", detail)
	}
}

func TestReviewUncapturedEncryptedEnvelopeRequiresRuntimeCapture(t *testing.T) {
	context, err := reviewUncapturedEncryptedResponse(unauthorizedProtocolContext{
		HasProtocolTrace: true, ResponseEncrypted: true, ResponseCiphertext: "ciphertext",
	})
	if err == nil {
		t.Fatal("expected encrypted envelope to stop unauthorized evaluation")
	}
	if context.DecryptionStatus != "needs_runtime_capture" || strings.Contains(context.DecryptionDetail, "静态") {
		t.Fatalf("unexpected runtime-capture context: %#v", context)
	}
}
