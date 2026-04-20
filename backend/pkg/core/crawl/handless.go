package crawl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

const (
	maxCapturedRequestBodySize  = 16 * 1024
	maxCapturedResponseBodySize = 128 * 1024
)

// NetworkRecord 表示浏览器运行时捕获到的接口请求/响应记录
type NetworkRecord struct {
	URL              string            `json:"url"`
	Method           string            `json:"method"`
	ResourceType     string            `json:"resource_type"`
	TraceID          string            `json:"trace_id,omitempty"`
	HasProtocolTrace bool              `json:"has_protocol_trace,omitempty"`
	RequestHeaders   map[string]string `json:"request_headers,omitempty"`
	RequestBody      string            `json:"request_body,omitempty"`
	ResponseHeaders  map[string]string `json:"response_headers,omitempty"`
	ResponseBody     string            `json:"response_body,omitempty"`
	ResponseCode     int               `json:"response_code"`
	MIMEType         string            `json:"mime_type,omitempty"`
	FetchedAt        time.Time         `json:"fetched_at"`
}

// 动态捕获网站访问时加载的所有链接
func CaptureNetworkURLs(url string) []string {
	networks, _, _ := CaptureNetworkActivity(url)
	return networks
}

// CaptureNetworkActivity 捕获页面加载过程中的网络链接和接口请求/响应记录
func CaptureNetworkActivity(url string) ([]string, []NetworkRecord, []ProtocolTraceRecord) {
	var networks []string
	var apiRecords []NetworkRecord
	var protocolTraces []ProtocolTraceRecord
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	// 延长超时到 120 秒，适应慢速网站
	ctx, cancel = context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	linkSet := make(map[string]bool)
	apiRecordSet := make(map[string]bool)
	protocolTraceIndex := make(map[string]int)
	requestMap := make(map[network.RequestID]*NetworkRecord)
	finalizedRequest := make(map[network.RequestID]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *runtime.EventBindingCalled:
			if ev.Name != protocolHookBindingName {
				return
			}

			var payload struct {
				Kind string `json:"kind"`
				ProtocolTraceRecord
			}
			if err := json.Unmarshal([]byte(ev.Payload), &payload); err != nil {
				return
			}
			if payload.Kind != "request-trace" && payload.Kind != "response-trace" && payload.Kind != "trace-update" {
				return
			}

			mu.Lock()
			upsertProtocolTraceRecord(protocolTraceIndex, &protocolTraces, payload.ProtocolTraceRecord)
			mu.Unlock()

		case *network.EventRequestWillBeSent:
			if !isHTTPURL(ev.Request.URL) {
				return
			}

			mu.Lock()
			requestMap[ev.RequestID] = &NetworkRecord{
				URL:            ev.Request.URL,
				Method:         ev.Request.Method,
				ResourceType:   string(ev.Type),
				RequestHeaders: stringifyHeaders(ev.Request.Headers),
				FetchedAt:      time.Now(),
			}
			mu.Unlock()

		case *network.EventResponseReceived:
			if !isHTTPURL(ev.Response.URL) {
				return
			}

			mu.Lock()
			if !linkSet[ev.Response.URL] {
				networks = append(networks, ev.Response.URL)
				linkSet[ev.Response.URL] = true
			}

			record, ok := requestMap[ev.RequestID]
			if !ok {
				record = &NetworkRecord{
					URL:       ev.Response.URL,
					FetchedAt: time.Now(),
				}
				requestMap[ev.RequestID] = record
			}
			record.URL = ev.Response.URL
			record.ResourceType = ev.Type.String()
			record.ResponseCode = int(ev.Response.Status)
			record.ResponseHeaders = stringifyHeaders(ev.Response.Headers)
			record.MIMEType = ev.Response.MimeType
			mu.Unlock()

		case *network.EventLoadingFinished:
			wg.Add(1)
			go func(requestID network.RequestID) {
				defer wg.Done()

				var (
					requestBody  string
					responseBody []byte
				)

				_ = chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
					postData, err := network.GetRequestPostData(requestID).Do(ctx)
					if err == nil {
						requestBody = postData
					}
					return nil
				}))

				responseErr := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
					var innerErr error
					responseBody, innerErr = network.GetResponseBody(requestID).Do(ctx)
					return innerErr
				}))

				mu.Lock()
				defer mu.Unlock()

				record, ok := requestMap[requestID]
				if !ok || finalizedRequest[requestID] {
					return
				}

				if requestBody != "" {
					record.RequestBody = limitCapturedBody(requestBody, maxCapturedRequestBodySize, "请求体过长，已截断")
				}
				if responseErr == nil {
					record.ResponseBody = normalizeCapturedResponseBody(record.MIMEType, responseBody)
				} else if isAPIResource(record) {
					logResponseBodyCaptureFailure(requestID, record, responseErr)
				}
				if responseErr == nil && isAPIResource(record) && strings.TrimSpace(record.ResponseBody) == "" {
					logEmptyAPIResponseBody(requestID, record, len(responseBody))
				}

				appendAPIRecord(apiRecordSet, &apiRecords, record)
				finalizedRequest[requestID] = true
			}(ev.RequestID)

		case *network.EventLoadingFailed:
			mu.Lock()
			defer mu.Unlock()

			record, ok := requestMap[ev.RequestID]
			if !ok || finalizedRequest[ev.RequestID] {
				return
			}

			appendAPIRecord(apiRecordSet, &apiRecords, record)
			finalizedRequest[ev.RequestID] = true
		}
	})

	err := chromedp.Run(ctx,
		runtime.Enable(),
		runtime.AddBinding(protocolHookBindingName),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(protocolHookScript).Do(ctx)
			return err
		}),
		network.Enable(),
		chromedp.Navigate(url),
		chromedp.Sleep(10*time.Second),
	)
	wg.Wait()
	backfillProtocolTraceResponsesFromAPIRecords(protocolTraces, apiRecords)
	linkAPIRecordsToProtocolTraces(apiRecords, protocolTraces)

	if err != nil {
		fmt.Printf("[ERROR] %s 动态捕获网络请求失败，已获取 %d 个URL、%d 条接口记录、%d 条协议轨迹, 错误原因: %v\n", url, len(networks), len(apiRecords), len(protocolTraces), err)
		return networks, apiRecords, protocolTraces
	}
	fmt.Printf("[INFO] %s 成功捕获 %d 个网络请求，提取 %d 条接口记录、%d 条协议轨迹\n", url, len(networks), len(apiRecords), len(protocolTraces))
	return networks, apiRecords, protocolTraces
}

func appendAPIRecord(apiRecordSet map[string]bool, apiRecords *[]NetworkRecord, record *NetworkRecord) {
	if record == nil || !isAPIResource(record) {
		return
	}

	key := record.Method + "|" + record.URL + "|" + record.RequestBody
	if apiRecordSet[key] {
		return
	}
	apiRecordSet[key] = true
	*apiRecords = append(*apiRecords, *record)
}

func upsertProtocolTraceRecord(traceIndex map[string]int, traces *[]ProtocolTraceRecord, record ProtocolTraceRecord) {
	record.normalize()
	traceKey := protocolTraceKey(record)
	if idx, ok := traceIndex[traceKey]; ok {
		mergeProtocolTraceRecord(&(*traces)[idx], record)
		return
	}

	traceIndex[traceKey] = len(*traces)
	*traces = append(*traces, record)
}

func protocolTraceKey(record ProtocolTraceRecord) string {
	if record.TraceID != "" {
		return record.TraceID
	}
	return record.Method + "|" + record.RequestURL + "|" + record.FinalRequestBody
}

func mergeProtocolTraceRecord(dst *ProtocolTraceRecord, src ProtocolTraceRecord) {
	if dst == nil {
		return
	}

	if dst.TaskID == "" {
		dst.TaskID = src.TaskID
	}
	if dst.TraceID == "" {
		dst.TraceID = src.TraceID
	}
	if dst.Transport == "" {
		dst.Transport = src.Transport
	}
	if dst.PageURL == "" {
		dst.PageURL = src.PageURL
	}
	if dst.RequestURL == "" {
		dst.RequestURL = src.RequestURL
	}
	if dst.Method == "" {
		dst.Method = src.Method
	}
	if dst.RequestBeforeTransform == "" {
		dst.RequestBeforeTransform = src.RequestBeforeTransform
	}
	if dst.FinalRequestBody == "" {
		dst.FinalRequestBody = src.FinalRequestBody
	}
	if dst.Stack == "" {
		dst.Stack = src.Stack
	}
	if src.CapturedAtMS > dst.CapturedAtMS {
		dst.CapturedAtMS = src.CapturedAtMS
	}
	if dst.CreatedAt.IsZero() || (!src.CreatedAt.IsZero() && src.CreatedAt.After(dst.CreatedAt)) {
		dst.CreatedAt = src.CreatedAt
	}

	dst.RequestHeaders = mergeStringMaps(dst.RequestHeaders, src.RequestHeaders)
	dst.DynamicParams = mergeStringMaps(dst.DynamicParams, src.DynamicParams)
	dst.SessionMaterials = mergeStringMaps(dst.SessionMaterials, src.SessionMaterials)
	dst.SignatureFields = mergeUniqueStrings(dst.SignatureFields, src.SignatureFields)
	dst.RequestSteps = mergeCryptoSteps(dst.RequestSteps, src.RequestSteps)
	dst.ResponseSteps = mergeCryptoSteps(dst.ResponseSteps, src.ResponseSteps)
	dst.normalize()
}

func mergeStringMaps(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]string, len(src))
	}
	for key, value := range src {
		if value == "" {
			continue
		}
		dst[key] = value
	}
	return dst
}

func mergeUniqueStrings(dst, src []string) []string {
	if len(src) == 0 {
		return dst
	}
	seen := make(map[string]bool, len(dst))
	for _, item := range dst {
		seen[item] = true
	}
	for _, item := range src {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		dst = append(dst, item)
	}
	return dst
}

func mergeCryptoSteps(dst, src []ProtocolCryptoStep) []ProtocolCryptoStep {
	if len(src) == 0 {
		return dst
	}
	seen := make(map[string]bool, len(dst))
	for _, step := range dst {
		seen[protocolCryptoStepKey(step)] = true
	}
	for _, step := range src {
		key := protocolCryptoStepKey(step)
		if seen[key] {
			continue
		}
		seen[key] = true
		dst = append(dst, step)
	}
	return dst
}

func protocolCryptoStepKey(step ProtocolCryptoStep) string {
	return step.Source + "|" + step.Algorithm + "|" + step.InputPreview + "|" + step.OutputPreview + "|" + step.CallID + "|" + step.ParentCallID + "|" + step.FunctionPath + "|" + step.ModuleID + "|" + step.Stack
}

func backfillProtocolTraceResponsesFromAPIRecords(traces []ProtocolTraceRecord, apiRecords []NetworkRecord) {
	if len(traces) == 0 || len(apiRecords) == 0 {
		return
	}

	traceIndicesByKey := make(map[string][]int)
	traceCursorByKey := make(map[string]int)
	for idx := range traces {
		key := protocolTraceResponseKey(traces[idx].Method, traces[idx].RequestURL)
		traceIndicesByKey[key] = append(traceIndicesByKey[key], idx)
	}

	for _, record := range apiRecords {
		if strings.TrimSpace(record.ResponseBody) == "" {
			continue
		}

		key := protocolTraceResponseKey(record.Method, record.URL)
		indices := traceIndicesByKey[key]
		if len(indices) == 0 {
			logUnmatchedAPIResponseForTrace(record)
			continue
		}

		cursor := traceCursorByKey[key]
		matched := false
		for ; cursor < len(indices); cursor++ {
			trace := &traces[indices[cursor]]
			if trace.SessionMaterials == nil {
				trace.SessionMaterials = make(map[string]string)
			}

			if isLikelyPlaintextResponse(record) {
				if trace.SessionMaterials["latest_response_plaintext"] == "" {
					trace.SessionMaterials["latest_response_plaintext"] = record.ResponseBody
				}
			} else {
				if trace.SessionMaterials["latest_response_ciphertext"] == "" {
					trace.SessionMaterials["latest_response_ciphertext"] = record.ResponseBody
				}
			}
			trace.normalize()
			traceCursorByKey[key] = cursor + 1
			matched = true
			break
		}
		if !matched {
			logTraceResponseBackfillExhausted(record, len(indices))
		}
	}
}

func protocolTraceResponseKey(method, requestURL string) string {
	return normalizeProtocolMethod(method) + "|" + strings.TrimSpace(requestURL)
}

func linkAPIRecordsToProtocolTraces(apiRecords []NetworkRecord, traces []ProtocolTraceRecord) {
	if len(apiRecords) == 0 || len(traces) == 0 {
		return
	}

	traceIndexByRequest := make(map[string][]int)
	traceCursorByRequest := make(map[string]int)
	for idx := range traces {
		key := protocolTraceRequestKey(traces[idx].Method, traces[idx].RequestURL, traces[idx].FinalRequestBody)
		traceIndexByRequest[key] = append(traceIndexByRequest[key], idx)
	}

	for idx := range apiRecords {
		key := protocolTraceRequestKey(apiRecords[idx].Method, apiRecords[idx].URL, apiRecords[idx].RequestBody)
		indices := traceIndexByRequest[key]
		if len(indices) == 0 {
			apiRecords[idx].HasProtocolTrace = false
			logAPIRecordTraceLinkMiss(apiRecords[idx], "no-request-match")
			continue
		}

		cursor := traceCursorByRequest[key]
		if cursor >= len(indices) {
			cursor = len(indices) - 1
		}
		if cursor < 0 {
			apiRecords[idx].HasProtocolTrace = false
			logAPIRecordTraceLinkMiss(apiRecords[idx], "invalid-cursor")
			continue
		}

		trace := traces[indices[cursor]]
		if strings.TrimSpace(trace.TraceID) == "" {
			apiRecords[idx].HasProtocolTrace = false
			logAPIRecordTraceLinkMiss(apiRecords[idx], "empty-trace-id")
			continue
		}

		apiRecords[idx].TraceID = trace.TraceID
		apiRecords[idx].HasProtocolTrace = true
		traceCursorByRequest[key] = cursor + 1
	}
}

func protocolTraceRequestKey(method, requestURL, requestBody string) string {
	return normalizeProtocolMethod(method) + "|" + strings.TrimSpace(requestURL) + "|" + strings.TrimSpace(requestBody)
}

func isLikelyPlaintextResponse(record NetworkRecord) bool {
	body := strings.TrimSpace(record.ResponseBody)
	if isLikelyEncodedPayloadResponse(body) {
		return false
	}

	mimeType := strings.ToLower(strings.TrimSpace(record.MIMEType))
	if strings.Contains(mimeType, "json") || strings.Contains(mimeType, "text") || strings.Contains(mimeType, "javascript") || strings.Contains(mimeType, "xml") {
		return true
	}

	return strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[")
}

func isLikelyEncodedPayloadResponse(body string) bool {
	trimmed := strings.TrimSpace(body)
	if len(trimmed) >= 2 && strings.HasPrefix(trimmed, `"`) && strings.HasSuffix(trimmed, `"`) {
		trimmed = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	}
	if len(trimmed) < 48 {
		return false
	}
	if !strings.ContainsAny(trimmed, "{[") {
		if isHexString(trimmed) && len(trimmed)%2 == 0 {
			return true
		}
		if isBase64Like(trimmed) {
			return true
		}
	}
	return false
}

func logResponseBodyCaptureFailure(requestID network.RequestID, record *NetworkRecord, err error) {
	if record == nil || err == nil {
		return
	}
	fmt.Printf(
		"[WARN] chromedp 响应体抓取失败 request_id=%s method=%s url=%s status=%d type=%s mime=%s err=%v\n",
		requestID,
		strings.TrimSpace(record.Method),
		strings.TrimSpace(record.URL),
		record.ResponseCode,
		strings.TrimSpace(record.ResourceType),
		strings.TrimSpace(record.MIMEType),
		err,
	)
}

func logEmptyAPIResponseBody(requestID network.RequestID, record *NetworkRecord, rawBodySize int) {
	if record == nil {
		return
	}
	fmt.Printf(
		"[WARN] API 响应完成但 body 为空 request_id=%s method=%s url=%s status=%d type=%s mime=%s raw_body_size=%d\n",
		requestID,
		strings.TrimSpace(record.Method),
		strings.TrimSpace(record.URL),
		record.ResponseCode,
		strings.TrimSpace(record.ResourceType),
		strings.TrimSpace(record.MIMEType),
		rawBodySize,
	)
}

func logUnmatchedAPIResponseForTrace(record NetworkRecord) {
	fmt.Printf(
		"[WARN] API 响应未找到可回填的协议轨迹 method=%s url=%s status=%d mime=%s response_len=%d\n",
		strings.TrimSpace(record.Method),
		strings.TrimSpace(record.URL),
		record.ResponseCode,
		strings.TrimSpace(record.MIMEType),
		len(record.ResponseBody),
	)
}

func logTraceResponseBackfillExhausted(record NetworkRecord, candidateCount int) {
	fmt.Printf(
		"[WARN] API 响应存在候选协议轨迹但未完成回填 method=%s url=%s candidates=%d status=%d response_len=%d\n",
		strings.TrimSpace(record.Method),
		strings.TrimSpace(record.URL),
		candidateCount,
		record.ResponseCode,
		len(record.ResponseBody),
	)
}

func logAPIRecordTraceLinkMiss(record NetworkRecord, reason string) {
	fmt.Printf(
		"[WARN] API 记录未关联到协议轨迹 reason=%s method=%s url=%s request_len=%d response_len=%d\n",
		reason,
		strings.TrimSpace(record.Method),
		strings.TrimSpace(record.URL),
		len(record.RequestBody),
		len(record.ResponseBody),
	)
}

func isHexString(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
			return false
		}
	}
	return true
}

func isBase64Like(value string) bool {
	if value == "" || len(value)%4 != 0 {
		return false
	}
	for _, ch := range value {
		if (ch < 'A' || ch > 'Z') &&
			(ch < 'a' || ch > 'z') &&
			(ch < '0' || ch > '9') &&
			ch != '+' && ch != '/' && ch != '=' {
			return false
		}
	}
	return true
}

func normalizeCapturedResponseBody(mimeType string, responseBody []byte) string {
	if len(responseBody) == 0 {
		return ""
	}
	if shouldStoreCapturedBodyAsText(mimeType, responseBody) {
		return limitCapturedBody(string(responseBody), maxCapturedResponseBodySize, "响应体过长，已截断")
	}
	return limitCapturedBody(base64.StdEncoding.EncodeToString(responseBody), maxCapturedResponseBodySize, "响应体过长，已截断")
}

func shouldStoreCapturedBodyAsText(mimeType string, responseBody []byte) bool {
	if len(responseBody) == 0 || !utf8.Valid(responseBody) {
		return false
	}

	body := strings.TrimSpace(string(responseBody))
	if strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[") {
		return true
	}

	mimeType = strings.ToLower(strings.TrimSpace(mimeType))
	if strings.Contains(mimeType, "json") || strings.Contains(mimeType, "javascript") || strings.Contains(mimeType, "xml") || strings.Contains(mimeType, "html") {
		return true
	}

	printable := 0
	for _, r := range body {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r < 127) {
			printable++
		}
	}
	return printable >= len(body)*9/10
}

func isHTTPURL(rawURL string) bool {
	return strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://")
}

func isAPIResource(record *NetworkRecord) bool {
	if record == nil {
		return false
	}

	switch strings.ToLower(record.ResourceType) {
	case "xhr", "fetch":
		return true
	default:
		return false
	}
}

func stringifyHeaders(headers network.Headers) map[string]string {
	if len(headers) == 0 {
		return nil
	}

	result := make(map[string]string, len(headers))
	for key, value := range headers {
		result[key] = fmt.Sprint(value)
	}
	return result
}

func limitCapturedBody(body string, maxSize int, message string) string {
	if body == "" || len(body) <= maxSize {
		return body
	}
	return body[:maxSize] + "\n...[内容过长，" + message + "]"
}
