package protocoltool

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"trailblazer/pkg/core/database"
)

const (
	HeaderAccessToken = "x-access-token"
	HeaderChannelCode = "channel-code"
	HeaderNonce       = "gv59JPPEesNW"
	HeaderTimestamp   = "KQN29pKXsTKN"
	HeaderSignature   = "BpzHepzRVcJy"
	HeaderKeyExchange = "6zzbinypyphq"
)

type DecryptResult struct {
	KeyHex       string `json:"key_hex"`
	Ciphertext   string `json:"ciphertext"`
	Plaintext    string `json:"plaintext"`
	Mode         string `json:"mode,omitempty"`
	Source       string `json:"source,omitempty"`
	Detail       string `json:"detail,omitempty"`
	FunctionHint string `json:"function_hint,omitempty"`
}

type EncryptResult struct {
	KeyHex      string            `json:"key_hex"`
	Plaintext   string            `json:"plaintext"`
	Ciphertext  string            `json:"ciphertext"`
	Headers     map[string]string `json:"headers"`
	RequestURL  string            `json:"request_url,omitempty"`
	Method      string            `json:"method,omitempty"`
	TraceID     string            `json:"trace_id,omitempty"`
	Signature   string            `json:"signature"`
	Nonce       string            `json:"nonce"`
	Timestamp   string            `json:"timestamp"`
	CurlPreview string            `json:"curl_preview,omitempty"`
}

var (
	decryptStoredBrowserRuntime  = DecryptWithStoredFrontendBrowserRuntime
	decryptStoredFrontendRuntime = DecryptWithStoredFrontendRuntime
)

func DecryptWithTrace(trace *database.ProtocolTraceRecord, keyHex, ciphertext string) (*DecryptResult, error) {
	resolvedCiphertext := normalizeCiphertext(ciphertext)
	if resolvedCiphertext == "" && trace != nil {
		resolvedCiphertext = normalizeCiphertext(trace.FinalRequestBody)
	}
	if resolvedCiphertext == "" {
		return nil, fmt.Errorf("缺少待解密密文")
	}

	if result := decryptFromCapturedPlaintext(trace, resolvedCiphertext); result != nil {
		return result, nil
	}

	resolvedKey := resolveSymmetricKeyHex(trace, keyHex)
	resolvedIV := resolveIVHex(trace)
	resolvedAESKey := resolveAESKeyMaterial(trace, keyHex)
	resolvedAESIV := resolveAESIVMaterial(trace)
	resolvedAESAAD := resolveAESAADMaterial(trace)
	detectedAlgorithms := collectDecryptAlgorithms(trace)

	if runtimeResult := decryptWithStoredRuntime(trace, resolvedCiphertext, resolvedKey); runtimeResult != nil {
		return runtimeResult, nil
	}

	if shouldTryAESCBCDecrypt(detectedAlgorithms, resolvedKey, resolvedIV) {
		if strings.TrimSpace(resolvedKey) == "" || strings.TrimSpace(resolvedIV) == "" {
			return nil, fmt.Errorf("检测到 AES-CBC 解密链路，但缺少可用 key/iv 材料")
		}

		plaintext, err := DecryptAESCBCHex(resolvedCiphertext, resolvedKey, resolvedIV)
		if err == nil {
			return &DecryptResult{
				KeyHex:     resolvedKey,
				Ciphertext: resolvedCiphertext,
				Plaintext:  strings.TrimRight(plaintext, "\x00"),
				Mode:       "offline",
				Source:     "aes-cbc",
			}, nil
		}
		return nil, err
	}

	if shouldTryAESGCMDecrypt(detectedAlgorithms, resolvedAESKey, resolvedAESIV) {
		if strings.TrimSpace(resolvedAESKey) == "" || strings.TrimSpace(resolvedAESIV) == "" {
			return nil, fmt.Errorf("检测到 AES-GCM 解密链路，但缺少可用 key/iv 材料")
		}

		plaintext, err := DecryptAESGCM(resolvedCiphertext, resolvedAESKey, resolvedAESIV, resolvedAESAAD)
		if err == nil {
			return &DecryptResult{
				KeyHex:     resolvedAESKey,
				Ciphertext: resolvedCiphertext,
				Plaintext:  strings.TrimRight(plaintext, "\x00"),
				Mode:       "offline",
				Source:     "aes-gcm",
			}, nil
		}
		if message, ok := unresolvedResponseDecryptMessage(trace, detectedAlgorithms); ok {
			return nil, fmt.Errorf("%s", message)
		}
		return nil, err
	}

	if hasDetectedAlgorithm(detectedAlgorithms, "aes-gcm") {
		if message, ok := unresolvedResponseDecryptMessage(trace, detectedAlgorithms); ok {
			return nil, fmt.Errorf("%s", message)
		}
		return nil, fmt.Errorf("检测到 AES-GCM 解密链路，但缺少可用 key/iv 材料")
	}

	if shouldTrySM4Decrypt(detectedAlgorithms, resolvedKey) {
		if strings.TrimSpace(resolvedKey) == "" {
			return nil, fmt.Errorf("检测到 SM4 解密链路，但缺少可用密钥材料")
		}

		plaintext, err := DecryptSM4Hex(resolvedCiphertext, resolvedKey)
		if err == nil {
			return &DecryptResult{
				KeyHex:     resolvedKey,
				Ciphertext: resolvedCiphertext,
				Plaintext:  strings.TrimRight(plaintext, "\x00"),
				Mode:       "offline",
				Source:     "sm4",
			}, nil
		}

		return nil, err
	}

	if message, ok := unresolvedResponseDecryptMessage(trace, detectedAlgorithms); ok {
		return nil, fmt.Errorf("%s", message)
	}

	if len(detectedAlgorithms) > 0 {
		return nil, fmt.Errorf("当前未支持该响应的解密算法: %s", strings.Join(detectedAlgorithms, ", "))
	}
	if strings.TrimSpace(resolvedKey) == "" {
		return nil, fmt.Errorf("缺少可用解密材料，且未识别出受支持的解密算法")
	}

	return nil, fmt.Errorf("未找到可用的解密器")
}

func RuntimeDecryptWithTrace(trace *database.ProtocolTraceRecord, ciphertext string) (*DecryptResult, error) {
	if trace == nil {
		return nil, fmt.Errorf("缺少协议轨迹，无法执行在线 runtime 解密")
	}
	if strings.TrimSpace(trace.TaskID) == "" {
		return nil, fmt.Errorf("协议轨迹缺少任务信息，无法执行在线 runtime 解密")
	}

	resolvedCiphertext := normalizeCiphertext(ciphertext)
	if resolvedCiphertext == "" {
		resolvedCiphertext = normalizeCiphertext(trace.SessionMaterials["latest_response_ciphertext"])
	}
	if resolvedCiphertext == "" {
		return nil, fmt.Errorf("缺少待解密密文")
	}

	return runtimeDecryptWithStoredRuntime(trace, resolvedCiphertext, resolveSymmetricKeyHex(trace, ""))
}

func decryptFromCapturedPlaintext(trace *database.ProtocolTraceRecord, resolvedCiphertext string) *DecryptResult {
	if trace == nil {
		return nil
	}

	if responseCiphertext := normalizeCiphertext(trace.SessionMaterials["latest_response_ciphertext"]); responseCiphertext != "" &&
		responseCiphertext == resolvedCiphertext &&
		strings.TrimSpace(trace.SessionMaterials["latest_response_plaintext"]) != "" {
		return &DecryptResult{
			KeyHex:     resolveSymmetricKeyHex(trace, ""),
			Ciphertext: resolvedCiphertext,
			Plaintext:  strings.TrimRight(strings.TrimSpace(trace.SessionMaterials["latest_response_plaintext"]), "\x00"),
			Mode:       "offline",
			Source:     "captured-response-plaintext",
		}
	}

	if requestCiphertext := normalizeCiphertext(trace.FinalRequestBody); requestCiphertext != "" &&
		requestCiphertext == resolvedCiphertext &&
		strings.TrimSpace(trace.RequestBeforeTransform) != "" {
		return &DecryptResult{
			KeyHex:     resolveSymmetricKeyHex(trace, ""),
			Ciphertext: resolvedCiphertext,
			Plaintext:  strings.TrimRight(strings.TrimSpace(trace.RequestBeforeTransform), "\x00"),
			Mode:       "offline",
			Source:     "captured-request-plaintext",
		}
	}

	return nil
}

func decryptWithStoredRuntime(trace *database.ProtocolTraceRecord, resolvedCiphertext, resolvedKey string) *DecryptResult {
	result, err := runtimeDecryptWithStoredRuntime(trace, resolvedCiphertext, resolvedKey)
	if err != nil {
		return nil
	}
	return result
}

func runtimeDecryptWithStoredRuntime(trace *database.ProtocolTraceRecord, resolvedCiphertext, resolvedKey string) (*DecryptResult, error) {
	if trace == nil || strings.TrimSpace(trace.TaskID) == "" {
		return nil, fmt.Errorf("缺少可复用的任务级浏览器上下文")
	}

	functionPath, moduleID := resolveResponseRuntimeFunction(trace)
	functionHint := firstNonEmpty(functionPath, defaultRuntimeFunctionHint(moduleID))

	browserPlaintext, browserErr := decryptStoredBrowserRuntime(trace.TaskID, trace.PageURL, trace.RequestURL, resolvedCiphertext, functionPath, moduleID)
	if browserErr == nil {
		return &DecryptResult{
			KeyHex:       resolvedKey,
			Ciphertext:   resolvedCiphertext,
			Plaintext:    strings.TrimRight(browserPlaintext, "\x00"),
			Mode:         "runtime",
			Source:       "browser-context",
			FunctionHint: functionHint,
			Detail:       "通过浏览器上下文在线执行页面解密逻辑完成还原",
		}, nil
	}
	frontendPlaintext, runtimeErr := decryptStoredFrontendRuntime(trace.TaskID, resolvedCiphertext, functionPath, moduleID)
	if runtimeErr == nil {
		return &DecryptResult{
			KeyHex:       resolvedKey,
			Ciphertext:   resolvedCiphertext,
			Plaintext:    strings.TrimRight(frontendPlaintext, "\x00"),
			Mode:         "runtime",
			Source:       "stored-frontend-runtime",
			FunctionHint: functionHint,
			Detail:       "通过存储的前端模块运行时离线重建解密逻辑完成还原",
		}, nil
	}

	return nil, fmt.Errorf("在线 runtime 解密失败: browser=%v; frontend=%v", browserErr, runtimeErr)
}

func resolveResponseRuntimeFunction(trace *database.ProtocolTraceRecord) (string, string) {
	if trace == nil {
		return "", ""
	}
	return strings.TrimSpace(trace.SessionMaterials["response_runtime_function_path"]),
		strings.TrimSpace(trace.SessionMaterials["response_runtime_module_id"])
}

func defaultRuntimeFunctionHint(moduleID string) string {
	if strings.TrimSpace(moduleID) != "" {
		return fmt.Sprintf("module[%s].sd", strings.TrimSpace(moduleID))
	}
	return "module.sd"
}

func resolveSymmetricKeyHex(trace *database.ProtocolTraceRecord, keyHex string) string {
	if strings.TrimSpace(keyHex) != "" {
		return strings.TrimSpace(keyHex)
	}
	if trace == nil {
		return ""
	}
	return firstNonEmpty(
		trace.SessionMaterials["crypto_key_hex"],
		trace.SessionMaterials["aes_key_hex"],
		trace.SessionMaterials["sm4_key_hex"],
		trace.DynamicParams["crypto_key_hex"],
		trace.DynamicParams["aes_key_hex"],
		trace.DynamicParams["sm4_key_hex"],
	)
}

func resolveIVHex(trace *database.ProtocolTraceRecord) string {
	if trace == nil {
		return ""
	}
	return firstNonEmpty(
		trace.SessionMaterials["crypto_iv_hex"],
		trace.SessionMaterials["aes_iv_hex"],
		trace.DynamicParams["crypto_iv_hex"],
		trace.DynamicParams["aes_iv_hex"],
	)
}

func resolveAESKeyMaterial(trace *database.ProtocolTraceRecord, key string) string {
	if strings.TrimSpace(key) != "" {
		return strings.TrimSpace(key)
	}
	if trace == nil {
		return ""
	}
	return firstNonEmpty(
		trace.SessionMaterials["crypto_key_raw"],
		trace.SessionMaterials["aes_key_raw"],
		trace.SessionMaterials["crypto_key_base64"],
		trace.SessionMaterials["aes_key_base64"],
		trace.SessionMaterials["crypto_key_hex"],
		trace.SessionMaterials["aes_key_hex"],
		trace.DynamicParams["crypto_key_raw"],
		trace.DynamicParams["aes_key_raw"],
		trace.DynamicParams["crypto_key_base64"],
		trace.DynamicParams["aes_key_base64"],
		trace.DynamicParams["crypto_key_hex"],
		trace.DynamicParams["aes_key_hex"],
	)
}

func resolveAESIVMaterial(trace *database.ProtocolTraceRecord) string {
	if trace == nil {
		return ""
	}
	return firstNonEmpty(
		trace.SessionMaterials["crypto_iv_base64"],
		trace.SessionMaterials["aes_iv_base64"],
		trace.SessionMaterials["crypto_iv_hex"],
		trace.SessionMaterials["aes_iv_hex"],
		trace.SessionMaterials["crypto_iv_raw"],
		trace.SessionMaterials["aes_iv_raw"],
		trace.DynamicParams["crypto_iv_base64"],
		trace.DynamicParams["aes_iv_base64"],
		trace.DynamicParams["crypto_iv_hex"],
		trace.DynamicParams["aes_iv_hex"],
		trace.DynamicParams["crypto_iv_raw"],
		trace.DynamicParams["aes_iv_raw"],
	)
}

func resolveAESAADMaterial(trace *database.ProtocolTraceRecord) string {
	if trace == nil {
		return ""
	}
	return firstNonEmpty(
		trace.SessionMaterials["crypto_aad_base64"],
		trace.SessionMaterials["aes_aad_base64"],
		trace.SessionMaterials["crypto_aad_hex"],
		trace.SessionMaterials["aes_aad_hex"],
		trace.SessionMaterials["crypto_aad_raw"],
		trace.SessionMaterials["aes_aad_raw"],
		trace.DynamicParams["crypto_aad_base64"],
		trace.DynamicParams["aes_aad_base64"],
		trace.DynamicParams["crypto_aad_hex"],
		trace.DynamicParams["aes_aad_hex"],
		trace.DynamicParams["crypto_aad_raw"],
		trace.DynamicParams["aes_aad_raw"],
	)
}

func collectDecryptAlgorithms(trace *database.ProtocolTraceRecord) []string {
	if trace == nil {
		return nil
	}

	seen := make(map[string]bool)
	algorithms := make([]string, 0, len(trace.Algorithms)+len(trace.RequestSteps)+len(trace.ResponseSteps))
	push := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || isNonDecryptAlgorithm(value) || seen[value] {
			return
		}
		seen[value] = true
		algorithms = append(algorithms, value)
	}

	for _, value := range trace.Algorithms {
		push(value)
	}
	for _, steps := range [][]database.ProtocolCryptoStep{trace.RequestSteps, trace.ResponseSteps} {
		for _, step := range steps {
			push(step.Algorithm)
		}
	}

	return algorithms
}

func shouldTrySM4Decrypt(algorithms []string, resolvedKey string) bool {
	if strings.TrimSpace(resolvedKey) != "" && len(algorithms) == 0 {
		return true
	}
	for _, algorithm := range algorithms {
		if strings.Contains(algorithm, "sm4") {
			return true
		}
	}
	return false
}

func shouldTryAESCBCDecrypt(algorithms []string, resolvedKey, resolvedIV string) bool {
	if strings.TrimSpace(resolvedKey) != "" && strings.TrimSpace(resolvedIV) != "" && len(algorithms) == 0 {
		return false
	}
	for _, algorithm := range algorithms {
		if strings.Contains(algorithm, "aes-cbc") {
			return true
		}
	}
	return false
}

func shouldTryAESGCMDecrypt(algorithms []string, resolvedKey, resolvedIV string) bool {
	if strings.TrimSpace(resolvedKey) == "" || strings.TrimSpace(resolvedIV) == "" {
		return false
	}
	if len(algorithms) == 0 {
		return true
	}
	for _, algorithm := range algorithms {
		if strings.Contains(algorithm, "aes-gcm") {
			return true
		}
	}
	return false
}

func hasDetectedAlgorithm(algorithms []string, needle string) bool {
	for _, algorithm := range algorithms {
		if strings.Contains(algorithm, needle) {
			return true
		}
	}
	return false
}

func isNonDecryptAlgorithm(value string) bool {
	switch value {
	case "json.stringify", "text.encode", "window.atob", "window.btoa", "hex", "base64":
		return true
	default:
		return false
	}
}

func unresolvedResponseDecryptMessage(trace *database.ProtocolTraceRecord, detectedAlgorithms []string) (string, bool) {
	if trace == nil {
		return "", false
	}

	responseCiphertext := strings.TrimSpace(trace.SessionMaterials["latest_response_ciphertext"])
	if responseCiphertext == "" || strings.TrimSpace(trace.SessionMaterials["latest_response_plaintext"]) != "" {
		return "", false
	}

	if !hasResponseProcessingSignal(trace, detectedAlgorithms) {
		return "", false
	}

	observed := ""
	if len(detectedAlgorithms) > 0 {
		observed = fmt.Sprintf("（观测到: %s）", strings.Join(detectedAlgorithms, ", "))
	}
	if hasExecutableResponseDecryptStep(trace) {
		return "已捕获响应处理步骤，但尚未得到可验证的明文结果" + observed, true
	}
	return "已识别响应处理链路，但未捕获可执行的响应解密步骤或明文结果" + observed, true
}

func hasResponseProcessingSignal(trace *database.ProtocolTraceRecord, detectedAlgorithms []string) bool {
	for _, algorithm := range detectedAlgorithms {
		if strings.Contains(algorithm, "aes") || strings.Contains(algorithm, "sm4") || strings.Contains(algorithm, "decode") || strings.Contains(algorithm, "decrypt") || strings.Contains(algorithm, "base64") {
			return true
		}
	}
	if trace == nil {
		return false
	}
	for _, step := range trace.ResponseSteps {
		source := strings.ToLower(strings.TrimSpace(step.Source))
		algorithm := strings.ToLower(strings.TrimSpace(step.Algorithm))
		if strings.Contains(source, "decode") || strings.Contains(source, "decrypt") || strings.Contains(source, "atob") || strings.Contains(algorithm, "decode") || strings.Contains(algorithm, "decrypt") {
			return true
		}
	}
	return false
}

func hasExecutableResponseDecryptStep(trace *database.ProtocolTraceRecord) bool {
	if trace == nil {
		return false
	}
	for _, step := range trace.ResponseSteps {
		source := strings.ToLower(strings.TrimSpace(step.Source))
		algorithm := strings.ToLower(strings.TrimSpace(step.Algorithm))
		if source == "sd" || strings.HasSuffix(source, ".sd") {
			return true
		}
		if strings.Contains(source, "decrypt") && !strings.Contains(source, "textdecoder.decode") {
			return true
		}
		if strings.Contains(algorithm, "sm4") || strings.Contains(algorithm, "aes-cbc") {
			return true
		}
	}
	return false
}

func EncryptWithTrace(trace *database.ProtocolTraceRecord, keyHex, plaintext, token, channelCode, keyExchangeHeader, nonce, timestamp string) (*EncryptResult, error) {
	if strings.TrimSpace(plaintext) == "" {
		return nil, fmt.Errorf("缺少明文内容")
	}

	resolvedKey := strings.TrimSpace(keyHex)
	if resolvedKey == "" && trace != nil {
		resolvedKey = trace.SessionMaterials["sm4_key_hex"]
	}
	if resolvedKey == "" {
		return nil, fmt.Errorf("缺少 sm4_key_hex，无法顺向加密")
	}

	resolvedToken := strings.TrimSpace(token)
	resolvedChannel := strings.TrimSpace(channelCode)
	resolvedExchange := strings.TrimSpace(keyExchangeHeader)
	if trace != nil {
		resolvedToken = firstNonEmpty(resolvedToken, trace.RequestHeaders["x-access-token"], trace.SessionMaterials["x_access_token"])
		resolvedChannel = firstNonEmpty(resolvedChannel, trace.RequestHeaders["channel-code"], trace.SessionMaterials["channel_code"])
		resolvedExchange = firstNonEmpty(resolvedExchange, trace.RequestHeaders[strings.ToLower(HeaderKeyExchange)], trace.SessionMaterials["key_exchange_header"], trace.RequestHeaders[HeaderKeyExchange])
	}
	if resolvedExchange == "" {
		return nil, fmt.Errorf("缺少 6zzbinypyphq 头值，无法复用当前协议会话材料")
	}

	resolvedNonce := strings.TrimSpace(nonce)
	if resolvedNonce == "" {
		resolvedNonce = randomString(8)
	}
	resolvedTimestamp := strings.TrimSpace(timestamp)
	if resolvedTimestamp == "" {
		resolvedTimestamp = fmt.Sprintf("%d", time.Now().UnixMilli())
	}

	ciphertext, err := EncryptSM4Hex(plaintext, resolvedKey)
	if err != nil {
		return nil, err
	}
	signature := md5Hex(md5Hex(resolvedTimestamp+ciphertext) + resolvedNonce)

	headers := map[string]string{
		HeaderNonce:       resolvedNonce,
		HeaderTimestamp:   resolvedTimestamp,
		HeaderSignature:   signature,
		HeaderKeyExchange: resolvedExchange,
	}
	if resolvedToken != "" {
		headers[HeaderAccessToken] = resolvedToken
	}
	if resolvedChannel != "" {
		headers[HeaderChannelCode] = resolvedChannel
	}

	result := &EncryptResult{
		KeyHex:     resolvedKey,
		Plaintext:  plaintext,
		Ciphertext: ciphertext,
		Headers:    headers,
		Signature:  signature,
		Nonce:      resolvedNonce,
		Timestamp:  resolvedTimestamp,
	}
	if trace != nil {
		result.TraceID = trace.TraceID
		result.RequestURL = trace.RequestURL
		result.Method = trace.Method
		result.CurlPreview = buildCurlPreview(trace.RequestURL, trace.Method, headers, ciphertext)
	}
	return result, nil
}

func md5Hex(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

func randomString(length int) string {
	const chars = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
	const fallback = "ABCDEFGH"
	if length <= 0 {
		return ""
	}
	if length > 128 {
		length = 128
	}
	result := make([]byte, length)
	seed := time.Now().UnixNano()
	for i := 0; i < length; i++ {
		idx := int((seed + int64(i*37)) % int64(len(chars)))
		if idx < 0 || idx >= len(chars) {
			result[i] = fallback[i%len(fallback)]
			continue
		}
		result[i] = chars[idx]
		seed = seed/3 + int64(idx*17) + int64(i+1)
	}
	return string(result)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func buildCurlPreview(requestURL, method string, headers map[string]string, body string) string {
	if strings.TrimSpace(requestURL) == "" {
		return ""
	}
	lines := []string{"curl '" + requestURL + "'"}
	if strings.TrimSpace(method) != "" {
		lines = append(lines, "  -X '"+strings.ToUpper(method)+"'")
	}
	for _, name := range []string{HeaderAccessToken, HeaderChannelCode, HeaderNonce, HeaderTimestamp, HeaderSignature, HeaderKeyExchange} {
		if value := headers[name]; value != "" {
			lines = append(lines, "  -H '"+name+": "+value+"'")
		}
	}
	lines = append(lines, "  --data-raw '"+body+"'")
	return strings.Join(lines, " \\\n")
}

func normalizeCiphertext(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	var asJSONString string
	if err := json.Unmarshal([]byte(trimmed), &asJSONString); err == nil {
		trimmed = strings.TrimSpace(asJSONString)
	}

	trimmed = strings.Trim(trimmed, "\"'")
	return strings.TrimSpace(trimmed)
}
