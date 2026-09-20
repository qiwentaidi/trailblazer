package protocoltool

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"strings"
	"time"
)

const (
	HeaderAccessToken = "x-access-token"
	HeaderChannelCode = "channel-code"
	HeaderNonce       = "gv59JPPEesNW"
	HeaderTimestamp   = "KQN29pKXsTKN"
	HeaderSignature   = "BpzHepzRVcJy"
	HeaderKeyExchange = "6zzbinypyphq"
)

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
