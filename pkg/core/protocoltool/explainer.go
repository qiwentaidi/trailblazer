package protocoltool

import (
	"encoding/json"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"strings"
)

type ProtocolExplainResult struct {
	TraceID     string `json:"trace_id"`
	Explanation string `json:"explanation"`
	Model       string `json:"model,omitempty"`
}

type protocolExplainPayload struct {
	TraceID            string                        `json:"trace_id"`
	Method             string                        `json:"method,omitempty"`
	RequestURL         string                        `json:"request_url,omitempty"`
	PageURL            string                        `json:"page_url,omitempty"`
	Algorithms         []string                      `json:"algorithms,omitempty"`
	RequestPlaintext   string                        `json:"request_before_transform,omitempty"`
	RequestCiphertext  string                        `json:"final_request_body,omitempty"`
	ResponseCiphertext string                        `json:"latest_response_ciphertext,omitempty"`
	ResponsePlaintext  string                        `json:"latest_response_plaintext,omitempty"`
	RequestHeaders     map[string]string             `json:"request_headers,omitempty"`
	SessionMaterials   map[string]string             `json:"session_materials,omitempty"`
	RequestSteps       []database.ProtocolCryptoStep `json:"request_steps,omitempty"`
	ResponseSteps      []database.ProtocolCryptoStep `json:"response_steps,omitempty"`
}

func BuildProtocolTraceExplanationInput(trace *database.ProtocolTraceRecord) (string, error) {
	if trace == nil {
		return "", nil
	}

	payload := protocolExplainPayload{
		TraceID:            strings.TrimSpace(trace.TraceID),
		Method:             strings.TrimSpace(trace.Method),
		RequestURL:         strings.TrimSpace(trace.RequestURL),
		PageURL:            strings.TrimSpace(trace.PageURL),
		Algorithms:         append([]string(nil), trace.Algorithms...),
		RequestPlaintext:   strings.TrimSpace(trace.RequestBeforeTransform),
		RequestCiphertext:  strings.TrimSpace(trace.FinalRequestBody),
		ResponseCiphertext: strings.TrimSpace(trace.SessionMaterials["latest_response_ciphertext"]),
		ResponsePlaintext:  strings.TrimSpace(trace.SessionMaterials["latest_response_plaintext"]),
		RequestHeaders:     pickProtocolExplainMap(trace.RequestHeaders, 12),
		SessionMaterials:   pickProtocolExplainMap(trace.SessionMaterials, 16),
		RequestSteps:       pickProtocolExplainSteps(trace.RequestSteps, 8),
		ResponseSteps:      pickProtocolExplainSteps(trace.ResponseSteps, 8),
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func pickProtocolExplainMap(source map[string]string, limit int) map[string]string {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]string)
	count := 0
	for _, key := range []string{
		"gv59jppeesnw",
		"kqn29pkxstkn",
		"bpzhepzrvcjy",
		"6zzbinypyphq",
		"x-access-token",
		"channel-code",
		"session_seed_b",
		"sm4_key_hex",
		"crypto_key_hex",
		"crypto_iv_hex",
		"nonce",
		"timestamp",
		"signature",
		"key_exchange_header",
		"key_exchange_public_key",
		"latest_ciphertext",
		"latest_plaintext",
		"latest_response_ciphertext",
		"latest_response_plaintext",
		"request_runtime_function_path",
		"request_runtime_module_id",
		"response_runtime_function_path",
		"response_runtime_module_id",
	} {
		for existingKey, value := range source {
			if strings.EqualFold(existingKey, key) && strings.TrimSpace(value) != "" {
				result[existingKey] = strings.TrimSpace(value)
				count++
				break
			}
		}
		if count >= limit {
			return result
		}
	}
	for key, value := range source {
		if count >= limit {
			break
		}
		if strings.TrimSpace(value) == "" {
			continue
		}
		if _, exists := result[key]; exists {
			continue
		}
		result[key] = strings.TrimSpace(value)
		count++
	}
	return result
}

func pickProtocolExplainSteps(steps []database.ProtocolCryptoStep, limit int) []database.ProtocolCryptoStep {
	if len(steps) == 0 {
		return nil
	}
	if len(steps) <= limit {
		return append([]database.ProtocolCryptoStep(nil), steps...)
	}
	out := make([]database.ProtocolCryptoStep, 0, limit)
	out = append(out, steps[:limit/2]...)
	out = append(out, steps[len(steps)-(limit-len(out)):]...)
	return out
}
