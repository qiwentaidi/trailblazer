package lib

import (
	"net/url"
	"strings"
)

const (
	TraceEvidenceResponsePlaintextCaptured = "response_plaintext_captured"
	TraceEvidenceResponsePathNotCaptured   = "response_path_not_captured"
	TraceEvidenceResponseDecryptAttempted  = "response_decrypt_attempted_without_plaintext"
	TraceEvidenceEncodingVariantSuspected  = "encoding_variant_suspected"
	TraceEvidenceRequestChainOnly          = "request_chain_only"
	TraceEvidenceInsufficient              = "insufficient_evidence"
)

type TraceVariantSuggestion struct {
	Parameter      string `json:"parameter"`
	Action         string `json:"action"`
	CurrentValue   string `json:"currentValue,omitempty"`
	CandidateValue string `json:"candidateValue,omitempty"`
	Reason         string `json:"reason,omitempty"`
	ExpectedEffect string `json:"expectedEffect,omitempty"`
}

type TraceEvidence struct {
	Status                 string                   `json:"status"`
	Summary                string                   `json:"summary"`
	DetectedAlgorithms     []string                 `json:"detectedAlgorithms,omitempty"`
	VariantSuggestions     []TraceVariantSuggestion `json:"variantSuggestions,omitempty"`
	HasResponseCiphertext  bool                     `json:"hasResponseCiphertext"`
	HasResponsePlaintext   bool                     `json:"hasResponsePlaintext"`
	HasResponseDecryptStep bool                     `json:"hasResponseDecryptStep"`
	HasResponseDecodeStep  bool                     `json:"hasResponseDecodeStep"`
	HasRequestEncryptStep  bool                     `json:"hasRequestEncryptStep"`
}

var standardEncodingValues = map[string]struct{}{
	"utf-8": {},
	"utf8":  {},
	"utf_8": {},
	"json":  {},
	"text":  {},
	"plain": {},
}

func analyzeQueryVariantSuggestions(rawURL string) []TraceVariantSuggestion {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	values := parsed.Query()
	encodingValue := strings.TrimSpace(values.Get("encoding"))
	if encodingValue == "" {
		return nil
	}

	if _, ok := standardEncodingValues[strings.ToLower(encodingValue)]; ok {
		return nil
	}

	return []TraceVariantSuggestion{
		{
			Parameter:      "encoding",
			Action:         "remove",
			CurrentValue:   encodingValue,
			Reason:         "检测到非常规 encoding 参数，可能触发站点自定义响应表示",
			ExpectedEffect: "验证删除该参数后是否返回可读 JSON 或常规文本",
		},
		{
			Parameter:      "encoding",
			Action:         "replace",
			CurrentValue:   encodingValue,
			CandidateValue: "utf-8",
			Reason:         "优先尝试回退到常见文本编码协商值",
			ExpectedEffect: "验证改为 utf-8 后是否直接返回可解析的明文内容",
		},
	}
}

func AnalyzeProtocolTrace(trace ProtocolTrace) TraceEvidence {
	evidence := TraceEvidence{
		DetectedAlgorithms:    append([]string(nil), trace.Algorithms...),
		VariantSuggestions:    analyzeQueryVariantSuggestions(trace.RequestURL),
		HasResponseCiphertext: strings.TrimSpace(trace.SessionMaterials["latest_response_ciphertext"]) != "",
		HasResponsePlaintext:  strings.TrimSpace(trace.SessionMaterials["latest_response_plaintext"]) != "",
	}

	for _, steps := range [][]ProtocolCryptoStep{trace.RequestSteps, trace.ResponseSteps} {
		for _, step := range steps {
			source := strings.ToLower(strings.TrimSpace(step.Source))
			algorithm := strings.ToLower(strings.TrimSpace(step.Algorithm))

			if source == "sd" || strings.HasSuffix(source, ".sd") {
				evidence.HasResponseDecryptStep = true
			}
			if strings.Contains(source, "decrypt") && !strings.Contains(source, "textdecoder.decode") {
				evidence.HasResponseDecryptStep = true
			}
			if strings.Contains(algorithm, "sm4") || strings.Contains(algorithm, "aes-cbc") {
				evidence.HasResponseDecryptStep = true
			}
			if strings.Contains(source, "decode") || strings.Contains(source, "atob") || strings.Contains(algorithm, "decode") {
				evidence.HasResponseDecodeStep = true
			}
			if strings.Contains(source, "encrypt") || strings.Contains(algorithm, "aes-gcm") || strings.Contains(algorithm, "sm4") {
				evidence.HasRequestEncryptStep = true
			}
		}
	}

	switch {
	case evidence.HasResponsePlaintext:
		evidence.Status = TraceEvidenceResponsePlaintextCaptured
		evidence.Summary = "已捕获响应明文，可直接核对字段正确性"
	case evidence.HasResponseCiphertext && evidence.HasResponseDecryptStep:
		evidence.Status = TraceEvidenceResponseDecryptAttempted
		evidence.Summary = "已捕获响应密文和解密步骤，但尚未得到可验证的明文结果"
	case evidence.HasResponseCiphertext && !evidence.HasResponsePlaintext && len(evidence.VariantSuggestions) > 0:
		evidence.Status = TraceEvidenceEncodingVariantSuspected
		evidence.Summary = "检测到非常规 encoding 参数，建议优先测试删除该参数或改为 utf-8 等常规值"
	case evidence.HasResponseCiphertext && (evidence.HasResponseDecodeStep || len(evidence.DetectedAlgorithms) > 0):
		evidence.Status = TraceEvidenceResponsePathNotCaptured
		evidence.Summary = "已识别响应处理链路，但未捕获可执行的响应解密步骤或明文结果"
	case evidence.HasRequestEncryptStep:
		evidence.Status = TraceEvidenceRequestChainOnly
		evidence.Summary = "当前主要证明了请求侧加密链路，响应侧证据仍不足"
	default:
		evidence.Status = TraceEvidenceInsufficient
		evidence.Summary = "当前证据不足，无法判断响应是否被正确解密"
	}

	return evidence
}
