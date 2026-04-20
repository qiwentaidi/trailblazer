package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"trailblazer/pkg/lib"
)

func preview(value string, limit int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func materialHexFromRaw(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	return hex.EncodeToString([]byte(raw))
}

func materialHexFromBase64(encoded string) string {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return ""
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(data)
}

func buildMaterialSummary(trace lib.ProtocolTrace) map[string]interface{} {
	materials := trace.SessionMaterials
	keyBase64 := firstNonEmpty(materials["crypto_key_base64"], materials["aes_key_base64"], materials["sm4_key_base64"])
	keyRaw := firstNonEmpty(materials["crypto_key_raw"], materials["aes_key_raw"], materials["sm4_key_raw"])
	ivBase64 := firstNonEmpty(materials["crypto_iv_base64"], materials["aes_iv_base64"])
	ivRaw := firstNonEmpty(materials["crypto_iv_raw"], materials["aes_iv_raw"])
	aadBase64 := firstNonEmpty(materials["crypto_aad_base64"], materials["aes_aad_base64"])

	summary := map[string]interface{}{
		"hasKeyMaterial": keyBase64 != "" || keyRaw != "",
		"hasIVMaterial":  ivBase64 != "" || ivRaw != "",
	}

	if keyBase64 != "" {
		summary["keyBase64"] = keyBase64
	}
	if keyRaw != "" {
		summary["keyRawPreview"] = preview(keyRaw, 80)
	}
	if keyHex := firstNonEmpty(materialHexFromBase64(keyBase64), materialHexFromRaw(keyRaw)); keyHex != "" {
		summary["keyHex"] = keyHex
	}

	if ivBase64 != "" {
		summary["ivBase64"] = ivBase64
	}
	if ivRaw != "" {
		summary["ivRawPreview"] = preview(ivRaw, 80)
	}
	if ivHex := firstNonEmpty(materialHexFromBase64(ivBase64), materialHexFromRaw(ivRaw)); ivHex != "" {
		summary["ivHex"] = ivHex
	}

	if aadBase64 != "" {
		summary["aadBase64"] = aadBase64
		if aadHex := materialHexFromBase64(aadBase64); aadHex != "" {
			summary["aadHex"] = aadHex
		}
	}

	return summary
}

func buildTraceSummaryEntry(trace lib.ProtocolTrace) map[string]interface{} {
	ciphertext := strings.TrimSpace(trace.SessionMaterials["latest_response_ciphertext"])
	plaintext := strings.TrimSpace(trace.SessionMaterials["latest_response_plaintext"])
	evidence := lib.AnalyzeProtocolTrace(trace)

	entry := map[string]interface{}{
		"traceId":                trace.TraceID,
		"requestURL":             trace.RequestURL,
		"method":                 trace.Method,
		"algorithms":             trace.Algorithms,
		"evidenceStatus":         evidence.Status,
		"evidenceSummary":        evidence.Summary,
		"variantSuggestions":     evidence.VariantSuggestions,
		"hasResponseDecryptStep": evidence.HasResponseDecryptStep,
		"hasResponseDecodeStep":  evidence.HasResponseDecodeStep,
		"hasResponseCiphertext":  ciphertext != "",
		"hasResponsePlaintext":   plaintext != "",
		"capturedPlaintextPreview": preview(
			trace.SessionMaterials["latest_response_plaintext"],
			160,
		),
	}

	if plaintext != "" {
		entry["decryptStatus"] = "not_needed"
		entry["decryptPreview"] = preview(plaintext, 160)
		return entry
	}

	entry["materialSummary"] = buildMaterialSummary(trace)
	if ciphertext == "" {
		entry["decryptStatus"] = "skipped"
		return entry
	}

	decryptResult, decryptErr := lib.DecryptProtocolTrace(trace, "", ciphertext)
	if decryptErr != nil {
		entry["decryptStatus"] = "error"
		entry["decryptError"] = decryptErr.Error()
		return entry
	}

	entry["decryptStatus"] = "ok"
	entry["decryptPreview"] = preview(decryptResult.Plaintext, 160)
	return entry
}

func main() {
	options := lib.NewScanOptions()
	options.OutputPath = "/tmp/yqq_sdk_scan_result.json"

	options.VulnDetection.SQLInjection.Enabled = false
	options.VulnDetection.LFI.Enabled = false
	options.VulnDetection.SSRF.Enabled = false
	options.VulnDetection.Redirect.Enabled = false
	options.VulnDetection.XSS.Enabled = false
	options.VulnDetection.Upload.Enabled = false

	result, err := lib.PerformScan([]string{"https://y.qq.com/"}, options)
	if err != nil {
		log.Fatalf("sdk scan failed: %v", err)
	}

	summary := map[string]interface{}{
		"scanTime":                 result.ScanTime,
		"targets":                  result.Summary.TotalTargets,
		"treeNodes":                result.Summary.TotalTreeNodes,
		"vulnerabilities":          result.Summary.TotalVulnerabilities,
		"risks":                    result.Summary.TotalRisks,
		"targetSummaries":          []map[string]interface{}{},
		"decryptionSummaries":      []map[string]interface{}{},
		"encodingVariantSuspected": 0,
	}

	for _, target := range result.Targets {
		targetSummary := map[string]interface{}{
			"target":         target.Target,
			"apiRecords":     len(target.APIRecords),
			"protocolTraces": len(target.ProtocolTraces),
			"apiRoutes":      len(target.Assets.APIRoutes),
			"apiRoots":       len(target.Assets.APIRoots),
		}
		summary["targetSummaries"] = append(summary["targetSummaries"].([]map[string]interface{}), targetSummary)

		for i, trace := range target.ProtocolTraces {
			if i >= 5 {
				break
			}
			entry := buildTraceSummaryEntry(trace)
			evidenceStatus, _ := entry["evidenceStatus"].(string)
			if evidenceStatus == string(lib.TraceEvidenceEncodingVariantSuspected) {
				summary["encodingVariantSuspected"] = summary["encodingVariantSuspected"].(int) + 1
			}
			summary["decryptionSummaries"] = append(summary["decryptionSummaries"].([]map[string]interface{}), entry)
		}
	}

	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		log.Fatalf("marshal summary failed: %v", err)
	}

	if err := os.WriteFile("/tmp/yqq_sdk_summary.json", data, 0644); err != nil {
		log.Fatalf("write summary failed: %v", err)
	}

	fmt.Println(string(data))
}
