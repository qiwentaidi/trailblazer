package protocoltool

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"trailblazer/pkg/core/database"
)

func TestDecryptWithTraceReturnsCapturedPlaintextWithoutSM4Key(t *testing.T) {
	trace := &database.ProtocolTraceRecord{
		SessionMaterials: map[string]string{
			"latest_response_ciphertext": "abcdef",
			"latest_response_plaintext":  "{\"code\":0}",
		},
	}

	result, err := DecryptWithTrace(trace, "", "abcdef")
	if err != nil {
		t.Fatalf("expected captured plaintext to be returned without sm4 key, got error: %v", err)
	}
	if result.Plaintext != "{\"code\":0}" {
		t.Fatalf("expected captured plaintext, got %q", result.Plaintext)
	}
}

func TestDecryptWithTraceUsesSM4WhenAlgorithmMatches(t *testing.T) {
	keyHex := "0123456789abcdeffedcba9876543210"
	plaintext := "{\"title\":\"song\"}"
	ciphertext, err := EncryptSM4Hex(plaintext, keyHex)
	if err != nil {
		t.Fatalf("expected ciphertext setup to succeed, got error: %v", err)
	}

	trace := &database.ProtocolTraceRecord{
		Algorithms: []string{"sm4"},
		SessionMaterials: map[string]string{
			"sm4_key_hex": keyHex,
		},
	}

	result, err := DecryptWithTrace(trace, "", ciphertext)
	if err != nil {
		t.Fatalf("expected sm4 decrypt to succeed, got error: %v", err)
	}
	if result.Plaintext != plaintext {
		t.Fatalf("expected plaintext %q, got %q", plaintext, result.Plaintext)
	}
}

func TestDecryptWithTraceUsesAESGCMWithCapturedMaterials(t *testing.T) {
	key := []byte("oKCs7e6qoKck7n**")
	nonce := []byte("1234567890ab")
	plaintext := "{\"code\":0,\"message\":\"ok\"}"

	ciphertext, err := EncryptAESGCMBase64(plaintext, key, nonce, nil)
	if err != nil {
		t.Fatalf("expected aes-gcm test ciphertext, got error: %v", err)
	}

	trace := &database.ProtocolTraceRecord{
		Algorithms: []string{"aes-gcm"},
		SessionMaterials: map[string]string{
			"crypto_key_raw":   string(key),
			"crypto_iv_base64": base64.StdEncoding.EncodeToString(nonce),
		},
	}

	result, err := DecryptWithTrace(trace, "", ciphertext)
	if err == nil {
		if result.Plaintext != plaintext {
			t.Fatalf("expected plaintext %q, got %q", plaintext, result.Plaintext)
		}
		return
	}
	t.Fatalf("expected aes-gcm decrypt to succeed, got error: %v", err)
}

func TestDecryptWithTraceReturnsMissingAESGCMMaterialsError(t *testing.T) {
	trace := &database.ProtocolTraceRecord{
		Algorithms: []string{"aes-gcm"},
	}

	_, err := DecryptWithTrace(trace, "", "abcdef")
	if err == nil {
		t.Fatalf("expected missing materials error")
	}
	if !strings.Contains(err.Error(), "AES-GCM") {
		t.Fatalf("expected AES-GCM missing-materials wording, got %q", err.Error())
	}
}

func TestDecryptWithTraceReturnsResponsePathNotCapturedError(t *testing.T) {
	trace := &database.ProtocolTraceRecord{
		Algorithms: []string{"aes-gcm", "text.decode"},
		ResponseSteps: []database.ProtocolCryptoStep{
			{Source: "TextDecoder.decode", Algorithm: "text.decode"},
		},
		SessionMaterials: map[string]string{
			"latest_response_ciphertext": "abcdef",
		},
	}

	_, err := DecryptWithTrace(trace, "", "abcdef")
	if err == nil {
		t.Fatalf("expected response-path-not-captured error")
	}
	if !strings.Contains(err.Error(), "未捕获可执行的响应解密步骤或明文结果") {
		t.Fatalf("expected clearer response path error, got %q", err.Error())
	}
}

func TestDecryptWithTracePrefersEvidenceMessageOverAESGCMAuthFailure(t *testing.T) {
	key := []byte("oKCs7e6qoKck7n**")
	nonce := []byte("1234567890ab")
	ciphertext := base64.StdEncoding.EncodeToString([]byte("not-a-valid-aes-gcm-payload"))

	trace := &database.ProtocolTraceRecord{
		Algorithms: []string{"aes-gcm", "text.decode"},
		ResponseSteps: []database.ProtocolCryptoStep{
			{Source: "TextDecoder.decode", Algorithm: "text.decode"},
		},
		SessionMaterials: map[string]string{
			"latest_response_ciphertext": ciphertext,
			"crypto_key_raw":             string(key),
			"crypto_iv_base64":           base64.StdEncoding.EncodeToString(nonce),
		},
	}

	_, err := DecryptWithTrace(trace, "", ciphertext)
	if err == nil {
		t.Fatalf("expected response-path-not-captured error")
	}
	if strings.Contains(err.Error(), "message authentication failed") {
		t.Fatalf("expected evidence message instead of low-level aes-gcm error, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "未捕获可执行的响应解密步骤或明文结果") {
		t.Fatalf("expected clearer response path error, got %q", err.Error())
	}
}

func TestDecryptWithTraceUsesAESCBCWithGenericCryptoMaterials(t *testing.T) {
	keyHex := "00112233445566778899aabbccddeeff"
	ivHex := "0102030405060708090a0b0c0d0e0f10"
	plaintext := "{\"album\":\"test\"}"

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatalf("expected valid key hex, got error: %v", err)
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		t.Fatalf("expected valid iv hex, got error: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("expected aes cipher setup to succeed, got error: %v", err)
	}

	padded := pkcs7Pad([]byte(plaintext), block.BlockSize())
	cipherBytes := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(cipherBytes, padded)

	trace := &database.ProtocolTraceRecord{
		Algorithms: []string{"aes-cbc"},
		SessionMaterials: map[string]string{
			"crypto_key_hex": keyHex,
			"crypto_iv_hex":  ivHex,
		},
	}

	result, err := DecryptWithTrace(trace, "", hex.EncodeToString(cipherBytes))
	if err != nil {
		t.Fatalf("expected aes-cbc decrypt to succeed, got error: %v", err)
	}
	if result.Plaintext != plaintext {
		t.Fatalf("expected plaintext %q, got %q", plaintext, result.Plaintext)
	}
}

func TestDecryptWithTracePrefersBrowserRuntimeOverNative(t *testing.T) {
	originalBrowser := decryptStoredBrowserRuntime
	originalFrontend := decryptStoredFrontendRuntime
	t.Cleanup(func() {
		decryptStoredBrowserRuntime = originalBrowser
		decryptStoredFrontendRuntime = originalFrontend
	})

	decryptStoredBrowserRuntime = func(taskID, pageURL, requestURL, ciphertext, functionPath, moduleID string) (string, error) {
		if functionPath != "crypto.decrypt" {
			t.Fatalf("expected browser runtime to receive captured function path, got %q", functionPath)
		}
		if moduleID != "2048" {
			t.Fatalf("expected browser runtime to receive captured module id, got %q", moduleID)
		}
		return "{\"source\":\"browser\"}", nil
	}
	decryptStoredFrontendRuntime = func(taskID, ciphertext, functionPath, moduleID string) (string, error) {
		t.Fatalf("expected frontend runtime not to run when browser runtime succeeds")
		return "", nil
	}

	keyHex := "0123456789abcdeffedcba9876543210"
	plaintext := "{\"source\":\"native\"}"
	ciphertext, err := EncryptSM4Hex(plaintext, keyHex)
	if err != nil {
		t.Fatalf("expected ciphertext setup to succeed, got error: %v", err)
	}

	trace := &database.ProtocolTraceRecord{
		TaskID:     "task-1",
		PageURL:    "https://example.com/",
		RequestURL: "https://example.com/api",
		Algorithms: []string{"sm4"},
		SessionMaterials: map[string]string{
			"sm4_key_hex":                    keyHex,
			"response_runtime_function_path": "crypto.decrypt",
			"response_runtime_module_id":     "2048",
		},
	}

	result, err := DecryptWithTrace(trace, "", ciphertext)
	if err != nil {
		t.Fatalf("expected decrypt to succeed, got error: %v", err)
	}
	if result.Plaintext != "{\"source\":\"browser\"}" {
		t.Fatalf("expected browser runtime plaintext, got %q", result.Plaintext)
	}
	if result.FunctionHint != "crypto.decrypt" {
		t.Fatalf("expected captured function hint, got %q", result.FunctionHint)
	}
}

func TestDecryptWithTraceFallsBackToNativeWhenRuntimeFails(t *testing.T) {
	originalBrowser := decryptStoredBrowserRuntime
	originalFrontend := decryptStoredFrontendRuntime
	t.Cleanup(func() {
		decryptStoredBrowserRuntime = originalBrowser
		decryptStoredFrontendRuntime = originalFrontend
	})

	decryptStoredBrowserRuntime = func(taskID, pageURL, requestURL, ciphertext, functionPath, moduleID string) (string, error) {
		return "", fmt.Errorf("browser runtime failed")
	}
	decryptStoredFrontendRuntime = func(taskID, ciphertext, functionPath, moduleID string) (string, error) {
		return "", fmt.Errorf("frontend runtime failed")
	}

	keyHex := "0123456789abcdeffedcba9876543210"
	plaintext := "{\"source\":\"native\"}"
	ciphertext, err := EncryptSM4Hex(plaintext, keyHex)
	if err != nil {
		t.Fatalf("expected ciphertext setup to succeed, got error: %v", err)
	}

	trace := &database.ProtocolTraceRecord{
		TaskID:     "task-1",
		PageURL:    "https://example.com/",
		RequestURL: "https://example.com/api",
		Algorithms: []string{"sm4"},
		SessionMaterials: map[string]string{
			"sm4_key_hex": keyHex,
		},
	}

	result, err := DecryptWithTrace(trace, "", ciphertext)
	if err != nil {
		t.Fatalf("expected native fallback to succeed, got error: %v", err)
	}
	if result.Plaintext != plaintext {
		t.Fatalf("expected native fallback plaintext %q, got %q", plaintext, result.Plaintext)
	}
}

func TestRuntimeDecryptWithTraceUsesBrowserRuntime(t *testing.T) {
	originalBrowser := decryptStoredBrowserRuntime
	originalFrontend := decryptStoredFrontendRuntime
	t.Cleanup(func() {
		decryptStoredBrowserRuntime = originalBrowser
		decryptStoredFrontendRuntime = originalFrontend
	})

	decryptStoredBrowserRuntime = func(taskID, pageURL, requestURL, ciphertext, functionPath, moduleID string) (string, error) {
		if functionPath != "crypto.decrypt" || moduleID != "2048" {
			t.Fatalf("unexpected runtime function routing: path=%q module=%q", functionPath, moduleID)
		}
		return "{\"source\":\"browser-runtime\"}", nil
	}
	decryptStoredFrontendRuntime = func(taskID, ciphertext, functionPath, moduleID string) (string, error) {
		t.Fatalf("expected frontend runtime not to run when browser runtime succeeds")
		return "", nil
	}

	trace := &database.ProtocolTraceRecord{
		TaskID:     "task-runtime-1",
		PageURL:    "https://example.com/app",
		RequestURL: "https://example.com/api/orders",
		SessionMaterials: map[string]string{
			"response_runtime_function_path": "crypto.decrypt",
			"response_runtime_module_id":     "2048",
		},
	}

	result, err := RuntimeDecryptWithTrace(trace, "abcdef")
	if err != nil {
		t.Fatalf("expected runtime decrypt to succeed, got error: %v", err)
	}
	if result.Mode != "runtime" {
		t.Fatalf("expected runtime mode, got %q", result.Mode)
	}
	if result.Source != "browser-context" {
		t.Fatalf("expected browser-context source, got %q", result.Source)
	}
	if result.Plaintext != "{\"source\":\"browser-runtime\"}" {
		t.Fatalf("unexpected runtime plaintext %q", result.Plaintext)
	}
	if result.FunctionHint != "crypto.decrypt" {
		t.Fatalf("expected runtime function hint, got %q", result.FunctionHint)
	}
}

func TestRuntimeDecryptWithTraceReturnsAggregatedRuntimeError(t *testing.T) {
	originalBrowser := decryptStoredBrowserRuntime
	originalFrontend := decryptStoredFrontendRuntime
	t.Cleanup(func() {
		decryptStoredBrowserRuntime = originalBrowser
		decryptStoredFrontendRuntime = originalFrontend
	})

	decryptStoredBrowserRuntime = func(taskID, pageURL, requestURL, ciphertext, functionPath, moduleID string) (string, error) {
		return "", fmt.Errorf("browser down")
	}
	decryptStoredFrontendRuntime = func(taskID, ciphertext, functionPath, moduleID string) (string, error) {
		return "", fmt.Errorf("module missing")
	}

	trace := &database.ProtocolTraceRecord{
		TaskID:     "task-runtime-2",
		PageURL:    "https://example.com/app",
		RequestURL: "https://example.com/api/orders",
		SessionMaterials: map[string]string{
			"latest_response_ciphertext": "abcdef",
		},
	}

	_, err := RuntimeDecryptWithTrace(trace, "")
	if err == nil {
		t.Fatal("expected runtime decrypt to fail")
	}
	if !strings.Contains(err.Error(), "browser down") || !strings.Contains(err.Error(), "module missing") {
		t.Fatalf("expected aggregated runtime errors, got %q", err.Error())
	}
}

func TestRuntimeDecryptWithTraceFallsBackToModuleHintWhenFunctionPathMissing(t *testing.T) {
	originalBrowser := decryptStoredBrowserRuntime
	originalFrontend := decryptStoredFrontendRuntime
	t.Cleanup(func() {
		decryptStoredBrowserRuntime = originalBrowser
		decryptStoredFrontendRuntime = originalFrontend
	})

	decryptStoredBrowserRuntime = func(taskID, pageURL, requestURL, ciphertext, functionPath, moduleID string) (string, error) {
		if functionPath != "" {
			t.Fatalf("expected empty function path, got %q", functionPath)
		}
		if moduleID != "7788" {
			t.Fatalf("expected module id hint, got %q", moduleID)
		}
		return "{\"source\":\"browser-runtime\"}", nil
	}
	decryptStoredFrontendRuntime = func(taskID, ciphertext, functionPath, moduleID string) (string, error) {
		t.Fatalf("expected frontend runtime not to run when browser runtime succeeds")
		return "", nil
	}

	trace := &database.ProtocolTraceRecord{
		TaskID:     "task-runtime-3",
		PageURL:    "https://example.com/app",
		RequestURL: "https://example.com/api/orders",
		SessionMaterials: map[string]string{
			"response_runtime_module_id": "7788",
		},
	}

	result, err := RuntimeDecryptWithTrace(trace, "abcdef")
	if err != nil {
		t.Fatalf("expected runtime decrypt to succeed, got error: %v", err)
	}
	if result.FunctionHint != "module[7788].sd" {
		t.Fatalf("expected module-based function hint, got %q", result.FunctionHint)
	}
}
