package crawl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
)

// This parser deliberately recognizes relationships rather than a particular
// response envelope. It scans every cached JS resource for a private-key
// decrypt function, follows its alias to an embedded material record, and only
// reports a key after it can be parsed as a real RSA private key.
var (
	// Restrict export-name recovery to RSA decrypt exports. Bundled modules reuse
	// short local names (for example, "f"), so a global map for every export can
	// otherwise attribute a decryptor to an unrelated module function.
	staticDecryptExportPattern   = regexp.MustCompile(`n\.d\([^,]+,\s*["'](rsaDecrypt[A-Za-z0-9_$]*)["']\s*,\s*function\(\)\s*\{\s*return\s+([A-Za-z_$][\w$]*)\s*\}`)
	staticDecryptFunctionPattern = regexp.MustCompile(`(?s)([A-Za-z_$][\w$]*)\s*=\s*function\s*\([^)]*\)\s*\{.{0,900}?decryptByPrivate\s*\(\s*[^,]+,\s*([A-Za-z_$][\w$]*)\s*\)`)
	staticDecryptAliasPattern    = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*=\s*Object\([^)]*\)\s*\(\s*["']([^"']+)["']\s*\)`)
	base64MaterialPattern        = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{128,}$`)
)

type staticResponseDecryptor struct {
	privateKey *rsa.PrivateKey
	evidence   database.CryptoKeyEvidence
}

type staticResponseDecryptIndex struct {
	decryptors []staticResponseDecryptor
}

func loadStaticResponseDecryptIndex(o structs.JSFindOptions) *staticResponseDecryptIndex {
	if strings.TrimSpace(o.TaskID) == "" {
		return nil
	}
	store := o.DataStore
	if store == nil {
		store = database.GetScanDataStore()
	}
	if store == nil {
		return nil
	}
	resources, err := store.ListJSResources(o.TaskID, o.Version)
	if err != nil || len(resources) == 0 {
		return nil
	}
	return discoverStaticResponseDecryptors(resources)
}

func discoverStaticResponseDecryptors(resources []database.JSResource) *staticResponseDecryptIndex {
	if len(resources) == 0 {
		return nil
	}

	type materialSource struct {
		value   string
		url     string
		decoder string
	}
	materials := make(map[string][]materialSource)
	for _, resource := range resources {
		content := resource.Content
		for _, alias := range extractStaticSecretAliases(content) {
			decoded, ok := decodeStaticSecretAlias(content, alias)
			if !ok {
				continue
			}
			materials[alias] = append(materials[alias], materialSource{
				value: decoded, url: resource.URL,
				decoder: fmt.Sprintf("%s → s/d 异或解码", alias),
			})
		}
	}

	seen := make(map[string]struct{})
	decryptors := make([]staticResponseDecryptor, 0, 2)
	for _, resource := range resources {
		for _, function := range extractStaticRSADecryptFunctions(resource.Content) {
			for _, material := range materials[function.alias] {
				privateKey, format, materialValue, ok := parseStaticRSAPrivateKey(material.value)
				if !ok {
					continue
				}
				fingerprint := staticRSAPublicKeyFingerprint(privateKey)
				if fingerprint == "" {
					continue
				}
				if _, exists := seen[fingerprint]; exists {
					continue
				}
				seen[fingerprint] = struct{}{}
				decryptors = append(decryptors, staticResponseDecryptor{
					privateKey: privateKey,
					evidence: database.CryptoKeyEvidence{
						Algorithm:       "RSA PKCS#1 v1.5",
						KeyType:         "RSA 私钥",
						KeyFormat:       format,
						KeyMaterial:     materialValue,
						KeyBits:         privateKey.N.BitLen(),
						Fingerprint:     fingerprint,
						SourceURL:       firstNonEmpty(material.url, resource.URL),
						DecoderPath:     material.decoder,
						DecryptFunction: function.name,
					},
				})
			}
		}
	}
	if len(decryptors) == 0 {
		return nil
	}
	sort.Slice(decryptors, func(i, j int) bool {
		return decryptors[i].evidence.SourceURL < decryptors[j].evidence.SourceURL
	})
	return &staticResponseDecryptIndex{decryptors: decryptors}
}

type staticDecryptFunction struct {
	name  string
	alias string
}

func extractStaticRSADecryptFunctions(content string) []staticDecryptFunction {
	if strings.TrimSpace(content) == "" {
		return nil
	}
	exportedNames := make(map[string]string)
	for _, match := range staticDecryptExportPattern.FindAllStringSubmatch(content, -1) {
		if len(match) == 3 {
			exportedNames[match[2]] = match[1]
		}
	}
	secretAliases := make(map[string]string)
	for _, match := range staticDecryptAliasPattern.FindAllStringSubmatch(content, -1) {
		if len(match) == 3 {
			secretAliases[match[1]] = match[2]
		}
	}
	functions := make([]staticDecryptFunction, 0, 2)
	seen := make(map[string]struct{})
	for _, match := range staticDecryptFunctionPattern.FindAllStringSubmatch(content, -1) {
		if len(match) != 3 {
			continue
		}
		// A direct decryptByPrivate call is sufficient evidence even when its
		// minified local name is not exported. Prefer a verified rsaDecrypt*
		// export and use a truthful generic label otherwise.
		name := firstNonEmpty(exportedNames[match[1]], "decryptByPrivate")
		alias := firstNonEmpty(secretAliases[match[2]], match[2])
		key := name + "\x00" + alias
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		functions = append(functions, staticDecryptFunction{name: name, alias: alias})
	}
	return functions
}

func extractStaticSecretAliases(content string) []string {
	matches := staticDecryptAliasPattern.FindAllStringSubmatch(content, -1)
	aliases := make([]string, 0, len(matches))
	seen := make(map[string]struct{})
	for _, match := range matches {
		if len(match) != 3 {
			continue
		}
		alias := strings.TrimSpace(match[2])
		if alias == "" {
			continue
		}
		if _, exists := seen[alias]; exists {
			continue
		}
		seen[alias] = struct{}{}
		aliases = append(aliases, alias)
	}
	return aliases
}

func decodeStaticSecretAlias(content, alias string) (string, bool) {
	pattern, err := regexp.Compile(`(?s)(?:["']?` + regexp.QuoteMeta(alias) + `["']?)\s*:\s*\{\s*s\s*:\s*(\d+)\s*,\s*d\s*:\s*\[([0-9,\s]+)\]`)
	if err != nil {
		return "", false
	}
	match := pattern.FindStringSubmatch(content)
	if len(match) != 3 {
		return "", false
	}
	seed, err := strconv.Atoi(match[1])
	if err != nil {
		return "", false
	}
	values := strings.Split(match[2], ",")
	var builder strings.Builder
	builder.Grow(len(values))
	for index, raw := range values {
		value, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || value < 0 || value > 255 {
			return "", false
		}
		builder.WriteByte(byte(value ^ ((seed + 17*index + index%13) & 255)))
	}
	decoded := strings.TrimSpace(builder.String())
	if !base64MaterialPattern.MatchString(decoded) && !strings.Contains(decoded, "BEGIN") {
		return "", false
	}
	return decoded, true
}

func parseStaticRSAPrivateKey(material string) (*rsa.PrivateKey, string, string, bool) {
	material = strings.TrimSpace(material)
	if material == "" {
		return nil, "", "", false
	}
	if block, _ := pem.Decode([]byte(material)); block != nil {
		if key, format, ok := parseRSAKeyDER(block.Bytes); ok {
			return key, "PEM " + format, material, true
		}
	}
	encoded := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, material)
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", "", false
	}
	key, format, ok := parseRSAKeyDER(der)
	if !ok {
		return nil, "", "", false
	}
	return key, "Base64 DER " + format, encoded, true
}

func parseRSAKeyDER(der []byte) (*rsa.PrivateKey, string, bool) {
	if parsed, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if key, ok := parsed.(*rsa.PrivateKey); ok {
			return key, "PKCS#8", true
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, "PKCS#1", true
	}
	return nil, "", false
}

func staticRSAPublicKeyFingerprint(key *rsa.PrivateKey) string {
	if key == nil {
		return ""
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func tryStaticResponseDecrypt(rawResponse, preferredCiphertext string, index *staticResponseDecryptIndex) (string, *database.CryptoKeyEvidence, bool) {
	if index == nil || len(index.decryptors) == 0 {
		return "", nil, false
	}
	for _, ciphertext := range staticResponseCiphertextCandidates(rawResponse, preferredCiphertext) {
		rawCiphertext, ok := decodeStaticCiphertext(ciphertext)
		if !ok {
			continue
		}
		for _, decryptor := range index.decryptors {
			blockSize := (decryptor.privateKey.N.BitLen() + 7) / 8
			if blockSize == 0 || len(rawCiphertext) == 0 || len(rawCiphertext)%blockSize != 0 {
				continue
			}
			plaintext := make([]byte, 0, len(rawCiphertext))
			valid := true
			for offset := 0; offset < len(rawCiphertext); offset += blockSize {
				block, err := rsa.DecryptPKCS1v15(rand.Reader, decryptor.privateKey, rawCiphertext[offset:offset+blockSize])
				if err != nil {
					valid = false
					break
				}
				plaintext = append(plaintext, block...)
			}
			if !valid || !json.Valid(plaintext) {
				continue
			}
			evidence := decryptor.evidence
			evidence.Verification = fmt.Sprintf("已静态解密并验证 JSON 响应（%d 个 RSA 块）", len(rawCiphertext)/blockSize)
			return string(plaintext), &evidence, true
		}
	}
	return "", nil, false
}

func saveStaticResponseDecryptTrace(o structs.JSFindOptions, apiReq structs.APIRequest, rawResponse, plaintext string, evidence *database.CryptoKeyEvidence) (string, bool) {
	if database.DB == nil || strings.TrimSpace(o.TaskID) == "" || evidence == nil || strings.TrimSpace(plaintext) == "" {
		return "", false
	}

	ciphertext := strings.TrimSpace(rawResponse)
	identity := strings.Join([]string{
		o.TaskID,
		strconv.Itoa(o.Version),
		apiReq.Method,
		apiReq.URL,
		evidence.Fingerprint,
		ciphertext,
	}, "\x00")
	sum := sha256.Sum256([]byte(identity))
	traceID := "static-rsa-" + hex.EncodeToString(sum[:12])
	headers := make(map[string]string, len(apiReq.Headers))
	for key, value := range apiReq.Headers {
		headers[key] = value
	}

	materials := make(map[string]string)
	for key, value := range map[string]string{
		"static_rsa_private_key":             evidence.KeyMaterial,
		"static_rsa_private_key_format":      evidence.KeyFormat,
		"static_rsa_private_key_fingerprint": evidence.Fingerprint,
		"static_rsa_private_key_source":      evidence.SourceURL,
		"static_rsa_decoder_path":            evidence.DecoderPath,
		"response_runtime_function_path":     evidence.DecryptFunction,
		"latest_response_ciphertext":         ciphertext,
		"latest_response_plaintext":          plaintext,
	} {
		if strings.TrimSpace(value) != "" {
			materials[key] = value
		}
	}

	trace := database.ProtocolTraceRecord{
		TaskID:         o.TaskID,
		Version:        o.Version,
		TargetURL:      o.HomeURL,
		TraceID:        traceID,
		Transport:      "static-js-analysis",
		PageURL:        o.HomeURL,
		RequestURL:     apiReq.URL,
		Method:         apiReq.Method,
		RequestHeaders: headers,
		ResponseSteps: []database.ProtocolCryptoStep{{
			Source:        "static-js." + firstNonEmpty(evidence.DecryptFunction, "decryptByPrivate"),
			Algorithm:     "rsa.pkcs1-v1_5.decrypt",
			InputPreview:  ciphertext,
			OutputPreview: plaintext,
			FunctionPath:  evidence.DecryptFunction,
		}},
		SessionMaterials: materials,
		Algorithms:       []string{"static-js-key-recovery", "rsa.pkcs1-v1_5.decrypt"},
		Stack:            fmt.Sprintf("静态恢复链路：%s", evidence.DecoderPath),
		CreatedAt:        time.Now(),
	}
	if err := database.SaveProtocolTrace(trace); err != nil {
		fmt.Printf("\n[错误] 保存静态 RSA 解密协议轨迹失败: %s %s，原因: %v\n", apiReq.Method, apiReq.URL, err)
		return "", false
	}
	return traceID, true
}

func staticResponseCiphertextCandidates(rawResponse, preferred string) []string {
	candidates := make([]string, 0, 12)
	seen := make(map[string]struct{})
	appendCandidate := func(value string) {
		value = strings.Trim(strings.TrimSpace(value), `"`)
		if value == "" {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		candidates = append(candidates, value)
	}
	appendCandidate(preferred)
	appendCandidate(rawResponse)
	var payload any
	if json.Unmarshal([]byte(rawResponse), &payload) != nil {
		return candidates
	}
	var visit func(any)
	visit = func(value any) {
		if len(candidates) >= 24 {
			return
		}
		switch typed := value.(type) {
		case map[string]any:
			for _, nested := range typed {
				visit(nested)
			}
		case []any:
			for _, nested := range typed {
				visit(nested)
			}
		case string:
			appendCandidate(typed)
		}
	}
	visit(payload)
	return candidates
}

func decodeStaticCiphertext(value string) ([]byte, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) < 64 {
		return nil, false
	}
	value += strings.Repeat("=", (4-len(value)%4)%4)
	decoded, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(value)
	}
	return decoded, err == nil
}

func recordStaticPrivateKeyFindings(o structs.JSFindOptions, collector VulnCollector, index *staticResponseDecryptIndex) {
	if index == nil || strings.TrimSpace(o.TaskID) == "" {
		return
	}
	for _, decryptor := range index.decryptors {
		evidence := decryptor.evidence
		record := database.VulnRecord{
			TaskID:            o.TaskID,
			Version:           o.Version,
			VulnID:            uuid.New().String(),
			Title:             "前端泄露响应解密私钥",
			Level:             "high",
			Type:              "前端私钥泄露",
			URL:               evidence.SourceURL,
			Confidence:        "high",
			ConfidenceReason:  "已从公开缓存 JS 恢复并解析为可用 RSA 私钥",
			CryptoKeyEvidence: &evidence,
			StaticContexts: []database.VulnStaticContext{{
				SourceURL: evidence.SourceURL,
				Snippet:   fmt.Sprintf("%s 使用 %s；%s", evidence.DecryptFunction, evidence.DecoderPath, evidence.KeyFormat),
			}},
			Description: fmt.Sprintf("前端公开 JavaScript 中包含可恢复的 %d 位 RSA 私钥，可用于解密受保护响应。提取链路：%s。", evidence.KeyBits, evidence.DecoderPath),
			CreatedAt:   time.Now(),
		}
		if collector != nil {
			collector.Collect(record)
			continue
		}
		if database.DB != nil {
			if err := database.SaveVuln(record); err != nil {
				fmt.Printf("\n[错误] 保存前端私钥泄露漏洞失败: %v\n", err)
			}
		}
	}
}
