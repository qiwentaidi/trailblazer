package crawl

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// tryDirectResponseDecoding only decodes an already-confirmed encrypted
// response envelope. It deliberately performs no JavaScript or key analysis.
func tryDirectResponseDecoding(rawResponse, preferredCiphertext string) (string, string, bool) {
	for _, candidate := range responseCiphertextCandidates(rawResponse, preferredCiphertext) {
		if decoded, ok := decodeResponseBase64(candidate); ok && json.Valid(decoded) {
			return string(decoded), "base64", true
		}

		candidate = strings.TrimSpace(candidate)
		if len(candidate) == 0 || len(candidate)%2 != 0 {
			continue
		}
		decoded, err := hex.DecodeString(candidate)
		if err == nil && json.Valid(decoded) {
			return string(decoded), "hex", true
		}
	}
	return "", "", false
}

func decodeResponseBase64(value string) ([]byte, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, false
	}
	for _, encoding := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
	} {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, true
		}
	}
	return nil, false
}

func responseCiphertextCandidates(rawResponse, preferredCiphertext string) []string {
	candidates := make([]string, 0, 2)
	for _, candidate := range []string{preferredCiphertext, rawResponse} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		duplicate := false
		for _, existing := range candidates {
			if candidate == existing {
				duplicate = true
				break
			}
		}
		if !duplicate {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}
