package crawl

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestTryDirectResponseDecodingAcceptsJSONTransportEncodings(t *testing.T) {
	plaintext := `{"code":0,"data":{"id":1,"message":"directly-decoded-transport-encoding"}}`

	decoded, encoding, ok := tryDirectResponseDecoding(base64.RawURLEncoding.EncodeToString([]byte(plaintext)), "")
	if !ok || encoding != "base64" || decoded != plaintext {
		t.Fatalf("base64 decode = (%q, %q, %v)", decoded, encoding, ok)
	}

	decoded, encoding, ok = tryDirectResponseDecoding("", fmt.Sprintf("%x", plaintext))
	if !ok || encoding != "hex" || decoded != plaintext {
		t.Fatalf("hex decode = (%q, %q, %v)", decoded, encoding, ok)
	}
}

func TestTryDirectResponseDecodingRejectsNonJSONPayload(t *testing.T) {
	if _, _, ok := tryDirectResponseDecoding(base64.RawStdEncoding.EncodeToString([]byte("not json")), ""); ok {
		t.Fatal("non-JSON Base64 payload must not be treated as a decoded response")
	}
}
