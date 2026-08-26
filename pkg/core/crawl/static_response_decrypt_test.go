package crawl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/qiwentaidi/trailblazer/pkg/core/database"
)

func TestStaticResponseDecryptorFindsObfuscatedRSAPrivateKeyAndDecrypts(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	const seed = 91
	encodedKey := base64.StdEncoding.EncodeToString(der)
	encodedValues := make([]string, 0, len(encodedKey))
	for index, value := range []byte(encodedKey) {
		encodedValues = append(encodedValues, fmt.Sprintf("%d", value^byte((seed+17*index+index%13)&255)))
	}
	content := `n.d(t,"rsaDecryptNew",function(){return f});var s=Object(i.a)("str3");f=function(e){return r.default.decryptByPrivate(e,s)};str3:{s:91,d:[` + strings.Join(encodedValues, ",") + `]}`
	index := discoverStaticResponseDecryptors([]database.JSResource{{
		URL:     "https://example.com/static/app.js",
		Content: content,
	}})
	if index == nil || len(index.decryptors) != 1 {
		t.Fatalf("expected one static decryptor, got %#v", index)
	}
	if got := index.decryptors[0].evidence.DecryptFunction; got != "rsaDecryptNew" {
		t.Fatalf("decrypt function = %q, want rsaDecryptNew", got)
	}
	if got := index.decryptors[0].evidence.KeyMaterial; got != encodedKey {
		t.Fatal("expected the recovered key material to be retained as evidence")
	}

	plaintext := []byte(`{"code":0,"state":"ok"}`)
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("EncryptPKCS1v15() error = %v", err)
	}
	decoded, evidence, ok := tryStaticResponseDecrypt(`{"opaque":"not-a-cipher","payload":"`+base64.RawURLEncoding.EncodeToString(ciphertext)+`"}`, "", index)
	if !ok || decoded != string(plaintext) {
		t.Fatalf("static decrypt result = %q, ok=%v", decoded, ok)
	}
	if evidence == nil || !strings.Contains(evidence.Verification, "JSON") {
		t.Fatalf("expected verification evidence, got %#v", evidence)
	}
}

func TestStaticResponseDecryptorRejectsInvalidKeyMaterial(t *testing.T) {
	content := `n.d(t,"rsaDecryptNew",function(){return f});var s=Object(i.a)("str3");f=function(e){return r.default.decryptByPrivate(e,s)};str3:{s:91,d:[1,2,3,4]}`
	if index := discoverStaticResponseDecryptors([]database.JSResource{{Content: content}}); index != nil {
		t.Fatalf("expected invalid material to be rejected, got %#v", index)
	}
}

func TestStaticResponseDecryptorDoesNotAttributeReusedBundleVariableToAnotherModule(t *testing.T) {
	functions := extractStaticRSADecryptFunctions(`
		n.d(t,"getBnStore",function(){return f});
		f=function(e){return r.default.decryptByPrivate(e,s)};
		var s=Object(i.a)("str3");
	`)
	if len(functions) != 1 {
		t.Fatalf("expected one decrypt function, got %#v", functions)
	}
	if got := functions[0].name; got != "decryptByPrivate" {
		t.Fatalf("decrypt function = %q, want generic decryptByPrivate label", got)
	}
}
