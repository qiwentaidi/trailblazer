package web

import (
	"testing"

	"github.com/qiwentaidi/trailblazer/pkg/core/database"
)

func TestBuildTaskVulnResponsesIncludesStaticDecryptEvidence(t *testing.T) {
	responses := buildTaskVulnResponses([]database.VulnRecord{{
		VulnID:            "vuln-static-rsa",
		ResponsePlaintext: `{"code":0,"data":{"id":1}}`,
		DecryptionStatus:  "decrypted_static",
		CryptoKeyEvidence: &database.CryptoKeyEvidence{
			KeyMaterial:     "private-key-material",
			Fingerprint:     "fingerprint",
			DecryptFunction: "rsaDecryptNew",
		},
	}})
	if len(responses) != 1 {
		t.Fatalf("response count = %d, want 1", len(responses))
	}
	if got := responses[0].ResponsePlaintext; got != `{"code":0,"data":{"id":1}}` {
		t.Fatalf("response plaintext = %q", got)
	}
	if responses[0].CryptoKeyEvidence == nil || responses[0].CryptoKeyEvidence.KeyMaterial == "" {
		t.Fatalf("expected private-key evidence in API response, got %#v", responses[0].CryptoKeyEvidence)
	}
}

func TestBuildTaskVulnResponsesIncludesBusinessClassification(t *testing.T) {
	responses := buildTaskVulnResponses([]database.VulnRecord{{
		VulnID:         "vuln-query",
		Title:          "业务查询结果未授权查询",
		Type:           "未授权访问",
		Category:       "访问控制缺陷",
		Subcategory:    "未授权业务查询",
		BusinessObject: "业务查询结果",
		NamingSource:   "ai",
	}})
	if len(responses) != 1 {
		t.Fatalf("response count = %d, want 1", len(responses))
	}
	if got := responses[0].Category; got != "访问控制缺陷" {
		t.Fatalf("category = %q", got)
	}
	if got := responses[0].Subcategory; got != "未授权业务查询" {
		t.Fatalf("subcategory = %q", got)
	}
	if got := responses[0].BusinessObject; got != "业务查询结果" {
		t.Fatalf("business object = %q", got)
	}
}
