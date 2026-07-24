package crawl

import "testing"

func TestParseUnauthorizedAIReviewRequiresEvidenceForConfirmed(t *testing.T) {
	valid := `{"verdict":"CONFIRMED","vulnerability_type":"UNAUTHENTICATED_ACCESS","confidence":95,"protected_resource":"true","sensitive_data_found":"true","evidence":["匿名请求返回用户数据"],"reason":"未认证仍返回受保护数据","impact":"泄露用户信息","risk_level":"HIGH","missing_evidence":[],"recommended_action":"增加认证和资源归属校验"}`

	jsonBytes, err := extractJSONObject(valid)
	if err != nil {
		t.Fatal(err)
	}
	review, err := decodeUnauthorizedAIReview(jsonBytes)
	if err != nil {
		t.Fatal(err)
	}
	if review.Verdict != "CONFIRMED" || review.Confidence != 95 || review.ProtectedResource != AITruthTrue {
		t.Fatalf("unexpected review: %#v", review)
	}
}

func TestUnmarshalUnauthorizedAIReviewAcceptsBooleanTruth(t *testing.T) {
	value := `{"verdict":"FALSE_POSITIVE","vulnerability_type":"PUBLIC_API","confidence":90,"protected_resource":false,"sensitive_data_found":false,"evidence":[],"reason":"公开初始化接口","impact":"无","risk_level":"NONE","missing_evidence":[],"recommended_action":"关闭误报"}`
	jsonBytes, err := extractJSONObject(value)
	if err != nil {
		t.Fatal(err)
	}
	review, err := decodeUnauthorizedAIReview(jsonBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !review.IsFalsePositive() || review.ProtectedResource != AITruthFalse || review.SensitiveDataFound != AITruthFalse {
		t.Fatalf("unexpected public API review: %#v", review)
	}
}

func TestValidateUnauthorizedAIReviewRejectsUnsupportedConfirmedResult(t *testing.T) {
	review := UnauthorizedAIReview{
		Verdict:           "CONFIRMED",
		VulnerabilityType: "PUBLIC_API",
		Confidence:        99,
		ProtectedResource: AITruthFalse,
		RiskLevel:         "HIGH",
		Evidence:          []string{"HTTP 200"},
	}
	if err := validateUnauthorizedAIReview(review); err == nil {
		t.Fatal("expected invalid confirmed public API review to be rejected")
	}
}
