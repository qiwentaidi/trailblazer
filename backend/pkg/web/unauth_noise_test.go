package web

import (
	"sync"
	"testing"
	"trailblazer/pkg/core/database"
)

const lowConfidenceStatement = "低置信：结果更像相似拒绝模板或通用错误响应"

type stubDenyTemplateAIReviewer struct {
	confirmed bool
	err       error
	calls     *int
}

func (s stubDenyTemplateAIReviewer) JudgeDenyTemplate(requestPreview, responsePreview string) (bool, string, error) {
	if s.calls != nil {
		*s.calls++
	}
	return s.confirmed, "", s.err
}

func resetDenyTemplateAIReviewCache() {
	denyTemplateAIReviewCache = sync.Map{}
}

func TestAnnotateUnauthorizedNoiseMarksAuthTemplateClusters(t *testing.T) {
	originalFactory := newDenyTemplateAIReviewer
	newDenyTemplateAIReviewer = func() denyTemplateAIReviewer { return nil }
	defer func() { newDenyTemplateAIReviewer = originalFactory }()
	resetDenyTemplateAIReviewCache()

	vulns := []database.VulnRecord{
		{
			VulnID:           "risk-1",
			Title:            "未授权访问",
			Type:             "未授权访问",
			Response:         `{"status_message":"找不到用户凭据","from":"weiban-jwt-auth","success":false,"status_code":10031}`,
			ResponseLength:   104,
			Confidence:       "medium",
			ConfidenceReason: "响应体很短",
		},
		{
			VulnID:         "risk-2",
			Title:          "未授权访问",
			Type:           "未授权访问",
			Response:       `{"status_message":"找不到用户凭据","from":"weiban-jwt-auth","success":false,"status_code":10031}`,
			ResponseLength: 104,
			Confidence:     "medium",
		},
		{
			VulnID:         "risk-3",
			Title:          "未授权访问",
			Type:           "未授权访问",
			Response:       `{"status_message":"找不到用户凭据","from":"weiban-jwt-auth","success":false,"status_code":10031}`,
			ResponseLength: 104,
		},
	}

	annotated := annotateUnauthorizedNoise(vulns)
	for _, vuln := range annotated {
		if vuln.DenyTemplateID == "" {
			t.Fatalf("expected deny template id for %#v", vuln)
		}
		if vuln.DenyTemplateKind != "auth_required" {
			t.Fatalf("deny template kind = %q, want auth_required", vuln.DenyTemplateKind)
		}
		if vuln.DenyTemplateCount != 3 {
			t.Fatalf("deny template count = %d, want 3", vuln.DenyTemplateCount)
		}
		if vuln.Confidence != "low" {
			t.Fatalf("confidence = %q, want low", vuln.Confidence)
		}
		if vuln.ConfidenceReason != lowConfidenceStatement {
			t.Fatalf("confidence reason = %q, want %q", vuln.ConfidenceReason, lowConfidenceStatement)
		}
	}
}

func TestAnnotateUnauthorizedNoiseSkipsSmallClusters(t *testing.T) {
	originalFactory := newDenyTemplateAIReviewer
	newDenyTemplateAIReviewer = func() denyTemplateAIReviewer { return nil }
	defer func() { newDenyTemplateAIReviewer = originalFactory }()
	resetDenyTemplateAIReviewCache()

	vulns := []database.VulnRecord{
		{
			VulnID:         "risk-1",
			Title:          "未授权访问",
			Type:           "未授权访问",
			Response:       `{"status_message":"找不到用户凭据","from":"weiban-jwt-auth","success":false,"status_code":10031}`,
			ResponseLength: 104,
			Confidence:     "medium",
		},
		{
			VulnID:         "risk-2",
			Title:          "未授权访问",
			Type:           "未授权访问",
			Response:       `{"status_message":"找不到用户凭据","from":"weiban-jwt-auth","success":false,"status_code":10031}`,
			ResponseLength: 104,
			Confidence:     "medium",
		},
	}

	annotated := annotateUnauthorizedNoise(vulns)
	for _, vuln := range annotated {
		if vuln.DenyTemplateID != "" {
			t.Fatalf("expected small cluster not to be annotated, got %#v", vuln)
		}
	}
}

func TestAnnotateUnauthorizedNoiseIgnoresVolatileErrorHint(t *testing.T) {
	originalFactory := newDenyTemplateAIReviewer
	newDenyTemplateAIReviewer = func() denyTemplateAIReviewer { return nil }
	defer func() { newDenyTemplateAIReviewer = originalFactory }()
	resetDenyTemplateAIReviewCache()

	vulns := []database.VulnRecord{
		{
			VulnID:           "risk-1",
			Title:            "未授权访问",
			Type:             "未授权访问",
			Response:         `{"error_hint":"wjmCi","status_code":10049,"status_message":"资源未找到","success":false}`,
			ResponseLength:   109,
			Confidence:       "high",
			ConfidenceReason: "响应体很短，可利用信息有限",
		},
		{
			VulnID:         "risk-2",
			Title:          "未授权访问",
			Type:           "未授权访问",
			Response:       `{"error_hint":"X9ksP","status_code":10049,"status_message":"资源未找到","success":false}`,
			ResponseLength: 109,
			Confidence:     "high",
		},
		{
			VulnID:         "risk-3",
			Title:          "未授权访问",
			Type:           "未授权访问",
			Response:       `{"error_hint":"aBc12","status_code":10049,"status_message":"资源未找到","success":false}`,
			ResponseLength: 109,
			Confidence:     "high",
		},
	}

	annotated := annotateUnauthorizedNoise(vulns)
	clusterID := annotated[0].DenyTemplateID
	if clusterID == "" {
		t.Fatal("expected volatile error_hint responses to be clustered")
	}

	for _, vuln := range annotated {
		if vuln.DenyTemplateID != clusterID {
			t.Fatalf("expected same cluster id, got %q and %q", clusterID, vuln.DenyTemplateID)
		}
		if vuln.DenyTemplateKind != "deny_template" {
			t.Fatalf("deny template kind = %q, want deny_template", vuln.DenyTemplateKind)
		}
		if vuln.DenyTemplateCount != 3 {
			t.Fatalf("deny template count = %d, want 3", vuln.DenyTemplateCount)
		}
		if vuln.Confidence != "low" {
			t.Fatalf("confidence = %q, want low", vuln.Confidence)
		}
		if vuln.ConfidenceReason != lowConfidenceStatement {
			t.Fatalf("confidence reason = %q, want %q", vuln.ConfidenceReason, lowConfidenceStatement)
		}
	}
}

func TestAnnotateUnauthorizedNoiseSkipsClusterWhenAIRejectsTemplate(t *testing.T) {
	originalFactory := newDenyTemplateAIReviewer
	newDenyTemplateAIReviewer = func() denyTemplateAIReviewer {
		return stubDenyTemplateAIReviewer{confirmed: false}
	}
	defer func() { newDenyTemplateAIReviewer = originalFactory }()
	resetDenyTemplateAIReviewCache()

	vulns := []database.VulnRecord{
		{
			VulnID:         "risk-1",
			Title:          "未授权访问",
			Type:           "未授权访问",
			Request:        "GET /ccat/step/getStepParamsByStepId?stepId=1 HTTP/1.1",
			Response:       `{"code":0,"message":"success","data":[]}`,
			ResponseLength: 40,
			Confidence:     "high",
		},
		{
			VulnID:         "risk-2",
			Title:          "未授权访问",
			Type:           "未授权访问",
			Request:        "GET /ccat/step/getStepParamsByStepId?stepId=2 HTTP/1.1",
			Response:       `{"code":0,"message":"success","data":[]}`,
			ResponseLength: 40,
			Confidence:     "high",
		},
		{
			VulnID:         "risk-3",
			Title:          "未授权访问",
			Type:           "未授权访问",
			Request:        "GET /ccat/step/getStepParamsByStepId?stepId=3 HTTP/1.1",
			Response:       `{"code":0,"message":"success","data":[]}`,
			ResponseLength: 40,
			Confidence:     "high",
		},
	}

	annotated := annotateUnauthorizedNoise(vulns)
	for _, vuln := range annotated {
		if vuln.DenyTemplateID != "" {
			t.Fatalf("expected AI to veto deny template cluster, got %#v", vuln)
		}
		if vuln.Confidence != "high" {
			t.Fatalf("confidence = %q, want original high", vuln.Confidence)
		}
		if !vuln.AIVerified {
			t.Fatalf("expected AI reviewed vuln to be marked ai verified, got %#v", vuln)
		}
	}
}

func TestAnnotateUnauthorizedNoiseKeepsClusterWhenAIConfirmsTemplate(t *testing.T) {
	originalFactory := newDenyTemplateAIReviewer
	newDenyTemplateAIReviewer = func() denyTemplateAIReviewer {
		return stubDenyTemplateAIReviewer{confirmed: true}
	}
	defer func() { newDenyTemplateAIReviewer = originalFactory }()
	resetDenyTemplateAIReviewCache()

	vulns := []database.VulnRecord{
		{
			VulnID:         "risk-1",
			Title:          "未授权访问",
			Type:           "未授权访问",
			Request:        "GET /api/user/profile HTTP/1.1",
			Response:       `{"status_message":"找不到用户凭据","from":"weiban-jwt-auth","success":false,"status_code":10031}`,
			ResponseLength: 104,
			Confidence:     "medium",
		},
		{
			VulnID:         "risk-2",
			Title:          "未授权访问",
			Type:           "未授权访问",
			Request:        "GET /api/user/menu HTTP/1.1",
			Response:       `{"status_message":"找不到用户凭据","from":"weiban-jwt-auth","success":false,"status_code":10031}`,
			ResponseLength: 104,
			Confidence:     "medium",
		},
		{
			VulnID:         "risk-3",
			Title:          "未授权访问",
			Type:           "未授权访问",
			Request:        "GET /api/user/roles HTTP/1.1",
			Response:       `{"status_message":"找不到用户凭据","from":"weiban-jwt-auth","success":false,"status_code":10031}`,
			ResponseLength: 104,
			Confidence:     "medium",
		},
	}

	annotated := annotateUnauthorizedNoise(vulns)
	for _, vuln := range annotated {
		if vuln.DenyTemplateID == "" {
			t.Fatalf("expected AI-confirmed cluster to be kept, got %#v", vuln)
		}
		if vuln.DenyTemplateKind != "auth_required" {
			t.Fatalf("deny template kind = %q, want auth_required", vuln.DenyTemplateKind)
		}
		if !vuln.AIVerified {
			t.Fatalf("expected AI reviewed vuln to be marked ai verified, got %#v", vuln)
		}
	}
}

func TestAnnotateUnauthorizedNoiseReusesCachedAIResult(t *testing.T) {
	originalFactory := newDenyTemplateAIReviewer
	callCount := 0
	newDenyTemplateAIReviewer = func() denyTemplateAIReviewer {
		return stubDenyTemplateAIReviewer{confirmed: true, calls: &callCount}
	}
	defer func() { newDenyTemplateAIReviewer = originalFactory }()
	resetDenyTemplateAIReviewCache()

	vulns := []database.VulnRecord{
		{
			VulnID:         "risk-1",
			Title:          "未授权访问",
			Type:           "未授权访问",
			Request:        "GET /api/user/profile HTTP/1.1",
			Response:       `{"status_message":"找不到用户凭据","from":"weiban-jwt-auth","success":false,"status_code":10031}`,
			ResponseLength: 104,
		},
		{
			VulnID:         "risk-2",
			Title:          "未授权访问",
			Type:           "未授权访问",
			Request:        "GET /api/user/menu HTTP/1.1",
			Response:       `{"status_message":"找不到用户凭据","from":"weiban-jwt-auth","success":false,"status_code":10031}`,
			ResponseLength: 104,
		},
		{
			VulnID:         "risk-3",
			Title:          "未授权访问",
			Type:           "未授权访问",
			Request:        "GET /api/user/roles HTTP/1.1",
			Response:       `{"status_message":"找不到用户凭据","from":"weiban-jwt-auth","success":false,"status_code":10031}`,
			ResponseLength: 104,
		},
	}

	first := annotateUnauthorizedNoise(append([]database.VulnRecord(nil), vulns...))
	second := annotateUnauthorizedNoise(append([]database.VulnRecord(nil), vulns...))

	if callCount != 1 {
		t.Fatalf("expected cached AI judgement to be reused, got %d calls", callCount)
	}

	for _, vuln := range append(first, second...) {
		if !vuln.AIVerified {
			t.Fatalf("expected cached AI result to still mark vuln as ai verified, got %#v", vuln)
		}
	}
}
