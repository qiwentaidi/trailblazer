package scanexec

import (
	"strings"
	"sync"
	"testing"
	"time"
	"trailblazer/pkg/core/database"
	"trailblazer/pkg/core/structs"
)

type denyTemplateReviewerStub struct {
	confirmed bool
}

func (s denyTemplateReviewerStub) JudgeDenyTemplate(requestPreview, responsePreview string) (bool, string, error) {
	return s.confirmed, "stub", nil
}

func TestBindStaticContexts(t *testing.T) {
	vulns := []database.VulnRecord{
		{
			URL: "https://example.com/api/common/getCitys",
		},
	}
	jsResources := []database.JSResource{
		{
			URL:       "https://example.com/app.js",
			Content:   `axios.get("/api/common/getCitys").then(renderCities)`,
			FetchedAt: time.Now(),
		},
		{
			URL:       "https://example.com/other.js",
			Content:   `fetch("/api/other/demo")`,
			FetchedAt: time.Now(),
		},
	}

	bindStaticContexts(vulns, jsResources)

	if len(vulns[0].StaticContexts) != 1 {
		t.Fatalf("expected 1 static context, got %d", len(vulns[0].StaticContexts))
	}
	if vulns[0].StaticContexts[0].SourceURL != "https://example.com/app.js" {
		t.Fatalf("unexpected source url: %s", vulns[0].StaticContexts[0].SourceURL)
	}
	if !strings.Contains(vulns[0].StaticContexts[0].Snippet, "/api/common/getCitys") {
		t.Fatalf("expected snippet to contain matched path, got %q", vulns[0].StaticContexts[0].Snippet)
	}
}

func TestBuildAssetInfoPreservesAIVerifiedFlag(t *testing.T) {
	assets := buildAssetInfo(structs.FindSomething{
		Sensitive: []structs.InfoSource{
			{Filed: "password=adminTest", Source: "https://example.com/app.js", AIVerified: true},
		},
	})

	if len(assets.Sensitive) != 1 {
		t.Fatalf("expected 1 sensitive asset, got %d", len(assets.Sensitive))
	}
	if !assets.Sensitive[0].AIVerified {
		t.Fatal("expected sensitive asset to preserve aiVerified")
	}
}

func TestAnnotateUnauthorizedNoiseMarksClusterAsAIVerified(t *testing.T) {
	denyTemplateAIReviewCache = sync.Map{}

	vulns := []database.VulnRecord{
		{
			Title:          "未授权访问",
			Type:           "未授权访问",
			URL:            "https://example.com/api/a",
			Request:        "GET /api/a HTTP/1.1",
			Response:       `{"success":false,"message":"请先登录","trace_id":"abc"}`,
			ResponseLength: 64,
		},
		{
			Title:          "未授权访问",
			Type:           "未授权访问",
			URL:            "https://example.com/api/b",
			Request:        "GET /api/b HTTP/1.1",
			Response:       `{"success":false,"message":"请先登录","trace_id":"def"}`,
			ResponseLength: 64,
		},
		{
			Title:          "未授权访问",
			Type:           "未授权访问",
			URL:            "https://example.com/api/c",
			Request:        "GET /api/c HTTP/1.1",
			Response:       `{"success":false,"message":"请先登录","trace_id":"ghi"}`,
			ResponseLength: 64,
		},
	}

	annotated := annotateUnauthorizedNoise(vulns, denyTemplateReviewerStub{confirmed: true})
	for _, vuln := range annotated {
		if !vuln.AIVerified {
			t.Fatalf("expected vuln %s to be ai verified", vuln.URL)
		}
		if vuln.DenyTemplateID == "" {
			t.Fatalf("expected vuln %s to receive deny template id", vuln.URL)
		}
	}
}
