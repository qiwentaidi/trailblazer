package web

import (
	"strings"
	"testing"
)

func TestBuildReportHTMLIncludesSearchControls(t *testing.T) {
	snapshot := reportSnapshot{}
	snapshot.Meta.TaskID = "task-1"
	snapshot.Meta.TaskName = "测试任务"
	snapshot.Meta.Status = "completed"
	snapshot.Meta.VersionLabel = "最新扫描"
	snapshot.Meta.GeneratedAt = "2026-04-16 12:00:00"
	snapshot.Meta.Targets = []string{"https://example.com"}
	snapshot.Risks.PageSize = 10
	snapshot.Risks.Items = []reportRiskItem{
		{
			Kind:            "single",
			ID:              "risk-1",
			Title:           "测试风险",
			Level:           "high",
			LevelLabel:      "高危",
			Confidence:      "high",
			ConfidenceLabel: "高可信",
			Type:            "xss",
			URL:             "https://example.com/api",
			Method:          "GET",
			Summary:         "摘要",
			Description:     "描述",
			RequestPreview:  "GET /api",
			ResponsePreview: "ok",
			CreatedAt:       "2026-04-16 10:00:00",
		},
	}
	snapshot.Assets.PageSize = 10
	snapshot.Assets.Rows = []reportAssetRow{
		{
			Type:      "email",
			TypeLabel: "邮箱",
			Value:     "admin@example.com",
			Source:    "站点树",
		},
	}

	html, err := buildReportHTML(snapshot)
	if err != nil {
		t.Fatalf("buildReportHTML returned error: %v", err)
	}

	checks := []string{
		`id="risk-search"`,
		`id="asset-search"`,
		`id="risk-count"`,
		`id="asset-count"`,
		`const filterRiskItems =`,
		`const filterAssetRows =`,
		`检索标题、URL、摘要、描述、请求包、响应包`,
		`检索类型、内容、来源`,
		`没有匹配的风险结果`,
		`没有匹配的资产结果`,
	}

	for _, check := range checks {
		if !strings.Contains(html, check) {
			t.Fatalf("generated html missing %q", check)
		}
	}
}
