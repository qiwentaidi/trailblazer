package crawl

import "testing"

func TestClassifyUnauthorizedFindingUsesSpecificBusinessQueryLabel(t *testing.T) {
	name := ClassifyUnauthorizedFinding(
		"https://example.test/ncoas/0581/qy/api/query",
		"GET",
		`{"data":{"records":[{"name":"example"}]}}`,
		"internal_business",
	)
	if name.Category != "访问控制缺陷" {
		t.Fatalf("category = %q", name.Category)
	}
	if name.Subcategory != "未授权业务查询" {
		t.Fatalf("subcategory = %q", name.Subcategory)
	}
	if name.Title != "业务查询结果未授权查询" {
		t.Fatalf("title = %q", name.Title)
	}
	if name.Source != "rule" {
		t.Fatalf("source = %q", name.Source)
	}
}

func TestNormalizeUnauthorizedFindingNameRejectsFreeFormAIClaim(t *testing.T) {
	name := normalizeUnauthorizedFindingName(UnauthorizedFindingName{
		Category:       "访问控制缺陷",
		Subcategory:    "任意管理员接管",
		BusinessObject: "后台",
		Source:         "ai",
	}, "https://example.test/api/query", "GET", "{}", "internal_business")
	if name.Source != "rule" || name.Subcategory != "未授权业务查询" {
		t.Fatalf("invalid AI label should fall back to rule, got %#v", name)
	}
}

func TestClassifyUnauthorizedFindingUsesSensitiveReadLabel(t *testing.T) {
	name := ClassifyUnauthorizedFinding("https://example.test/api/user/list", "GET", `{}`, "sensitive_data")
	if name.Subcategory != "未授权敏感信息读取" {
		t.Fatalf("subcategory = %q", name.Subcategory)
	}
}
