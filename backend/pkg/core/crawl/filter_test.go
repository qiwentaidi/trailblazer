package crawl

import "testing"

func TestFilterAPIRoutesDropsSuspiciousLocalizedSlugs(t *testing.T) {
	filter := &Filter{}

	routes := []string{
		"https://uc.caocaoglobal.com/api/v1/صفحة",
		"https://uc.caocaoglobal.com/api/v1/страница",
		"https://uc.caocaoglobal.com/api/v1/σελιδα",
		"https://uc.caocaoglobal.com/api/v1/หน้า",
		"https://uc.caocaoglobal.com/api/v1/users",
		"https://uc.caocaoglobal.com/api/v1/orders/list",
	}

	filtered := filter.FilterAPIRoutes(routes)

	for _, rejected := range []string{
		"https://uc.caocaoglobal.com/api/v1/صفحة",
		"https://uc.caocaoglobal.com/api/v1/страница",
		"https://uc.caocaoglobal.com/api/v1/σελιδα",
		"https://uc.caocaoglobal.com/api/v1/หน้า",
	} {
		for _, got := range filtered {
			if got == rejected {
				t.Fatalf("expected suspicious localized route %q to be filtered out, got %#v", rejected, filtered)
			}
		}
	}

	for _, kept := range []string{
		"https://uc.caocaoglobal.com/api/v1/users",
		"https://uc.caocaoglobal.com/api/v1/orders/list",
	} {
		found := false
		for _, got := range filtered {
			if got == kept {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected normal api route %q to be kept, got %#v", kept, filtered)
		}
	}
}

func TestFilterAPIRoutesKeepsChineseBusinessRoutes(t *testing.T) {
	filter := &Filter{}

	routes := []string{
		"/api/v1/用户列表",
		"/api/v1/订单详情",
	}

	filtered := filter.FilterAPIRoutes(routes)
	if len(filtered) != len(routes) {
		t.Fatalf("expected chinese business routes to be kept, got %#v", filtered)
	}
}

func TestFilterAPIRoutesDropsDotSegments(t *testing.T) {
	filter := &Filter{}

	routes := []string{
		"http://wecombot.caocaokeji.cn/..",
		"/api/../admin",
		"/api/%2e%2e/config",
		"/api/v1/users",
	}

	filtered := filter.FilterAPIRoutes(routes)

	for _, rejected := range []string{
		"http://wecombot.caocaokeji.cn/..",
		"/api/../admin",
		"/api/%2e%2e/config",
	} {
		for _, got := range filtered {
			if got == rejected {
				t.Fatalf("expected dot-segment route %q to be filtered out, got %#v", rejected, filtered)
			}
		}
	}

	if len(filtered) != 1 || filtered[0] != "/api/v1/users" {
		t.Fatalf("expected only normal api route to remain, got %#v", filtered)
	}
}
