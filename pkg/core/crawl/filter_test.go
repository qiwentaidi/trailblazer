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

func TestFilterAPIRoutesDropsWhitespaceAndContentTypeNoise(t *testing.T) {
	filter := &Filter{}

	routes := []string{
		"/ page",
		"/api/v1/users",
		"multipart/form-data",
		"application/json",
		"/api/order/list",
	}

	filtered := filter.FilterAPIRoutes(routes)

	for _, rejected := range []string{
		"/ page",
		"multipart/form-data",
		"application/json",
	} {
		for _, got := range filtered {
			if got == rejected {
				t.Fatalf("expected noisy route %q to be filtered out, got %#v", rejected, filtered)
			}
		}
	}

	for _, kept := range []string{
		"/api/v1/users",
		"/api/order/list",
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

func TestFilterAPIRoutesDropsSuspiciousShortSingleSegmentRoutes(t *testing.T) {
	filter := &Filter{}

	routes := []string{
		"/AB",
		"/A1",
		"/POA",
		"/SeX",
		"/T2A",
		"/byt",
		"/a/b",
		"/a/i",
		"/im",
		"/v1",
		"/api/v1/users",
		"/ccat/step/getSteps",
		"/im/20231030/653f182403668167a4489460",
		"/sms",
	}

	filtered := filter.FilterAPIRoutes(routes)

	for _, rejected := range []string{
		"/AB",
		"/A1",
		"/POA",
		"/SeX",
		"/T2A",
	} {
		for _, got := range filtered {
			if got == rejected {
				t.Fatalf("expected suspicious short route %q to be filtered out, got %#v", rejected, filtered)
			}
		}
	}

	for _, kept := range []string{
		"/byt",
		"/a/b",
		"/a/i",
		"/api/v1/users",
		"/im",
		"/v1",
		"/ccat/step/getSteps",
		"/im/20231030/653f182403668167a4489460",
		"/sms",
	} {
		found := false
		for _, got := range filtered {
			if got == kept {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected route %q to be kept, got %#v", kept, filtered)
		}
	}
}

func TestAPIRootsKeepsPrefixedAPISegment(t *testing.T) {
	filter := &Filter{}

	roots := filter.APIRoots([]string{
		"/ccat/api/getApisGroupByApp",
		"/ccat/api/refreshApiInfoByInterfaceName",
	}, 1)

	expected := map[string]bool{
		"/api/":      true,
		"/ccat/api/": true,
	}

	for _, root := range roots {
		delete(expected, root)
	}
	if len(expected) != 0 {
		t.Fatalf("expected prefixed api roots to be preserved, missing %#v from %#v", expected, roots)
	}
}

func TestAPIRootsKeepsPrefixedVersionedAPISegment(t *testing.T) {
	filter := &Filter{}

	roots := filter.APIRoots([]string{
		"/gateway/api/v1/orders/list",
	}, 1)

	expected := map[string]bool{
		"/api/v1/":         true,
		"/gateway/api/v1/": true,
	}

	for _, root := range roots {
		delete(expected, root)
	}
	if len(expected) != 0 {
		t.Fatalf("expected versioned prefixed api roots to be preserved, missing %#v from %#v", expected, roots)
	}
}

func TestDeduplicateSimilarAPIRoutesKeepsOneDynamicPathRepresentative(t *testing.T) {
	routes := DeduplicateSimilarAPIRoutes([]string{
		"https://example.com/api/users/123",
		"https://example.com/api/users/456",
		"https://example.com/api/users/789?detail=true",
		"https://example.com/api/users/789?brief=true",
		"/api/orders/550e8400-e29b-41d4-a716-446655440000",
		"/api/orders/550e8400-e29b-41d4-a716-446655440001",
	})

	want := []string{
		"https://example.com/api/users/123",
		"https://example.com/api/users/789?detail=true",
		"https://example.com/api/users/789?brief=true",
		"/api/orders/550e8400-e29b-41d4-a716-446655440000",
	}
	if len(routes) != len(want) {
		t.Fatalf("expected %d deduped routes, got %#v", len(want), routes)
	}
	for idx, expected := range want {
		if routes[idx] != expected {
			t.Fatalf("route[%d] = %q, want %q; all routes %#v", idx, routes[idx], expected, routes)
		}
	}
}
