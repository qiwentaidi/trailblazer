package crawl

import "testing"

func TestExtractDiscoveryLinksFromKnownFiles(t *testing.T) {
	content := `
Sitemap: /sitemap.xml
Disallow: /hidden/admin
{"start_url":"/app","precache":["/static/app.js","/api/users?id=1"]}
<url><loc>https://example.com/api/orders?page=1</loc></url>
`

	links := extractDiscoveryLinks("https://example.com/robots.txt", content)
	want := map[string]bool{
		"https://example.com/sitemap.xml":       false,
		"https://example.com/hidden/admin":      false,
		"https://example.com/static/app.js":     false,
		"https://example.com/api/users?id=1":    false,
		"https://example.com/api/orders?page=1": false,
	}

	for _, link := range links {
		if _, ok := want[link]; ok {
			want[link] = true
		}
	}
	for link, found := range want {
		if !found {
			t.Fatalf("expected discovered link %s in %#v", link, links)
		}
	}
}

func TestShouldFetchDiscoveryFrontierURLSkipsBinaryAssets(t *testing.T) {
	if shouldFetchDiscoveryFrontierURL("https://example.com/assets/logo.png") {
		t.Fatal("expected binary asset to be skipped")
	}
	if !shouldFetchDiscoveryFrontierURL("https://example.com/service-worker.js") {
		t.Fatal("expected service worker to be fetchable")
	}
	if !shouldFetchDiscoveryFrontierURL("https://example.com/admin") {
		t.Fatal("expected extensionless page to be fetchable")
	}
	if shouldFetchDiscoveryFrontierURL("https://example.com/api/users") {
		t.Fatal("expected extensionless api route to be kept out of frontier fetches")
	}
}
