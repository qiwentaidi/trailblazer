package crawl

import (
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/qiwentaidi/clients"
	arrayutil "github.com/qiwentaidi/utils/array"
)

const (
	defaultFrontierMaxDepth = 1
	defaultFrontierMaxPages = 12
)

var (
	discoveryLocPattern       = regexp.MustCompile(`(?is)<loc>\s*([^<]+)\s*</loc>`)
	discoveryRobotLinePattern = regexp.MustCompile(`(?im)^\s*(?:sitemap|allow|disallow)\s*:\s*([^\s#]+)`)
	discoveryURLPattern       = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>]+`)
)

var knownDiscoveryPaths = []string{
	"/robots.txt",
	"/sitemap.xml",
	"/sitemap_index.xml",
	"/manifest.json",
	"/asset-manifest.json",
	"/service-worker.js",
	"/sw.js",
}

type DiscoveryFrontierOptions struct {
	MaxDepth    int
	MaxPages    int
	BlackDomain []string
}

type discoveryQueueItem struct {
	URL   string
	Depth int
}

// DiscoverKnownFileLinks fetches common metadata files that often expose hidden
// pages, JavaScript bundles, API routes, and sitemap entries.
func DiscoverKnownFileLinks(targetURL string, blackDomain []string) []string {
	baseURL := siteBaseURL(targetURL)
	if baseURL == "" {
		return nil
	}

	filter := Filter{}
	discovered := make([]string, 0, len(knownDiscoveryPaths)*2)
	for _, candidatePath := range knownDiscoveryPaths {
		knownURL := baseURL + candidatePath
		if filter.IsBlacklist(knownURL, blackDomain) {
			continue
		}

		resp, err := clients.SimpleGet(knownURL, clients.NewRestyClient(nil, true))
		if err != nil || resp == nil || resp.StatusCode() >= 400 {
			continue
		}

		discovered = append(discovered, knownURL)
		discovered = append(discovered, extractDiscoveryLinks(knownURL, string(resp.Body()))...)
	}

	return filter.Blacklist(arrayutil.RemoveDuplicates(discovered), blackDomain)
}

// DiscoverFrontierLinks performs a small same-site crawl over discovered pages.
// It is intentionally budgeted so it expands coverage without replacing the
// browser runtime capture path.
func DiscoverFrontierLinks(targetURL string, seeds []string, options DiscoveryFrontierOptions) []string {
	baseURL := siteBaseURL(targetURL)
	if baseURL == "" {
		return nil
	}
	baseParsed, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	maxDepth := options.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultFrontierMaxDepth
	}
	maxPages := options.MaxPages
	if maxPages <= 0 {
		maxPages = defaultFrontierMaxPages
	}

	filter := Filter{}
	queue := []discoveryQueueItem{{URL: targetURL, Depth: 0}}
	for _, seed := range seeds {
		if resolved := resolveDiscoveryURL(baseURL, seed); resolved != "" {
			queue = append(queue, discoveryQueueItem{URL: resolved, Depth: 0})
		}
	}

	visited := make(map[string]struct{}, len(queue))
	discovered := make([]string, 0, maxPages*8)
	fetched := 0

	for len(queue) > 0 && fetched < maxPages {
		item := queue[0]
		queue = queue[1:]

		current := strings.TrimSpace(item.URL)
		if current == "" {
			continue
		}
		if _, ok := visited[current]; ok {
			continue
		}
		visited[current] = struct{}{}

		if filter.IsBlacklist(current, options.BlackDomain) || !sameDiscoveryHost(baseParsed, current) || !shouldFetchDiscoveryFrontierURL(current) {
			continue
		}

		resp, err := clients.SimpleGet(current, clients.NewRestyClient(nil, true))
		if err != nil || resp == nil || resp.StatusCode() >= 400 {
			continue
		}
		fetched++

		links := extractDiscoveryLinks(current, string(resp.Body()))
		discovered = append(discovered, current)
		discovered = append(discovered, links...)
		if item.Depth >= maxDepth {
			continue
		}

		for _, link := range links {
			if _, ok := visited[link]; ok {
				continue
			}
			if sameDiscoveryHost(baseParsed, link) && shouldFetchDiscoveryFrontierURL(link) {
				queue = append(queue, discoveryQueueItem{URL: link, Depth: item.Depth + 1})
			}
		}
	}

	return filter.Blacklist(arrayutil.RemoveDuplicates(discovered), options.BlackDomain)
}

func extractDiscoveryLinks(baseURL, content string) []string {
	if strings.TrimSpace(baseURL) == "" || strings.TrimSpace(content) == "" {
		return nil
	}
	if len(content) > maxResponseSize {
		content = content[:maxResponseSize]
	}

	candidates := make([]string, 0, 16)
	for _, match := range discoveryLocPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			candidates = append(candidates, match[1])
		}
	}
	for _, match := range discoveryRobotLinePattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 && match[1] != "*" && match[1] != "/" {
			candidates = append(candidates, match[1])
		}
	}
	for _, raw := range discoveryURLPattern.FindAllString(content, -1) {
		candidates = append(candidates, raw)
	}
	for _, raw := range Link.FindAllString(content, -1) {
		candidates = append(candidates, raw)
	}

	resolved := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if value := resolveDiscoveryURL(baseURL, cleanDiscoveryCandidate(candidate)); value != "" {
			resolved = append(resolved, value)
		}
	}
	return arrayutil.RemoveDuplicates(resolved)
}

func cleanDiscoveryCandidate(candidate string) string {
	candidate = html.UnescapeString(strings.TrimSpace(candidate))
	candidate = strings.Trim(candidate, `"'`+"`")
	candidate = strings.TrimRight(candidate, ".,;)")
	return strings.TrimSpace(candidate)
}

func resolveDiscoveryURL(baseURL, candidate string) string {
	candidate = cleanDiscoveryCandidate(candidate)
	if candidate == "" || candidate == "#" || strings.HasPrefix(candidate, "javascript:") || strings.HasPrefix(candidate, "data:") {
		return ""
	}

	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return ""
	}

	parsed, err := url.Parse(candidate)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(parsed)
	resolved.Fragment = ""
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}
	return strings.TrimRight(resolved.String(), "#")
}

func siteBaseURL(targetURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
}

func sameDiscoveryHost(base *url.URL, candidate string) bool {
	parsed, err := url.Parse(strings.TrimSpace(candidate))
	if err != nil || parsed.Host == "" {
		return false
	}
	return strings.EqualFold(parsed.Host, base.Host)
}

func shouldFetchDiscoveryFrontierURL(rawURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	if path == "" || strings.HasSuffix(path, "/") {
		return true
	}
	for _, suffix := range []string{".html", ".htm", ".json", ".xml", ".txt", ".js"} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	if looksLikeDiscoveryAPIPath(path) {
		return false
	}
	if strings.Contains(path, ".") {
		return false
	}
	return true
}

func looksLikeDiscoveryAPIPath(pathValue string) bool {
	pathValue = strings.TrimSpace(pathValue)
	if pathValue == "" {
		return false
	}
	if allowSimple.MatchString(pathValue) {
		return true
	}
	for _, segment := range strings.Split(strings.Trim(pathValue, "/"), "/") {
		if segmentApiRe.MatchString(segment) {
			return true
		}
	}
	return false
}
