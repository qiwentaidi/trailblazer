package crawl

import (
	"net/url"
	"strings"
)

// ResolveResourceURL resolves a discovered resource link using browser URL
// semantics: relative paths use the current page directory, while leading
// slash paths stay rooted at the origin.
func ResolveResourceURL(pageURL, resourceLink string) string {
	resourceLink = strings.TrimSpace(resourceLink)
	if resourceLink == "" {
		return ""
	}

	base, err := url.Parse(strings.TrimSpace(pageURL))
	if err != nil || base == nil || base.Scheme == "" || base.Host == "" {
		return resourceLink
	}

	parsed, err := url.Parse(resourceLink)
	if err != nil {
		return resourceLink
	}
	return base.ResolveReference(parsed).String()
}
