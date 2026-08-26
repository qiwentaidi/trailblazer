package crawl

import "testing"

func TestResolveResourceURLUsesPageDirectoryForRelativeLinks(t *testing.T) {
	got := ResolveResourceURL("https://web.cupdata.com/ncoas/0581/m/", "static/js/app.js")
	want := "https://web.cupdata.com/ncoas/0581/m/static/js/app.js"
	if got != want {
		t.Fatalf("ResolveResourceURL() = %q, want %q", got, want)
	}
}

func TestFormatURLUsesSharedResourceResolution(t *testing.T) {
	got := formatURL("https://web.cupdata.com/ncoas/0581/m/", "static/js/app.js")
	want := ResolveResourceURL("https://web.cupdata.com/ncoas/0581/m/", "static/js/app.js")
	if got != want {
		t.Fatalf("formatURL() = %q, want %q", got, want)
	}
}

func TestShouldRejectSensitiveCandidateForCodeFragments(t *testing.T) {
	candidates := []string{
		`password:De(c),rememberMe:S===void`,
		`username:[{required:!0,trigger:"`,
		`password:P),type:"`,
	}

	for _, candidate := range candidates {
		if !shouldRejectSensitiveCandidate(candidate) {
			t.Fatalf("expected candidate to be locally rejected: %q", candidate)
		}
	}
}

func TestShouldConfirmSensitiveCandidateForWeakCredentials(t *testing.T) {
	candidates := []string{
		`username:"admin"`,
		`password:"admin123"`,
	}

	for _, candidate := range candidates {
		if !shouldConfirmSensitiveCandidate(candidate) {
			t.Fatalf("expected candidate to be locally confirmed: %q", candidate)
		}
	}
}

func TestShouldNotConfirmCodeLikeCredentialCandidate(t *testing.T) {
	candidate := `password:De(c),rememberMe:S===void`
	if shouldConfirmSensitiveCandidate(candidate) {
		t.Fatalf("expected code-like candidate not to be locally confirmed: %q", candidate)
	}
}
