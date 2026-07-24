package crawl

import "testing"

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
