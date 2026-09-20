package crawl

import (
	"strings"
	"testing"
	"time"
)

func TestResolveStaticIdentifierRootsChainDepthBudget(t *testing.T) {
	// A cyclic identifier definition must terminate instead of recursing
	// without bound.
	cyclic := `var baseA = baseB + "/a"; var baseB = baseA + "/b";`
	start := time.Now()
	roots := resolveStaticIdentifierRoots(cyclic, "baseA")
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cyclic identifier resolution exceeded budget: %s", elapsed)
	}
	t.Logf("cyclic resolution returned %v", roots)

	// A long linear chain resolves within the depth budget and terminates.
	var chain strings.Builder
	chain.WriteString(`var c0 = "/api";`)
	for i := 1; i < 40; i++ {
		chain.WriteString("var c" + strings.Repeat("", 0) + "")
		chain.WriteString("var c" + intName(i) + " = c" + intName(i-1) + ";")
	}
	start = time.Now()
	roots = resolveStaticIdentifierRoots(chain.String(), "c39")
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("chain resolution exceeded budget: %s", elapsed)
	}
	// Beyond the depth budget the chain resolves to nothing rather than
	// hanging; shallow chains still resolve.
	shallow := `var s0 = "/api"; var s1 = s0; var s2 = s1;`
	if got := resolveStaticIdentifierRoots(shallow, "s2"); len(got) == 0 || got[0] != "/api" {
		t.Fatalf("expected shallow chain to resolve, got %v", got)
	}
	_ = roots
}

func intName(i int) string {
	digits := "0123456789"
	if i < 10 {
		return string(digits[i])
	}
	return intName(i/10) + string(digits[i%10])
}
