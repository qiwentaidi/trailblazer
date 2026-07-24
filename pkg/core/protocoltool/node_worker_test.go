package protocoltool

import (
	"strings"
	"testing"
)

func TestNodeWorkerCommandArgsEnforceIsolation(t *testing.T) {
	args := nodeWorkerCommandArgs("node:22-alpine")
	joined := strings.Join(args, " ")

	for _, required := range []string{
		"--network none",
		"--read-only",
		"--user 65532:65532",
		"--cap-drop ALL",
		"--security-opt no-new-privileges",
		"--pids-limit 64",
		"--memory 256m",
		"--memory-swap 256m",
		"--cpus 1",
		"--tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("worker command is missing isolation option %q: %s", required, joined)
		}
	}

	if strings.Contains(joined, "--volume") || strings.Contains(joined, " -v ") {
		t.Fatalf("worker command must not mount host paths: %s", joined)
	}
}

func TestReadLimitedDetectsOversizedOutput(t *testing.T) {
	result := readLimited(strings.NewReader("123456"), 5)
	if !result.exceeded {
		t.Fatal("expected oversized output to be detected")
	}
	if string(result.data) != "12345" {
		t.Fatalf("limited output = %q, want %q", result.data, "12345")
	}
}
