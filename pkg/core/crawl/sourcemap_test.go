package crawl

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveSourceMapOutputPathKeepsSourcesUnderRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "example.js")

	got, err := resolveSourceMapOutputPath(root, "webpack://./src/app.js")
	if err != nil {
		t.Fatalf("expected safe source path, got error: %v", err)
	}

	want := filepath.Join(root, "src", "app.js")
	if got != want {
		t.Fatalf("resolved source map path = %q, want %q", got, want)
	}
}

func TestResolveSourceMapOutputPathRejectsTraversal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "example.js")
	paths := []string{
		"../../outside.js",
		"webpack://../../outside.js",
		"/tmp/outside.js",
	}

	for _, sourcePath := range paths {
		t.Run(strings.ReplaceAll(sourcePath, "/", "_"), func(t *testing.T) {
			if got, err := resolveSourceMapOutputPath(root, sourcePath); err == nil {
				t.Fatalf("expected source path %q to be rejected, got %q", sourcePath, got)
			}
		})
	}
}
