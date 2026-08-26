package database

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSaveJSResourceNormalizesUTF8(t *testing.T) {
	previous := DB
	t.Cleanup(func() {
		if DB != nil && DB != previous {
			_ = DB.Close()
		}
		DB = previous
	})
	if err := InitSQLite(filepath.Join(t.TempDir(), "scan.db")); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	resource := JSResource{
		TaskID: "task-utf8", Version: 1, URL: "https://example.test/app.js",
		Content:   "\ufeffconst title = '中文';\r\n" + string([]byte{0xff}) + "tail",
		FetchedAt: time.Now(),
	}
	if err := SaveJSResource(resource); err != nil {
		t.Fatalf("SaveJSResource() error = %v", err)
	}
	resources, err := QueryJSByTaskID(resource.TaskID, 1)
	if err != nil {
		t.Fatalf("QueryJSByTaskID() error = %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("resource count = %d, want 1", len(resources))
	}
	if strings.HasPrefix(resources[0].Content, "\ufeff") || strings.Contains(resources[0].Content, "\r") {
		t.Fatalf("content was not normalized: %q", resources[0].Content)
	}
	if !strings.Contains(resources[0].Content, "中文") || !strings.Contains(resources[0].Content, "\uFFFD") {
		t.Fatalf("content did not retain UTF-8 text and replace invalid bytes: %q", resources[0].Content)
	}
}
