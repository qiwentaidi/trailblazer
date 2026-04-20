package database

import (
	"fmt"
	"testing"
	"time"
)

func TestToLegacyAssetRecordFlattensAssetObjects(t *testing.T) {
	record := toLegacyAssetRecord(AssetRecord{
		TaskID:  "task-1",
		Version: 2,
		Email: []AssetValue{
			{Value: "antd@2.0", Source: []string{"a.js"}},
			{Value: "antd@2.0", Source: []string{"b.js"}},
			{Value: "demo@example.com", Source: []string{"c.js"}},
		},
		APIRouter: []AssetValue{
			{Value: "/api/demo", Source: []string{"main.js"}},
		},
		CreatedAt: time.Unix(1700000000, 0),
	})

	if len(record.Email) != 2 {
		t.Fatalf("expected flattened emails to deduplicate by value, got %#v", record.Email)
	}
	if record.Email[0] != "antd@2.0" || record.Email[1] != "demo@example.com" {
		t.Fatalf("unexpected flattened emails: %#v", record.Email)
	}
	if len(record.APIRouter) != 1 || record.APIRouter[0] != "/api/demo" {
		t.Fatalf("unexpected flattened api routers: %#v", record.APIRouter)
	}
}

func TestIsLegacyAssetMappingErrorRecognizesTextFieldConflict(t *testing.T) {
	err := fmt.Errorf(`error response from ES: [400 Bad Request] {"error":{"type":"document_parsing_exception","reason":"failed to parse field [email]","caused_by":{"type":"illegal_argument_exception","reason":"Expected text at 1:72 but found START_OBJECT"}},"status":400}`)
	if !isLegacyAssetMappingError(err) {
		t.Fatal("expected legacy asset mapping error to be recognized")
	}
}
