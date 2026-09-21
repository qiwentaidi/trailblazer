package database

import (
	"github.com/qiwentaidi/katana/pkg/apiaudit"
	"strings"
	"testing"
)

func TestAuthorizationRecordUsesActualReasonAndEvidence(t *testing.T) {
	verdict := apiaudit.AuthzVerdict{Confidence: "low", Reasons: []string{"基线缺少 JSON 结构证据，需人工复核"}, Baseline: &apiaudit.HTTPExchange{URL: "https://example.test/users/123", Method: "POST"}, Anonymous: &apiaudit.HTTPExchange{Request: "POST /users/123 HTTP/1.1\r\n\r\n", Response: "HTTP/1.1 200 OK\r\n\r\nhello", ContentType: "text/plain", ResponseLength: 5, ResponseBodyRecorded: true}}
	record := NewAuthorizationVulnRecord("task", 1, "op", "https://example.test/users/999", "GET", verdict)
	if record.Description != verdict.Reasons[0] || strings.Contains(record.Description, "确认业务响应结构一致") {
		t.Fatalf("misleading description: %s", record.Description)
	}
	if record.URL != verdict.Baseline.URL || record.Method != "POST" || record.ResponseLength != 5 || record.Response != verdict.Anonymous.Response || record.AuthorizationEvidence == nil {
		t.Fatalf("evidence lost: %+v", record)
	}
}
