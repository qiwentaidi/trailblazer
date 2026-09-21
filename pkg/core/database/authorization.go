package database

import (
	"strings"
	"time"

	"github.com/qiwentaidi/katana/pkg/apiaudit"
)

// NewAuthorizationVulnRecord preserves comparative evidence for both SDK pipelines.
func NewAuthorizationVulnRecord(taskID string, version int, operationID, url, method string, verdict apiaudit.AuthzVerdict) VulnRecord {
	level := "medium"
	if verdict.Confidence == "high" {
		level = "high"
	}
	reason := strings.Join(verdict.Reasons, "；")
	if reason == "" {
		reason = "认证对照未记录判定理由，需人工复核。"
	}
	if verdict.Baseline != nil {
		if verdict.Baseline.URL != "" {
			url = verdict.Baseline.URL
		}
		if verdict.Baseline.Method != "" {
			method = verdict.Baseline.Method
		}
	}
	record := VulnRecord{
		TaskID:                taskID,
		Version:               version,
		VulnID:                "authz-" + operationID,
		Title:                 "未授权访问（认证对照）",
		Level:                 level,
		Type:                  "authorization",
		URL:                   url,
		Method:                method,
		Confidence:            verdict.Confidence,
		ConfidenceReason:      reason,
		Description:           reason,
		CreatedAt:             time.Now(),
		AuthorizationEvidence: &verdict,
	}
	if verdict.Anonymous != nil {
		record.Request = verdict.Anonymous.Request
		record.Response = verdict.Anonymous.Response
		record.ResponseType = verdict.Anonymous.ContentType
		record.ResponseLength = verdict.Anonymous.ResponseLength
	}
	return record
}
