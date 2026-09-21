package sdk

import (
	"fmt"
	"strings"
	"time"

	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln/redirect"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln/upload"
)

// redirectFuzzer adapts the existing open-redirect detector to OperationSpec.
type redirectFuzzer struct{ cfg RedirectConfig }

// NewRedirectFuzzer creates an open-redirect fuzzer for operation templates.
func NewRedirectFuzzer(cfg RedirectConfig) OperationFuzzer { return redirectFuzzer{cfg: cfg} }

func (f redirectFuzzer) Name() string { return "redirect" }

func (f redirectFuzzer) Fuzz(spec crawl.OperationSpec) []database.VulnRecord {
	request, targets := apiRequestFromOperationSpec(spec)
	if targets == 0 || request.URL == "" {
		return nil
	}
	result, err := redirect.TestRedirectVulnerability(request, f.cfg)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return []database.VulnRecord{{
		VulnID:         "redirect-" + spec.ID,
		Title:          "开放重定向",
		Level:          "medium",
		Type:           "REDIRECT",
		URL:            request.URL,
		Method:         strings.ToUpper(strings.TrimSpace(spec.Method)),
		Request:        vuln.BuildRawRequest(request),
		Response:       result.Response,
		ResponseLength: len(result.Response),
		Description:    fmt.Sprintf("发现开放重定向漏洞，Payload: %s，原因: %s", result.Payload, result.Reason),
		CreatedAt:      time.Now(),
	}}
}

// fileUploadFuzzer adapts the existing file-upload detector to OperationSpec.
// The underlying detector only probes POST endpoints whose URL identifies an
// upload action; it builds its own multipart body and does not reuse template
// body values as a file payload.
type fileUploadFuzzer struct {
	cfg       UploadConfig
	aiChecker FileUploadAIChecker
}

// NewFileUploadFuzzer creates a file-upload fuzzer. aiChecker is optional but
// required by the core detector to confirm that an uploaded test file is
// accessible from the response.
func NewFileUploadFuzzer(cfg UploadConfig, aiChecker FileUploadAIChecker) OperationFuzzer {
	return fileUploadFuzzer{cfg: cfg, aiChecker: aiChecker}
}

func (f fileUploadFuzzer) Name() string { return "file-upload" }

func (f fileUploadFuzzer) Fuzz(spec crawl.OperationSpec) []database.VulnRecord {
	request, _ := apiRequestFromOperationSpec(spec)
	if request.URL == "" {
		return nil
	}
	result, err := upload.TestFileUpload(request, f.cfg, f.aiChecker)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	rawRequest := result.RawRequest
	if rawRequest == "" {
		rawRequest = vuln.BuildRawRequest(request)
	}
	description := fmt.Sprintf("发现文件上传漏洞，Payload: %s，原因: %s", result.Payload, result.Reason)
	if result.UploadURL != "" {
		description += fmt.Sprintf("，上传文件URL: %s", result.UploadURL)
	}
	return []database.VulnRecord{{
		VulnID:         "upload-" + spec.ID,
		Title:          "文件上传漏洞",
		Level:          "high",
		Type:           "FILE_UPLOAD",
		URL:            request.URL,
		Method:         strings.ToUpper(strings.TrimSpace(spec.Method)),
		Request:        rawRequest,
		Response:       result.Response,
		ResponseLength: len(result.Response),
		Description:    description,
		CreatedAt:      time.Now(),
	}}
}
