package lib

import (
	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
)

// Configuration aliases keep integrations from depending on the YAML loader's
// internal package layout while preserving the existing ScanOptions fields.
type (
	ConfigYAML          = config.ConfigYAML
	SQLInjectionConfig  = config.SQLInjectionConfig
	SQLiPayloadRule     = config.SQLiPayloadRule
	LFIConfig           = config.LFIConfig
	LFIPayloadRule      = config.LFIPayloadRule
	SSRFConfig          = config.SSRFConfig
	RedirectConfig      = config.RedirectConfig
	XSSConfig           = config.XSSConfig
	XSSPayloadRule      = config.XSSPayloadRule
	UploadConfig        = config.UploadConfig
	ScanDataStore       = database.ScanDataStore
	MemoryScanDataStore = database.MemoryScanDataStore
	JSResource          = database.JSResource
	APIResource         = database.APIResource
	ProtocolTraceRecord = database.ProtocolTraceRecord

	StaticProtocolEndpoint       = crawl.StaticProtocolEndpoint
	StaticProtocolProfile        = crawl.StaticProtocolProfile
	StaticProtocolAnalysisResult = crawl.StaticProtocolAnalysisResult
)

// NewMemoryScanDataStore creates an in-memory store for one scan session.
var NewMemoryScanDataStore = database.NewMemoryScanDataStore

// AnalyzeStoredJSProtocolsWithStore analyzes stored JS protocol traces without
// requiring callers to import the crawl implementation package directly.
func AnalyzeStoredJSProtocolsWithStore(taskID string, store ScanDataStore, versions ...int) (*StaticProtocolAnalysisResult, error) {
	return crawl.AnalyzeStoredJSProtocolsWithStore(taskID, store, versions...)
}
