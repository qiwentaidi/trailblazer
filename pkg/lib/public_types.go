package lib

import (
	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"github.com/qiwentaidi/trailblazer/pkg/logger"
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
	Logger              = logger.Logger
	LogEntry            = logger.Entry
	LogLevel            = logger.Level

	StaticProtocolEndpoint       = crawl.StaticProtocolEndpoint
	StaticProtocolProfile        = crawl.StaticProtocolProfile
	StaticProtocolAnalysisResult = crawl.StaticProtocolAnalysisResult
	RequestBlueprint             = crawl.RequestBlueprint
	RequestBlueprintParam        = crawl.RequestBlueprintParam
	RequestBlueprintHeader       = crawl.RequestBlueprintHeader
	RequestBlueprintInterceptor  = crawl.RequestBlueprintInterceptor
	RequestBlueprintSource       = crawl.RequestBlueprintSource
)

// NewMemoryScanDataStore creates an in-memory store for one scan session.
var NewMemoryScanDataStore = database.NewMemoryScanDataStore

const (
	LogDebug   = logger.DEBUG
	LogInfo    = logger.INFO
	LogWarning = logger.WARNING
	LogError   = logger.ERROR
	LogVuln    = logger.VULN
)

var (
	DefaultLogger          = logger.Default
	SetLogOutput           = logger.SetOutput
	SetLogOutputFile       = logger.SetOutputFile
	ConfigureLogOutput     = logger.ConfigureOutput
	InstallStandardLogHook = logger.InstallStandardCapture
)

// AnalyzeStoredJSProtocolsWithStore analyzes stored JS protocol traces without
// requiring callers to import the crawl implementation package directly.
func AnalyzeStoredJSProtocolsWithStore(taskID string, store ScanDataStore, versions ...int) (*StaticProtocolAnalysisResult, error) {
	return crawl.AnalyzeStoredJSProtocolsWithStore(taskID, store, versions...)
}

func BuildJSRequestBlueprints(jsResources []JSResource) []RequestBlueprint {
	return crawl.BuildJSRequestBlueprints(jsResources)
}
