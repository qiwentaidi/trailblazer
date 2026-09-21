// Package sdk is the stable public entry point for the Trailblazer scanner.
//
// The implementation currently lives in pkg/lib for compatibility with older
// consumers. New integrations should import this package instead of relying
// on the internal package layout.
package sdk

import (
	"github.com/qiwentaidi/trailblazer/pkg/lib"
)

type (
	VulnRecord                   = lib.VulnRecord
	ScanEventType                = lib.ScanEventType
	ScanEvent                    = lib.ScanEvent
	ScanCallback                 = lib.ScanCallback
	ScanOptions                  = lib.ScanOptions
	OpenAIOptions                = lib.OpenAIOptions
	VulnDetectionOptions         = lib.VulnDetectionOptions
	ScanResult                   = lib.ScanResult
	TargetResult                 = lib.TargetResult
	APIRecord                    = lib.APIRecord
	ProtocolTrace                = lib.ProtocolTrace
	AssetInfo                    = lib.AssetInfo
	SensitiveItem                = lib.SensitiveItem
	VulnerabilityItem            = lib.VulnerabilityItem
	Summary                      = lib.Summary
	AssetCount                   = lib.AssetCount
	SeverityCount                = lib.SeverityCount
	AuxiliaryCount               = lib.AuxiliaryCount
	FindingDigest                = lib.FindingDigest
	VulnerabilityOverview        = lib.VulnerabilityOverview
	AuthorizationCheck           = lib.AuthorizationCheck
	TraceEvidence                = lib.TraceEvidence
	TraceVariantSuggestion       = lib.TraceVariantSuggestion
	ConfigYAML                   = lib.ConfigYAML
	SQLInjectionConfig           = lib.SQLInjectionConfig
	LFIConfig                    = lib.LFIConfig
	SSRFConfig                   = lib.SSRFConfig
	RedirectConfig               = lib.RedirectConfig
	XSSConfig                    = lib.XSSConfig
	UploadConfig                 = lib.UploadConfig
	AuthorizationConfig          = lib.AuthorizationConfig
	ScanDataStore                = lib.ScanDataStore
	MemoryScanDataStore          = lib.MemoryScanDataStore
	JSResource                   = lib.JSResource
	APIResource                  = lib.APIResource
	ProtocolTraceRecord          = lib.ProtocolTraceRecord
	Logger                       = lib.Logger
	LogEntry                     = lib.LogEntry
	LogLevel                     = lib.LogLevel
	ProtocolCryptoStep           = lib.ProtocolCryptoStep
	StaticProtocolEndpoint       = lib.StaticProtocolEndpoint
	StaticProtocolProfile        = lib.StaticProtocolProfile
	StaticProtocolAnalysisResult = lib.StaticProtocolAnalysisResult
	RequestBlueprint             = lib.RequestBlueprint
	RequestBlueprintParam        = lib.RequestBlueprintParam
	RequestBlueprintHeader       = lib.RequestBlueprintHeader
	RequestBlueprintInterceptor  = lib.RequestBlueprintInterceptor
	RequestBlueprintSource       = lib.RequestBlueprintSource
	VulnCollector                = lib.VulnCollector
	CLIVulnCollector             = lib.CLIVulnCollector
)

const (
	EventTypeVulnerability = lib.EventTypeVulnerability
	EventTypeAsset         = lib.EventTypeAsset
	EventTypeAPIRecord     = lib.EventTypeAPIRecord
	EventTypeProtocolTrace = lib.EventTypeProtocolTrace
	EventTypeProgress      = lib.EventTypeProgress
	EventTypeError         = lib.EventTypeError
	LogDebug               = lib.LogDebug
	LogInfo                = lib.LogInfo
	LogWarning             = lib.LogWarning
	LogError               = lib.LogError
	LogVuln                = lib.LogVuln
)

var (
	NewScanOptions                    = lib.NewScanOptions
	LoadScanOptionsFromFile           = lib.LoadScanOptionsFromFile
	PerformScan                       = lib.PerformScan
	PerformScanWithConfigFile         = lib.PerformScanWithConfigFile
	AnalyzeProtocolTrace              = lib.AnalyzeProtocolTrace
	AnalyzeStoredJSProtocolsWithStore = lib.AnalyzeStoredJSProtocolsWithStore
	BuildJSRequestBlueprints          = lib.BuildJSRequestBlueprints
	NewCLIVulnCollector               = lib.NewCLIVulnCollector
	NewSDKVulnCollectorAdapter        = lib.NewSDKVulnCollectorAdapter
	NewMemoryScanDataStore            = lib.NewMemoryScanDataStore
	DefaultLogger                     = lib.DefaultLogger
	SetLogOutput                      = lib.SetLogOutput
	SetLogOutputFile                  = lib.SetLogOutputFile
	ConfigureLogOutput                = lib.ConfigureLogOutput
	InstallStandardLogHook            = lib.InstallStandardLogHook
)
