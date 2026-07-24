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
	VulnRecord            = lib.VulnRecord
	ScanEventType         = lib.ScanEventType
	ScanEvent             = lib.ScanEvent
	ScanCallback          = lib.ScanCallback
	ScanOptions           = lib.ScanOptions
	OpenAIOptions         = lib.OpenAIOptions
	VulnDetectionOptions  = lib.VulnDetectionOptions
	ScanResult            = lib.ScanResult
	TargetResult          = lib.TargetResult
	APIRecord             = lib.APIRecord
	ProtocolTrace         = lib.ProtocolTrace
	AssetInfo             = lib.AssetInfo
	SensitiveItem         = lib.SensitiveItem
	VulnerabilityItem     = lib.VulnerabilityItem
	Summary               = lib.Summary
	AssetCount            = lib.AssetCount
	SeverityCount         = lib.SeverityCount
	AuxiliaryCount        = lib.AuxiliaryCount
	FindingDigest         = lib.FindingDigest
	VulnerabilityOverview = lib.VulnerabilityOverview
	DecryptResult         = lib.DecryptResult
	VulnCollector         = lib.VulnCollector
	CLIVulnCollector      = lib.CLIVulnCollector
)

const (
	EventTypeVulnerability = lib.EventTypeVulnerability
	EventTypeAsset         = lib.EventTypeAsset
	EventTypeAPIRecord     = lib.EventTypeAPIRecord
	EventTypeProtocolTrace = lib.EventTypeProtocolTrace
	EventTypeProgress      = lib.EventTypeProgress
	EventTypeError         = lib.EventTypeError
)

var (
	NewScanOptions             = lib.NewScanOptions
	LoadScanOptionsFromFile    = lib.LoadScanOptionsFromFile
	PerformScan                = lib.PerformScan
	PerformScanWithConfigFile  = lib.PerformScanWithConfigFile
	DecryptProtocolTrace       = lib.DecryptProtocolTrace
	NewCLIVulnCollector        = lib.NewCLIVulnCollector
	NewSDKVulnCollectorAdapter = lib.NewSDKVulnCollectorAdapter
)
