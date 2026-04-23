package main

import (
	"fmt"
	"log"

	"trailblazer/pkg/lib"
)

type localSink struct{}

func (localSink) OnAsset(event lib.ScanEvent) {
	fmt.Printf("[asset] %#v\n", event.Data)
}

func (localSink) OnRisk(event lib.ScanEvent) {
	fmt.Printf("[risk] %#v\n", event.Data)
}

func (localSink) OnVulnerability(event lib.ScanEvent) {
	fmt.Printf("[vuln] %#v\n", event.Data)
}

func (localSink) OnAPIRecord(event lib.ScanEvent) {
	fmt.Printf("[api] %#v\n", event.Data)
}

func (localSink) OnProtocolTrace(event lib.ScanEvent) {
	fmt.Printf("[trace] %#v\n", event.Data)
}

type EventSink interface {
	OnAsset(event lib.ScanEvent)
	OnRisk(event lib.ScanEvent)
	OnVulnerability(event lib.ScanEvent)
	OnAPIRecord(event lib.ScanEvent)
	OnProtocolTrace(event lib.ScanEvent)
}

func RunTrailblazerScan(target string, sink EventSink) (*lib.ScanResult, error) {
	options := lib.NewScanOptions()
	options.OpenAI.Enabled = false
	options.VulnDetection.Enabled = true

	options.OnResult = func(event lib.ScanEvent) bool {
		switch event.Type {
		case lib.EventTypeAsset:
			sink.OnAsset(event)
		case lib.EventTypeRisk:
			sink.OnRisk(event)
		case lib.EventTypeVulnerability:
			sink.OnVulnerability(event)
		case lib.EventTypeAPIRecord:
			sink.OnAPIRecord(event)
		case lib.EventTypeProtocolTrace:
			sink.OnProtocolTrace(event)
		case lib.EventTypeError:
			log.Printf("[trailblazer] %v", event.Data)
		}
		return true
	}

	return lib.PerformScan([]string{target}, options)
}

func main() {
	result, err := RunTrailblazerScan("https://example.com", localSink{})
	if err != nil {
		log.Fatalf("scan failed: %v", err)
	}

	fmt.Printf("targets=%d vulns=%d risks=%d\n",
		result.Summary.TotalTargets,
		result.Summary.TotalVulnerabilities,
		result.Summary.TotalRisks,
	)
}
