package main

import (
	"testing"
	"trailblazer/pkg/lib"
)

func TestBuildConclusionsMarksNoDecryptPath(t *testing.T) {
	summary := map[string]interface{}{
		"decryptionSummaries": []map[string]interface{}{
			{
				"hasResponseCiphertext":  false,
				"hasResponsePlaintext":   false,
				"hasResponseDecryptStep": false,
			},
		},
	}

	conclusions := buildConclusions(summary)
	if conclusions["coreFinding"] == "" {
		t.Fatalf("expected core finding to be populated")
	}
}

func TestBuildRunSummaryCountsTargetsAndTraces(t *testing.T) {
	result := &lib.ScanResult{
		Summary: lib.Summary{
			TotalTargets:   1,
			TotalTreeNodes: 3,
		},
		Targets: []lib.TargetResult{
			{
				Target:         "https://jzsc.mohurd.gov.cn/",
				APIRecords:     []lib.APIRecord{{URL: "https://jzsc.mohurd.gov.cn/api"}},
				ProtocolTraces: []lib.ProtocolTrace{{TraceID: "trace-1"}},
			},
		},
	}

	summary := buildRunSummary(result)
	if summary["targets"] != 1 {
		t.Fatalf("expected targets=1, got %#v", summary["targets"])
	}
	if summary["treeNodes"] != 3 {
		t.Fatalf("expected treeNodes=3, got %#v", summary["treeNodes"])
	}

	targetSummaries, ok := summary["targetSummaries"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected targetSummaries slice, got %#v", summary["targetSummaries"])
	}
	if len(targetSummaries) != 1 {
		t.Fatalf("expected 1 target summary, got %d", len(targetSummaries))
	}
	if targetSummaries[0]["protocolTraces"] != 1 {
		t.Fatalf("expected protocolTraces=1, got %#v", targetSummaries[0]["protocolTraces"])
	}
}
