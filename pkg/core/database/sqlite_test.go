package database

import "testing"

func TestHighestRiskLevelFromVulns(t *testing.T) {
	tests := []struct {
		name  string
		vulns []VulnRecord
		want  string
	}{
		{
			name: "returns blank for empty list",
			want: "",
		},
		{
			name: "prefers high over lower levels",
			vulns: []VulnRecord{
				{Level: "low"},
				{Level: "medium"},
				{Level: "high"},
			},
			want: "high",
		},
		{
			name: "falls back to medium when no high exists",
			vulns: []VulnRecord{
				{Level: "info"},
				{Level: "medium"},
			},
			want: "medium",
		},
		{
			name: "falls back to low before info",
			vulns: []VulnRecord{
				{Level: "info"},
				{Level: "low"},
			},
			want: "low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := highestRiskLevelFromVulns(tt.vulns); got != tt.want {
				t.Fatalf("highestRiskLevelFromVulns() = %q, want %q", got, tt.want)
			}
		})
	}
}
