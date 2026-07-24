package database

import "testing"

func TestNormalizeVulnStatus(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "open", input: "open", want: "open"},
		{name: "resolved with spaces", input: " Resolved ", want: "resolved"},
		{name: "ignored uppercase", input: "IGNORED", want: "ignored"},
		{name: "empty", input: "", wantErr: true},
		{name: "unsupported", input: "closed", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeVulnStatus(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeVulnStatus() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeVulnStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}
