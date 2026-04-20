package crawl

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"testing"
)

func TestBuildParameterProbeURL(t *testing.T) {
	tests := []struct {
		name   string
		apiURL string
		params url.Values
		want   string
	}{
		{
			name:   "no params does not append question mark",
			apiURL: "https://example.com/api/demo",
			params: url.Values{},
			want:   "https://example.com/api/demo",
		},
		{
			name:   "query params are encoded normally",
			apiURL: "https://example.com/api/demo",
			params: url.Values{"id": {"1"}, "name": {"test"}},
			want:   "https://example.com/api/demo?id=1&name=test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildParameterProbeURL(tt.apiURL, tt.params); got != tt.want {
				t.Fatalf("buildParameterProbeURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractMissingParams(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    *Parameter
	}{
		{
			name:    "original format",
			message: "required string 'userId'",
			want:    &Parameter{Name: "userId", Type: "string"},
		},
		{
			name:    "spring boot format",
			message: "Required request parameter 'pageNo' for method parameter type int is not present",
			want:    &Parameter{Name: "pageNo", Type: "int"},
		},
		{
			name:    "simple required format",
			message: "parameter 'keyword' is required",
			want:    &Parameter{Name: "keyword", Type: "string"},
		},
		{
			name:    "no missing parameter hint",
			message: "{\"code\":200,\"success\":true}",
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMissingParams(tt.message)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("extractMissingParams() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestGenerateDefaultValue(t *testing.T) {
	tests := []struct {
		name      string
		paramType string
		want      interface{}
	}{
		{name: "string", paramType: "string", want: "test"},
		{name: "int", paramType: "int", want: 0},
		{name: "long", paramType: "long", want: int64(0)},
		{name: "double", paramType: "double", want: 0.0},
		{name: "boolean", paramType: "boolean", want: false},
		{name: "date", paramType: "date", want: "1970-01-01"},
		{name: "arraylist", paramType: "arraylist", want: []string{"1"}},
		{name: "fallback", paramType: "unknown", want: "defaultValue"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateDefaultValue(tt.paramType)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("generateDefaultValue() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestCompleteParametersStopsAfterMissingHintsDisappear(t *testing.T) {
	originalProbe := parameterProbeFunc
	t.Cleanup(func() {
		parameterProbeFunc = originalProbe
	})

	callCount := 0
	parameterProbeFunc = func(
		_ context.Context,
		_ string,
		fullURL string,
	) (string, error) {
		callCount++
		switch callCount {
		case 1:
			if fullURL != "https://example.com/api/demo" {
				t.Fatalf("unexpected first probe url: %s", fullURL)
			}
			return "Required request parameter 'pageNo' for method parameter type int is not present", nil
		case 2:
			if fullURL != "https://example.com/api/demo?pageNo=0" {
				t.Fatalf("unexpected second probe url: %s", fullURL)
			}
			return `{"code":200,"success":true}`, nil
		default:
			t.Fatalf("unexpected extra probe: %d", callCount)
			return "", nil
		}
	}

	got := completeParameters("GET", "https://example.com/api/demo", nil)
	want := url.Values{"pageNo": {"0"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("completeParameters() = %#v, want %#v", got, want)
	}
}

func TestCompleteParametersCapsProbeAttempts(t *testing.T) {
	originalProbe := parameterProbeFunc
	t.Cleanup(func() {
		parameterProbeFunc = originalProbe
	})

	callCount := 0
	parameterProbeFunc = func(
		_ context.Context,
		_ string,
		_ string,
	) (string, error) {
		callCount++
		return fmt.Sprintf("parameter 'loop_%d' is required", callCount), nil
	}

	got := completeParameters("GET", "https://example.com/api/demo", nil)
	if callCount != maxParameterProbeAttempts {
		t.Fatalf("probe call count = %d, want %d", callCount, maxParameterProbeAttempts)
	}
	if len(got) != maxParameterProbeAttempts {
		t.Fatalf("parameter count = %d, want %d", len(got), maxParameterProbeAttempts)
	}
}
