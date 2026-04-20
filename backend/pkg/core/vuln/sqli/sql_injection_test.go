package sqli

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"trailblazer/pkg/config"
	"trailblazer/pkg/core/structs"
)

func TestSQLInjectionDetectsErrorBasedVulnerability(t *testing.T) {
	apiReq := structs.APIRequest{
		URL:     "http://localhost:8082/sqli",
		Method:  http.MethodGet,
		Headers: map[string]string{},
		Params:  url.Values{"user": {""}},
	}

	cfg := config.SQLInjectionConfig{
		Enabled: true,
		Rules: []config.SQLiPayloadRule{
			{
				Payloads:     []string{"'"},
				Type:         "error-based",
				BodyContains: []string{"StatementCallback"},
			},
		},
	}

	result, err := TestSQLInjection(apiReq, cfg)
	if err != nil {
		t.Fatalf("TestSQLInjection returned error: %v", err)
	}
	fmt.Printf("result: %v\n", result)
}
