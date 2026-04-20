package vuln

import (
	"net/url"
	"strings"
	"testing"
	"trailblazer/pkg/core/structs"
)

func TestResolveAPIRequestTransportSerializesJSONPayloadFromParams(t *testing.T) {
	finalURL, body := resolveAPIRequestTransport(structs.APIRequest{
		URL:            "https://example.com/api/orders/query",
		Method:         "POST",
		Headers:        map[string]string{"Content-Type": "application/json"},
		PayloadCarrier: "body",
		PayloadFormat:  "json",
		Params: url.Values{
			"id":     []string{"1"},
			"status": []string{"active"},
		},
	})

	if finalURL != "https://example.com/api/orders/query" {
		t.Fatalf("expected unchanged URL, got %q", finalURL)
	}
	if !strings.Contains(body, `"id":"1"`) || !strings.Contains(body, `"status":"active"`) {
		t.Fatalf("expected json body built from params, got %q", body)
	}
}

func TestResolveAPIRequestTransportMovesQueryCarrierIntoURL(t *testing.T) {
	finalURL, body := resolveAPIRequestTransport(structs.APIRequest{
		URL:            "https://example.com/api/orders/list",
		Method:         "POST",
		PayloadCarrier: "params",
		PayloadFormat:  "query",
		Params: url.Values{
			"tenant": []string{"a"},
			"page":   []string{"1"},
		},
	})

	if body != "" {
		t.Fatalf("expected empty body for query-carried payload, got %q", body)
	}
	if !strings.Contains(finalURL, "tenant=a") || !strings.Contains(finalURL, "page=1") {
		t.Fatalf("expected query params appended to URL, got %q", finalURL)
	}
}

func TestResolveAPIRequestTransportKeepsGETQueryAndExplicitBodyTogether(t *testing.T) {
	finalURL, body := resolveAPIRequestTransport(structs.APIRequest{
		URL:            "https://example.com/api/refreshApiInfoByInterfaceName",
		Method:         "GET",
		Headers:        map[string]string{"Content-Type": "application/json"},
		PayloadCarrier: "params",
		PayloadFormat:  "query",
		Params: url.Values{
			"env":           []string{"TEST33"},
			"interfaceName": []string{"test"},
		},
		Body: `{"env":"TEST33","interfaceName":"test"}`,
	})

	if !strings.Contains(finalURL, "env=TEST33") || !strings.Contains(finalURL, "interfaceName=test") {
		t.Fatalf("expected GET query params appended to URL, got %q", finalURL)
	}
	if body != `{"env":"TEST33","interfaceName":"test"}` {
		t.Fatalf("expected GET body to be preserved alongside query, got %q", body)
	}
}

func TestBuildRawRequestUsesResolvedJSONBody(t *testing.T) {
	raw := BuildRawRequest(structs.APIRequest{
		URL:            "https://example.com/api/orders/query",
		Method:         "POST",
		Headers:        map[string]string{"Content-Type": "application/json"},
		PayloadCarrier: "body",
		PayloadFormat:  "json",
		Params: url.Values{
			"id": []string{"1"},
		},
	})

	if !strings.Contains(raw, "Content-Type: application/json") {
		t.Fatalf("expected raw request to include json content-type, got %q", raw)
	}
	if !strings.Contains(raw, `{"id":"1"}`) {
		t.Fatalf("expected raw request to include resolved json body, got %q", raw)
	}
}

func TestResolveAPIRequestTransportKeepsGETJSONBodyWhenHinted(t *testing.T) {
	finalURL, body := resolveAPIRequestTransport(structs.APIRequest{
		URL:            "https://example.com/ccat/step/getStepParamsByStepId",
		Method:         "GET",
		Headers:        map[string]string{"Content-Type": "application/json"},
		PayloadCarrier: "body",
		PayloadFormat:  "json",
		Params: url.Values{
			"stepId": []string{"123"},
		},
	})

	if finalURL != "https://example.com/ccat/step/getStepParamsByStepId" {
		t.Fatalf("expected unchanged URL for GET body request, got %q", finalURL)
	}
	if body != `{"stepId":"123"}` {
		t.Fatalf("expected GET body to be serialized as json, got %q", body)
	}
}

func TestResolveAPIRequestTransportKeepsExplicitGETBody(t *testing.T) {
	finalURL, body := resolveAPIRequestTransport(structs.APIRequest{
		URL:            "https://example.com/api/demo",
		Method:         "GET",
		Headers:        map[string]string{"Content-Type": "application/json"},
		PayloadCarrier: "body",
		PayloadFormat:  "json",
		Body:           `{"id":"1"}`,
	})

	if finalURL != "https://example.com/api/demo" {
		t.Fatalf("expected unchanged URL for explicit GET body, got %q", finalURL)
	}
	if body != `{"id":"1"}` {
		t.Fatalf("expected explicit GET body to be preserved, got %q", body)
	}
}
