package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

func TestSaveConfigPersistsGlobalVulnDetectionSwitch(t *testing.T) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, configPath)
	initialConfig := []byte(`
openai:
  api_key: ""
  base_url: "https://api.openai.com/v1"
  model: "qwen-plus"
  enabled: false
black-domain: []
high-risk-router: []
authentication: []
placeholder: {}
vuln-detection:
  enabled: true
  sql-injection:
    enabled: true
  lfi:
    enabled: true
  ssrf:
    enabled: true
  redirect:
    enabled: true
  xss:
    enabled: true
  upload:
    enabled: true
`)
	if err := os.WriteFile(configFile, initialConfig, 0o644); err != nil {
		t.Fatalf("expected seed config to be written: %v", err)
	}

	previousWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("expected working directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(previousWD)
	}()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("expected to chdir into temp dir: %v", err)
	}

	body := map[string]any{
		"openai": map[string]any{
			"api_key":  "",
			"base_url": "https://api.openai.com/v1",
			"model":    "qwen-plus",
			"enabled":  false,
		},
		"blackDomain":    []string{},
		"highRiskRouter": []string{},
		"authentication": []string{},
		"placeholder":    map[string]string{},
		"vulnDetection": map[string]any{
			"enabled": false,
			"sqlInjection": map[string]any{
				"enabled": true,
			},
			"lfi": map[string]any{
				"enabled": true,
			},
			"ssrf": map[string]any{
				"enabled": true,
			},
			"redirect": map[string]any{
				"enabled": true,
			},
			"xss": map[string]any{
				"enabled": true,
			},
			"upload": map[string]any{
				"enabled": true,
			},
		},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("expected request body to marshal: %v", err)
	}

	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodPost, "/api/config", bytes.NewReader(payload))
	context.Request.Header.Set("Content-Type", "application/json")

	saveConfig(context)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected saveConfig to return 200, got %d with body %s", recorder.Code, recorder.Body.String())
	}

	savedConfig, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("expected saved config to be readable: %v", err)
	}

	var raw struct {
		VulnDetection struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"vuln-detection"`
	}
	if err := yaml.Unmarshal(savedConfig, &raw); err != nil {
		t.Fatalf("expected saved yaml to parse: %v", err)
	}

	if raw.VulnDetection.Enabled == nil {
		t.Fatalf("expected vuln-detection.enabled to be present in yaml, got %s", string(savedConfig))
	}
	if *raw.VulnDetection.Enabled {
		t.Fatalf("expected vuln-detection.enabled to be false in yaml")
	}
}

func TestGetConfigReturnsGlobalVulnDetectionSwitch(t *testing.T) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, configPath)
	configData := []byte(`
openai:
  api_key: ""
  base_url: "https://api.openai.com/v1"
  model: "qwen-plus"
  enabled: false
black-domain: []
high-risk-router: []
authentication: []
placeholder: {}
vuln-detection:
  enabled: false
  sql-injection:
    enabled: true
  lfi:
    enabled: true
  ssrf:
    enabled: true
  redirect:
    enabled: true
  xss:
    enabled: true
  upload:
    enabled: true
`)
	if err := os.WriteFile(configFile, configData, 0o644); err != nil {
		t.Fatalf("expected config file to be written: %v", err)
	}

	previousWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("expected working directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(previousWD)
	}()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("expected to chdir into temp dir: %v", err)
	}

	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodGet, "/api/config", nil)

	getConfig(context)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected getConfig to return 200, got %d with body %s", recorder.Code, recorder.Body.String())
	}

	var response struct {
		Data struct {
			VulnDetection struct {
				Enabled bool `json:"enabled"`
			} `json:"vulnDetection"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("expected response body to parse: %v", err)
	}

	if response.Data.VulnDetection.Enabled {
		t.Fatalf("expected getConfig to return vulnDetection.enabled=false, got true")
	}
}
