package auth_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"trailblazer/pkg/core/database"
	"trailblazer/pkg/web"

	"github.com/gin-gonic/gin"
)

func setupAuthTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "auth-test.db")
	if err := database.InitSQLite(dbPath); err != nil {
		t.Fatalf("failed to init sqlite: %v", err)
	}

	r := gin.New()
	web.RegisterRoutes(r)
	return r
}

func performJSONRequest(t *testing.T, r http.Handler, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()

	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("failed to marshal request: %v", err)
		}
	}

	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	return resp
}

func TestInitializeAccountAndChangePasswordFlow(t *testing.T) {
	router := setupAuthTestRouter(t)

	statusResp := performJSONRequest(t, router, http.MethodGet, "/api/auth/status", nil, "")
	if statusResp.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", statusResp.Code, http.StatusOK)
	}

	var status struct {
		Initialized bool `json:"initialized"`
	}
	if err := json.Unmarshal(statusResp.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to decode status response: %v", err)
	}
	if status.Initialized {
		t.Fatal("expected system to be uninitialized")
	}

	initResp := performJSONRequest(t, router, http.MethodPost, "/api/auth/initialize", map[string]string{
		"username": "admin",
		"password": "admin123456",
	}, "")
	if initResp.Code != http.StatusOK {
		t.Fatalf("initialize code = %d, want %d, body=%s", initResp.Code, http.StatusOK, initResp.Body.String())
	}

	reinitResp := performJSONRequest(t, router, http.MethodPost, "/api/auth/initialize", map[string]string{
		"username": "admin2",
		"password": "admin123456",
	}, "")
	if reinitResp.Code != http.StatusConflict {
		t.Fatalf("reinitialize code = %d, want %d", reinitResp.Code, http.StatusConflict)
	}

	loginResp := performJSONRequest(t, router, http.MethodPost, "/api/auth/login", map[string]string{
		"username": "admin",
		"password": "admin123456",
	}, "")
	if loginResp.Code != http.StatusOK {
		t.Fatalf("login code = %d, want %d, body=%s", loginResp.Code, http.StatusOK, loginResp.Body.String())
	}

	var loginResult struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(loginResp.Body.Bytes(), &loginResult); err != nil {
		t.Fatalf("failed to decode login response: %v", err)
	}
	if loginResult.Token == "" {
		t.Fatal("expected login token")
	}

	changeResp := performJSONRequest(t, router, http.MethodPost, "/api/auth/change-password", map[string]string{
		"oldPassword": "admin123456",
		"newPassword": "newpass123456",
	}, loginResult.Token)
	if changeResp.Code != http.StatusOK {
		t.Fatalf("change password code = %d, want %d, body=%s", changeResp.Code, http.StatusOK, changeResp.Body.String())
	}

	oldLoginResp := performJSONRequest(t, router, http.MethodPost, "/api/auth/login", map[string]string{
		"username": "admin",
		"password": "admin123456",
	}, "")
	if oldLoginResp.Code != http.StatusUnauthorized {
		t.Fatalf("old password login code = %d, want %d", oldLoginResp.Code, http.StatusUnauthorized)
	}

	newLoginResp := performJSONRequest(t, router, http.MethodPost, "/api/auth/login", map[string]string{
		"username": "admin",
		"password": "newpass123456",
	}, "")
	if newLoginResp.Code != http.StatusOK {
		t.Fatalf("new password login code = %d, want %d, body=%s", newLoginResp.Code, http.StatusOK, newLoginResp.Body.String())
	}
}
