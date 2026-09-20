package ssrf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
)

// apiRequestTo 构造一个带 url 参数的测试请求。
func apiRequestTo(target string) structs.APIRequest {
	return structs.APIRequest{
		Method: http.MethodGet,
		URL:    target + "?url=https://news.example.com",
		Params: url.Values{"url": []string{"https://news.example.com"}},
	}
}

func TestDetectsEchoSSRF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟服务端取回了注入的 example.com 并回显内容
		w.Write([]byte(`<html><head><title>Example Domain</title></head></html>`))
	}))
	defer srv.Close()

	result, err := TestServerSideRequestForgery(apiRequestTo(srv.URL), config.SSRFConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Vulnerable {
		t.Fatalf("expected vulnerable, got %+v", result)
	}
	if result.Payload != "http://example.com" {
		t.Errorf("payload = %q", result.Payload)
	}
}

func TestDetectsFileRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::"))
	}))
	defer srv.Close()

	result, err := TestServerSideRequestForgery(apiRequestTo(srv.URL), config.SSRFConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Vulnerable || result.Payload != "file:///etc/passwd" {
		t.Errorf("expected file probe hit, got %+v", result)
	}
}

func TestRejectsRedirectPassThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 原样 302 跳转到注入的载荷 —— 只是开放重定向行为，不是 SSRF
		http.Redirect(w, r, "http://example.com", http.StatusFound)
	}))
	defer srv.Close()

	result, err := TestServerSideRequestForgery(apiRequestTo(srv.URL), config.SSRFConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Vulnerable {
		t.Errorf("redirect pass-through must not be vulnerable: %+v", result)
	}
}

func TestRejectsUnrelatedContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"code":0,"message":"ok"}`))
	}))
	defer srv.Close()

	result, err := TestServerSideRequestForgery(apiRequestTo(srv.URL), config.SSRFConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Vulnerable {
		t.Errorf("unrelated content must not be vulnerable: %+v", result)
	}
	if result.DispatchedCallback {
		t.Error("no callback configured, should not dispatch")
	}
}

func TestCallbackDispatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"code":0}`))
	}))
	defer srv.Close()

	result, err := TestServerSideRequestForgery(apiRequestTo(srv.URL), config.SSRFConfig{
		CallbackURL: "https://oob.example.net/probe123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Vulnerable {
		t.Errorf("callback dispatch alone must not mark vulnerable: %+v", result)
	}
	if !result.DispatchedCallback {
		t.Error("expected DispatchedCallback=true")
	}
}
