package login

import (
	"testing"

	"github.com/chromedp/cdproto/network"
)

func TestLooksLikeLoginPageURL(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{raw: "http://example.com/login", want: true},
		{raw: "http://example.com/superadmin/login?redirect=%2F", want: true},
		{raw: "http://example.com/dashboard", want: false},
	}

	for _, tc := range cases {
		if got := looksLikeLoginPageURL(tc.raw); got != tc.want {
			t.Fatalf("looksLikeLoginPageURL(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestInferSuccessFromPageStateByRedirect(t *testing.T) {
	initial := pageStateResult{URL: "http://example.com/login"}
	final := pageStateResult{URL: "http://example.com/dashboard"}

	if !inferSuccessFromPageState(initial, final) {
		t.Fatal("expected redirect away from login to be treated as success")
	}
}

func TestInferSuccessFromPageStateByStorageOnLoginPage(t *testing.T) {
	initial := pageStateResult{URL: "http://example.com/login"}
	final := pageStateResult{
		URL:          "http://example.com/login",
		HasAuthState: true,
	}

	if inferSuccessFromPageState(initial, final) {
		t.Fatal("expected login page with storage markers to remain a failure")
	}
}

func TestInferSuccessFromPageStateRejectsFailureText(t *testing.T) {
	initial := pageStateResult{URL: "http://example.com/login"}
	final := pageStateResult{
		URL:         "http://example.com/dashboard",
		HasFailText: true,
	}

	if inferSuccessFromPageState(initial, final) {
		t.Fatal("expected failure text to override redirect success")
	}
}

func TestIsSuccessfulLoginResponse(t *testing.T) {
	if !isSuccessfulLoginResponse("http://example.com/api/login", `{"access_token":"abc"}`) {
		t.Fatal("expected token response to be treated as login success")
	}
	if !isSuccessfulLoginResponse("http://example.com/api/login", `{"message":"authenticated","authenticated":true,"principal":"labuser"}`) {
		t.Fatal("expected authenticated=true response to be treated as login success")
	}
	if !isSuccessfulLoginResponse("http://example.com/login", `HTTP 200 { "message": "authenticated", "authenticated": true, "principal": "labuser" }`) {
		t.Fatal("expected rendered authenticated=true response to be treated as login success")
	}
	if isSuccessfulLoginResponse("http://example.com/api/login", `{"error":"invalid password"}`) {
		t.Fatal("expected invalid password response to be treated as login failure")
	}
	if isSuccessfulLoginResponse("http://example.com/api/login", `{"message":"invalid credentials","authenticated":false,"principal":null}`) {
		t.Fatal("expected authenticated=false response to be treated as login failure")
	}
}

func TestAssessLoginAgainstNegativeControlPromotesDistinctStructuredSuccess(t *testing.T) {
	negative := &WeakFormLoginResult{
		Vulnerable: false,
		Response:   `{"message":"invalid credentials","authenticated":false,"principal":null}`,
	}
	candidate := &WeakFormLoginResult{
		Vulnerable:        false,
		Username:          "<prefilled>",
		Password:          "<prefilled>",
		Response:          `HTTP 200 { "message": "authenticated", "authenticated": true, "principal": "labuser" }`,
		Reason:            "登录失败（clicked_submit_control_with_prefilled_credentials）",
		UsedPrefilledCred: true,
	}

	result := assessLoginAgainstNegativeControl(candidate, negative)
	if result == nil || !result.Vulnerable {
		t.Fatalf("expected candidate to be promoted to vulnerable, got %#v", result)
	}
	if !result.UsedPrefilledCred {
		t.Fatalf("expected prefilled marker to be preserved, got %#v", result)
	}
}

func TestAssessLoginAgainstNegativeControlRejectsSameSuccessfulBaseline(t *testing.T) {
	negative := &WeakFormLoginResult{
		Vulnerable: true,
		Response:   `{"authenticated":true,"principal":"anyone"}`,
	}
	candidate := &WeakFormLoginResult{
		Vulnerable: true,
		Username:   "admin",
		Password:   "admin",
		Response:   `{"authenticated":true,"principal":"anyone"}`,
	}

	result := assessLoginAgainstNegativeControl(candidate, negative)
	if result == nil || result.Vulnerable {
		t.Fatalf("expected random-success baseline to suppress weak-login finding, got %#v", result)
	}
}

func TestIsLoginRequestCandidate(t *testing.T) {
	cases := []struct {
		name     string
		rawURL   string
		method   string
		postData string
		want     bool
	}{
		{name: "login endpoint", rawURL: "http://example.com/api/login", method: "POST", want: true},
		{name: "credential payload", rawURL: "http://example.com/api/auth", method: "POST", postData: `{"username":"admin","password":"secret"}`, want: true},
		{name: "wrong method", rawURL: "http://example.com/api/login", method: "GET", want: false},
		{name: "non login request", rawURL: "http://example.com/api/profile", method: "POST", postData: `{"user":"admin"}`, want: false},
	}

	for _, tc := range cases {
		if got := isLoginRequestCandidate(tc.rawURL, tc.method, tc.postData); got != tc.want {
			t.Fatalf("%s: isLoginRequestCandidate(...) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCollectAuthoritativeLoginResult(t *testing.T) {
	records := map[network.RequestID]*loginRequestRecord{
		network.RequestID("1"): {
			URL:          "http://example.com/api/login",
			Method:       "POST",
			Matched:      true,
			Success:      true,
			ResponseBody: `{"token":"abc"}`,
		},
		network.RequestID("2"): {
			URL:         "http://example.com/api/other",
			Method:      "GET",
			Matched:     false,
			AuthCookies: []string{"session=1"},
		},
	}

	result := collectAuthoritativeLoginResult(records)
	if !result.LoginRequestSeen {
		t.Fatal("expected matched login request to be observed")
	}
	if !result.Success {
		t.Fatal("expected successful login response to be authoritative")
	}
	if result.ResponseBody == "" {
		t.Fatal("expected response body to be carried through")
	}
}

func TestInferAuthStateEstablished(t *testing.T) {
	initial := pageStateResult{URL: "http://example.com/login"}
	final := pageStateResult{
		URL:          "http://example.com/dashboard",
		HasAuthState: true,
		StorageState: "token=abc",
	}
	if !inferAuthStateEstablished(initial, final, false) {
		t.Fatal("expected new storage auth state to be treated as authenticated")
	}

	failFinal := pageStateResult{
		URL:          "http://example.com/dashboard",
		HasAuthState: true,
		HasFailText:  true,
		StorageState: "token=abc",
	}
	if inferAuthStateEstablished(initial, failFinal, true) {
		t.Fatal("expected failure text to override auth-state success")
	}
}

func TestTestWeakFormLoginRejectsMalformedCreds(t *testing.T) {
	result, err := TestWeakFormLogin("http://example.com/login", []string{"invalid"})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Vulnerable {
		t.Fatal("expected malformed weak credential input not to report success")
	}
}

func TestBuildWeakLoginChromeFlagsUsesHeadlessMode(t *testing.T) {
	flags := buildWeakLoginChromeFlags()

	if got, ok := flags["headless"].(bool); !ok || !got {
		t.Fatalf("expected weak login detection to use headless=true, got %#v", flags["headless"])
	}
}
