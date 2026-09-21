package crawl

import (
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"net/url"
	"strings"
	"testing"
)

func TestExtractTraceMatchedEndpointsMatchesAgainstAPIBase(t *testing.T) {
	traces := []database.ProtocolTraceRecord{
		{
			TraceID:    "trace-1",
			Method:     "POST",
			RequestURL: "https://szpz.wsjkw.hangzhou.gov.cn/api/apiUser/channel/bind",
		},
		{
			TraceID:    "trace-2",
			Method:     "POST",
			RequestURL: "https://other.example.com/no-match",
		},
	}

	endpoints := extractTraceMatchedEndpoints(traces, []string{
		"https://szpz.wsjkw.hangzhou.gov.cn/api",
	})

	if len(endpoints) != 1 {
		t.Fatalf("expected 1 matched endpoint, got %d", len(endpoints))
	}
	if got := endpoints[0].Method; got != "POST" {
		t.Fatalf("expected method POST, got %q", got)
	}
	if got := endpoints[0].Path; got != "/apiUser/channel/bind" {
		t.Fatalf("expected normalized path to strip api base, got %q", got)
	}
	if got := endpoints[0].Client; got != "protocol-trace" {
		t.Fatalf("expected protocol-trace client, got %q", got)
	}
	if got := endpoints[0].Snippet; got != "https://szpz.wsjkw.hangzhou.gov.cn/api/apiUser/channel/bind" {
		t.Fatalf("expected snippet to preserve original request url, got %q", got)
	}
}

func TestExtractTraceMatchedEndpointsDeduplicatesSameMethodAndPath(t *testing.T) {
	traces := []database.ProtocolTraceRecord{
		{
			TraceID:    "trace-1",
			Method:     "POST",
			RequestURL: "https://szpz.wsjkw.hangzhou.gov.cn/api/apiUser/getInfo",
		},
		{
			TraceID:    "trace-2",
			Method:     "POST",
			RequestURL: "https://szpz.wsjkw.hangzhou.gov.cn/api/apiUser/getInfo",
		},
	}

	endpoints := extractTraceMatchedEndpoints(traces, []string{
		"https://szpz.wsjkw.hangzhou.gov.cn/api",
	})

	if len(endpoints) != 1 {
		t.Fatalf("expected duplicate traces to collapse into 1 endpoint, got %d", len(endpoints))
	}
}

func TestBuildStaticAPIContextsMatchesJSCapturedSnippets(t *testing.T) {
	apiResources := []database.APIResource{
		{
			URL:              "https://example.com/api/poc/sync-setting",
			Method:           "post",
			TraceID:          "trace-1",
			HasProtocolTrace: true,
			RequestBody:      `{"enable":true}`,
			RequestHeaders: map[string]string{
				"Content-Type": "application/json",
			},
		},
	}
	jsResources := []database.JSResource{
		{
			URL: "https://example.com/assets/index.js",
			Content: `
const submit=()=>request.post("/api/poc/sync-setting",{enable:true,scope:"all"});
`,
		},
	}

	contexts := buildStaticAPIContexts(apiResources, jsResources)
	if len(contexts) != 1 {
		t.Fatalf("expected 1 matched context, got %#v", contexts)
	}
	if contexts[0].Method != "POST" {
		t.Fatalf("expected method to normalize to POST, got %q", contexts[0].Method)
	}
	if contexts[0].SourceFile != "https://example.com/assets/index.js" {
		t.Fatalf("unexpected source file: %q", contexts[0].SourceFile)
	}
	if !strings.Contains(contexts[0].Snippet, "/api/poc/sync-setting") {
		t.Fatalf("expected snippet to contain matched path, got %q", contexts[0].Snippet)
	}
	if contexts[0].RequestBody != `{"enable":true}` {
		t.Fatalf("expected request body to be preserved, got %q", contexts[0].RequestBody)
	}
	if contexts[0].RequestHeaders["Content-Type"] != "application/json" {
		t.Fatalf("expected request headers to be preserved, got %#v", contexts[0].RequestHeaders)
	}
}

func TestResolveStaticTemplateLiteralRejectsSingleBacktick(t *testing.T) {
	if got := resolveStaticTemplateLiteral("", "`", 0); got != "" {
		t.Fatalf("expected a single backtick to be rejected, got %q", got)
	}
}

func TestSelectPrimaryTraceEndpointPrefersMostCompleteTrace(t *testing.T) {
	endpoints := []StaticProtocolEndpoint{
		{
			Path:    "/apiUser/channel/bind",
			Method:  "POST",
			TraceID: "trace-light",
			SessionMaterials: map[string]string{
				"latest_response_plaintext": `{"code":0}`,
			},
		},
		{
			Path:                   "/apiUser/channel/userinfo",
			Method:                 "POST",
			TraceID:                "trace-full",
			RequestBeforeTransform: `{}`,
			FinalRequestBody:       "abcdef1234567890",
			RequestSteps: []database.ProtocolCryptoStep{
				{Source: "JSON.stringify"},
				{Source: "crypto.encrypt"},
			},
			ResponseSteps: []database.ProtocolCryptoStep{
				{Source: "crypto.decrypt"},
				{Source: "JSON.parse"},
			},
			SessionMaterials: map[string]string{
				"latest_response_ciphertext": "deadbeef",
				"latest_response_plaintext":  `{"code":0}`,
			},
		},
	}

	selected := selectPrimaryTraceEndpoint(endpoints)
	if selected == nil {
		t.Fatal("expected a primary endpoint to be selected")
	}
	if selected.TraceID != "trace-full" {
		t.Fatalf("expected most complete trace to win, got %q", selected.TraceID)
	}
}

func TestExtractHTTPContextEndpointsCapturesWrapperParamMappings(t *testing.T) {
	content := `
Iv(e,"getStepParams",(function(t,r,n,a){
  rn({
    type:"post",
    url:"".concat(Xr,"/ccat/step/getStepParams"),
    body:{caseId:t,stepId:r,httpReqType:"query"}
  }).then((function(i){
    rn({
      type:"post",
      url:"".concat(Xr,"/ccat/step/getStepParams"),
      body:{caseId:t,stepId:r,httpReqType:"body"}
    })
  }))
}));
e.getStepParams(r.caseId,r.id,r.info1,r.info3);
`

	endpoints := extractHTTPContextEndpoints("https://example.com/main.js", content)
	if len(endpoints) == 0 {
		t.Fatal("expected wrapper endpoints to be extracted")
	}

	var matched *StaticProtocolEndpoint
	for index := range endpoints {
		if endpoints[index].Path == "/ccat/step/getStepParams" {
			matched = &endpoints[index]
			break
		}
	}
	if matched == nil {
		t.Fatalf("expected /ccat/step/getStepParams endpoint, got %#v", endpoints)
	}
	if matched.Method != "POST" {
		t.Fatalf("expected POST method, got %q", matched.Method)
	}
	if matched.Client != "wrapper:getStepParams -> rn" {
		t.Fatalf("expected wrapper rn client, got %q", matched.Client)
	}

	paramNames := make(map[string]bool)
	for _, param := range matched.Params {
		paramNames[param.Name] = true
	}
	for _, required := range []string{"caseId", "stepId", "httpReqType"} {
		if !paramNames[required] {
			t.Fatalf("expected param %q in %#v", required, matched.Params)
		}
	}

	contextText := strings.Join(matched.Context, "\n")
	for _, required := range []string{
		"封装函数: getStepParams",
		"封装形参: t, r, n, a",
		"参数映射: caseId <- t",
		"参数映射: stepId <- r",
		"参数常量: httpReqType = query",
		"实参样例: caseId <- r.caseId",
		"实参样例: stepId <- r.id",
		"调用样例: getStepParams(r.caseId,r.id,r.info1,r.info3)",
	} {
		if !strings.Contains(contextText, required) {
			t.Fatalf("expected context to contain %q, got %s", required, contextText)
		}
	}
}

func TestBuildStaticConstantParamHintsExtractsDeterministicConstants(t *testing.T) {
	jsResources := []database.JSResource{
		{
			URL: "https://example.com/main.js",
			Content: `
Iv(e,"getStepParams",(function(t,r,n,a){
  rn({
    type:"post",
    url:"".concat(Xr,"/ccat/step/getStepParams"),
    body:{caseId:t,stepId:r,httpReqType:"query"}
  })
}));
`,
		},
	}

	hints := BuildStaticConstantParamHints(jsResources)
	key := "POST\x00/ccat/step/getStepParams"
	if len(hints) == 0 {
		t.Fatal("expected non-empty static constant hints")
	}
	if got := hints[key].Get("httpReqType"); got != "query" {
		t.Fatalf("expected httpReqType=query hint, got %q", got)
	}
	if got := hints[key].Get("caseId"); got != "" {
		t.Fatalf("expected dynamic param caseId not to be converted into constant hint, got %q", got)
	}
}

func TestBuildStaticRequestPayloadHintsExtractsJSONAndQueryHints(t *testing.T) {
	jsResources := []database.JSResource{
		{
			URL: "https://example.com/main.js",
			Content: `
rn({type:"post",url:"/api/demo",body:{caseId:t,stepId:r,httpReqType:"query"}})
axios.get("/api/list",{params:{tenantId:"tenant-a"}})
`,
		},
	}

	hints := BuildStaticRequestPayloadHints(jsResources)
	if len(hints) == 0 {
		t.Fatal("expected non-empty payload hints")
	}

	postHint, ok := hints["POST\x00/api/demo"]
	if !ok {
		t.Fatal("expected POST /api/demo payload hint")
	}
	if postHint.Carrier != "body" || postHint.Format != "json" {
		t.Fatalf("expected json body hint, got %#v", postHint)
	}

	getHint, ok := hints["GET\x00/api/list"]
	if !ok {
		t.Fatal("expected GET /api/list payload hint")
	}
	if getHint.Carrier != "params" || getHint.Format != "query" {
		t.Fatalf("expected query params hint, got %#v", getHint)
	}
}

func TestBuildStaticHeaderHintsExtractsReusableHeadersOnly(t *testing.T) {
	jsResources := []database.JSResource{
		{
			URL: "https://example.com/main.js",
			Content: `
axios.post("/api/orders", payload, {
  headers: {
    "channel-code": "miniapp",
    "Authorization": token,
    "X-Request-From": "console"
  }
})
`,
		},
	}

	hints := BuildStaticHeaderHints(jsResources)
	headers := hints["POST\x00/api/orders"]
	if headers["channel-code"] != "miniapp" {
		t.Fatalf("expected reusable channel-code header, got %#v", headers)
	}
	if headers["X-Request-From"] != "console" {
		t.Fatalf("expected reusable X-Request-From header, got %#v", headers)
	}
	if got := headers["Authorization"]; got != "" {
		t.Fatalf("expected Authorization to be filtered, got %q", got)
	}
}

func TestBuildStaticEndpointHintBundleAggregatesHintsInSinglePass(t *testing.T) {
	jsResources := []database.JSResource{
		{
			URL: "https://example.com/main.js",
			Content: `
const host="https://api.example.com";
const prefix="/per-front";
const apiBase=host + prefix;
axios.post("/api/orders", payload, {
  headers: {
    "channel-code": "miniapp"
  }
})
Iv(e,"getStepParams",(function(t,r,n,a){
  rn({
    type:"post",
    url:"".concat(apiBase,"/dataFactory/dynamicStartDriverData"),
    body:{serverId:t,httpReqType:"query"}
  })
}));
`,
		},
	}

	bundle := BuildStaticEndpointHintBundle(jsResources)
	if got := bundle.Headers["POST\x00/api/orders"]["channel-code"]; got != "miniapp" {
		t.Fatalf("expected aggregated header hint, got %#v", bundle.Headers)
	}
	if got := bundle.RequestPayload["POST\x00/dataFactory/dynamicStartDriverData"].Format; got != "json" {
		t.Fatalf("expected aggregated payload hint, got %#v", bundle.RequestPayload)
	}
	if got := bundle.ConstantParams["POST\x00/dataFactory/dynamicStartDriverData"].Get("httpReqType"); got != "query" {
		t.Fatalf("expected aggregated constant param hint, got %#v", bundle.ConstantParams)
	}
	if got := bundle.Methods["/api/orders"]; got != "POST" {
		t.Fatalf("expected POST method hint for /api/orders, got %#v", bundle.Methods)
	}
	if got := bundle.Methods["/dataFactory/dynamicStartDriverData"]; got != "POST" {
		t.Fatalf("expected POST method hint for wrapper endpoint, got %#v", bundle.Methods)
	}
}

func TestBuildStaticEndpointHintBundleCapturesWrapperConfigHints(t *testing.T) {
	jsResources := []database.JSResource{
		{
			URL: "https://example.com/main.js",
			Content: `
const nn="https://api.example.com";
dn({type:"get",url:"".concat(nn,"/ccat/api/getApisGroupByApp"),body:{app:e},showErrorModal:!0});
`,
		},
	}

	bundle := BuildStaticEndpointHintBundle(jsResources)
	if got := bundle.Methods["/ccat/api/getApisGroupByApp"]; got != "GET" {
		t.Fatalf("expected GET method hint, got %#v", bundle.Methods)
	}

	hint, ok := bundle.RequestPayload["GET\x00/ccat/api/getApisGroupByApp"]
	if !ok {
		t.Fatalf("expected request payload hint, got %#v", bundle.RequestPayload)
	}
	if hint.Carrier != "body" || hint.Format != "json" || hint.Preview != "{app:e}" {
		t.Fatalf("unexpected request payload hint: %#v", hint)
	}
}

func TestExtractHTTPContextEndpointsCapturesHeaderSourceHints(t *testing.T) {
	content := `
const token = localStorage.getItem("token");
fetch("/api/orders", {
  method: "GET",
  headers: {
    "X-Env": process.env.API_ENV,
    "X-Token": token,
    "X-Trace": window.__APP_CONFIG__.traceId,
    "X-Session": sessionStorage.getItem("sid"),
    "X-Cookie-Token": document.cookie
  }
})
`

	endpoints := extractHTTPContextEndpoints("https://example.com/main.js", content)
	for _, endpoint := range endpoints {
		if endpoint.Path != "/api/orders" {
			continue
		}
		contextText := strings.Join(endpoint.Context, "\n")
		for _, required := range []string{
			"来源线索: header X-Env <- process.env",
			"来源线索: header X-Trace <- window config",
			"来源线索: header X-Session <- sessionStorage",
			"来源线索: header X-Cookie-Token <- cookie",
		} {
			if !strings.Contains(contextText, required) {
				t.Fatalf("expected context to contain %q, got %s", required, contextText)
			}
		}
		return
	}
	t.Fatalf("expected /api/orders endpoint to be extracted")
}

func TestExtractHTTPContextEndpointsCapturesAxiosInstanceMethods(t *testing.T) {
	content := `
const host="https://api.example.com";
const env="per-front";
const client=axios.create({baseURL:` + "`" + `${host}/${env}` + "`" + `});
client.post("/dataFactory/dynamicStartDriverData",{serverId:e,detailId:t});
`

	endpoints := extractHTTPContextEndpoints("https://example.com/main.js", content)
	for _, endpoint := range endpoints {
		if endpoint.Path == "/dataFactory/dynamicStartDriverData" {
			if endpoint.Method != "POST" {
				t.Fatalf("expected POST method, got %q", endpoint.Method)
			}
			if endpoint.Client != "axios-instance:client.post" {
				t.Fatalf("expected axios-instance client, got %q", endpoint.Client)
			}
			return
		}
	}
	t.Fatalf("expected axios instance endpoint, got %#v", endpoints)
}

func TestParseRequestPathRejectsConfigLikeDotPath(t *testing.T) {
	if got := parseRequestPath(`"axisLine.onZeroAxisIndex"`); got != "" {
		t.Fatalf("expected dot-only config key to be ignored, got %q", got)
	}
	if got := parseRequestPath(`"borderColor"`); got != "" {
		t.Fatalf("expected plain config key to be ignored, got %q", got)
	}
}

func TestExtractHTTPContextEndpointsSkipsAxiosInstanceConfigLookups(t *testing.T) {
	content := `
const o=axios.create({baseURL:"https://example.com/api"});
o.get("axisLine.onZeroAxisIndex");
o.get("borderColor");
o.get("/auth/token");
`

	endpoints := extractHTTPContextEndpoints("https://example.com/main.js", content)
	if len(endpoints) != 1 {
		t.Fatalf("expected only real request path to remain, got %#v", endpoints)
	}
	if endpoints[0].Path != "/auth/token" {
		t.Fatalf("expected /auth/token to remain, got %#v", endpoints)
	}
	if endpoints[0].Client != "axios-instance:o.get" {
		t.Fatalf("expected axios-instance client label, got %q", endpoints[0].Client)
	}
}

func TestExtractHTTPContextEndpointsResolvesVariableGETPayloadObject(t *testing.T) {
	content := `
const o=axios.create({baseURL:"https://example.com/api"});
const reqPayload={app:t};
o.get("/ccat/api/getApisGroupByApp", reqPayload);
`

	endpoints := extractHTTPContextEndpoints("https://example.com/main.js", content)
	for _, endpoint := range endpoints {
		if endpoint.Path != "/ccat/api/getApisGroupByApp" {
			continue
		}
		if endpoint.Method != "GET" {
			t.Fatalf("expected GET method, got %q", endpoint.Method)
		}
		if endpoint.RequestPayloadFormat != "json" {
			t.Fatalf("expected json payload format from variable object, got %#v", endpoint)
		}
		if endpoint.RequestPayloadCarrier != "body" {
			t.Fatalf("expected body payload carrier from variable object, got %#v", endpoint)
		}

		foundApp := false
		for _, param := range endpoint.Params {
			if param.Name == "app" {
				foundApp = true
				break
			}
		}
		if !foundApp {
			t.Fatalf("expected app param to be extracted, got %#v", endpoint.Params)
		}
		return
	}

	t.Fatalf("expected getApisGroupByApp endpoint, got %#v", endpoints)
}

func TestExtractHTTPContextEndpointsCapturesWrapperConfigCalls(t *testing.T) {
	content := `
const nn="https://api.example.com";
dn({type:"get",url:"".concat(nn,"/ccat/api/getApisGroupByApp"),body:{app:e},showErrorModal:!0});
dn({url:"".concat(nn,"/ccat/testcases/getCaseList"),type:"post",body:{caseName:t||a.caseName,status:"",priority:"",caseDesc:"",moduleId:[],pageNum:1,pageSize:10},showLoading:!0});
`

	endpoints := extractHTTPContextEndpoints("https://example.com/main.js", content)
	if len(endpoints) < 2 {
		t.Fatalf("expected wrapper-config endpoints, got %#v", endpoints)
	}

	var getGroup *StaticProtocolEndpoint
	var getCaseList *StaticProtocolEndpoint
	for index := range endpoints {
		switch endpoints[index].Path {
		case "/ccat/api/getApisGroupByApp":
			getGroup = &endpoints[index]
		case "/ccat/testcases/getCaseList":
			getCaseList = &endpoints[index]
		}
	}

	if getGroup == nil {
		t.Fatalf("expected getApisGroupByApp endpoint, got %#v", endpoints)
	}
	if getGroup.Method != "GET" {
		t.Fatalf("expected GET method, got %q", getGroup.Method)
	}
	if getGroup.Client != "wrapper-config:dn" {
		t.Fatalf("expected wrapper-config client, got %q", getGroup.Client)
	}
	if getGroup.RequestPayloadCarrier != "body" || getGroup.RequestPayloadFormat != "json" {
		t.Fatalf("expected GET body payload metadata, got %#v", getGroup)
	}
	groupParams := make(map[string]bool)
	for _, param := range getGroup.Params {
		groupParams[param.Name] = true
	}
	if !groupParams["app"] {
		t.Fatalf("expected app param in %#v", getGroup.Params)
	}

	if getCaseList == nil {
		t.Fatalf("expected getCaseList endpoint, got %#v", endpoints)
	}
	if getCaseList.Method != "POST" {
		t.Fatalf("expected POST method, got %q", getCaseList.Method)
	}
	if getCaseList.RequestPayloadCarrier != "body" || getCaseList.RequestPayloadFormat != "json" {
		t.Fatalf("expected POST body payload metadata, got %#v", getCaseList)
	}
	caseParams := make(map[string]bool)
	for _, param := range getCaseList.Params {
		caseParams[param.Name] = true
	}
	for _, required := range []string{"caseName", "status", "priority", "caseDesc", "moduleId", "pageNum", "pageSize"} {
		if !caseParams[required] {
			t.Fatalf("expected param %q in %#v", required, getCaseList.Params)
		}
	}
}

func TestExtractHTTPContextEndpointsDetectsPayloadCarrierAndFormat(t *testing.T) {
	content := `
rn({type:"post",url:"/api/demo",body:{caseId:t,stepId:r,httpReqType:"query"}})
fetch("/api/query",{method:"POST",body:JSON.stringify({id:1,name:"demo"})})
`

	endpoints := extractHTTPContextEndpoints("https://example.com/main.js", content)
	if len(endpoints) < 2 {
		t.Fatalf("expected at least 2 endpoints, got %d", len(endpoints))
	}

	var bodyEndpoint *StaticProtocolEndpoint
	var fetchEndpoint *StaticProtocolEndpoint
	for index := range endpoints {
		switch endpoints[index].Path {
		case "/api/demo":
			bodyEndpoint = &endpoints[index]
		case "/api/query":
			fetchEndpoint = &endpoints[index]
		}
	}

	if bodyEndpoint == nil || bodyEndpoint.RequestPayloadCarrier != "body" || bodyEndpoint.RequestPayloadFormat != "json" {
		t.Fatalf("expected rn body endpoint payload detection, got %#v", bodyEndpoint)
	}
	if fetchEndpoint == nil || fetchEndpoint.RequestPayloadCarrier != "body" || fetchEndpoint.RequestPayloadFormat != "json" {
		t.Fatalf("expected fetch body payload detection, got %#v", fetchEndpoint)
	}
}

func TestMergeStaticEndpointCollectionsAggregatesDuplicateClients(t *testing.T) {
	merged := mergeStaticEndpointCollections(
		[]StaticProtocolEndpoint{
			{
				Path:       "/stat/queryTop10ScriptsAuthorInfo",
				Method:     "GET",
				Client:     "wrapper:So -> rn",
				SourceFile: "https://example.com/main.js",
			},
		},
		[]StaticProtocolEndpoint{
			{
				Path:       "/stat/queryTop10ScriptsAuthorInfo",
				Method:     "GET",
				Client:     "rn",
				SourceFile: "https://example.com/main.js",
			},
		},
	)

	if len(merged) != 1 {
		t.Fatalf("expected duplicate endpoints to be merged, got %d", len(merged))
	}
	if got := merged[0].Client; got != "wrapper:So -> rn | rn" {
		t.Fatalf("expected merged client labels, got %q", got)
	}
}

func TestMergeStaticEndpointCollectionsPrefersObservedGETQueryPayload(t *testing.T) {
	merged := mergeStaticEndpointCollections(
		[]StaticProtocolEndpoint{
			{
				Path:                  "/ccat/api/refreshApiInfoByInterfaceName",
				Method:                "GET",
				Client:                "wrapper:rn",
				RequestPayloadCarrier: "body",
				RequestPayloadFormat:  "json",
				SourceFile:            "https://example.com/main.js",
			},
		},
		[]StaticProtocolEndpoint{
			{
				Path:                  "/ccat/api/refreshApiInfoByInterfaceName",
				Method:                "GET",
				Client:                "api-resource",
				RequestPayloadCarrier: "params",
				RequestPayloadFormat:  "query",
				SourceFile:            "api-resource",
			},
		},
	)

	if len(merged) != 1 {
		t.Fatalf("expected merged endpoint count 1, got %d", len(merged))
	}
	if merged[0].RequestPayloadCarrier != "params" {
		t.Fatalf("expected observed query carrier to override static body, got %q", merged[0].RequestPayloadCarrier)
	}
	if merged[0].RequestPayloadFormat != "query" {
		t.Fatalf("expected observed query format to override static json, got %q", merged[0].RequestPayloadFormat)
	}
}

func TestInferObservedPayloadCarrierPrefersQueryForGETEvenWhenBodyExists(t *testing.T) {
	parsed, err := url.Parse("https://example.com/ccat/api/refreshApiInfoByInterfaceName?env=TEST33&interfaceName=test")
	if err != nil {
		t.Fatalf("failed to parse url: %v", err)
	}

	got := inferObservedPayloadCarrier("GET", parsed, `{"env":"TEST33","interfaceName":"test"}`)
	if got != "params" {
		t.Fatalf("expected GET with query to prefer params, got %q", got)
	}
}
