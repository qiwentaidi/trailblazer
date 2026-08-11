package crawl

import (
	"testing"

	"github.com/qiwentaidi/trailblazer/pkg/core/database"
)

func TestBuildJSRequestBlueprintsExtractsComparableRequestCounts(t *testing.T) {
	jsResources := []database.JSResource{
		{
			URL: "https://example.com/app.js",
			Content: `
				const service = axios.create({
					baseURL: '/api',
					headers: { 'X-App': 'trailblazer' }
				})
				service.interceptors.request.use(config => {
					config.headers.Authorization = getToken()
					config.headers['X-Sign'] = sign(config)
					return config
				})
				export function createUser(form) {
					return service.post('/users/create', { name: form.name, roleId: form.roleId })
				}
				export function ping() {
					return axios.get('/public/ping?type=a')
				}
				export function report(id) {
					return fetch('/reports/export', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({ reportId: id })
					})
				}
			`,
		},
	}

	blueprints := BuildJSRequestBlueprints(jsResources)
	if len(blueprints) != 3 {
		t.Fatalf("expected 3 request blueprints, got %d: %#v", len(blueprints), blueprints)
	}

	createUser := findRequestBlueprint(blueprints, "POST", "/users/create")
	if createUser == nil {
		t.Fatalf("expected POST /users/create blueprint, got %#v", blueprints)
	}
	if createUser.BaseURL != "/api" {
		t.Fatalf("expected axios instance baseURL to be propagated, got %q", createUser.BaseURL)
	}
	if !hasRequestBlueprintHeader(createUser.Headers, "Authorization", true) {
		t.Fatalf("expected dynamic Authorization header from request interceptor, got %#v", createUser.Headers)
	}
	if !hasRequestBlueprintHeader(createUser.Headers, "X-Sign", true) {
		t.Fatalf("expected dynamic X-Sign header from request interceptor, got %#v", createUser.Headers)
	}
	if !hasRequestBlueprintParam(createUser.Params, "name", "json") || !hasRequestBlueprintParam(createUser.Params, "roleId", "json") {
		t.Fatalf("expected JSON body params from service.post payload, got %#v", createUser.Params)
	}

	report := findRequestBlueprint(blueprints, "POST", "/reports/export")
	if report == nil {
		t.Fatalf("expected POST /reports/export blueprint, got %#v", blueprints)
	}
	if report.PayloadFormat != "json" || report.PayloadCarrier != "body" {
		t.Fatalf("expected fetch JSON body metadata, got carrier=%q format=%q", report.PayloadCarrier, report.PayloadFormat)
	}
	if !hasRequestBlueprintParam(report.Params, "reportId", "json") {
		t.Fatalf("expected reportId JSON param, got %#v", report.Params)
	}
}

func TestBuildJSRequestBlueprintsExtractsMinifiedAxiosLikeInstances(t *testing.T) {
	jsResources := []database.JSResource{
		{
			URL:     "https://example.com/min.js",
			Content: "var x=1,y=2,a=b.create({baseURL:T(),timeout:1e4});a.interceptors.request.use(e=>{return e.headers=e.headers||{},e.headers[`X-Token`]=token(),e});function c(e){return a.post(`/base/login`,e)}function d(e){return a.get(`/user/detail`,{params:{ID:e}})}",
		},
	}

	blueprints := BuildJSRequestBlueprints(jsResources)
	if len(blueprints) != 2 {
		t.Fatalf("expected 2 request blueprints from minified axios-like instance, got %d: %#v", len(blueprints), blueprints)
	}
	login := findRequestBlueprint(blueprints, "POST", "/base/login")
	if login == nil {
		t.Fatalf("expected POST /base/login blueprint, got %#v", blueprints)
	}
	if login.Client != "axios-instance:a.post" {
		t.Fatalf("expected generic minified instance client label, got %q", login.Client)
	}
	if !hasRequestBlueprintHeader(login.Headers, "X-Token", true) {
		t.Fatalf("expected dynamic X-Token header from minified interceptor, got %#v", login.Headers)
	}
	user := findRequestBlueprint(blueprints, "GET", "/user/detail")
	if user == nil {
		t.Fatalf("expected GET /user/${e} blueprint, got %#v", blueprints)
	}
	if !hasRequestBlueprintParam(user.Params, "ID", "query") {
		t.Fatalf("expected query ID param from minified config, got %#v", user.Params)
	}
}

func TestBuildJSRequestBlueprintsKeepsValueExpressionsAndUnresolvedSymbols(t *testing.T) {
	jsResources := []database.JSResource{
		{
			URL:     "https://example.com/context.js",
			Content: "const fixedApp=`test`;function f(s,c,l){return dn({url:`/ccat/jar/getMethodDetail`,type:`post`,body:{groupId:s,art:c,version:l,interfaceName:`test`,appName:fixedApp}})}",
		},
	}

	blueprints := BuildJSRequestBlueprints(jsResources)
	blueprint := findRequestBlueprint(blueprints, "POST", "/ccat/jar/getMethodDetail")
	if blueprint == nil {
		t.Fatalf("expected POST /ccat/jar/getMethodDetail blueprint, got %#v", blueprints)
	}

	groupID := findRequestBlueprintParam(blueprint.Params, "groupId")
	if groupID == nil {
		t.Fatalf("expected groupId param, got %#v", blueprint.Params)
	}
	if groupID.ValueExpr != "s" || !groupID.Resolved || groupID.ResolvedFrom != "function-parameter" {
		t.Fatalf("expected groupId to retain expression and resolve to function parameter, got %#v", groupID)
	}

	appName := findRequestBlueprintParam(blueprint.Params, "appName")
	if appName == nil {
		t.Fatalf("expected appName param, got %#v", blueprint.Params)
	}
	if appName.ValueExpr != "fixedApp" || !appName.Resolved || appName.ResolvedFrom != "symbol:constant" || appName.Value != "test" {
		t.Fatalf("expected appName to resolve through same-file constant, got %#v", appName)
	}
	if len(blueprint.UnresolvedSymbols) != 0 {
		t.Fatalf("expected no unresolved symbols after function parameter and constant resolution, got %#v", blueprint.UnresolvedSymbols)
	}
}

func TestBuildJSRequestBlueprintsInfersBodyShapeFromWrapperCallsites(t *testing.T) {
	jsResources := []database.JSResource{
		{
			URL:     "https://example.com/min.js",
			Content: "var WN=TN.create({baseURL:Tke(),timeout:1e4});function SAe(e){return WN.post(`/asset/domain/add`,e)}async function submit(e){let t=(await SAe({domains:e})).data;return t}",
		},
	}

	blueprints := BuildJSRequestBlueprints(jsResources)
	blueprint := findRequestBlueprint(blueprints, "POST", "/asset/domain/add")
	if blueprint == nil {
		t.Fatalf("expected POST /asset/domain/add blueprint, got %#v", blueprints)
	}

	if len(blueprint.Params) != 1 {
		t.Fatalf("expected callsite body shape to replace generic body params, got %#v", blueprint.Params)
	}
	domains := findRequestBlueprintParam(blueprint.Params, "domains")
	if domains == nil {
		t.Fatalf("expected domains param from SAe({domains:e}) callsite, got %#v", blueprint.Params)
	}
	if domains.ValueExpr != "e" || domains.Source != "callsite-body" || domains.ResolvedFrom != "callsite-object-field:e" {
		t.Fatalf("expected domains to carry callsite expression metadata, got %#v", domains)
	}
	if blueprint.PayloadPreview != "{domains:e}" {
		t.Fatalf("expected callsite payload preview, got %q", blueprint.PayloadPreview)
	}
}

func TestBuildJSRequestBlueprintsExtractsWebpackAxiosDefaultCalls(t *testing.T) {
	jsResources := []database.JSResource{
		{
			URL: "https://example.com/bundle.js",
			Content: `
				var API_BASE_URL = '/api';
				function listMessages(pageSize) {
					return axios__WEBPACK_IMPORTED_MODULE_0__["default"].get("".concat(API_BASE_URL, "/telegram/db-messages/"), {
						params: { page: 1, pageSize: pageSize, count_mode: 'fast' },
						timeout: 8000
					});
				}
				function createAccount(accountData) {
					return axios__WEBPACK_IMPORTED_MODULE_0__["default"].post("".concat(API_BASE_URL, "/telegram/accounts/"), accountData);
				}
				createAccount({ username: 'demo', phone: mobile });
			`,
		},
	}

	blueprints := BuildJSRequestBlueprints(jsResources)
	messages := findRequestBlueprint(blueprints, "GET", "/api/telegram/db-messages/")
	if messages == nil {
		t.Fatalf("expected webpack axios GET blueprint, got %#v", blueprints)
	}
	if !hasRequestBlueprintParam(messages.Params, "page", "query") || !hasRequestBlueprintParam(messages.Params, "pageSize", "query") {
		t.Fatalf("expected query params from webpack axios config, got %#v", messages.Params)
	}

	account := findRequestBlueprint(blueprints, "POST", "/api/telegram/accounts/")
	if account == nil {
		t.Fatalf("expected webpack axios POST blueprint, got %#v", blueprints)
	}
	if !hasRequestBlueprintParam(account.Params, "username", "json") || !hasRequestBlueprintParam(account.Params, "phone", "json") {
		t.Fatalf("expected callsite body params from webpack axios wrapper, got %#v", account.Params)
	}
}

func TestBuildJSRequestBlueprintsInfersLocalVariableShapes(t *testing.T) {
	jsResources := []database.JSResource{
		{
			URL: "https://example.com/local-vars.js",
			Content: `
				var API_BASE_URL = '/api';
				function listGroups(page, pageSize, keyword) {
					var params = { page: page, page_size: pageSize, keyword: keyword || '' };
					return axios__WEBPACK_IMPORTED_MODULE_0__["default"].get("".concat(API_BASE_URL, "/telegram/groups/"), { params: params });
				}
				function sendCommand(groupUrls, status, reason) {
					var requestData = { command: 'monitor' };
					requestData.group_urls = groupUrls;
					requestData.status = status;
					if (reason) requestData.reason = reason;
					return axios__WEBPACK_IMPORTED_MODULE_0__["default"].post("".concat(API_BASE_URL, "/telegram/accounts/send_monitor_command/"), requestData);
				}
			`,
		},
	}

	blueprints := BuildJSRequestBlueprints(jsResources)
	groups := findRequestBlueprint(blueprints, "GET", "/api/telegram/groups/")
	if groups == nil {
		t.Fatalf("expected GET /api/telegram/groups/ blueprint, got %#v", blueprints)
	}
	for _, name := range []string{"page", "page_size", "keyword"} {
		if !hasRequestBlueprintParam(groups.Params, name, "query") {
			t.Fatalf("expected local params object field %q, got %#v", name, groups.Params)
		}
	}

	command := findRequestBlueprint(blueprints, "POST", "/api/telegram/accounts/send_monitor_command/")
	if command == nil {
		t.Fatalf("expected POST send_monitor_command blueprint, got %#v", blueprints)
	}
	for _, name := range []string{"command", "group_urls", "status", "reason"} {
		if !hasRequestBlueprintParam(command.Params, name, "json") {
			t.Fatalf("expected local requestData field %q, got %#v", name, command.Params)
		}
	}
}

func TestBuildJSRequestBlueprintsExtractsObjectRequestWrapperAcrossChunks(t *testing.T) {
	jsResources := []database.JSResource{
		{
			URL: "https://example.com/main.js",
			Content: `
				"9h9Y":function(e,t,r){"use strict";r.d(t,"a",(function(){return u}));var c="/",u="/taxi-saas";}
				function request(e){var token=window.localStorage.getItem("token");return e.headers={"X-Requested-With":"XMLHttpRequest","X-SAAS-TOKEN":token},e}
			`,
		},
		{
			URL: "https://example.com/3.fba48c22.js",
			Content: `
				var m=r("9h9Y"),f=r("7Qib");
				function addResource(e){
					return Object(f.d)({url:"".concat(m.a,"/resource/add"),type:"get",body:{id:e,resourceName:"demo"}});
				}
				function updateRole(n,o){
					return Object(f.d)({url:"".concat(m.a,"/role/").concat(n),type:"post",body:o});
				}
			`,
		},
	}

	blueprints := BuildJSRequestBlueprints(jsResources)
	resource := findRequestBlueprint(blueprints, "GET", "/taxi-saas/resource/add")
	if resource == nil {
		t.Fatalf("expected object wrapper GET blueprint, got %#v", blueprints)
	}
	if !hasRequestBlueprintParam(resource.Params, "id", "query") || !hasRequestBlueprintParam(resource.Params, "resourceName", "query") {
		t.Fatalf("expected GET body fields to be treated as query params, got %#v", resource.Params)
	}
	if !hasRequestBlueprintHeader(resource.Headers, "X-SAAS-TOKEN", true) {
		t.Fatalf("expected dynamic wrapper token header, got %#v", resource.Headers)
	}

	role := findRequestBlueprint(blueprints, "POST", "/taxi-saas/role/{n}")
	if role == nil {
		t.Fatalf("expected dynamic role path blueprint, got %#v", blueprints)
	}
	if !containsString(role.UnresolvedSymbols, "n") {
		t.Fatalf("expected dynamic path symbol n to be unresolved, got %#v", role.UnresolvedSymbols)
	}
}

func TestBuildJSRequestBlueprintsExtractsJQueryAjaxURLsFromSharedScope(t *testing.T) {
	jsResources := []database.JSResource{
		{
			URL: "https://example.com/login-inline.js",
			Content: `
				var _EmployeeLoginUrl = 'https://auth.caocaoglobal.com/api/credential/login';
				var _EmployeePincodeUrl = 'https://auth.caocaoglobal.com/api/credential/pincode';
				var _VUE_APP_SMS_SEND_KEY = 'SMSAUTH_B305B66C0AE5418E92FDCFCAEF234772';
			`,
		},
		{
			URL: "https://example.com/Scripts/newsignin.js",
			Content: `
				function validateEmpEmpty() {
					var empPhone = $('#EmpPhone').val(), pwd = $('#EmpPassword').val();
					var data = {
						"loginid": "EMPLOYEEWEBAUTH_943902F525774A4FAA18CBDFF0FE0058",
						"openid": pwd,
						"pincode": "",
						"phoneNumber": empPhone,
					};
					$.ajax({
						type: 'POST',
						url: _EmployeeLoginUrl,
						data: JSON.stringify(data),
						contentType: 'application/json',
					});
				}
				function sendValidationCode() {
					var mobilePhone = $('#EmpPhone').val();
					$.ajax({
						url: _EmployeePincodeUrl,
						type: 'post',
						data: JSON.stringify({ PhoneNumber: mobilePhone, LoginAs: _VUE_APP_SMS_SEND_KEY }),
						contentType: 'application/json',
					});
				}
			`,
		},
	}

	blueprints := BuildJSRequestBlueprints(jsResources)
	login := findRequestBlueprint(blueprints, "POST", "https://auth.caocaoglobal.com/api/credential/login")
	if login == nil {
		t.Fatalf("expected jQuery ajax login blueprint, got %#v", blueprints)
	}
	for _, name := range []string{"loginid", "openid", "pincode", "phoneNumber"} {
		if !hasRequestBlueprintParam(login.Params, name, "json") {
			t.Fatalf("expected login JSON param %q, got %#v", name, login.Params)
		}
	}

	pincode := findRequestBlueprint(blueprints, "POST", "https://auth.caocaoglobal.com/api/credential/pincode")
	if pincode == nil {
		t.Fatalf("expected jQuery ajax pincode blueprint, got %#v", blueprints)
	}
	for _, name := range []string{"PhoneNumber", "LoginAs"} {
		if !hasRequestBlueprintParam(pincode.Params, name, "json") {
			t.Fatalf("expected pincode JSON param %q, got %#v", name, pincode.Params)
		}
	}
}

func TestBuildJSRequestBlueprintsExpandsJQuerySerializedFormFields(t *testing.T) {
	jsResources := []database.JSResource{
		{
			URL: "https://example.com/admin-login.html",
			Content: `
				<form class="layui-form" id="login-form">
					<input id="username" name="username" />
					<input id="password" name="password" type="password" />
					<!-- <input id="captcha" name="captcha" /> -->
					<input id="remember" name="remember" type="checkbox" value="1" />
					<button id="subBtn" type="button">login</button>
				</form>
				<script>
					function login(){
						$.ajax({
							type: "POST",
							url: "/index.php?r=public%2Flogin",
							data: $("#login-form").serialize(),
							headers: {'X-CSRF-Token': 'token'},
							dataType: "json"
						});
					}
				</script>
			`,
		},
	}

	blueprints := BuildJSRequestBlueprints(jsResources)
	if len(blueprints) != 1 {
		t.Fatalf("expected one jQuery ajax blueprint without wrapper-config duplicate, got %d: %#v", len(blueprints), blueprints)
	}
	login := findRequestBlueprint(blueprints, "POST", "/index.php?r=public%2Flogin")
	if login == nil {
		t.Fatalf("expected serialized login blueprint, got %#v", blueprints)
	}
	for _, name := range []string{"username", "password", "remember"} {
		if !hasRequestBlueprintParam(login.Params, name, "body") {
			t.Fatalf("expected serialized form body param %q, got %#v", name, login.Params)
		}
	}
	if findRequestBlueprintParam(login.Params, "captcha") != nil {
		t.Fatalf("did not expect commented captcha input to be extracted, got %#v", login.Params)
	}
	if login.PayloadFormat != "form" {
		t.Fatalf("expected serialized payload format form, got %q", login.PayloadFormat)
	}
}

func TestBuildJSRequestBlueprintsExtractsGenericHTTPMethodWrappers(t *testing.T) {
	jsResources := []database.JSResource{
		{
			URL: "https://example.com/common.js",
			Content: `
				class Client {
					get(e, t) { return this.instance.get(e, t).then(e => e.data) }
					post(e, t, s) { return this.instance.post(e, t, s).then(e => e.data) }
				}
				const api = new Client();
				const auth = {
					login: e => api.post("/aggregate_chat/user/login", e),
					me: () => api.get("/aggregate_chat/user/me"),
					list: e => api.get("/aggregate_chat/chat/session_list", { params: e }),
				};
			`,
		},
	}

	blueprints := BuildJSRequestBlueprints(jsResources)
	login := findRequestBlueprint(blueprints, "POST", "/aggregate_chat/user/login")
	if login == nil {
		t.Fatalf("expected generic wrapper POST blueprint, got %#v", blueprints)
	}
	me := findRequestBlueprint(blueprints, "GET", "/aggregate_chat/user/me")
	if me == nil {
		t.Fatalf("expected generic wrapper GET blueprint, got %#v", blueprints)
	}
	list := findRequestBlueprint(blueprints, "GET", "/aggregate_chat/chat/session_list")
	if list == nil {
		t.Fatalf("expected generic wrapper GET params blueprint, got %#v", blueprints)
	}
	if list.PayloadCarrier != "params" || list.PayloadFormat != "query" {
		t.Fatalf("expected GET wrapper params metadata, got carrier=%q format=%q", list.PayloadCarrier, list.PayloadFormat)
	}
}

func findRequestBlueprint(items []RequestBlueprint, method, path string) *RequestBlueprint {
	for index := range items {
		if items[index].Method == method && items[index].Path == path {
			return &items[index]
		}
	}
	return nil
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func hasRequestBlueprintHeader(items []RequestBlueprintHeader, name string, dynamic bool) bool {
	for _, item := range items {
		if item.Name == name && item.Dynamic == dynamic {
			return true
		}
	}
	return false
}

func hasRequestBlueprintParam(items []RequestBlueprintParam, name, location string) bool {
	for _, item := range items {
		if item.Name == name && item.Location == location {
			return true
		}
	}
	return false
}

func findRequestBlueprintParam(items []RequestBlueprintParam, name string) *RequestBlueprintParam {
	for index := range items {
		if items[index].Name == name {
			return &items[index]
		}
	}
	return nil
}
