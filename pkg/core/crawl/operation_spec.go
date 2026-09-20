package crawl

import (
	"crypto/sha1"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

// OperationSpec is the safely persistable interface definition. It feeds
// OpenAPI export, interface analysis, and parameter fuzzing. It stores
// origin, method, path template, parameter expressions, source location,
// confidence, and unresolved symbols — never credential-bearing runtime
// values. Anything dynamic (tokens, signatures, nonces, timestamps, user
// input) is marked and must be completed from runtime traffic.
type OperationSpec struct {
	ID                    string                 `json:"id"`
	Origin                string                 `json:"origin,omitempty"`
	Method                string                 `json:"method"`
	PathTemplate          string                 `json:"pathTemplate"`
	Params                []OperationSpecParam   `json:"params,omitempty"`
	Headers               []OperationSpecHeader  `json:"headers,omitempty"`
	PayloadCarrier        string                 `json:"payloadCarrier,omitempty"`
	PayloadFormat         string                 `json:"payloadFormat,omitempty"`
	PayloadTemplate       string                 `json:"payloadTemplate,omitempty"`
	Source                RequestBlueprintSource `json:"source,omitempty"`
	Confidence            string                 `json:"confidence"`
	ConfidenceReason      string                 `json:"confidenceReason,omitempty"`
	UnresolvedSymbols     []string               `json:"unresolvedSymbols,omitempty"`
	RequiresRuntime       []string               `json:"requiresRuntime,omitempty"`
	ExtractionSource      string                 `json:"extractionSource"`
	AnalysisStage         string                 `json:"analysisStage,omitempty"`
	CompatibleAPIRequests int                    `json:"compatibleApiRequests,omitempty"`
}

// OperationSpecParam is a parameter template. Dynamic params carry no value;
// runtime traffic must supply them.
type OperationSpecParam struct {
	Name          string `json:"name"`
	Location      string `json:"location,omitempty"`
	ValueExpr     string `json:"valueExpr,omitempty"`
	Value         string `json:"value,omitempty"`
	Dynamic       bool   `json:"dynamic,omitempty"`
	DynamicReason string `json:"dynamicReason,omitempty"`
	Confidence    string `json:"confidence,omitempty"`
}

// OperationSpecHeader keeps the header name and only statically safe values.
type OperationSpecHeader struct {
	Name    string `json:"name"`
	Value   string `json:"value,omitempty"`
	Dynamic bool   `json:"dynamic,omitempty"`
}

var dynamicParamNamePattern = regexp.MustCompile(`(?i)(^|[_\-.\[\]])(token|access_?token|id_?token|refresh_?token|sign|signature|sig|nonce|timestamp|ts|ticket|session|sessionid|secret|api_?key|apikey|appkey|passwd|password|authorization|auth|cookie|csrf|xsrf|captcha|code)($|[_\-.\[\]])`)

var dynamicValuePattern = regexp.MustCompile(`^[A-Za-z0-9_\-]{24,}$|^[a-f0-9]{32,}$|^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.`)

// IsDynamicParamName reports whether a parameter name denotes a
// runtime-supplied dynamic value (token, signature, nonce, timestamp, ...).
func IsDynamicParamName(name string) bool {
	return dynamicParamNamePattern.MatchString(strings.TrimSpace(name))
}

// isDynamicParamValue reports whether a static value looks like an ephemeral
// credential or digest rather than a reusable literal.
func isDynamicParamValue(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) >= 24 && dynamicValuePattern.MatchString(value)
}

// operationSpecSensitiveHeaderNames are headers whose values are
// credential-bearing and must never persist in an OperationSpec.
var operationSpecSensitiveHeaderNames = map[string]struct{}{
	"authorization": {}, "proxy-authorization": {}, "cookie": {}, "set-cookie": {},
	"x-api-key": {}, "x-auth-token": {}, "x-access-token": {}, "x-csrf-token": {},
	"x-xsrf-token": {}, "x-session-token": {},
}

// IsSensitiveHeaderName reports whether a header typically carries
// credentials.
func IsSensitiveHeaderName(name string) bool {
	_, ok := operationSpecSensitiveHeaderNames[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// OperationSpecsFromBlueprints converts static request blueprints into
// persistable operation templates. Dynamic values are stripped and listed in
// RequiresRuntime so the template honestly marks what runtime traffic must
// supply.
func OperationSpecsFromBlueprints(blueprints []RequestBlueprint, origin string) []OperationSpec {
	specs := make([]OperationSpec, 0, len(blueprints))
	for _, blueprint := range blueprints {
		specs = append(specs, OperationSpecFromBlueprint(blueprint, origin))
	}
	return specs
}

// OperationSpecFromBlueprint converts one blueprint into a template-only
// operation spec.
func OperationSpecFromBlueprint(blueprint RequestBlueprint, origin string) OperationSpec {
	spec := OperationSpec{
		Origin:                strings.TrimSpace(origin),
		Method:                strings.ToUpper(strings.TrimSpace(blueprint.Method)),
		PathTemplate:          strings.TrimSpace(blueprint.Path),
		PayloadCarrier:        strings.TrimSpace(blueprint.PayloadCarrier),
		PayloadFormat:         strings.TrimSpace(blueprint.PayloadFormat),
		PayloadTemplate:       strings.TrimSpace(blueprint.PayloadPreview),
		Source:                blueprint.Source,
		Confidence:            blueprint.Confidence,
		ConfidenceReason:      blueprint.ConfidenceReason,
		UnresolvedSymbols:     append([]string(nil), blueprint.UnresolvedSymbols...),
		ExtractionSource:      blueprint.ExtractionSource,
		AnalysisStage:         blueprint.AnalysisStage,
		CompatibleAPIRequests: blueprint.CompatibleAPIRequests,
	}
	if spec.Origin == "" && isAbsoluteHTTPURL(blueprint.BaseURL) {
		spec.Origin = originFromURL(blueprint.BaseURL)
	}

	for _, param := range blueprint.Params {
		specParam := OperationSpecParam{
			Name:       strings.TrimSpace(param.Name),
			Location:   strings.TrimSpace(param.Location),
			ValueExpr:  strings.TrimSpace(param.ValueExpr),
			Confidence: strings.TrimSpace(param.Confidence),
		}
		value := strings.TrimSpace(param.Value)
		switch {
		case !param.Resolved:
			specParam.Dynamic = true
			specParam.DynamicReason = "unresolved-symbol"
		case IsDynamicParamName(specParam.Name):
			specParam.Dynamic = true
			specParam.DynamicReason = "dynamic-name"
		case value != "" && isDynamicParamValue(value):
			specParam.Dynamic = true
			specParam.DynamicReason = "ephemeral-value"
		default:
			specParam.Value = value
		}
		if specParam.Dynamic {
			spec.RequiresRuntime = appendUniqueStrings(spec.RequiresRuntime, specParam.Location+":"+specParam.Name)
		}
		spec.Params = append(spec.Params, specParam)
	}

	for _, header := range blueprint.Headers {
		specHeader := OperationSpecHeader{
			Name:    strings.TrimSpace(header.Name),
			Dynamic: header.Dynamic || IsSensitiveHeaderName(header.Name),
		}
		if !specHeader.Dynamic {
			specHeader.Value = strings.TrimSpace(header.Value)
		}
		if specHeader.Dynamic {
			spec.RequiresRuntime = appendUniqueStrings(spec.RequiresRuntime, "header:"+specHeader.Name)
		}
		spec.Headers = append(spec.Headers, specHeader)
	}

	sort.SliceStable(spec.Params, func(i, j int) bool {
		if spec.Params[i].Location == spec.Params[j].Location {
			return spec.Params[i].Name < spec.Params[j].Name
		}
		return spec.Params[i].Location < spec.Params[j].Location
	})
	sort.Strings(spec.RequiresRuntime)
	spec.ID = buildOperationSpecID(spec)
	return spec
}

func buildOperationSpecID(spec OperationSpec) string {
	hash := sha1.Sum([]byte(strings.Join([]string{
		strings.ToUpper(strings.TrimSpace(spec.Method)),
		strings.TrimSpace(spec.Origin),
		strings.TrimSpace(spec.PathTemplate),
	}, "\x00")))
	return "ops_" + hex.EncodeToString(hash[:8])
}

func isAbsoluteHTTPURL(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func originFromURL(value string) string {
	value = strings.TrimSpace(value)
	schemeEnd := strings.Index(value, "://")
	if schemeEnd < 0 {
		return ""
	}
	rest := value[schemeEnd+3:]
	if slash := strings.Index(rest, "/"); slash >= 0 {
		rest = rest[:slash]
	}
	return value[:schemeEnd+3] + rest
}
