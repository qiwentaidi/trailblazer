package sqli

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// SQLInjectionResult 表示 SQL 注入测试结果
type SQLInjectionResult struct {
	Vulnerable     bool   `json:"vulnerable"`
	Payload        string `json:"payload"`
	Response       string `json:"response"`
	ResponseLength int    `json:"response_length"`
	Reason         string `json:"reason"`
	Type           string `json:"type"` // 注入类型：error-based, boolean-based
}

type responseSnapshot struct {
	statusCode int
	body       string
	bodyLower  string
	packet     string
	duration   time.Duration
}

const (
	maxSQLiProbeRequests  = 48
	sqlProbeTimeoutSecs   = 5
	timeDelayThreshold    = 1800 * time.Millisecond
	timeDelayProbeSeconds = 2
)

var errSQLiProbeBudgetExceeded = errors.New("SQL injection probe request budget exceeded")

type probeSender struct {
	remaining int
}

func newProbeSender(limit int) *probeSender {
	return &probeSender{remaining: limit}
}

func (s *probeSender) send(apiReq structs.APIRequest) (responseSnapshot, error) {
	if s.remaining <= 0 {
		return responseSnapshot{}, errSQLiProbeBudgetExceeded
	}
	s.remaining--
	return sendSnapshot(apiReq)
}

// TestSQLInjection 测试SQL注入漏洞
// apiReq: 原始 API 请求
// cfg: SQL注入配置（包含payloads、匹配关键词）
// returns: SQLInjectionResult 测试结果
func TestSQLInjection(apiReq structs.APIRequest, cfg config.SQLInjectionConfig) (*SQLInjectionResult, error) {
	sender := newProbeSender(maxSQLiProbeRequests)
	baselineResp, err := sender.send(cloneAPIRequest(apiReq))
	if err != nil {
		return nil, err
	}

	// 获取所有参数名
	paramNames := make([]string, 0, len(apiReq.Params))
	for paramName := range apiReq.Params {
		paramNames = append(paramNames, paramName)
	}
	sort.Strings(paramNames)

	// 如果没有参数，跳过测试
	if len(paramNames) == 0 {
		return nil, nil
	}

	// 对每个参数都进行测试
	for _, paramName := range paramNames {
		// 检测布尔盲注
		vulnerable, evidenceResp, boolPayload := isBooleanBasedSQLInjection(sender, apiReq, paramName)
		if vulnerable {
			return &SQLInjectionResult{
				Vulnerable:     true,
				Payload:        boolPayload,
				Response:       vuln.TruncateResponse(evidenceResp.packet),
				ResponseLength: len(evidenceResp.body),
				Reason:         "检测到布尔盲注SQL注入漏洞 (参数: " + paramName + ")",
				Type:           "boolean-based",
			}, nil
		}

		vulnerable, evidenceResp, timePayload := isTimeBasedSQLInjection(sender, apiReq, paramName, baselineResp)
		if vulnerable {
			return &SQLInjectionResult{
				Vulnerable:     true,
				Payload:        timePayload,
				Response:       vuln.TruncateResponse(evidenceResp.packet),
				ResponseLength: len(evidenceResp.body),
				Reason:         "检测到时间盲注SQL注入漏洞 (参数: " + paramName + ")",
				Type:           "time-based",
			}, nil
		}

		for _, rule := range buildSQLiPayloadRules(cfg) {
			payloadList := rule.Payloads
			if len(payloadList) == 0 {
				continue
			}

			for _, payload := range payloadList {
				// 创建修改后的请求，只修改当前测试的参数
				modifiedReq := buildTestRequest(apiReq, paramName, payload)

				resp, err := sender.send(modifiedReq)
				if err != nil {
					if errors.Is(err, errSQLiProbeBudgetExceeded) {
						return nonVulnerableSQLiResult("SQL注入检测达到请求预算，已停止剩余探针"), nil
					}
					continue
				}

				// 按规则先做响应体关键词校验

				ruleBodyHit := false
				if len(rule.BodyContains) > 0 {
					for _, kw := range rule.BodyContains {
						if strings.Contains(resp.bodyLower, strings.ToLower(kw)) && !strings.Contains(baselineResp.bodyLower, strings.ToLower(kw)) {
							ruleBodyHit = true
							break
						}
					}
				}

				// 类型判定
				vulnerable := false
				switch rule.Type {
				case "error-based":
					vulnerable = ruleBodyHit || hasNewErrorBasedSignal(resp.bodyLower, baselineResp.bodyLower) || hasNewKeywordMatch(resp.bodyLower, baselineResp.bodyLower, cfg.MatchKeywords)
				default:
					vulnerable = ruleBodyHit || hasNewKeywordMatch(resp.bodyLower, baselineResp.bodyLower, cfg.MatchKeywords)
				}

				if vulnerable {
					ruleType := rule.Type
					if ruleType == "" {
						ruleType = "unknown"
					}
					return &SQLInjectionResult{
						Vulnerable:     true,
						Payload:        payload,
						Response:       vuln.TruncateResponse(resp.packet),
						ResponseLength: len(resp.body),
						Reason:         fmt.Sprintf("检测到%s SQL注入漏洞 (参数: %s)", ruleType, paramName),
						Type:           ruleType,
					}, nil
				}
			}
		}
	}

	return &SQLInjectionResult{
		Vulnerable: false,
		Payload:    "",
		Response:   "",
		Reason:     "未检测到SQL注入漏洞",
		Type:       "",
	}, nil
}

func nonVulnerableSQLiResult(reason string) *SQLInjectionResult {
	return &SQLInjectionResult{
		Vulnerable: false,
		Payload:    "",
		Response:   "",
		Reason:     reason,
		Type:       "",
	}
}

// 奇数单引号组（1 个和 3 个）的响应必须相同，偶数单引号组（2 个和 4 个）的响应也必须相同，
// 且两组响应必须不同，才判定为布尔盲注。基线响应不参与该判定。
func isBooleanBasedSQLInjection(sender *probeSender, apiReq structs.APIRequest, paramName string) (bool, responseSnapshot, string) {
	for _, probe := range buildBooleanProbePairs() {
		trueResp1, err := sender.send(buildTestRequest(apiReq, paramName, probe.truePayload1))
		if err != nil {
			if errors.Is(err, errSQLiProbeBudgetExceeded) {
				return false, responseSnapshot{}, ""
			}
			continue
		}
		trueResp2, err := sender.send(buildTestRequest(apiReq, paramName, probe.truePayload2))
		if err != nil {
			if errors.Is(err, errSQLiProbeBudgetExceeded) {
				return false, responseSnapshot{}, ""
			}
			continue
		}
		falseResp1, err := sender.send(buildTestRequest(apiReq, paramName, probe.falsePayload1))
		if err != nil {
			if errors.Is(err, errSQLiProbeBudgetExceeded) {
				return false, responseSnapshot{}, ""
			}
			continue
		}
		falseResp2, err := sender.send(buildTestRequest(apiReq, paramName, probe.falsePayload2))
		if err != nil {
			if errors.Is(err, errSQLiProbeBudgetExceeded) {
				return false, responseSnapshot{}, ""
			}
			continue
		}

		if !responsesEquivalent(trueResp1, trueResp2) || !responsesEquivalent(falseResp1, falseResp2) {
			continue
		}
		if !responsesDifferent(trueResp1, falseResp1) {
			continue
		}
		if isStatusOnlyEmptyBodyDifference(trueResp1, falseResp1) {
			continue
		}

		return true, trueResp1, probe.truePayload1
	}

	return false, responseSnapshot{}, ""
}

func isTimeBasedSQLInjection(sender *probeSender, apiReq structs.APIRequest, paramName string, baseline responseSnapshot) (bool, responseSnapshot, string) {
	for _, probe := range buildTimeProbePairs() {
		controlResp, err := sender.send(buildTestRequest(apiReq, paramName, probe.controlPayload))
		if err != nil {
			if errors.Is(err, errSQLiProbeBudgetExceeded) {
				return false, responseSnapshot{}, ""
			}
			continue
		}
		delayedResp, err := sender.send(buildTestRequest(apiReq, paramName, probe.delayedPayload))
		if err != nil {
			if errors.Is(err, errSQLiProbeBudgetExceeded) {
				return false, responseSnapshot{}, ""
			}
			continue
		}
		if delayedResp.duration-controlResp.duration >= timeDelayThreshold &&
			delayedResp.duration-baseline.duration >= timeDelayThreshold {
			return true, delayedResp, probe.delayedPayload
		}
	}
	return false, responseSnapshot{}, ""
}

// isErrorBasedSQLInjection 检测基于错误的SQL注入（扩展 sqlmap/常见错误签名）
func isErrorBasedSQLInjection(bodyLower string) []string {
	var matches []string
	for _, pattern := range errorPatterns {
		if strings.Contains(bodyLower, pattern) {
			matches = append(matches, pattern)
		}
	}
	return matches
}

var errorPatterns = []string{
	// MySQL / MariaDB 常见
	"you have an error in your sql syntax;",
	"mysql_fetch",
	"mysql_num_rows",
	"mysql_fetch_array",
	"mysql_fetch_assoc",
	"mysql_fetch_object",
	"mysql_fetch_row",
	"mysql_error",
	"mysql_connect",
	"mysql_select_db",
	"mysql_query",
	"mysqlnd",
	"warning: mysql",
	"fatal error: mysql",
	"com.mysql.jdbc.exceptions.jdbc4.msqlsyntaxerrorexception",
	"mysqlsyntaxerrorexception",

	// PostgreSQL 常见
	"syntax error at or near",
	"pg_query",
	"pg_fetch_array",
	"pg_fetch_assoc",
	"pg_fetch_object",
	"pg_fetch_row",
	"psql: error",
	"org.postgresql.util.psqlexception",
	"postgresql error",
	"warning: postgresql",
	"fatal error: postgresql",
	"postgresql",

	// Microsoft SQL Server / T-SQL
	"unclosed quotation mark after the character string",
	"microsoft ole db",
	"odbc sql server driver",
	"sql server",
	"sqlserverexception",
	"system.data.sqlclient.sqlexception",
	"sqlexception",
	"microsoft sql server native client",
	"fatal error: sqlserver",

	// Oracle
	"ora-",
	"oracle error",
	"oracle_query",
	"oracle_fetch_array",
	"oracle_fetch_assoc",
	"oracle_fetch_object",
	"oracle_fetch_row",
	"warning: oracle",
	"fatal error: oracle",
	"oracle",

	// SQLite
	"sqlite",
	"sqlite error",
	"sqlite_query",
	"sqlite_fetch_array",
	"sqlite_fetch_assoc",
	"sqlite_fetch_object",
	"sqlite_fetch_row",
	"sqlite3::sqlexception",
	"sqliteexception",
	"no such table",
	"no such column",

	// 通用 / 驱动 / JDBC / Java 异常
	"sql syntax",
	"sql error",
	"database error",
	"query failed",
	"java.sql.sqlexception",
	"org.hibernate.exception.sqlgrammarexception",
	"javax.persistence",
	"sqlstate",
	"sqlsyntaxerrorexception",
	"data truncation",

	// 常见字段/列/表错误提示
	"unknown column",
	"invalid column name",
	"ambiguous column name",
	"column count doesn't match value count",
	"column not found",

	// 权限 / 连接 / 其他
	"permission denied",
	"could not connect to server",
	"connect failed",
	"cannot open database",
	"could not find driver",

	// DB2 / Informix / Sybase / Firebird 等常见词
	"db2",
	"informix",
	"sybase",
	"adaptive server",
	"firebird",
	"ibm db2",

	// ODBC / PDO / PHP 提示
	"odbc",
	"pdoexception",
	"warning: odbc",
	"warning: pdo",
	"on line", // 结合其他模式可增加命中（谨慎使用）

	// 其它常见识别串（来自各种 DB 驱动/库）
	"fatal error",
	"warning:",
	"internal server error", // 注意：此项容易误报，按需启用/禁用
	"sql syntax error",
	"unterminated quoted string",
	"quoted string not properly terminated",
	"syntax error in string in query expression",
}

func hasNewKeywordMatch(bodyLower string, baselineLower string, words []string) bool {
	if len(words) == 0 {
		return false
	}
	for _, w := range words {
		lowerWord := strings.ToLower(w)
		if strings.Contains(bodyLower, lowerWord) && !strings.Contains(baselineLower, lowerWord) {
			return true
		}
	}
	return false
}

func hasNewErrorBasedSignal(bodyLower string, baselineLower string) bool {
	for _, match := range isErrorBasedSQLInjection(bodyLower) {
		if !strings.Contains(baselineLower, match) {
			return true
		}
	}
	return false
}

type booleanProbePair struct {
	truePayload1  string
	truePayload2  string
	falsePayload1 string
	falsePayload2 string
}

func buildBooleanProbePairs() []booleanProbePair {
	return []booleanProbePair{
		{
			truePayload1:  "'",
			truePayload2:  "'''",
			falsePayload1: "''",
			falsePayload2: "''''",
		},
		{
			truePayload1:  "1 AND 1=1",
			truePayload2:  "1 AND 2=2",
			falsePayload1: "1 AND 1=2",
			falsePayload2: "1 AND 2=3",
		},
		{
			truePayload1:  "' AND '1'='1",
			truePayload2:  "' AND '2'='2",
			falsePayload1: "' AND '1'='2",
			falsePayload2: "' AND '2'='3",
		},
		{
			truePayload1:  "') AND ('1'='1",
			truePayload2:  "') AND ('2'='2",
			falsePayload1: "') AND ('1'='2",
			falsePayload2: "') AND ('2'='3",
		},
		{
			truePayload1:  "\" AND \"1\"=\"1",
			truePayload2:  "\" AND \"2\"=\"2",
			falsePayload1: "\" AND \"1\"=\"2",
			falsePayload2: "\" AND \"2\"=\"3",
		},
	}
}

type timeProbePair struct {
	controlPayload string
	delayedPayload string
}

func buildTimeProbePairs() []timeProbePair {
	delay := fmt.Sprintf("%d", timeDelayProbeSeconds)
	return []timeProbePair{
		{controlPayload: "1", delayedPayload: "1 AND SLEEP(" + delay + ")"},
		{controlPayload: "1", delayedPayload: "1 AND pg_sleep(" + delay + ")"},
		{controlPayload: "1", delayedPayload: "1; WAITFOR DELAY '0:0:" + delay + "'--"},
		{controlPayload: "' AND '1'='1", delayedPayload: "' AND SLEEP(" + delay + ")-- "},
	}
}

func buildSQLiPayloadRules(cfg config.SQLInjectionConfig) []config.SQLiPayloadRule {
	rules := append([]config.SQLiPayloadRule{}, cfg.Rules...)
	if len(cfg.Payloads) > 0 {
		rules = append(rules, config.SQLiPayloadRule{
			Payloads: cfg.Payloads,
			Type:     "error-based",
		})
	}
	if len(rules) > 0 {
		return rules
	}
	return []config.SQLiPayloadRule{
		{
			Payloads: []string{
				"'",
				"\"",
				"')",
				"\")",
				"'--",
				"\"--",
				"' OR '1'='1",
				"\" OR \"1\"=\"1",
				"1 OR 1=1",
			},
			Type: "error-based",
		},
	}
}

// buildTestRequest 构建测试请求
func buildTestRequest(apiReq structs.APIRequest, paramName, testValue string) structs.APIRequest {
	modifiedReq := cloneAPIRequest(apiReq)
	modifiedReq.Params[paramName] = []string{testValue}
	modifiedReq.Body = injectPayloadIntoBody(modifiedReq, paramName, testValue)
	return modifiedReq
}

func injectPayloadIntoBody(apiReq structs.APIRequest, paramName, testValue string) string {
	body := strings.TrimSpace(apiReq.Body)
	if body == "" {
		return apiReq.Body
	}

	payloadCarrier := strings.ToLower(strings.TrimSpace(apiReq.PayloadCarrier))
	payloadFormat := strings.ToLower(strings.TrimSpace(apiReq.PayloadFormat))
	contentType := strings.ToLower(headerValue(apiReq.Headers, "Content-Type"))
	if payloadCarrier != "body" && payloadCarrier != "data" &&
		payloadFormat != "json" && payloadFormat != "form" &&
		!strings.Contains(contentType, "application/json") &&
		!strings.Contains(contentType, "application/x-www-form-urlencoded") {
		return apiReq.Body
	}

	if payloadFormat == "json" || strings.Contains(contentType, "application/json") || strings.HasPrefix(body, "{") {
		if updated, ok := injectJSONPayload(body, paramName, testValue); ok {
			return updated
		}
	}
	if payloadFormat == "form" || strings.Contains(contentType, "application/x-www-form-urlencoded") || strings.Contains(body, "=") {
		if updated, ok := injectFormPayload(body, paramName, testValue); ok {
			return updated
		}
	}
	return apiReq.Body
}

func injectJSONPayload(body, paramName, testValue string) (string, bool) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return "", false
	}
	payload[paramName] = testValue
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", false
	}
	return string(encoded), true
}

func injectFormPayload(body, paramName, testValue string) (string, bool) {
	form, err := url.ParseQuery(body)
	if err != nil {
		return "", false
	}
	form.Set(paramName, testValue)
	return form.Encode(), true
}

func cloneAPIRequest(apiReq structs.APIRequest) structs.APIRequest {
	cloned := structs.APIRequest{
		URL:            apiReq.URL,
		Method:         apiReq.Method,
		Body:           apiReq.Body,
		PayloadCarrier: apiReq.PayloadCarrier,
		PayloadFormat:  apiReq.PayloadFormat,
	}
	if len(apiReq.Headers) == 0 {
		cloned.Headers = map[string]string{}
	} else {
		cloned.Headers = make(map[string]string, len(apiReq.Headers))
		for key, value := range apiReq.Headers {
			cloned.Headers[key] = value
		}
	}
	cloned.Params = make(url.Values, len(apiReq.Params))
	for key, values := range apiReq.Params {
		cloned.Params[key] = append([]string(nil), values...)
	}
	return cloned
}

func sendSnapshot(apiReq structs.APIRequest) (responseSnapshot, error) {
	start := time.Now()
	resp, err := vuln.SendAPIRequestWithTimeout(apiReq, false, sqlProbeTimeoutSecs)
	duration := time.Since(start)
	if err != nil {
		return responseSnapshot{}, err
	}
	body := string(resp.Body())
	return responseSnapshot{
		statusCode: resp.StatusCode(),
		body:       body,
		bodyLower:  strings.ToLower(body),
		packet:     buildResponsePacket(resp.Status(), resp.Header(), body),
		duration:   duration,
	}, nil
}

func headerValue(headers map[string]string, key string) string {
	for existingKey, value := range headers {
		if strings.EqualFold(existingKey, key) {
			return value
		}
	}
	return ""
}

func buildResponsePacket(status string, headers map[string][]string, body string) string {
	var builder strings.Builder
	if strings.TrimSpace(status) != "" {
		builder.WriteString("HTTP/1.1 ")
		builder.WriteString(strings.TrimSpace(status))
		builder.WriteString("\n")
	}

	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range headers[key] {
			builder.WriteString(key)
			builder.WriteString(": ")
			builder.WriteString(value)
			builder.WriteString("\n")
		}
	}

	if builder.Len() > 0 {
		builder.WriteString("\n")
	}
	builder.WriteString(body)
	return builder.String()
}

func normalizeBody(body string) string {
	return strings.TrimSpace(body)
}

var dynamicBodyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`),
	regexp.MustCompile(`\b\d{10,}\b`),
	regexp.MustCompile(`(?i)\b[0-9a-f]{16,}\b`),
}

func responsesEquivalent(left, right responseSnapshot) bool {
	if left.statusCode != right.statusCode {
		return false
	}

	leftCanonical := canonicalizeBody(left.body)
	rightCanonical := canonicalizeBody(right.body)
	if leftCanonical == rightCanonical {
		return true
	}

	if edgeSignature(leftCanonical) != edgeSignature(rightCanonical) {
		return false
	}

	leftLen := len(leftCanonical)
	rightLen := len(rightCanonical)
	diff := math.Abs(float64(leftLen - rightLen))
	return diff <= 8 || (maxInt(leftLen, rightLen) > 0 && diff/float64(maxInt(leftLen, rightLen)) <= 0.02)
}

func responsesDifferent(left, right responseSnapshot) bool {
	return !responsesEquivalent(left, right)
}

func isStatusOnlyEmptyBodyDifference(left, right responseSnapshot) bool {
	return canonicalizeBody(left.body) == "" &&
		canonicalizeBody(right.body) == "" &&
		left.statusCode != right.statusCode
}

func canonicalizeBody(body string) string {
	canonical := strings.ToLower(strings.TrimSpace(body))
	for _, pattern := range dynamicBodyPatterns {
		canonical = pattern.ReplaceAllString(canonical, "{dyn}")
	}
	canonical = strings.Join(strings.Fields(canonical), " ")
	return canonical
}

func edgeSignature(body string) string {
	if len(body) <= 160 {
		return body
	}
	return body[:80] + "|" + body[len(body)-80:]
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
