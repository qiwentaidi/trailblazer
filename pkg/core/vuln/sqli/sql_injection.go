package sqli

import (
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"
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
}

// TestSQLInjection 测试SQL注入漏洞
// apiReq: 原始 API 请求
// cfg: SQL注入配置（包含payloads、匹配关键词）
// returns: SQLInjectionResult 测试结果
func TestSQLInjection(apiReq structs.APIRequest, cfg config.SQLInjectionConfig) (*SQLInjectionResult, error) {
	baselineResp, err := sendSnapshot(cloneAPIRequest(apiReq))
	if err != nil {
		return nil, err
	}

	// 获取所有参数名
	paramNames := make([]string, 0, len(apiReq.Params))
	for paramName := range apiReq.Params {
		paramNames = append(paramNames, paramName)
	}

	// 如果没有参数，跳过测试
	if len(paramNames) == 0 {
		return nil, nil
	}

	// 对每个参数都进行测试
	for _, paramName := range paramNames {
		// 检测布尔盲注
		vulnerable, evidenceResp, boolPayload := isBooleanBasedSQLInjection(apiReq, paramName)
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

		for _, rule := range cfg.Rules {
			payloadList := rule.Payloads
			if len(payloadList) == 0 {
				continue
			}

			for _, payload := range payloadList {
				// 创建修改后的请求，只修改当前测试的参数
				modifiedReq := cloneAPIRequest(apiReq)
				modifiedReq.Params[paramName] = []string{payload}

				resp, err := sendSnapshot(modifiedReq)
				if err != nil {
					continue // 跳过失败的请求
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

// 奇数单引号组（1 个和 3 个）的响应必须相同，偶数单引号组（2 个和 4 个）的响应也必须相同，
// 且两组响应必须不同，才判定为布尔盲注。基线响应不参与该判定。
func isBooleanBasedSQLInjection(apiReq structs.APIRequest, paramName string) (bool, responseSnapshot, string) {
	for _, probe := range buildBooleanProbePairs() {
		oddResp1, err := sendSnapshot(buildTestRequest(apiReq, paramName, probe.oddPayload1))
		if err != nil {
			continue
		}
		oddResp3, err := sendSnapshot(buildTestRequest(apiReq, paramName, probe.oddPayload3))
		if err != nil {
			continue
		}
		evenResp2, err := sendSnapshot(buildTestRequest(apiReq, paramName, probe.evenPayload2))
		if err != nil {
			continue
		}
		evenResp4, err := sendSnapshot(buildTestRequest(apiReq, paramName, probe.evenPayload4))
		if err != nil {
			continue
		}

		if !responsesEquivalent(oddResp1, oddResp3) || !responsesEquivalent(evenResp2, evenResp4) {
			continue
		}
		if !responsesDifferent(oddResp1, evenResp2) {
			continue
		}
		if isStatusOnlyEmptyBodyDifference(oddResp1, evenResp2) {
			continue
		}

		return true, oddResp1, probe.oddPayload1
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
	"syntax error",
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
	oddPayload1  string
	oddPayload3  string
	evenPayload2 string
	evenPayload4 string
}

func buildBooleanProbePairs() []booleanProbePair {
	return []booleanProbePair{
		{
			oddPayload1:  "'",
			oddPayload3:  "'''",
			evenPayload2: "''",
			evenPayload4: "''''",
		},
	}
}

// buildTestRequest 构建测试请求
func buildTestRequest(apiReq structs.APIRequest, paramName, testValue string) structs.APIRequest {
	modifiedReq := cloneAPIRequest(apiReq)
	modifiedReq.Params[paramName] = []string{testValue}
	return modifiedReq
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
	resp, err := vuln.SendAPIRequest(apiReq, false)
	if err != nil {
		return responseSnapshot{}, err
	}
	body := string(resp.Body())
	return responseSnapshot{
		statusCode: resp.StatusCode(),
		body:       body,
		bodyLower:  strings.ToLower(body),
		packet:     buildResponsePacket(resp.Status(), resp.Header(), body),
	}, nil
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
