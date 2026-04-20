package sqli

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"trailblazer/pkg/config"
	"trailblazer/pkg/core/structs"
	"trailblazer/pkg/core/vuln"

	"github.com/go-resty/resty/v2"
)

// SQLInjectionResult 表示 SQL 注入测试结果
type SQLInjectionResult struct {
	Vulnerable bool   `json:"vulnerable"`
	Payload    string `json:"payload"`
	Response   string `json:"response"`
	Reason     string `json:"reason"`
	Type       string `json:"type"` // 注入类型：error-based, time-based, boolean-based
}

// TestSQLInjection 测试SQL注入漏洞
// apiReq: 原始 API 请求
// cfg: SQL注入配置（包含payloads、匹配关键词）
// returns: SQLInjectionResult 测试结果
func TestSQLInjection(apiReq structs.APIRequest, cfg config.SQLInjectionConfig) (*SQLInjectionResult, error) {
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
		vulnerable, oddBody1 := isBooleanBasedSQLInjection(apiReq, paramName)
		if vulnerable {
			return &SQLInjectionResult{
				Vulnerable: true,
				Payload:    "'",
				Response:   vuln.TruncateResponse(oddBody1),
				Reason:     "检测到布尔盲注SQL注入漏洞 (参数: " + paramName + ")",
				Type:       "boolean-based",
			}, nil
		}

		for _, rule := range cfg.Rules {
			payloadList := rule.Payloads
			if len(payloadList) == 0 {
				continue
			}

			for _, payload := range payloadList {
				// 创建修改后的请求，只修改当前测试的参数
				modifiedReq := apiReq
				if modifiedReq.Params == nil {
					modifiedReq.Params = make(map[string][]string)
				}
				modifiedReq.Params[paramName] = []string{payload}

				resp, err := vuln.SendAPIRequest(modifiedReq, false)
				if err != nil {
					continue // 跳过失败的请求
				}

				// 按规则先做响应体关键词校验

				body := string(resp.Body())
				ruleBodyHit := false
				if len(rule.BodyContains) > 0 {
					bl := strings.ToLower(body)
					for _, kw := range rule.BodyContains {
						if strings.Contains(bl, strings.ToLower(kw)) {
							ruleBodyHit = true
							break
						}
					}
					if !ruleBodyHit {
						continue
					}
				}

				// 类型判定
				vulnerable := false
				loweredBody := strings.ToLower(body)
				switch rule.Type {
				case "error-based":
					vulnerable = ruleBodyHit || isErrorBasedSQLInjection(loweredBody) || containsAny(loweredBody, cfg.MatchKeywords)
				case "time-based":
					vulnerable = ruleBodyHit || isTimeBasedSQLInjectionWithThreshold(resp, rule.MinDelayMs)
				default:
					vulnerable = ruleBodyHit || containsAny(loweredBody, cfg.MatchKeywords)
				}

				if vulnerable {
					ruleType := rule.Type
					if ruleType == "" {
						ruleType = "unknown"
					}
					return &SQLInjectionResult{
						Vulnerable: true,
						Payload:    payload,
						Response:   vuln.TruncateResponse(body),
						Reason:     fmt.Sprintf("检测到%s SQL注入漏洞 (参数: %s)", ruleType, paramName),
						Type:       ruleType,
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

// oddBody1: 1个单引号的响应
// oddBody3: 3个单引号的响应
// evenBody2: 2个单引号的响应
// evenBody4: 4个单引号的响应
// 如果奇数响应组（1和3）相同，偶数响应组（2和4）相同，但两组不同，则判断为布尔盲注
func isBooleanBasedSQLInjection(apiReq structs.APIRequest, paramName string) (bool, string) {
	var oddBody1, oddBody3, evenBody2, evenBody4 string

	// 测试 1 个单引号
	if resp, err := vuln.SendAPIRequest(buildTestRequest(apiReq, paramName, "'"), false); err == nil {
		oddBody1 = string(resp.Body())
	}
	// 测试 3 个单引号
	if resp, err := vuln.SendAPIRequest(buildTestRequest(apiReq, paramName, "'''"), false); err == nil {
		oddBody3 = string(resp.Body())
	}
	// 测试 2 个单引号
	if resp, err := vuln.SendAPIRequest(buildTestRequest(apiReq, paramName, "''"), false); err == nil {
		evenBody2 = string(resp.Body())
	}
	// 测试 4 个单引号
	if resp, err := vuln.SendAPIRequest(buildTestRequest(apiReq, paramName, "''''"), false); err == nil {
		evenBody4 = string(resp.Body())
	}

	if evenBody2 == evenBody4 && len(oddBody3)-len(oddBody1) <= 1 && oddBody1 != evenBody2 {
		return true, oddBody1
	}

	return false, ""
}

// isErrorBasedSQLInjection 检测基于错误的SQL注入（扩展 sqlmap/常见错误签名）
func isErrorBasedSQLInjection(bodyLower string) bool {
	errorPatterns := []string{
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

	for _, pattern := range errorPatterns {
		if strings.Contains(bodyLower, pattern) {
			return true
		}
	}
	return false
}

// isTimeBasedSQLInjectionWithThreshold 按指定阈值（毫秒）判定 time-based 成功
func isTimeBasedSQLInjectionWithThreshold(resp *resty.Response, minDelayMs int) bool {
	if minDelayMs <= 0 {
		return false
	}
	// 仅在服务端返回成功/可用的状态码时考虑时间阈值，以减少网络异常带来的误判
	if resp.StatusCode() == 0 || (resp.StatusCode() < http.StatusOK || resp.StatusCode() >= 600) {
		// 没有有效状态码信息，保守起见不据此判定
	}
	return resp.Time() >= time.Duration(minDelayMs)*time.Millisecond
}

func containsAny(bodyLower string, words []string) bool {
	if len(words) == 0 {
		return false
	}
	bl := strings.ToLower(bodyLower)
	for _, w := range words {
		if strings.Contains(bl, strings.ToLower(w)) {
			return true
		}
	}
	return false
}

// buildTestRequest 构建测试请求
func buildTestRequest(apiReq structs.APIRequest, paramName, testValue string) structs.APIRequest {
	modifiedReq := apiReq
	if modifiedReq.Params == nil {
		modifiedReq.Params = make(map[string][]string)
	}
	modifiedReq.Params[paramName] = []string{testValue}
	return modifiedReq
}
