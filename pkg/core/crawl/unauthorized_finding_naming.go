package crawl

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

const unauthorizedFindingCategory = "访问控制缺陷"

var (
	unauthorizedFindingSubcategories = map[string]struct{}{
		"未授权敏感信息读取": {},
		"未授权业务数据读取": {},
		"未授权业务查询":   {},
		"未授权状态变更":   {},
		"未授权业务接口访问": {},
	}
	unauthorizedFindingUnsafeName = regexp.MustCompile(`[\r\n\t<>]{1,}|[\x00-\x1f]`)
)

// UnauthorizedFindingName describes a finding after the detector has already
// established that the request is an unauthorized-access candidate. Naming
// never participates in the vulnerability verdict or risk calculation.
type UnauthorizedFindingName struct {
	Category       string
	Subcategory    string
	BusinessObject string
	Title          string
	Source         string
}

type unauthorizedFindingNamer interface {
	NameUnauthorizedFinding(targetURL, method, requestPreview, responsePreview, dataExposure string) (UnauthorizedFindingName, error)
}

// ClassifyUnauthorizedFinding deterministically labels a confirmed candidate.
// It is intentionally conservative so cached historical findings can be
// improved without calling an AI service when the task detail is opened.
func ClassifyUnauthorizedFinding(targetURL, method, responsePreview, dataExposure string) UnauthorizedFindingName {
	subcategory := "未授权业务接口访问"
	switch strings.TrimSpace(dataExposure) {
	case "sensitive_data":
		subcategory = "未授权敏感信息读取"
	case "internal_business":
		if isUnauthorizedWriteOperation(targetURL, method) {
			subcategory = "未授权状态变更"
		} else if strings.EqualFold(strings.TrimSpace(method), "GET") || isUnauthorizedQueryOperation(targetURL) {
			subcategory = "未授权业务查询"
		} else {
			subcategory = "未授权业务数据读取"
		}
	case "basic_reference", "public_data":
		subcategory = "未授权业务数据读取"
	default:
		if isUnauthorizedWriteOperation(targetURL, method) {
			subcategory = "未授权状态变更"
		} else if isUnauthorizedQueryOperation(targetURL) {
			subcategory = "未授权业务查询"
		}
	}

	businessObject := deriveUnauthorizedBusinessObject(targetURL, responsePreview)
	return normalizeUnauthorizedFindingName(UnauthorizedFindingName{
		Category:       unauthorizedFindingCategory,
		Subcategory:    subcategory,
		BusinessObject: businessObject,
		Title:          buildUnauthorizedFindingTitle(businessObject, subcategory),
		Source:         "rule",
	}, targetURL, method, responsePreview, dataExposure)
}

func normalizeUnauthorizedFindingName(name UnauthorizedFindingName, targetURL, method, responsePreview, dataExposure string) UnauthorizedFindingName {
	fallback := ClassifyUnauthorizedFindingFallback(targetURL, method, responsePreview, dataExposure)
	if strings.TrimSpace(name.Category) != unauthorizedFindingCategory {
		return fallback
	}
	name.Subcategory = strings.TrimSpace(name.Subcategory)
	if _, ok := unauthorizedFindingSubcategories[name.Subcategory]; !ok {
		return fallback
	}
	name.BusinessObject = normalizeUnauthorizedBusinessObject(name.BusinessObject)
	if name.BusinessObject == "" {
		return fallback
	}
	// Compose the title locally: the AI may select an allowed category and
	// identify the business object, but cannot invent a free-form claim.
	name.Title = buildUnauthorizedFindingTitle(name.BusinessObject, name.Subcategory)
	if name.Source != "ai" {
		name.Source = "rule"
	}
	return name
}

// ClassifyUnauthorizedFindingFallback is split out to avoid recursion while
// validating a potentially malformed AI reply.
func ClassifyUnauthorizedFindingFallback(targetURL, method, responsePreview, dataExposure string) UnauthorizedFindingName {
	subcategory := "未授权业务接口访问"
	switch strings.TrimSpace(dataExposure) {
	case "sensitive_data":
		subcategory = "未授权敏感信息读取"
	case "internal_business":
		if isUnauthorizedWriteOperation(targetURL, method) {
			subcategory = "未授权状态变更"
		} else if strings.EqualFold(strings.TrimSpace(method), "GET") || isUnauthorizedQueryOperation(targetURL) {
			subcategory = "未授权业务查询"
		} else {
			subcategory = "未授权业务数据读取"
		}
	case "basic_reference", "public_data":
		subcategory = "未授权业务数据读取"
	default:
		if isUnauthorizedWriteOperation(targetURL, method) {
			subcategory = "未授权状态变更"
		} else if isUnauthorizedQueryOperation(targetURL) {
			subcategory = "未授权业务查询"
		}
	}
	businessObject := deriveUnauthorizedBusinessObject(targetURL, responsePreview)
	return UnauthorizedFindingName{
		Category:       unauthorizedFindingCategory,
		Subcategory:    subcategory,
		BusinessObject: businessObject,
		Title:          buildUnauthorizedFindingTitle(businessObject, subcategory),
		Source:         "rule",
	}
}

func buildUnauthorizedFindingTitle(businessObject, subcategory string) string {
	suffixes := map[string]string{
		"未授权敏感信息读取": "未授权读取",
		"未授权业务数据读取": "未授权读取",
		"未授权业务查询":   "未授权查询",
		"未授权状态变更":   "未授权变更",
		"未授权业务接口访问": "未授权访问",
	}
	if suffix, ok := suffixes[subcategory]; ok {
		return businessObject + suffix
	}
	return businessObject + "未授权访问"
}

func isUnauthorizedWriteOperation(targetURL, method string) bool {
	if !strings.EqualFold(strings.TrimSpace(method), "GET") && !strings.EqualFold(strings.TrimSpace(method), "HEAD") {
		lower := strings.ToLower(targetURL)
		return strings.Contains(lower, "save") || strings.Contains(lower, "update") || strings.Contains(lower, "delete") || strings.Contains(lower, "remove") || strings.Contains(lower, "create") || strings.Contains(lower, "submit") || strings.Contains(lower, "approve") || strings.Contains(lower, "audit") || strings.Contains(lower, "check")
	}
	return false
}

func isUnauthorizedQueryOperation(targetURL string) bool {
	lower := strings.ToLower(targetURL)
	for _, token := range []string{"query", "search", "list", "detail", "info", "find", "get", "select"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func deriveUnauthorizedBusinessObject(targetURL, _ string) string {
	parsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil {
		return "业务资源"
	}
	last := strings.ToLower(path.Base(strings.TrimSuffix(parsed.Path, "/")))
	switch {
	case strings.Contains(last, "query"), strings.Contains(last, "search"):
		return "业务查询结果"
	case strings.Contains(last, "check"), strings.Contains(last, "verify"):
		return "业务核验结果"
	case strings.Contains(last, "list"):
		return "业务列表"
	case strings.Contains(last, "detail"), strings.Contains(last, "info"):
		return "业务详情"
	case strings.Contains(last, "config"):
		return "业务配置"
	case last != "" && last != "." && last != "/":
		return fmt.Sprintf("%s资源", last)
	default:
		return "业务资源"
	}
}

func normalizeUnauthorizedBusinessObject(value string) string {
	value = strings.TrimSpace(unauthorizedFindingUnsafeName.ReplaceAllString(value, ""))
	value = strings.Join(strings.Fields(value), " ")
	if value == "" || len([]rune(value)) > 32 {
		return ""
	}
	return value
}
