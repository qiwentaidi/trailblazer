package web

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const denyTemplateMinClusterSize = 3

type denyTemplateAIReviewer interface {
	JudgeDenyTemplate(requestPreview, responsePreview string) (bool, string, error)
}

type denyTemplateAIReviewResult struct {
	confirmed bool
}

var newDenyTemplateAIReviewer = func() denyTemplateAIReviewer {
	openAIConfig, err := loadProtocolOpenAIConfig()
	if err != nil || !openAIConfig.Enabled || strings.TrimSpace(openAIConfig.APIKey) == "" {
		return nil
	}

	return crawl.NewSensitiveInfoChecker(
		openAIConfig.APIKey,
		openAIConfig.BaseURL,
		openAIConfig.Model,
	)
}

var denyTemplateAIReviewCache sync.Map

var volatileResponseKeys = map[string]struct{}{
	"error_hint":   {},
	"hint":         {},
	"trace_id":     {},
	"traceid":      {},
	"request_id":   {},
	"requestid":    {},
	"req_id":       {},
	"reqid":        {},
	"timestamp":    {},
	"time":         {},
	"ts":           {},
	"nonce":        {},
	"sign":         {},
	"signature":    {},
	"rand":         {},
	"random":       {},
	"token":        {},
	"access_token": {},
}

type denyTemplateCluster struct {
	id          string
	kind        string
	label       string
	fingerprint string
	items       []*database.VulnRecord
}

func annotateUnauthorizedNoise(vulns []database.VulnRecord) []database.VulnRecord {
	if len(vulns) == 0 {
		return vulns
	}

	clusters := map[string]*denyTemplateCluster{}
	reviewer := newDenyTemplateAIReviewer()

	for index := range vulns {
		vuln := &vulns[index]
		if !isUnauthorizedVuln(*vuln) {
			continue
		}

		fingerprint, kind, label, ok := buildDenyTemplateFingerprint(*vuln)
		if !ok {
			continue
		}

		clusterID := shortHash(kind + ":" + fingerprint)
		cluster, exists := clusters[clusterID]
		if !exists {
			cluster = &denyTemplateCluster{
				id:          clusterID,
				kind:        kind,
				label:       label,
				fingerprint: fingerprint,
				items:       []*database.VulnRecord{},
			}
			clusters[clusterID] = cluster
		}
		cluster.items = append(cluster.items, vuln)
	}

	for _, cluster := range clusters {
		if len(cluster.items) < denyTemplateMinClusterSize {
			continue
		}
		keep, aiVerified := shouldKeepDenyTemplateCluster(cluster, reviewer)
		if aiVerified {
			for _, vuln := range cluster.items {
				vuln.AIVerified = true
			}
		}
		if !keep {
			continue
		}
		for _, vuln := range cluster.items {
			vuln.DenyTemplateID = cluster.id
			vuln.DenyTemplateKind = cluster.kind
			vuln.DenyTemplateLabel = cluster.label
			vuln.DenyTemplateCount = len(cluster.items)

			vuln.Confidence = "low"
			vuln.ConfidenceReason = "低置信：结果更像相似拒绝模板或通用错误响应"
		}
	}

	return vulns
}

func isUnauthorizedVuln(vuln database.VulnRecord) bool {
	return vuln.Type == "未授权访问" || vuln.Title == "未授权访问"
}

func shouldKeepDenyTemplateCluster(cluster *denyTemplateCluster, reviewer denyTemplateAIReviewer) (bool, bool) {
	if cluster == nil || len(cluster.items) == 0 {
		return false, false
	}
	if reviewer == nil {
		return true, false
	}

	cacheKey := cluster.kind + ":" + cluster.fingerprint
	if cached, ok := denyTemplateAIReviewCache.Load(cacheKey); ok {
		if result, ok := cached.(denyTemplateAIReviewResult); ok {
			return result.confirmed, true
		}
	}

	sample := pickDenyTemplateRepresentative(cluster.items)
	if sample == nil {
		return true, false
	}

	confirmed, _, err := reviewer.JudgeDenyTemplate(sample.Request, sample.Response)
	if err != nil {
		return true, false
	}

	denyTemplateAIReviewCache.Store(cacheKey, denyTemplateAIReviewResult{confirmed: confirmed})
	return confirmed, true
}

func pickDenyTemplateRepresentative(items []*database.VulnRecord) *database.VulnRecord {
	if len(items) == 0 {
		return nil
	}

	best := items[0]
	bestScore := denyTemplateRepresentativeScore(best)
	for _, item := range items[1:] {
		score := denyTemplateRepresentativeScore(item)
		if score > bestScore {
			best = item
			bestScore = score
		}
	}
	return best
}

func denyTemplateRepresentativeScore(vuln *database.VulnRecord) int {
	if vuln == nil {
		return -1
	}
	return len(strings.TrimSpace(vuln.Request))*2 + len(strings.TrimSpace(vuln.Response))
}

func buildDenyTemplateFingerprint(vuln database.VulnRecord) (string, string, string, bool) {
	normalizedResponse := strings.TrimSpace(vuln.Response)
	if normalizedResponse == "" {
		return "", "", "", false
	}

	shortResponse := len(normalizedResponse) <= 1024
	normalizedBody := normalizeResponseFingerprint(normalizedResponse)
	if normalizedBody == "" {
		return "", "", "", false
	}

	score := 0
	kind := "deny_template"
	label := "疑似统一拒绝模板"

	if shortResponse {
		score += 2
	}
	if vuln.ResponseLength > 0 && vuln.ResponseLength <= 256 {
		score += 2
	}

	if strings.Contains(normalizedBody, `"success":false`) ||
		strings.Contains(normalizedBody, `"ok":false`) {
		score += 2
	}

	authSignalCount := countAuthSignals(normalizedBody)
	if authSignalCount > 0 {
		score += authSignalCount * 2
		kind = "auth_required"
		label = "疑似统一认证拒绝模板"
	}

	if strings.Contains(normalizedBody, `"data":null`) ||
		strings.Contains(normalizedBody, `"result":null`) {
		score += 1
	}

	if strings.Contains(normalizedBody, `"from":"`) && strings.Contains(normalizedBody, `auth`) {
		score += 2
		kind = "auth_required"
		label = "疑似统一认证拒绝模板"
	}

	if score < 4 {
		return "", "", "", false
	}

	fingerprint := normalizedBody
	if len(fingerprint) > 512 {
		fingerprint = fingerprint[:512]
	}

	return fingerprint, kind, label, true
}

func normalizeResponseFingerprint(response string) string {
	trimmed := strings.TrimSpace(response)
	if trimmed == "" {
		return ""
	}

	var data any
	if err := json.Unmarshal([]byte(trimmed), &data); err == nil {
		return canonicalizeJSONValue(data)
	}

	lower := strings.ToLower(trimmed)
	return strings.Join(strings.Fields(lower), " ")
}

func canonicalizeJSONValue(value any) string {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			normalizedKey := strings.ToLower(key)
			if isVolatileResponseKey(normalizedKey) {
				parts = append(parts, strconv.Quote(normalizedKey)+`:"<volatile>"`)
				continue
			}
			parts = append(parts, strconv.Quote(normalizedKey)+":"+canonicalizeJSONValue(typed[key]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	case []any:
		if len(typed) == 0 {
			return "[]"
		}
		if len(typed) > 3 {
			typed = typed[:3]
		}
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, canonicalizeJSONValue(item))
		}
		return "[" + strings.Join(parts, ",") + "]"
	case string:
		normalized := strings.ToLower(strings.TrimSpace(typed))
		normalized = strings.Join(strings.Fields(normalized), " ")
		return strconv.Quote(normalized)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case nil:
		return "null"
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func countAuthSignals(body string) int {
	signals := []string{
		"auth",
		"jwt",
		"token",
		"credential",
		"login",
		"session",
		"unauthorized",
		"forbidden",
		"permission",
		"凭据",
		"认证",
		"鉴权",
		"登录",
		"令牌",
		"未登录",
		"无权限",
	}

	count := 0
	for _, signal := range signals {
		if strings.Contains(body, signal) {
			count++
		}
	}
	return count
}

func isVolatileResponseKey(key string) bool {
	if _, ok := volatileResponseKeys[key]; ok {
		return true
	}

	// 对常见动态标识做兜底，避免同一拒绝模板仅因 trace/request/error 随机字段被拆散。
	return strings.Contains(key, "trace") ||
		strings.Contains(key, "request") ||
		strings.Contains(key, "nonce") ||
		strings.Contains(key, "timestamp") ||
		strings.Contains(key, "error_hint")
}

func shortHash(value string) string {
	sum := sha1.Sum([]byte(value))
	return fmt.Sprintf("%x", sum[:6])
}
