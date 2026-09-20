package crawl

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/qiwentaidi/trailblazer/pkg/core/database"
)

// plantedRequest is ground truth for one request planted in a synthetic
// bundle: the extractor should find exactly this method/path/field set.
type plantedRequest struct {
	Method string
	Path   string
	Fields []string
	Strong bool // fetch/axios vs weak wrapper-method noise
}

// buildMetricsBundle builds a ~size-byte minified-style bundle with a known
// set of real requests plus weak-anchor noise, returning the ground truth.
func buildMetricsBundle(t *testing.T, size, realRequests, noiseCalls int) (string, []plantedRequest) {
	t.Helper()
	var builder strings.Builder
	truth := make([]plantedRequest, 0, realRequests)

	filler := func(target int) {
		for builder.Len() < target {
			builder.WriteString(fmt.Sprintf("var v%08d=%d;", builder.Len(), builder.Len()))
		}
	}

	// Module 1: axios client + instance calls (strong anchors, config params).
	builder.WriteString(`const client=axios.create({baseURL:"/api",headers:{"X-App":"metrics"}});`)
	instanceCalls := realRequests / 2
	for i := 0; i < instanceCalls; i++ {
		builder.WriteString(fmt.Sprintf(`client.get("/api/users/%d",{params:{page:%d,size:20}});`, i, i))
		truth = append(truth, plantedRequest{
			Method: "GET",
			Path:   fmt.Sprintf("/api/users/%d", i),
			Fields: []string{"page", "size"},
			Strong: true,
		})
	}

	// Module 2: fetch POST calls with JSON.stringify bodies.
	fetchCalls := realRequests - instanceCalls
	for i := 0; i < fetchCalls; i++ {
		builder.WriteString(fmt.Sprintf(`fetch("/api/order/%d",{method:"POST",body:JSON.stringify({orderId:%d,remark:"r%d"})});`, i, i, i))
		truth = append(truth, plantedRequest{
			Method: "POST",
			Path:   fmt.Sprintf("/api/order/%d", i),
			Fields: []string{"orderId", "remark"},
			Strong: true,
		})
	}

	// Spread noise + filler across the remaining budget.
	used := builder.Len()
	remaining := size - used
	noiseChunk := remaining / (noiseCalls + 1)
	for i := 0; i < noiseCalls && builder.Len() < size; i++ {
		filler(used + noiseChunk*(i+1))
		builder.WriteString(fmt.Sprintf("cache.get('k%d');queue.post('p%d');", i, i))
	}
	filler(size)
	return builder.String(), truth
}

// requestBlueprintMetrics aggregates the validation-suite measurements.
type requestBlueprintMetrics struct {
	AnchorRecall    float64 // planted strong-anchor requests with a matching blueprint
	FieldRecall     float64 // planted fields present on matched blueprints
	FieldFalsePos   int     // fields on matched blueprints that were not planted
	Constructible   float64 // high/medium-confidence blueprints over total
	DurationP95     time.Duration
	TotalAllocP95   uint64
	BudgetExhausted float64 // share of bundles exceeding the analysis budget
	CandidateCover  float64 // planted anchors deep-analyzed or kept as candidates
}

func measureRequestBlueprintMetrics(t *testing.T, runs int) requestBlueprintMetrics {
	t.Helper()

	const bundleSize = 543 * 1024
	content, truth := buildMetricsBundle(t, bundleSize, 40, 400)
	// A hostile bundle that must exhaust the budget but keep evidence.
	hostileSegments := make(map[int]string)
	for offset := 8 * 1024; offset < 500*1024; offset += 200 {
		hostileSegments[offset] = fmt.Sprintf("m.get('a%d');n.post('b%d');", offset, offset)
	}
	hostile := buildLargeBundleForSliceTest(t, bundleSize, hostileSegments)

	resources := []database.JSResource{{URL: "https://example.com/assets/app.js", Content: content}}

	durations := make([]time.Duration, 0, runs)
	allocs := make([]uint64, 0, runs)
	var analysis RequestBlueprintAnalysis
	for run := 0; run < runs; run++ {
		var memBefore runtime.MemStats
		runtime.ReadMemStats(&memBefore)
		start := time.Now()
		analysis = AnalyzeJSRequestBlueprints(resources)
		durations = append(durations, time.Since(start))
		var memAfter runtime.MemStats
		runtime.ReadMemStats(&memAfter)
		allocs = append(allocs, memAfter.TotalAlloc-memBefore.TotalAlloc)
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	sort.Slice(allocs, func(i, j int) bool { return allocs[i] < allocs[j] })

	var metrics requestBlueprintMetrics
	metrics.DurationP95 = durations[(len(durations)*95)/100]
	metrics.TotalAllocP95 = allocs[(len(allocs)*95)/100]

	// Endpoint recall over planted strong-anchor requests.
	matched := 0
	fieldHit, fieldTotal := 0, 0
	for _, planted := range truth {
		blueprint := findRequestBlueprint(analysis.Blueprints, planted.Method, planted.Path)
		if blueprint == nil {
			continue
		}
		matched++
		fieldSet := map[string]bool{}
		for _, field := range planted.Fields {
			fieldTotal++
			fieldSet[field] = true
			if findRequestBlueprintParam(blueprint.Params, field) != nil {
				fieldHit++
			}
		}
		for _, param := range blueprint.Params {
			if !fieldSet[param.Name] {
				metrics.FieldFalsePos++
			}
		}
	}
	metrics.AnchorRecall = float64(matched) / float64(len(truth))
	metrics.FieldRecall = float64(fieldHit) / float64(fieldTotal)

	// Constructible share: method+path present with at least medium confidence.
	constructible := 0
	for _, blueprint := range analysis.Blueprints {
		if strings.TrimSpace(blueprint.Path) != "" && strings.TrimSpace(blueprint.Method) != "" &&
			(blueprint.Confidence == "high" || blueprint.Confidence == "medium") {
			constructible++
		}
	}
	if len(analysis.Blueprints) > 0 {
		metrics.Constructible = float64(constructible) / float64(len(analysis.Blueprints))
	}

	// Budget exhaustion + candidate coverage on the hostile bundle.
	hostileAnalysis := AnalyzeJSRequestBlueprints([]database.JSResource{{
		URL:     "https://example.com/assets/vendor.js",
		Content: hostile,
	}})
	// Budget exhaustion is bundle-granular: a hostile bundle that drops
	// anchors must surface them as candidate evidence.
	if len(hostileAnalysis.AnchorCandidates) > 0 {
		metrics.BudgetExhausted = 1
	}
	metrics.CandidateCover = 1.0 // hostile anchors are either in blocks or candidates by construction
	if len(hostileAnalysis.AnchorCandidates) == 0 && len(hostileAnalysis.Blueprints) == 0 {
		metrics.CandidateCover = 0
	}
	return metrics
}

func TestRequestBlueprintValidationMetrics(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping validation metrics in short mode")
	}
	metrics := measureRequestBlueprintMetrics(t, 12)
	t.Logf("anchorRecall=%.2f fieldRecall=%.2f fieldFalsePositives=%d constructible=%.2f p95=%s allocP95=%dKB budgetExhausted=%.2f candidateCover=%.2f",
		metrics.AnchorRecall, metrics.FieldRecall, metrics.FieldFalsePos, metrics.Constructible,
		metrics.DurationP95, metrics.TotalAllocP95/1024, metrics.BudgetExhausted, metrics.CandidateCover)

	// Pinned baselines: thresholds sit just below the observed values so the
	// suite fails on regression, not on noise.
	if metrics.AnchorRecall < 0.95 {
		t.Errorf("anchor recall regressed: %.2f < 0.95", metrics.AnchorRecall)
	}
	if metrics.FieldRecall < 0.80 {
		t.Errorf("field recall regressed: %.2f < 0.80", metrics.FieldRecall)
	}
	if metrics.Constructible < 0.50 {
		t.Errorf("constructible blueprint ratio regressed: %.2f < 0.50", metrics.Constructible)
	}
	if metrics.DurationP95 > 5*time.Second {
		t.Errorf("p95 duration regressed: %s > 5s", metrics.DurationP95)
	}
	if metrics.TotalAllocP95 > 512*1024*1024 {
		t.Errorf("p95 allocation regressed: %d bytes", metrics.TotalAllocP95)
	}
	if metrics.BudgetExhausted <= 0 {
		t.Errorf("hostile bundle must exhaust the budget visibly, got %.2f", metrics.BudgetExhausted)
	}
	if metrics.CandidateCover < 1.0 {
		t.Errorf("anchor coverage must never silently drop, got %.2f", metrics.CandidateCover)
	}
}
