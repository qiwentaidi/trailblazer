package crawl

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/qiwentaidi/trailblazer/pkg/core/database"
)

// buildLargeBundleForSliceTest builds a >128KB script with the given segments
// placed at explicit offsets and filler around them.
func buildLargeBundleForSliceTest(t *testing.T, totalSize int, segments map[int]string) string {
	t.Helper()
	var builder strings.Builder
	cursor := 0
	offsets := make([]int, 0, len(segments))
	for offset := range segments {
		offsets = append(offsets, offset)
	}
	for index := 0; index < len(offsets); index++ {
		for j := index + 1; j < len(offsets); j++ {
			if offsets[j] < offsets[index] {
				offsets[index], offsets[j] = offsets[j], offsets[index]
			}
		}
	}
	for _, offset := range offsets {
		segment := segments[offset]
		if offset < cursor {
			t.Fatalf("overlapping test segments near offset %d", offset)
		}
		for cursor < offset {
			builder.WriteString(fmt.Sprintf("var v%08d=%d;", cursor, cursor))
			cursor = builder.Len()
		}
		builder.WriteString(segment)
		cursor = builder.Len()
	}
	for builder.Len() < totalSize {
		builder.WriteString(fmt.Sprintf("var f%08d=%d;", builder.Len(), builder.Len()))
	}
	return builder.String()
}

func TestBuildRequestBlueprintAnalysisInputsMergesDenseAnchorCluster(t *testing.T) {
	var cluster strings.Builder
	cluster.WriteString("const client=axios.create({baseURL:'/api'});")
	for index := 0; index < 40; index++ {
		cluster.WriteString(fmt.Sprintf("client.get('/api/item/%d');client.post('/api/item/%d',{});", index, index))
	}
	content := buildLargeBundleForSliceTest(t, 300*1024, map[int]string{200 * 1024: cluster.String()})

	inputs, candidates := buildRequestBlueprintAnalysisInputs("https://example.com/app.js", content)
	if len(inputs) != 1 {
		t.Fatalf("expected dense cluster to merge into one analysis block, got %d", len(inputs))
	}
	if len(candidates) != 0 {
		t.Fatalf("expected no dropped candidates for a single cluster, got %d", len(candidates))
	}
	input := inputs[0]
	if input.Stage != "anchor-slice" {
		t.Fatalf("expected anchor-slice stage, got %q", input.Stage)
	}
	if len(input.Content) >= maxRequestBlueprintSliceSize {
		t.Fatalf("expected dense block below per-block cap, got %d bytes", len(input.Content))
	}
	if !strings.Contains(input.Content, "client.get('/api/item/0')") || !strings.Contains(input.Content, "client.post('/api/item/39',{})") {
		t.Fatalf("expected block to cover the whole dense cluster, got %d bytes", len(input.Content))
	}
}

func TestBuildRequestBlueprintAnalysisInputsAreDisjointAndBudgeted(t *testing.T) {
	// A ~543KB bundle with weak method-call anchors every ~900 bytes: the
	// previous design produced dozens of overlapping 48KB slices.
	segments := make(map[int]string)
	for offset := 8 * 1024; offset < 530*1024; offset += 900 {
		segments[offset] = fmt.Sprintf("store.get('key%d');", offset)
	}
	content := buildLargeBundleForSliceTest(t, 543*1024, segments)

	inputs, candidates := buildRequestBlueprintAnalysisInputs("https://example.com/vendor.js", content)
	if len(inputs) == 0 {
		t.Fatal("expected analysis inputs for large bundle")
	}

	total := 0
	previousEnd := -1
	for _, input := range inputs {
		if input.StartOffset < previousEnd {
			t.Fatalf("expected disjoint blocks, block at %d overlaps previous end %d", input.StartOffset, previousEnd)
		}
		if len(input.Content) > maxRequestBlueprintSliceSize+requestBlueprintBoundarySnapRange {
			t.Fatalf("expected per-block cap, got %d bytes", len(input.Content))
		}
		if !input.BudgetExceeded {
			t.Fatal("expected budget-exceeded marker on analyzed blocks")
		}
		if input.DroppedAnchors == 0 {
			t.Fatal("expected dropped anchor count on analyzed blocks")
		}
		previousEnd = input.StartOffset + len(input.Content)
		total += len(input.Content)
	}
	if total > maxRequestBlueprintSliceTotalBytes {
		t.Fatalf("expected total analyzed bytes <= %d, got %d", maxRequestBlueprintSliceTotalBytes, total)
	}
	if len(candidates) == 0 {
		t.Fatal("expected dropped anchors to be preserved as candidate evidence")
	}
	if len(candidates) > maxRequestBlueprintAnchorCandidates {
		t.Fatalf("expected candidate cap %d, got %d", maxRequestBlueprintAnchorCandidates, len(candidates))
	}
	for _, candidate := range candidates {
		if candidate.File != "https://example.com/vendor.js" || candidate.Offset <= 0 || candidate.CallType == "" || candidate.Snippet == "" {
			t.Fatalf("candidate evidence incomplete: %#v", candidate)
		}
	}
}

func TestBuildRequestBlueprintAnalysisInputsPrioritizesStrongAnchors(t *testing.T) {
	// Weak noise anchors fill the front of the bundle; a real fetch call sits
	// near the end. Strong blocks must be scheduled before weak ones.
	segments := make(map[int]string)
	for offset := 8 * 1024; offset < 400*1024; offset += 700 {
		segments[offset] = fmt.Sprintf("map.get('k%d');", offset)
	}
	segments[500*1024] = `fetch("/api/late/report", { method: "POST", body: JSON.stringify({accountId: 1}) });`
	content := buildLargeBundleForSliceTest(t, 543*1024, segments)

	analysis := AnalyzeJSRequestBlueprints([]database.JSResource{{
		URL:     "https://example.com/app.js",
		Content: content,
	}})
	report := findRequestBlueprint(analysis.Blueprints, "POST", "/api/late/report")
	if report == nil {
		t.Fatalf("expected strong-anchor block to survive the budget, got %#v", analysis.Blueprints)
	}
	if !report.AnalysisBudgetExceeded {
		t.Fatal("expected budget-exceeded marker on blueprint")
	}
	if !containsString(report.Context, "静态分析预算: 请求锚点转为候选证据(未深挖)") &&
		!containsContextPrefix(report.Context, "静态分析预算: ") {
		t.Fatalf("expected budget note in context, got %#v", report.Context)
	}
	if len(analysis.AnchorCandidates) == 0 {
		t.Fatal("expected anchor candidates for dropped weak anchors")
	}
	for _, candidate := range analysis.AnchorCandidates {
		if candidate.CallType == "fetch" {
			t.Fatalf("strong fetch anchor must never be dropped: %#v", candidate)
		}
	}
}

func containsContextPrefix(items []string, prefix string) bool {
	for _, item := range items {
		if strings.HasPrefix(item, prefix) {
			return true
		}
	}
	return false
}

func TestBuildJSRequestBlueprintsLargeBundlePerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large bundle performance regression in short mode")
	}
	segments := make(map[int]string)
	for offset := 8 * 1024; offset < 500*1024; offset += 800 {
		segments[offset] = fmt.Sprintf("cache.get('k%d');queue.post('p%d');", offset, offset)
	}
	segments[260*1024] = `
		const service = axios.create({ baseURL: "/api", headers: { "X-App": "trail" } });
		export function loadReport(id) {
			return service.post("/api/reports/load", { reportId: id, includeInactive: false });
		}
	`
	content := buildLargeBundleForSliceTest(t, 543*1024, segments)

	start := time.Now()
	analysis := AnalyzeJSRequestBlueprints([]database.JSResource{{
		URL:     "https://example.com/assets/app.js",
		Content: content,
	}})
	elapsed := time.Since(start)
	t.Logf("large bundle analysis took %s, blueprints=%d candidates=%d", elapsed, len(analysis.Blueprints), len(analysis.AnchorCandidates))
	if elapsed > 10*time.Second {
		t.Fatalf("large bundle analysis exceeded 10s budget: %s", elapsed)
	}
	report := findRequestBlueprint(analysis.Blueprints, "POST", "/api/reports/load")
	if report == nil {
		t.Fatalf("expected report blueprint from strong anchor block, got %#v", analysis.Blueprints)
	}
}
