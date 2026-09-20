package crawl

import (
	"sort"
	"strconv"
	"strings"
)

const (
	// maxRequestBlueprintSliceTotalBytes bounds how many bytes of one large
	// bundle are ever fed to the extractor set. The previous design allowed
	// 64 slices of 48KB each (~3MB), and overlapping windows meant the same
	// source region was repeatedly analyzed by every extractor.
	maxRequestBlueprintSliceTotalBytes = 320 * 1024

	// Default context kept around an isolated request anchor. Wrapper
	// definitions (axios.create, helper functions) usually sit within a few
	// KB of the call in a minified module.
	requestBlueprintAnchorContextBefore = 16 * 1024
	requestBlueprintAnchorContextAfter  = 24 * 1024

	// Dense clusters (many anchors in a small span) only need the enclosing
	// function/object boundary, not a uniform wide window.
	requestBlueprintDenseAnchorContextBefore = 4 * 1024
	requestBlueprintDenseAnchorContextAfter  = 6 * 1024
	requestBlueprintDenseAnchorMinCount      = 4
	requestBlueprintDenseAnchorMaxSpan       = 8 * 1024

	// Anchors whose analysis windows sit within this gap share one block so a
	// dense request module is analyzed exactly once.
	requestBlueprintAnchorMergeGap = 2 * 1024

	// Scan and evidence caps. Hitting either marks the analysis as budget
	// exceeded; dropped anchors are still emitted as candidate evidence.
	maxRequestBlueprintAnchors          = 8192
	maxRequestBlueprintAnchorCandidates = 256

	// Boundary snapping extends a block edge to the nearest statement
	// boundary so slices rarely cut through an expression.
	requestBlueprintBoundarySnapRange = 1536
)

// RequestAnchorCandidate is evidence for a request-like anchor that was not
// deeply analyzed because the static analysis budget was exhausted. Keeping
// these anchors visible prevents coverage from silently shrinking when the
// budget kicks in.
type RequestAnchorCandidate struct {
	File     string `json:"file"`
	Offset   int    `json:"offset"`
	CallType string `json:"callType"`
	Snippet  string `json:"snippet,omitempty"`
}

// requestBlueprintAnalysisInput is either a complete small resource or a
// bounded, request-adjacent view of a large bundle. The latter preserves API
// discovery without repeatedly running every extractor over a minified bundle.
type requestBlueprintAnalysisInput struct {
	Content        string
	StartOffset    int
	Stage          string
	BudgetExceeded bool
	DroppedAnchors int
	Anchors        []requestBlueprintAnchor
}

type requestBlueprintAnchor struct {
	Offset   int
	CallType string
	Strong   bool
}

type requestBlueprintAnchorBlock struct {
	Start   int
	End     int
	Strong  bool
	Anchors []requestBlueprintAnchor
}

// requestBlueprintAnchorMarkers is ordered so that specific, high-precision
// markers win over generic method-call markers when both match nearby.
var requestBlueprintAnchorMarkers = []struct {
	Marker   string
	CallType string
	Strong   bool
}{
	{"fetch(", "fetch", true},
	{"$.ajax", "jquery.ajax", true},
	{"jQuery.ajax", "jquery.ajax", true},
	{"XMLHttpRequest", "xmlhttprequest", true},
	{"uni.request", "uni.request", true},
	{"postRequest(", "postRequest", true},
	{"axios", "axios", true},
	{".get(", "method:get", false},
	{".post(", "method:post", false},
	{".put(", "method:put", false},
	{".delete(", "method:delete", false},
	{".patch(", "method:patch", false},
	{".request(", "method:request", false},
}

func buildRequestBlueprintAnalysisInputs(fileURL, content string) ([]requestBlueprintAnalysisInput, []RequestAnchorCandidate) {
	if len(content) <= maxRequestBlueprintSourceSize {
		if !shouldAnalyzeJSRequestBlueprintContent("", content) {
			return nil, nil
		}
		return []requestBlueprintAnalysisInput{{Content: content, Stage: "full-resource"}}, nil
	}

	anchors, scanExceeded := findRequestBlueprintAnchors(content)
	if len(anchors) == 0 {
		return nil, nil
	}
	blocks := buildRequestBlueprintAnchorBlocks(content, anchors)
	accepted, dropped := selectRequestBlueprintAnchorBlocks(blocks)
	budgetExceeded := scanExceeded || len(dropped) > 0

	droppedCount := 0
	for _, block := range dropped {
		droppedCount += len(block.Anchors)
	}

	inputs := make([]requestBlueprintAnalysisInput, 0, len(accepted))
	for _, block := range accepted {
		inputs = append(inputs, requestBlueprintAnalysisInput{
			Content:        content[block.Start:block.End],
			StartOffset:    block.Start,
			Stage:          "anchor-slice",
			BudgetExceeded: budgetExceeded,
			DroppedAnchors: droppedCount,
			Anchors:        append([]requestBlueprintAnchor(nil), block.Anchors...),
		})
	}
	droppedAnchors := make([]requestBlueprintAnchor, 0, droppedCount)
	for _, block := range dropped {
		droppedAnchors = append(droppedAnchors, block.Anchors...)
	}
	return inputs, buildRequestAnchorCandidates(fileURL, content, droppedAnchors)
}

// findRequestBlueprintAnchors walks the source once per marker using
// strings.Index. It intentionally keeps the marker set broad: this phase is
// for recall, while existing extractors decide whether a block contains a
// real request.
func findRequestBlueprintAnchors(content string) ([]requestBlueprintAnchor, bool) {
	anchors := make([]requestBlueprintAnchor, 0, 64)
	exceeded := false
	for _, marker := range requestBlueprintAnchorMarkers {
		for start := 0; start < len(content); {
			index := strings.Index(content[start:], marker.Marker)
			if index < 0 {
				break
			}
			absolute := start + index
			anchors = append(anchors, requestBlueprintAnchor{
				Offset:   absolute,
				CallType: marker.CallType,
				Strong:   marker.Strong,
			})
			if len(anchors) >= maxRequestBlueprintAnchors {
				return anchors, true
			}
			start = absolute + len(marker.Marker)
		}
	}
	sort.SliceStable(anchors, func(i, j int) bool {
		return anchors[i].Offset < anchors[j].Offset
	})
	return anchors, exceeded
}

// buildRequestBlueprintAnchorBlocks clusters nearby anchors and emits one
// disjoint analysis block per cluster. Dense clusters keep only the
// request-adjacent function/object boundary instead of a uniform wide window.
func buildRequestBlueprintAnchorBlocks(content string, anchors []requestBlueprintAnchor) []requestBlueprintAnchorBlock {
	clusters := clusterRequestBlueprintAnchors(anchors)
	blocks := make([]requestBlueprintAnchorBlock, 0, len(clusters))
	for _, cluster := range clusters {
		before, after := requestBlueprintAnchorMargins(cluster)
		first := cluster[0].Offset
		last := cluster[len(cluster)-1].Offset

		start := first - before
		if start < 0 {
			start = 0
		}
		end := last + after
		if end > len(content) {
			end = len(content)
		}
		start = snapRequestBlueprintBoundaryBackward(content, start)
		end = snapRequestBlueprintBoundaryForward(content, end)

		strong := false
		for _, anchor := range cluster {
			if anchor.Strong {
				strong = true
				break
			}
		}
		block := requestBlueprintAnchorBlock{
			Start:   start,
			End:     end,
			Strong:  strong,
			Anchors: append([]requestBlueprintAnchor(nil), cluster...),
		}
		for _, chunk := range splitRequestBlueprintAnchorBlock(content, block) {
			blocks = appendRequestBlueprintAnchorBlock(blocks, chunk, len(content))
		}
	}
	return blocks
}

// splitRequestBlueprintAnchorBlock caps a cluster block at
// maxRequestBlueprintSliceSize by splitting it into disjoint chunks. Anchors
// are assigned to the chunk that contains them so every anchor keeps exactly
// one analysis window.
func splitRequestBlueprintAnchorBlock(content string, block requestBlueprintAnchorBlock) []requestBlueprintAnchorBlock {
	if block.End-block.Start <= maxRequestBlueprintSliceSize {
		return []requestBlueprintAnchorBlock{block}
	}
	chunks := make([]requestBlueprintAnchorBlock, 0, (block.End-block.Start)/maxRequestBlueprintSliceSize+1)
	position := block.Start
	anchorIndex := 0
	for position < block.End {
		end := position + maxRequestBlueprintSliceSize
		if end >= block.End {
			end = block.End
		} else {
			snapped := snapRequestBlueprintBoundaryForward(content, end)
			if snapped > position && snapped <= block.End {
				end = snapped
			}
		}
		if end <= position {
			end = block.End
		}

		chunk := requestBlueprintAnchorBlock{Start: position, End: end}
		for anchorIndex < len(block.Anchors) && block.Anchors[anchorIndex].Offset < end {
			chunk.Anchors = append(chunk.Anchors, block.Anchors[anchorIndex])
			if block.Anchors[anchorIndex].Strong {
				chunk.Strong = true
			}
			anchorIndex++
		}
		chunks = append(chunks, chunk)
		position = end
	}
	// Anchors sitting exactly on a trailing edge belong to the last chunk.
	if anchorIndex < len(block.Anchors) && len(chunks) > 0 {
		last := &chunks[len(chunks)-1]
		for ; anchorIndex < len(block.Anchors); anchorIndex++ {
			last.Anchors = append(last.Anchors, block.Anchors[anchorIndex])
			if block.Anchors[anchorIndex].Strong {
				last.Strong = true
			}
		}
	}
	return chunks
}

// clusterRequestBlueprintAnchors groups anchors whose analysis windows would
// overlap or nearly touch, so each source region is analyzed exactly once.
func clusterRequestBlueprintAnchors(anchors []requestBlueprintAnchor) [][]requestBlueprintAnchor {
	clusters := make([][]requestBlueprintAnchor, 0, 32)
	for _, anchor := range anchors {
		if len(clusters) > 0 {
			last := clusters[len(clusters)-1]
			lastAnchor := last[len(last)-1]
			if anchor.Offset-lastAnchor.Offset <= requestBlueprintAnchorMergeGap {
				clusters[len(clusters)-1] = append(last, anchor)
				continue
			}
		}
		clusters = append(clusters, []requestBlueprintAnchor{anchor})
	}
	return clusters
}

func requestBlueprintAnchorMargins(cluster []requestBlueprintAnchor) (before, after int) {
	span := cluster[len(cluster)-1].Offset - cluster[0].Offset
	if len(cluster) >= requestBlueprintDenseAnchorMinCount && span <= requestBlueprintDenseAnchorMaxSpan {
		return requestBlueprintDenseAnchorContextBefore, requestBlueprintDenseAnchorContextAfter
	}
	return requestBlueprintAnchorContextBefore, requestBlueprintAnchorContextAfter
}

// appendRequestBlueprintAnchorBlock merges the new block into the previous
// one when they overlap. Blocks are never allowed to overlap in the output;
// when a merge would exceed the per-block cap the new block starts where the
// previous one ended instead of re-covering the same bytes.
func appendRequestBlueprintAnchorBlock(blocks []requestBlueprintAnchorBlock, block requestBlueprintAnchorBlock, contentLength int) []requestBlueprintAnchorBlock {
	if len(blocks) == 0 {
		return append(blocks, block)
	}
	last := &blocks[len(blocks)-1]
	if block.Start > last.End {
		return append(blocks, block)
	}
	if block.Start < last.Start {
		block.Start = last.Start
	}
	mergedEnd := block.End
	if mergedEnd < last.End {
		mergedEnd = last.End
	}
	if mergedEnd-last.Start <= maxRequestBlueprintSliceSize {
		last.End = mergedEnd
		last.Strong = last.Strong || block.Strong
		last.Anchors = append(last.Anchors, block.Anchors...)
		return blocks
	}
	// The merge would exceed the cap: close the previous block and continue
	// with a disjoint block starting at the previous block's end.
	block.Start = last.End
	if block.End < block.Start {
		block.End = block.Start
	}
	if block.End-block.Start > maxRequestBlueprintSliceSize {
		block.End = block.Start + maxRequestBlueprintSliceSize
	}
	if block.End > contentLength {
		block.End = contentLength
	}
	if block.End <= block.Start {
		last.Strong = last.Strong || block.Strong
		last.Anchors = append(last.Anchors, block.Anchors...)
		return blocks
	}
	return append(blocks, block)
}

// selectRequestBlueprintAnchorBlocks fills the per-resource byte budget.
// Blocks containing strong request markers are scheduled first so generic
// `.get(`/`.post(` noise cannot starve real request modules.
func selectRequestBlueprintAnchorBlocks(blocks []requestBlueprintAnchorBlock) (accepted, dropped []requestBlueprintAnchorBlock) {
	ordered := append([]requestBlueprintAnchorBlock(nil), blocks...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Strong != ordered[j].Strong {
			return ordered[i].Strong
		}
		return ordered[i].Start < ordered[j].Start
	})

	used := 0
	accepted = make([]requestBlueprintAnchorBlock, 0, len(ordered))
	for _, block := range ordered {
		size := block.End - block.Start
		if used+size > maxRequestBlueprintSliceTotalBytes && len(accepted) > 0 {
			dropped = append(dropped, block)
			continue
		}
		used += size
		accepted = append(accepted, block)
	}
	sort.SliceStable(accepted, func(i, j int) bool {
		return accepted[i].Start < accepted[j].Start
	})
	return accepted, dropped
}

// buildRequestAnchorCandidates preserves anchors that fell outside the
// analysis budget as candidate evidence with source position, call type, and
// a short snippet.
func buildRequestAnchorCandidates(fileURL, content string, anchors []requestBlueprintAnchor) []RequestAnchorCandidate {
	if len(anchors) == 0 {
		return nil
	}
	candidates := make([]RequestAnchorCandidate, 0, 32)
	seen := make(map[string]struct{})
	for _, anchor := range anchors {
		key := anchor.CallType + "\x00" + strconv.Itoa(anchor.Offset)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		candidates = append(candidates, RequestAnchorCandidate{
			File:     fileURL,
			Offset:   anchor.Offset,
			CallType: anchor.CallType,
			Snippet:  requestAnchorCandidateSnippet(content, anchor.Offset),
		})
		if len(candidates) >= maxRequestBlueprintAnchorCandidates {
			return candidates
		}
	}
	return candidates
}

func requestAnchorCandidateSnippet(content string, offset int) string {
	start := offset - 120
	if start < 0 {
		start = 0
	}
	end := offset + 120
	if end > len(content) {
		end = len(content)
	}
	return strings.Join(strings.Fields(content[start:end]), " ")
}

// snapRequestBlueprintBoundaryBackward extends a block start to the nearest
// preceding statement boundary so slices do not begin mid-expression.
func snapRequestBlueprintBoundaryBackward(content string, start int) int {
	if start <= 0 {
		return 0
	}
	limit := start - requestBlueprintBoundarySnapRange
	if limit < 0 {
		limit = 0
	}
	for index := start - 1; index >= limit; index-- {
		switch content[index] {
		case '\n', ';':
			return index + 1
		}
	}
	return start
}

// snapRequestBlueprintBoundaryForward extends a block end to the nearest
// following statement boundary.
func snapRequestBlueprintBoundaryForward(content string, end int) int {
	if end >= len(content) {
		return len(content)
	}
	limit := end + requestBlueprintBoundarySnapRange
	if limit > len(content) {
		limit = len(content)
	}
	for index := end; index < limit; index++ {
		switch content[index] {
		case '\n', ';':
			return index + 1
		}
	}
	return end
}

func applyRequestBlueprintAnalysisMetadata(blueprint RequestBlueprint, input requestBlueprintAnalysisInput) RequestBlueprint {
	blueprint.AnalysisStage = input.Stage
	blueprint.AnalysisBudgetExceeded = input.BudgetExceeded
	if snippet := strings.TrimSpace(blueprint.Source.Snippet); snippet != "" {
		if relative := strings.Index(input.Content, snippet); relative >= 0 {
			blueprint.Source.StartOffset = input.StartOffset + relative
			blueprint.Source.EndOffset = blueprint.Source.StartOffset + len(snippet)
		}
	}
	if input.Stage == "anchor-slice" {
		blueprint.Context = appendUniqueStrings(blueprint.Context, "静态分析: 请求锚点局部切片")
	}
	if input.DroppedAnchors > 0 {
		blueprint.Context = appendUniqueStrings(blueprint.Context, "静态分析预算: "+strconv.Itoa(input.DroppedAnchors)+" 个请求锚点转为候选证据(未深挖)")
	} else if input.BudgetExceeded {
		blueprint.Context = appendUniqueStrings(blueprint.Context, "静态分析预算: 请求锚点数量已截断")
	}
	return blueprint
}
