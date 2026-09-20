package crawl

import (
	"strings"
	"time"
)

const (
	// maxJSSourceIndexEntries bounds the recorded anchors/brackets/calls per
	// index. Reaching the cap truncates the index and consumers fall back to
	// the legacy scanners, so a pathological bundle can never make indexing
	// unbounded.
	maxJSSourceIndexEntries = 256 * 1024
	// jsSourceIndexTimeBudget bounds the single lexical scan. Blocks are
	// capped well below 48KB, so this is generous; it exists so the scan
	// itself is never the unbounded step.
	jsSourceIndexTimeBudget = 500 * time.Millisecond
	// maxRequestBlueprintResourceAnalysisTime bounds total extractor time per
	// JS resource. Remaining blocks are converted to anchor candidates rather
	// than silently dropped.
	maxRequestBlueprintResourceAnalysisTime = 15 * time.Second
	// maxStaticArgumentResolveDepth bounds recursive static parameter tracing
	// (JSON.stringify unwrapping, identifier re-resolution) to local scope.
	maxStaticArgumentResolveDepth = 8
)

// jsSourceIndex is the result of one lexical scan over an analysis block. It
// records bracket pairs, call positions, assignment positions, and function
// keyword/arrow positions so later parsing pulls local fragments from the
// index instead of every extractor rescanning the same slice.
type jsSourceIndex struct {
	content           string
	matching          map[int]int // open bracket offset -> close bracket offset
	assignments       map[string][]int
	calls             map[string][]int
	functionPositions []int
	arrowPositions    []int
	truncated         bool

	functionSpans []jsFunctionSpan
	spansComputed bool
}

type jsFunctionSpan struct {
	Start int
	End   int
}

// buildJSSourceIndex performs the single lexical scan. It is quote- and
// escape-aware like the legacy scanners (comments and regex literals follow
// the same treatment as before), and it records:
//   - bracket pairs (parentheses, braces, brackets)
//   - call positions per callee identifier
//   - assignment positions per identifier
//   - function keyword and arrow-function positions
func buildJSSourceIndex(content string) *jsSourceIndex {
	index := &jsSourceIndex{
		content:     content,
		matching:    make(map[int]int, 1024),
		assignments: make(map[string][]int, 64),
		calls:       make(map[string][]int, 64),
	}
	deadline := time.Now().Add(jsSourceIndexTimeBudget)
	entries := 0

	type openBracket struct {
		position int
	}
	stack := make([]openBracket, 0, 64)
	pairs := map[byte]byte{')': '(', '}': '{', ']': '['}

	quote := byte(0)
	escaped := false
	position := 0
	for position < len(content) {
		if entries&0x3FF == 0 && time.Now().After(deadline) {
			index.truncated = true
			return index
		}
		if entries > maxJSSourceIndexEntries {
			index.truncated = true
			return index
		}
		ch := content[position]
		if quote != 0 {
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == quote {
				quote = 0
			}
			position++
			continue
		}

		switch {
		case ch == '"' || ch == '\'' || ch == '`':
			quote = ch
			position++
		case isJSIdentifierStart(ch):
			start := position
			for position < len(content) && isJSIdentifierContinuation(content[position]) {
				position++
			}
			name := content[start:position]
			if name == "function" {
				index.functionPositions = append(index.functionPositions, start)
			}
			next := position
			for next < len(content) && isJSWhitespace(content[next]) {
				next++
			}
			if next < len(content) {
				switch {
				case content[next] == '(' && next == position:
					// Record only immediately-adjacent calls so semantics
					// match the legacy `callee + "("` scanner exactly.
					index.calls[name] = append(index.calls[name], next)
					entries++
				case content[next] == '=' && next+1 < len(content) && content[next+1] != '=' && content[next+1] != '>':
					// Member assignments such as `obj.name = ...` are not
					// local symbol definitions.
					if start == 0 || content[start-1] != '.' {
						index.assignments[name] = append(index.assignments[name], next+1)
						entries++
					}
				case content[next] == '=' && next+1 < len(content) && content[next+1] == '>':
					index.arrowPositions = append(index.arrowPositions, start)
				}
			}
		case ch == '(' || ch == '{' || ch == '[':
			stack = append(stack, openBracket{position: position})
			entries++
			position++
		case ch == ')' || ch == '}' || ch == ']':
			want := pairs[ch]
			for len(stack) > 0 {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if content[top.position] == want {
					index.matching[top.position] = position
					break
				}
			}
			position++
		default:
			position++
		}
	}
	return index
}

func isJSIdentifierStart(value byte) bool {
	return value == '$' || value == '_' ||
		(value >= 'a' && value <= 'z') ||
		(value >= 'A' && value <= 'Z')
}

func isJSWhitespace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\n' || value == '\r'
}

// balanced returns the contents and close offset of the bracket pair opened
// at openIndex, using the precomputed table when possible.
func (index *jsSourceIndex) balanced(openIndex int, openChar, closeChar byte) (string, int, bool) {
	if index != nil && !index.truncated && openIndex >= 0 && openIndex < len(index.content) && index.content[openIndex] == openChar {
		if close, ok := index.matching[openIndex]; ok {
			return index.content[openIndex+1 : close], close, true
		}
	}
	return extractBalancedJS(index.content, openIndex, openChar, closeChar)
}

// assignmentPositions returns offsets just after `name =` in source order.
func (index *jsSourceIndex) assignmentPositions(name string) []int {
	return index.assignments[name]
}

// callPositions returns offsets of the `(` following each `name` occurrence.
func (index *jsSourceIndex) callPositions(name string) []int {
	return index.calls[name]
}

// enclosingFunction returns the smallest recorded function span containing
// position. Spans are resolved lazily from the bracket table so the scan
// itself stays single-pass.
func (index *jsSourceIndex) enclosingFunction(position int) (jsFunctionSpan, bool) {
	spans := index.computedFunctionSpans()
	best := jsFunctionSpan{}
	found := false
	for _, span := range spans {
		if span.Start <= position && position <= span.End {
			if !found || span.End-span.Start < best.End-best.Start {
				best = span
				found = true
			}
		}
	}
	return best, found
}

func (index *jsSourceIndex) computedFunctionSpans() []jsFunctionSpan {
	if index.spansComputed {
		return index.functionSpans
	}
	index.spansComputed = true
	content := index.content
	for _, keyword := range index.functionPositions {
		cursor := keyword + len("function")
		for cursor < len(content) && isJSWhitespace(content[cursor]) {
			cursor++
		}
		// Optional function name.
		if cursor < len(content) && isJSIdentifierStart(content[cursor]) {
			for cursor < len(content) && isJSIdentifierContinuation(content[cursor]) {
				cursor++
			}
			for cursor < len(content) && isJSWhitespace(content[cursor]) {
				cursor++
			}
		}
		if cursor >= len(content) || content[cursor] != '(' {
			continue
		}
		paramsClose, ok := index.matching[cursor]
		if !ok {
			continue
		}
		body := paramsClose + 1
		for body < len(content) && isJSWhitespace(content[body]) {
			body++
		}
		if body >= len(content) || content[body] != '{' {
			continue
		}
		bodyClose, ok := index.matching[body]
		if !ok {
			continue
		}
		index.functionSpans = append(index.functionSpans, jsFunctionSpan{Start: keyword, End: bodyClose + 1})
	}
	return index.functionSpans
}

// findJSAssignmentExpressionWithIndex resolves `name = <expr>` using the
// precomputed assignment index, falling back to the regex scanner when the
// index is unavailable or truncated.
func findJSAssignmentExpressionWithIndex(index *jsSourceIndex, content, name string) (string, bool) {
	if index == nil || index.truncated {
		return findJSAssignmentExpression(content, name)
	}
	name = strings.TrimSpace(name)
	if !identifierPattern.MatchString(name) {
		return "", false
	}
	for _, position := range index.assignmentPositions(name) {
		if expr, ok := readJSAssignmentExpression(content, position, 1000); ok {
			return expr, true
		}
	}
	return "", false
}

// findCallExpressionsWithIndex resolves call expressions for a plain
// identifier callee using the precomputed call index. Dotted callees and
// truncated indexes fall back to the legacy scanner so behavior is unchanged
// for member expressions such as `axios.post`.
func findCallExpressionsWithIndex(index *jsSourceIndex, content, callee string) []callExpression {
	if index == nil || index.truncated || !identifierPattern.MatchString(callee) {
		return findCallExpressions(content, callee)
	}
	positions := index.callPositions(callee)
	if len(positions) == 0 {
		return nil
	}
	results := make([]callExpression, 0, len(positions))
	lastEnd := -1
	for _, openIndex := range positions {
		callStart := openIndex - len(callee)
		if callStart < 0 {
			continue
		}
		// Match legacy behavior: nested same-name calls inside an already
		// consumed call expression are skipped.
		if lastEnd >= 0 && callStart <= lastEnd {
			continue
		}
		// Whitespace between callee and `(` is allowed by the index; trim the
		// call text start to the identifier.
		args, endIndex, ok := index.balanced(openIndex, '(', ')')
		if !ok {
			continue
		}
		results = append(results, callExpression{
			Index:    callStart,
			Args:     args,
			CallText: content[callStart : endIndex+1],
			Callee:   callee,
		})
		lastEnd = endIndex
	}
	return results
}
