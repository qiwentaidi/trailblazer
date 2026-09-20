package crawl

import (
	"strings"
	"time"
)

const (
	// maxJSExprParseNodes and maxJSExprParseDepth bound the fault-tolerant
	// expression parser; jsExprParseTimeBudget bounds wall time. The parser
	// only ever runs on local fragments around a hit, never on a whole
	// bundle.
	maxJSExprParseNodes   = 2048
	maxJSExprParseDepth   = 32
	jsExprParseTimeBudget = 200 * time.Millisecond
	// maxJSExprParseBytes caps the fragment size handed to the parser.
	maxJSExprParseBytes = 32 * 1024
)

type jsExprKind int

const (
	jsExprUnknown jsExprKind = iota
	jsExprLiteral
	jsExprIdentifier
	jsExprObject
	jsExprArray
	jsExprTemplate
	jsExprCall
	jsExprMember
	jsExprBinary
	jsExprRaw
)

// jsExpr is a node of the fault-tolerant local expression tree.
type jsExpr struct {
	Kind     jsExprKind
	Value    string // literal value (unquoted), identifier name, or raw text
	Fields   []jsObjectField
	Elements []*jsExpr
	Parts    []jsTemplatePart
	Callee   string
	Args     []*jsExpr
	Op       string
	Left     *jsExpr
	Right    *jsExpr
	Start    int
	End      int
}

type jsObjectField struct {
	Key    string
	Value  *jsExpr
	Spread bool
}

type jsTemplatePart struct {
	Static string
	Expr   *jsExpr // nil for static parts
}

// jsExprParser is a small fault-tolerant recursive-descent parser for the
// expression forms that appear around request construction: object/array
// literals (nested, with spread), template strings, member/call chains,
// string concatenation, and the JSON.stringify / URLSearchParams / FormData
// idioms. It never fails hard: unrecognized input degrades to raw nodes.
type jsExprParser struct {
	src      string
	pos      int
	nodes    int
	deadline time.Time
}

// parseJSExpression parses one JavaScript expression from a local fragment.
// The input is capped and the parse is budgeted; on any irregularity the
// remaining input is preserved as a raw node so callers keep evidence.
func parseJSExpression(raw string) *jsExpr {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if len(raw) > maxJSExprParseBytes {
		raw = raw[:maxJSExprParseBytes]
	}
	parser := &jsExprParser{src: raw, deadline: time.Now().Add(jsExprParseTimeBudget)}
	expr := parser.parseExpression(0)
	if expr == nil {
		return &jsExpr{Kind: jsExprRaw, Value: raw, Start: 0, End: len(raw)}
	}
	return expr
}

func (p *jsExprParser) budgeted() bool {
	p.nodes++
	if p.nodes > maxJSExprParseNodes {
		return false
	}
	if p.nodes&0x3F == 0 && time.Now().After(p.deadline) {
		return false
	}
	return true
}

func (p *jsExprParser) parseExpression(depth int) *jsExpr {
	if depth > maxJSExprParseDepth || !p.budgeted() {
		return p.consumeRaw()
	}
	left := p.parsePrimary(depth)
	if left == nil {
		return nil
	}
	left = p.parsePostfix(left, depth)
	// Minimal binary support: string concatenation is the dominant operator
	// in URL and payload construction.
	for {
		p.skipSpace()
		if p.pos >= len(p.src) || p.src[p.pos] != '+' {
			break
		}
		if p.pos+1 < len(p.src) && (p.src[p.pos+1] == '+' || p.src[p.pos+1] == '=') {
			break
		}
		p.pos++
		right := p.parsePrimary(depth + 1)
		if right == nil {
			break
		}
		right = p.parsePostfix(right, depth+1)
		if !p.budgeted() {
			break
		}
		left = &jsExpr{Kind: jsExprBinary, Op: "+", Left: left, Right: right, Start: left.Start, End: right.End}
	}
	return left
}

func (p *jsExprParser) parsePrimary(depth int) *jsExpr {
	p.skipSpace()
	if p.pos >= len(p.src) || !p.budgeted() {
		return nil
	}
	start := p.pos
	ch := p.src[p.pos]
	switch {
	case ch == '{':
		return p.parseObject(depth)
	case ch == '[':
		return p.parseArray(depth)
	case ch == '"' || ch == '\'':
		return p.parseQuoted(ch)
	case ch == '`':
		return p.parseTemplate(depth)
	case ch == '(':
		// Parenthesized expression: parse inner and return it.
		p.pos++
		inner := p.parseExpression(depth + 1)
		p.skipSpace()
		if p.pos < len(p.src) && p.src[p.pos] == ')' {
			p.pos++
		}
		return inner
	case isJSIdentifierStart(ch):
		return p.parseIdentifierLike()
	case ch == '.' && strings.HasPrefix(p.src[p.pos:], "..."):
		p.pos += 3
		target := p.parsePrimary(depth + 1)
		if target == nil {
			return nil
		}
		return &jsExpr{Kind: jsExprMember, Value: "...", Left: target, Start: start, End: target.End}
	case ch >= '0' && ch <= '9' || (ch == '-' && p.pos+1 < len(p.src) && p.src[p.pos+1] >= '0' && p.src[p.pos+1] <= '9'):
		return p.parseNumber()
	case ch == '!' || ch == '-' || ch == '~':
		p.pos++
		operand := p.parsePrimary(depth + 1)
		return &jsExpr{Kind: jsExprRaw, Value: p.src[start:p.pos], Left: operand, Start: start, End: p.pos}
	default:
		return p.consumeRaw()
	}
}

// parsePostfix consumes member access and call chains after a primary.
func (p *jsExprParser) parsePostfix(expr *jsExpr, depth int) *jsExpr {
	for {
		p.skipSpace()
		if p.pos >= len(p.src) || !p.budgeted() {
			return expr
		}
		ch := p.src[p.pos]
		switch {
		case ch == '.' && p.pos+1 < len(p.src) && isJSIdentifierStart(p.src[p.pos+1]):
			p.pos++
			nameStart := p.pos
			for p.pos < len(p.src) && isJSIdentifierContinuation(p.src[p.pos]) {
				p.pos++
			}
			name := p.src[nameStart:p.pos]
			expr = &jsExpr{Kind: jsExprMember, Value: name, Left: expr, Start: expr.Start, End: p.pos}
		case ch == '(':
			args, end := p.parseArguments(depth + 1)
			callee := strings.TrimSpace(p.src[expr.Start:expr.End])
			expr = &jsExpr{Kind: jsExprCall, Callee: callee, Args: args, Start: expr.Start, End: end}
		case ch == '[':
			p.pos++
			inner := p.parseExpression(depth + 1)
			p.skipSpace()
			if p.pos < len(p.src) && p.src[p.pos] == ']' {
				p.pos++
			}
			expr = &jsExpr{Kind: jsExprMember, Value: "[]", Left: expr, Right: inner, Start: expr.Start, End: p.pos}
		default:
			return expr
		}
	}
}

func (p *jsExprParser) parseArguments(depth int) ([]*jsExpr, int) {
	// Caller guarantees src[pos] == '('.
	p.pos++
	args := make([]*jsExpr, 0, 4)
	for p.pos < len(p.src) {
		p.skipSpace()
		if p.pos >= len(p.src) {
			break
		}
		if p.src[p.pos] == ')' {
			p.pos++
			return args, p.pos
		}
		if p.src[p.pos] == ',' {
			p.pos++
			continue
		}
		arg := p.parseExpression(depth)
		if arg == nil {
			// Fault tolerance: skip to the next top-level delimiter.
			p.skipToDelimiter()
			continue
		}
		args = append(args, arg)
		p.skipSpace()
		if p.pos < len(p.src) && p.src[p.pos] == ',' {
			p.pos++
		}
	}
	return args, p.pos
}

func (p *jsExprParser) parseObject(depth int) *jsExpr {
	start := p.pos
	p.pos++ // consume '{'
	object := &jsExpr{Kind: jsExprObject, Start: start}
	for p.pos < len(p.src) {
		p.skipSpace()
		if p.pos >= len(p.src) {
			break
		}
		if p.src[p.pos] == '}' {
			p.pos++
			break
		}
		if !p.budgeted() {
			break
		}
		if strings.HasPrefix(p.src[p.pos:], "...") {
			p.pos += 3
			target := p.parseExpression(depth + 1)
			object.Fields = append(object.Fields, jsObjectField{Spread: true, Value: target})
		} else {
			key := p.parseObjectKey()
			if key == "" {
				p.skipToDelimiter()
				continue
			}
			p.skipSpace()
			value := &jsExpr{Kind: jsExprIdentifier, Value: key} // shorthand {key}
			if p.pos < len(p.src) && p.src[p.pos] == ':' {
				p.pos++
				if parsed := p.parseExpression(depth + 1); parsed != nil {
					value = parsed
				}
			}
			object.Fields = append(object.Fields, jsObjectField{Key: key, Value: value})
		}
		p.skipSpace()
		if p.pos < len(p.src) && p.src[p.pos] == ',' {
			p.pos++
		}
	}
	object.End = p.pos
	return object
}

func (p *jsExprParser) parseObjectKey() string {
	p.skipSpace()
	if p.pos >= len(p.src) {
		return ""
	}
	ch := p.src[p.pos]
	if ch == '"' || ch == '\'' {
		literal := p.parseQuoted(ch)
		if literal == nil {
			return ""
		}
		return literal.Value
	}
	if ch == '[' { // computed key: keep raw marker
		p.skipToDelimiter()
		return ""
	}
	start := p.pos
	for p.pos < len(p.src) && isJSIdentifierContinuation(p.src[p.pos]) {
		p.pos++
	}
	return p.src[start:p.pos]
}

func (p *jsExprParser) parseArray(depth int) *jsExpr {
	start := p.pos
	p.pos++ // consume '['
	array := &jsExpr{Kind: jsExprArray, Start: start}
	for p.pos < len(p.src) {
		p.skipSpace()
		if p.pos >= len(p.src) {
			break
		}
		if p.src[p.pos] == ']' {
			p.pos++
			break
		}
		if p.src[p.pos] == ',' {
			p.pos++
			continue
		}
		element := p.parseExpression(depth + 1)
		if element == nil {
			p.skipToDelimiter()
			continue
		}
		array.Elements = append(array.Elements, element)
		p.skipSpace()
		if p.pos < len(p.src) && p.src[p.pos] == ',' {
			p.pos++
		}
	}
	array.End = p.pos
	return array
}

func (p *jsExprParser) parseQuoted(quote byte) *jsExpr {
	start := p.pos
	p.pos++ // consume quote
	var value strings.Builder
	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		if ch == '\\' && p.pos+1 < len(p.src) {
			value.WriteByte(p.src[p.pos+1])
			p.pos += 2
			continue
		}
		if ch == quote {
			p.pos++
			return &jsExpr{Kind: jsExprLiteral, Value: value.String(), Start: start, End: p.pos}
		}
		value.WriteByte(ch)
		p.pos++
	}
	return &jsExpr{Kind: jsExprLiteral, Value: value.String(), Start: start, End: p.pos}
}

func (p *jsExprParser) parseTemplate(depth int) *jsExpr {
	start := p.pos
	p.pos++ // consume '`'
	template := &jsExpr{Kind: jsExprTemplate, Start: start}
	var static strings.Builder
	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		if ch == '\\' && p.pos+1 < len(p.src) {
			static.WriteByte(p.src[p.pos+1])
			p.pos += 2
			continue
		}
		if ch == '`' {
			p.pos++
			break
		}
		if ch == '$' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '{' {
			if static.Len() > 0 {
				template.Parts = append(template.Parts, jsTemplatePart{Static: static.String()})
				static.Reset()
			}
			p.pos += 2
			inner := p.parseExpression(depth + 1)
			p.skipSpace()
			if p.pos < len(p.src) && p.src[p.pos] == '}' {
				p.pos++
			}
			template.Parts = append(template.Parts, jsTemplatePart{Expr: inner})
			continue
		}
		static.WriteByte(ch)
		p.pos++
	}
	if static.Len() > 0 || len(template.Parts) == 0 {
		template.Parts = append(template.Parts, jsTemplatePart{Static: static.String()})
	}
	template.End = p.pos
	return template
}

func (p *jsExprParser) parseIdentifierLike() *jsExpr {
	start := p.pos
	for p.pos < len(p.src) && isJSIdentifierContinuation(p.src[p.pos]) {
		p.pos++
	}
	name := p.src[start:p.pos]
	switch name {
	case "true", "false", "null", "undefined", "NaN":
		return &jsExpr{Kind: jsExprLiteral, Value: name, Start: start, End: p.pos}
	case "new":
		p.skipSpace()
		if p.pos < len(p.src) && isJSIdentifierStart(p.src[p.pos]) {
			target := p.parseIdentifierLike()
			return &jsExpr{Kind: jsExprCall, Callee: "new " + target.Value, Start: start, End: p.pos}
		}
		return &jsExpr{Kind: jsExprIdentifier, Value: name, Start: start, End: p.pos}
	default:
		return &jsExpr{Kind: jsExprIdentifier, Value: name, Start: start, End: p.pos}
	}
}

func (p *jsExprParser) parseNumber() *jsExpr {
	start := p.pos
	if p.src[p.pos] == '-' {
		p.pos++
	}
	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		if (ch >= '0' && ch <= '9') || ch == '.' || ch == 'e' || ch == 'E' || ch == 'x' ||
			(ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
			p.pos++
			continue
		}
		break
	}
	return &jsExpr{Kind: jsExprLiteral, Value: p.src[start:p.pos], Start: start, End: p.pos}
}

// consumeRaw preserves unparsable input as evidence instead of failing.
func (p *jsExprParser) consumeRaw() *jsExpr {
	start := p.pos
	p.skipToDelimiter()
	if p.pos == start {
		p.pos++
	}
	return &jsExpr{Kind: jsExprRaw, Value: strings.TrimSpace(p.src[start:p.pos]), Start: start, End: p.pos}
}

// skipToDelimiter advances to the next top-level delimiter, respecting
// nesting and quotes.
func (p *jsExprParser) skipToDelimiter() {
	depth := 0
	quote := byte(0)
	escaped := false
	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		if quote != 0 {
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == quote {
				quote = 0
			}
			p.pos++
			continue
		}
		switch ch {
		case '"', '\'', '`':
			quote = ch
		case '(', '{', '[':
			depth++
		case ')', '}', ']':
			if depth == 0 {
				return
			}
			depth--
		case ',', ';':
			if depth == 0 {
				return
			}
		}
		p.pos++
	}
}

func (p *jsExprParser) skipSpace() {
	for p.pos < len(p.src) && isJSWhitespace(p.src[p.pos]) {
		p.pos++
	}
}

// evalJSExprStatic attempts a purely static evaluation of an expression.
// resolve resolves identifiers (from the symbol index); it may be nil.
func evalJSExprStatic(expr *jsExpr, resolve func(name string) (string, bool)) (string, bool) {
	if expr == nil {
		return "", false
	}
	switch expr.Kind {
	case jsExprLiteral:
		return expr.Value, true
	case jsExprIdentifier:
		if resolve == nil {
			return "", false
		}
		return resolve(expr.Value)
	case jsExprTemplate:
		var out strings.Builder
		for _, part := range expr.Parts {
			if part.Expr == nil {
				out.WriteString(part.Static)
				continue
			}
			value, ok := evalJSExprStatic(part.Expr, resolve)
			if !ok {
				return "", false
			}
			out.WriteString(value)
		}
		return out.String(), true
	case jsExprBinary:
		if expr.Op != "+" {
			return "", false
		}
		left, lok := evalJSExprStatic(expr.Left, resolve)
		right, rok := evalJSExprStatic(expr.Right, resolve)
		if !lok || !rok {
			return "", false
		}
		return left + right, true
	default:
		return "", false
	}
}

// jsParsedField is one structurally extracted field from a parsed object or
// params carrier.
type jsParsedField struct {
	Name    string
	Value   string // statically resolved when non-empty
	Expr    *jsExpr
	RawExpr string // source text of the value expression when available
	Spread  bool
}

// jsFieldsFromExpression extracts fields from a parsed expression, handling
// nested object literals, spread, JSON.stringify, and URLSearchParams. The
// spread resolver maps an identifier to its object expression text (from the
// symbol index); it may be nil.
func jsFieldsFromExpression(expr *jsExpr, spreadResolve func(name string) (*jsExpr, bool), depth int) []jsParsedField {
	if expr == nil || depth > maxStaticArgumentResolveDepth {
		return nil
	}
	switch expr.Kind {
	case jsExprObject:
		fields := make([]jsParsedField, 0, len(expr.Fields))
		for _, field := range expr.Fields {
			if field.Spread {
				if field.Value != nil && field.Value.Kind == jsExprIdentifier && spreadResolve != nil {
					if spreadExpr, ok := spreadResolve(field.Value.Value); ok {
						fields = append(fields, jsFieldsFromExpression(spreadExpr, spreadResolve, depth+1)...)
					}
				}
				continue
			}
			if field.Key == "" {
				continue
			}
			parsed := jsParsedField{Name: field.Key, Expr: field.Value}
			if value, ok := evalJSExprStatic(field.Value, nil); ok {
				parsed.Value = value
			}
			fields = append(fields, parsed)
		}
		return fields
	case jsExprCall:
		callee := strings.TrimSpace(expr.Callee)
		switch {
		case callee == "JSON.stringify" && len(expr.Args) == 1:
			return jsFieldsFromExpression(expr.Args[0], spreadResolve, depth+1)
		case (callee == "new URLSearchParams" || callee == "URLSearchParams") && len(expr.Args) == 1:
			return jsFieldsFromExpression(expr.Args[0], spreadResolve, depth+1)
		}
	}
	return nil
}
