package crawl

import (
	"strings"
)

// extractFormDataAppendFields recovers fields from the statement-level
// FormData idiom:
//
//	var fd = new FormData();
//	fd.append("file", file);
//	fd.append("remark", "hi");
//
// The scan is local (the caller passes an analysis block), boundary-checked,
// and each append call is parsed through the expression parser so values keep
// both static values and expressions. `.set(` is supported as well.
func extractFormDataAppendFields(content, variable string) []jsParsedField {
	variable = strings.TrimSpace(variable)
	if !identifierPattern.MatchString(variable) {
		return nil
	}
	if !isFormDataConstructorAssignment(content, variable) {
		return nil
	}

	fields := make([]jsParsedField, 0, 4)
	seen := make(map[string]struct{})
	for _, method := range []string{"append", "set"} {
		needle := variable + "." + method + "("
		for start := 0; start+len(needle) <= len(content); {
			index := strings.Index(content[start:], needle)
			if index < 0 {
				break
			}
			callStart := start + index
			start = callStart + len(needle)
			if callStart > 0 && isJSIdentifierContinuation(content[callStart-1]) {
				continue
			}
			openIndex := callStart + len(needle) - 1
			args, _, ok := extractBalancedJS(content, openIndex, '(', ')')
			if !ok {
				continue
			}
			parts := splitTopLevelCSV(args)
			if len(parts) < 2 {
				continue
			}
			key := parseStaticStringLikeValue(content, strings.TrimSpace(parts[0]))
			if key == "" {
				continue
			}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			valueExpr := strings.TrimSpace(parts[1])
			field := jsParsedField{Name: key, RawExpr: valueExpr}
			if value, ok := evalJSExprStatic(parseJSExpression(valueExpr), nil); ok {
				field.Value = value
			}
			fields = append(fields, field)
		}
	}
	return fields
}

// isFormDataConstructorAssignment reports whether the variable is assigned a
// `new FormData()` value anywhere in the local scope.
func isFormDataConstructorAssignment(content, variable string) bool {
	expr, ok := findJSAssignmentExpression(content, variable)
	if !ok {
		return false
	}
	compact := strings.ReplaceAll(expr, " ", "")
	return strings.HasPrefix(compact, "newFormData(")
}
