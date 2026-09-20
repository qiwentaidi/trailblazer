package crawl

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/qiwentaidi/trailblazer/pkg/core/database"
)

const (
	// maxModuleResolverModules bounds the module table across all resources.
	maxModuleResolverModules = 4096
	// maxModuleResolverFileBytes skips indexing absurdly large resources.
	maxModuleResolverFileBytes = 8 * 1024 * 1024
	// maxModuleSymbolLookups bounds on-demand queries per analysis input.
	maxModuleSymbolLookups = 24
	// moduleResolverTimeBudget bounds resolver construction.
	moduleResolverTimeBudget = 2 * time.Second
)

// jsModuleInfo is one detected module inside a JS resource: a webpack bundle
// module, an ESM file, or a source-map-restored source file.
type jsModuleInfo struct {
	File      string
	ID        string // webpack numeric/string id, or module path
	Path      string // original path when known (webpack jsonp key / source map)
	Start     int
	End       int
	Exported  map[string]struct{}
	Clients   []string
	SourceMap bool
}

// jsResolvedSymbol is the result of an on-demand cross-module symbol query.
type jsResolvedSymbol struct {
	Name       string
	File       string
	ModulePath string
	ValueExpr  string
	Value      string
	Kind       string
	Fields     []string
}

// jsModuleResolver replaces the previous whole-corpus resolverContent
// concatenation with on-demand symbol queries scoped by module boundaries:
// same-module first, same-file exporting modules next, and cross-file only
// when an explicit import/export or source-map link exists — preventing
// cross-file false associations.
type jsModuleResolver struct {
	files      map[string]string
	modules    []jsModuleInfo
	byFile     map[string][]int // file -> module indexes
	moduleByID map[string][]int // webpack module id -> module indexes
	indexes    map[int]*jsSourceIndex
	// esmImports maps importing file -> symbol -> defining file.
	esmImports map[string]map[string]string
	// webpackEdges maps file -> module indexes referenced via require calls.
	webpackEdges map[string]map[int]struct{}
	truncated    bool
}

var (
	webpackModuleBoundaryPattern = regexp.MustCompile(`([{,])\s*(?:"([^"]+)"|(\d+))\s*:\s*function\s*\(`)
	webpackExportPattern         = regexp.MustCompile(`\.d\s*\(\s*[A-Za-z_$][\w$]*\s*,\s*\{`)
	webpackRequireCallPattern    = regexp.MustCompile(`[A-Za-z_$][\w$]*\(\s*(?:"([^"]+)"|(\d+))\s*\)`)
	esmImportPattern             = regexp.MustCompile(`import\s*\{([^}]*)\}\s*from\s*["']([^"']+)["']`)
	esmExportNamePattern         = regexp.MustCompile(`export\s+(?:const|let|var|function|async\s+function)\s+([A-Za-z_$][\w$]*)`)
	esmExportListPattern         = regexp.MustCompile(`export\s*\{([^}]*)\}`)
	webpackExportNamePattern     = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*:\s*(?:\(\)\s*=>|function)`)
	sourceMapURLPattern          = regexp.MustCompile(`//#\s*sourceMappingURL=\s*(\S+)`)
)

// maxScopedResolverBytes bounds the per-file resolution corpus handed to the
// endpoint extractors. It replaces the previous whole-corpus concatenation.
const maxScopedResolverBytes = 256 * 1024

// maxScopedFileHeadBytes bounds how much of a webpack-edged file's top-level
// (non-module) region is shared: wrapper helpers such as a global `request`
// function live there.
const maxScopedFileHeadBytes = 32 * 1024

// maxGlobalScriptBytes bounds single-module script files shared as global
// scope (classic non-bundled pages share globals across script tags).
const maxGlobalScriptBytes = 64 * 1024

// newJSModuleResolver builds the module table. Module contents are indexed
// lazily, so construction stays cheap even for large resource sets.
func newJSModuleResolver(jsResources []database.JSResource) *jsModuleResolver {
	resolver := &jsModuleResolver{
		files:        make(map[string]string, len(jsResources)),
		byFile:       make(map[string][]int, len(jsResources)),
		moduleByID:   make(map[string][]int),
		indexes:      make(map[int]*jsSourceIndex),
		esmImports:   make(map[string]map[string]string),
		webpackEdges: make(map[string]map[int]struct{}),
	}
	deadline := time.Now().Add(moduleResolverTimeBudget)
	sourceMaps := make(map[string]SourceMap)

	for _, resource := range jsResources {
		content := strings.TrimSpace(resource.Content)
		if content == "" || len(content) > maxModuleResolverFileBytes {
			continue
		}
		if strings.HasSuffix(resource.URL, ".map") || looksLikeSourceMap(content) {
			var sm SourceMap
			if err := json.Unmarshal([]byte(content), &sm); err == nil && len(sm.Sources) == len(sm.SourcesContent) {
				sourceMaps[resource.URL] = sm
			}
			continue
		}
		resolver.files[resource.URL] = content
	}
	for file, content := range resolver.files {
		if time.Now().After(deadline) || len(resolver.modules) >= maxModuleResolverModules {
			resolver.truncated = true
			break
		}
		resolver.addFileModules(file, content)
	}
	for index, module := range resolver.modules {
		if module.ID != "" {
			resolver.moduleByID[module.ID] = append(resolver.moduleByID[module.ID], index)
		}
	}
	resolver.linkWebpackEdges()
	resolver.linkSourceMaps(sourceMaps)
	resolver.linkESMImports()
	return resolver
}

// linkWebpackEdges records cross-file webpack require references: a chunk
// calling r("9h9Y") links to the module with id 9h9Y wherever it is defined.
func (r *jsModuleResolver) linkWebpackEdges() {
	for file, content := range r.files {
		for _, match := range webpackRequireCallPattern.FindAllStringSubmatch(content, -1) {
			id := match[1]
			if id == "" {
				id = match[2]
			}
			targets := r.moduleByID[id]
			if len(targets) == 0 {
				continue
			}
			if r.webpackEdges[file] == nil {
				r.webpackEdges[file] = make(map[int]struct{})
			}
			for _, target := range targets {
				r.webpackEdges[file][target] = struct{}{}
			}
		}
	}
}

func looksLikeSourceMap(content string) bool {
	return strings.HasPrefix(content, "{") && strings.Contains(content, `"sourcesContent"`) && strings.Contains(content, `"mappings"`)
}

// addFileModules detects webpack module boundaries; when none exist the whole
// file is treated as one ESM module.
func (r *jsModuleResolver) addFileModules(file, content string) {
	matches := webpackModuleBoundaryPattern.FindAllStringSubmatchIndex(content, -1)
	if len(matches) == 0 {
		moduleIndex := len(r.modules)
		r.modules = append(r.modules, jsModuleInfo{
			File:     file,
			ID:       file,
			Start:    0,
			End:      len(content),
			Exported: esmExportedNames(content),
			Clients:  axiosClientNames(content),
		})
		r.byFile[file] = append(r.byFile[file], moduleIndex)
		return
	}

	index := buildJSSourceIndex(content)
	for position, match := range matches {
		if len(r.modules) >= maxModuleResolverModules {
			r.truncated = true
			return
		}
		id := ""
		if match[4] >= 0 {
			id = content[match[4]:match[5]]
		} else if match[6] >= 0 {
			id = content[match[6]:match[7]]
		}
		// Body extent: the function's opening brace via the bracket table.
		openParen := match[1] - 1
		start := match[0] + 1 // skip the leading '{' or ','
		end := len(content)
		if position+1 < len(matches) {
			end = matches[position+1][0] + 1
		}
		if paramsClose, ok := index.matching[openParen]; ok {
			body := paramsClose + 1
			for body < len(content) && isJSWhitespace(content[body]) {
				body++
			}
			if body < len(content) && content[body] == '{' {
				if bodyClose, ok := index.matching[body]; ok && bodyClose+1 < end {
					end = bodyClose + 1
				}
			}
		}
		fragment := content[start:end]
		moduleIndex := len(r.modules)
		path := id
		if !strings.Contains(id, "/") {
			path = ""
		}
		r.modules = append(r.modules, jsModuleInfo{
			File:     file,
			ID:       id,
			Path:     path,
			Start:    start,
			End:      end,
			Exported: webpackExportedNames(fragment),
			Clients:  axiosClientNames(fragment),
		})
		r.byFile[file] = append(r.byFile[file], moduleIndex)
	}
}

// webpackExportedNames extracts names exported via `n.d(exports, {...})`.
func webpackExportedNames(fragment string) map[string]struct{} {
	if !webpackExportPattern.MatchString(fragment) {
		return nil
	}
	exported := make(map[string]struct{})
	for _, match := range webpackExportNamePattern.FindAllStringSubmatch(fragment, -1) {
		if len(match) >= 2 {
			exported[match[1]] = struct{}{}
		}
	}
	return exported
}

func esmExportedNames(content string) map[string]struct{} {
	exported := make(map[string]struct{})
	for _, match := range esmExportNamePattern.FindAllStringSubmatch(content, -1) {
		exported[match[1]] = struct{}{}
	}
	for _, match := range esmExportListPattern.FindAllStringSubmatch(content, -1) {
		for _, part := range strings.Split(match[1], ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if alias := strings.Split(part, " as "); len(alias) == 2 {
				exported[strings.TrimSpace(alias[1])] = struct{}{}
			} else {
				exported[part] = struct{}{}
			}
		}
	}
	if len(exported) == 0 {
		return nil
	}
	return exported
}

// axiosClientNames records axios-like instance names created in a fragment so
// modules using the same client can be linked without cross-file guessing.
func axiosClientNames(fragment string) []string {
	var names []string
	for _, call := range findAxiosLikeCreateCalls(fragment) {
		names = appendUniqueStrings(names, call.InstanceName)
	}
	return names
}

// linkSourceMaps registers source-map-restored sources as virtual modules so
// symbol queries can recover module paths and original variable names.
func (r *jsModuleResolver) linkSourceMaps(sourceMaps map[string]SourceMap) {
	for mapURL, sm := range sourceMaps {
		jsURL := strings.TrimSuffix(mapURL, ".map")
		for i, sourcePath := range sm.Sources {
			if i >= len(sm.SourcesContent) || len(r.modules) >= maxModuleResolverModules {
				r.truncated = true
				break
			}
			content := sm.SourcesContent[i]
			if strings.TrimSpace(content) == "" {
				continue
			}
			virtualFile := jsURL + "#sm:" + sourcePath
			r.files[virtualFile] = content
			moduleIndex := len(r.modules)
			r.modules = append(r.modules, jsModuleInfo{
				File:      virtualFile,
				ID:        sourcePath,
				Path:      sourcePath,
				Start:     0,
				End:       len(content),
				Exported:  esmExportedNames(content),
				Clients:   axiosClientNames(content),
				SourceMap: true,
			})
			r.byFile[virtualFile] = append(r.byFile[virtualFile], moduleIndex)
		}
	}
}

// linkESMImports records explicit import/export edges between files.
func (r *jsModuleResolver) linkESMImports() {
	for file, content := range r.files {
		for _, match := range esmImportPattern.FindAllStringSubmatch(content, -1) {
			specifier := match[2]
			target := r.resolveSpecifier(file, specifier)
			if target == "" {
				continue
			}
			if r.esmImports[file] == nil {
				r.esmImports[file] = make(map[string]string)
			}
			for _, part := range strings.Split(match[1], ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				name := part
				if alias := strings.Split(part, " as "); len(alias) == 2 {
					name = strings.TrimSpace(alias[1])
				}
				r.esmImports[file][name] = target
			}
		}
	}
}

// resolveSpecifier maps a relative ESM specifier to a known resource URL.
func (r *jsModuleResolver) resolveSpecifier(fromFile, specifier string) string {
	if !strings.HasPrefix(specifier, ".") {
		return ""
	}
	base := fromFile
	if slash := strings.LastIndex(base, "/"); slash >= 0 {
		base = base[:slash+1]
	}
	for _, part := range strings.Split(specifier, "/") {
		switch part {
		case ".", "":
		case "..":
			if trimmed := base[:len(base)-1]; strings.LastIndex(trimmed, "/") >= 0 {
				base = base[:strings.LastIndex(trimmed, "/")+1]
			}
		default:
			base += part + "/"
		}
	}
	candidate := strings.TrimSuffix(base, "/")
	if _, ok := r.files[candidate]; ok {
		return candidate
	}
	return ""
}

// moduleIndex returns a lazy per-module lexical index.
func (r *jsModuleResolver) moduleIndex(moduleIdx int) *jsSourceIndex {
	if index, ok := r.indexes[moduleIdx]; ok {
		return index
	}
	module := r.modules[moduleIdx]
	content := r.files[module.File]
	if module.Start >= 0 && module.End <= len(content) && module.Start < module.End {
		content = content[module.Start:module.End]
	}
	index := buildJSSourceIndex(content)
	r.indexes[moduleIdx] = index
	return index
}

func (r *jsModuleResolver) moduleContent(moduleIdx int) string {
	module := r.modules[moduleIdx]
	content := r.files[module.File]
	if module.Start >= 0 && module.End <= len(content) && module.Start < module.End {
		return content[module.Start:module.End]
	}
	return content
}

// lookupSymbol answers an on-demand symbol query. Search order: the module
// containing the hit, other modules in the same file (exporting modules
// first), explicit ESM import edges, then source-map-restored sources.
// Cross-file matches require an explicit link, preventing false association.
func (r *jsModuleResolver) lookupSymbol(name, fromFile string, fromOffset, limit int) []jsResolvedSymbol {
	if limit <= 0 {
		limit = 2
	}
	results := make([]jsResolvedSymbol, 0, limit)
	seen := make(map[int]struct{})

	try := func(moduleIdx int) bool {
		if _, ok := seen[moduleIdx]; ok {
			return false
		}
		seen[moduleIdx] = struct{}{}
		if symbol, ok := r.symbolFromModule(moduleIdx, name); ok {
			results = append(results, symbol)
			return len(results) >= limit
		}
		return false
	}

	// 1. Same module.
	if moduleIdx, ok := r.moduleAt(fromFile, fromOffset); ok {
		if try(moduleIdx) {
			return results
		}
	}
	// 2. Same file, exporting modules first.
	sameFile := r.byFile[fromFile]
	for _, pass := range []bool{true, false} {
		for _, moduleIdx := range sameFile {
			module := r.modules[moduleIdx]
			_, exports := module.Exported[name]
			if exports != pass {
				continue
			}
			if try(moduleIdx) {
				return results
			}
		}
	}
	// 3. Explicit ESM import edge.
	if imports := r.esmImports[fromFile]; imports != nil {
		if target, ok := imports[name]; ok {
			for _, moduleIdx := range r.byFile[target] {
				module := r.modules[moduleIdx]
				if _, exports := module.Exported[name]; !exports && len(module.Exported) > 0 {
					continue
				}
				if try(moduleIdx) {
					return results
				}
			}
		}
	}
	// 4. Source-map-restored sources whose path hints match.
	for moduleIdx, module := range r.modules {
		if !module.SourceMap {
			continue
		}
		if try(moduleIdx) {
			return results
		}
	}
	return results
}

// symbolFromModule resolves a name inside one module via its lazy index.
// Besides `name = <expr>` assignments it recognizes function declarations
// (`export function name(...)`), which ESM modules use heavily.
func (r *jsModuleResolver) symbolFromModule(moduleIdx int, name string) (jsResolvedSymbol, bool) {
	module := r.modules[moduleIdx]
	content := r.moduleContent(moduleIdx)
	index := r.moduleIndex(moduleIdx)
	if expr, ok := findJSAssignmentExpressionWithIndex(index, content, name); ok {
		symbol := jsResolvedSymbol{
			Name:       name,
			File:       module.File,
			ModulePath: module.Path,
			ValueExpr:  strings.TrimSpace(expr),
			Kind:       "module",
		}
		if literal := parseStaticStringLikeValue(content, symbol.ValueExpr); literal != "" {
			symbol.Kind = "constant"
			symbol.Value = literal
		}
		if parsed := parseJSExpression(symbol.ValueExpr); parsed != nil && parsed.Kind == jsExprObject {
			symbol.Kind = "object"
			for _, field := range parsed.Fields {
				if field.Key != "" {
					symbol.Fields = append(symbol.Fields, field.Key)
				}
			}
			sort.Strings(symbol.Fields)
		}
		return symbol, true
	}
	if symbol, ok := functionDeclarationSymbol(index, content, module, name); ok {
		return symbol, true
	}
	return jsResolvedSymbol{}, false
}

// functionDeclarationSymbol detects `function name(...)` declarations
// (optionally preceded by export/async) using the call index and bracket
// table.
func functionDeclarationSymbol(index *jsSourceIndex, content string, module jsModuleInfo, name string) (jsResolvedSymbol, bool) {
	for _, openParen := range index.callPositions(name) {
		tokenStart := openParen - len(name)
		prefix := strings.TrimSpace(content[:tokenStart])
		if !strings.HasSuffix(prefix, "function") {
			continue
		}
		paramsClose, ok := index.matching[openParen]
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
		return jsResolvedSymbol{
			Name:       name,
			File:       module.File,
			ModulePath: module.Path,
			ValueExpr:  strings.TrimSpace(content[tokenStart : bodyClose+1]),
			Kind:       "function",
		}, true
	}
	return jsResolvedSymbol{}, false
}

// moduleAt finds the module containing an offset within a file.
func (r *jsModuleResolver) moduleAt(file string, offset int) (int, bool) {
	for _, moduleIdx := range r.byFile[file] {
		module := r.modules[moduleIdx]
		if offset >= module.Start && offset < module.End {
			return moduleIdx, true
		}
	}
	return -1, false
}

// sourceMapURL extracts the declared source map URL from JS content.
func sourceMapURL(content string) string {
	match := sourceMapURLPattern.FindStringSubmatch(content)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

// scopedResolverContent builds the per-file resolution corpus for the
// endpoint extractors, replacing the previous whole-corpus concatenation.
// It includes only evidence-linked material:
//   - module fragments referenced by this file's webpack require edges,
//     plus the defining file's top-level head (where wrapper helpers live)
//   - files linked by explicit ESM import edges
//   - source-map-restored sources belonging to this file
//   - small single-module global scripts (classic pages share globals
//     across script tags), excluding the file itself
//
// The corpus is byte-capped and deterministic.
func (r *jsModuleResolver) scopedResolverContent(file string, maxBytes int) string {
	if r == nil {
		return ""
	}
	if maxBytes <= 0 {
		maxBytes = maxScopedResolverBytes
	}
	var builder strings.Builder
	used := 0
	write := func(fragment string) bool {
		fragment = strings.TrimSpace(fragment)
		if fragment == "" {
			return true
		}
		if used+len(fragment) > maxBytes {
			return false
		}
		if builder.Len() > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(fragment)
		used += len(fragment)
		return true
	}

	// 1. webpack require edges: referenced module fragments + defining file
	//    head (top-level helpers).
	edgedFiles := make(map[string]struct{})
	moduleIndexes := make([]int, 0, len(r.webpackEdges[file]))
	for moduleIdx := range r.webpackEdges[file] {
		moduleIndexes = append(moduleIndexes, moduleIdx)
	}
	sort.Ints(moduleIndexes)
	for _, moduleIdx := range moduleIndexes {
		module := r.modules[moduleIdx]
		if module.File == file {
			continue
		}
		edgedFiles[module.File] = struct{}{}
		if !write(r.moduleContent(moduleIdx)) {
			return builder.String()
		}
	}
	edgedFileList := make([]string, 0, len(edgedFiles))
	for edgedFile := range edgedFiles {
		edgedFileList = append(edgedFileList, edgedFile)
	}
	sort.Strings(edgedFileList)
	for _, edgedFile := range edgedFileList {
		if !write(r.fileHead(edgedFile, maxScopedFileHeadBytes)) {
			return builder.String()
		}
	}

	// 2. Explicit ESM import edges: target files.
	esmTargets := make(map[string]struct{})
	for _, target := range r.esmImports[file] {
		if target != file {
			esmTargets[target] = struct{}{}
		}
	}
	esmTargetList := make([]string, 0, len(esmTargets))
	for target := range esmTargets {
		esmTargetList = append(esmTargetList, target)
	}
	sort.Strings(esmTargetList)
	for _, target := range esmTargetList {
		if !write(r.fileHead(target, maxGlobalScriptBytes)) {
			return builder.String()
		}
	}

	// 3. Source-map-restored sources belonging to this file.
	for _, moduleIdx := range r.byFile[file] {
		module := r.modules[moduleIdx]
		if !module.SourceMap {
			continue
		}
		if !write(r.moduleContent(moduleIdx)) {
			return builder.String()
		}
	}

	// 4. Small global scripts from other files (shared page globals).
	otherFiles := make([]string, 0, len(r.files))
	for other := range r.files {
		if other != file {
			otherFiles = append(otherFiles, other)
		}
	}
	sort.Strings(otherFiles)
	for _, other := range otherFiles {
		moduleIdxs := r.byFile[other]
		if len(moduleIdxs) != 1 {
			continue // module-structured bundles are shared only via edges
		}
		module := r.modules[moduleIdxs[0]]
		if module.SourceMap || module.ID != other {
			continue
		}
		content := r.files[other]
		if len(content) > maxGlobalScriptBytes {
			continue
		}
		if _, edged := edgedFiles[other]; edged {
			continue // already shared via the webpack edge
		}
		if !write(content) {
			return builder.String()
		}
	}
	return builder.String()
}

// fileHead returns the top-level region of a file before its first module
// boundary, capped. Files without module structure return their (capped)
// whole content.
func (r *jsModuleResolver) fileHead(file string, maxBytes int) string {
	content := r.files[file]
	if content == "" {
		return ""
	}
	head := len(content)
	firstStart := -1
	for _, moduleIdx := range r.byFile[file] {
		module := r.modules[moduleIdx]
		if module.ID == file {
			continue // single-module file: no boundary head
		}
		if firstStart < 0 || module.Start < firstStart {
			firstStart = module.Start
		}
	}
	if firstStart > 0 {
		head = firstStart
	}
	if head > maxBytes {
		head = maxBytes
	}
	return content[:head]
}
