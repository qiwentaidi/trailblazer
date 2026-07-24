package protocoltool

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

var (
	frontendDecryptCallPattern = regexp.MustCompile(`\(\s*0\s*,\s*d\.sd\s*\)\(\s*e\.data\s*,\s*atob\(atob\(y\)\)\s*\)`)
	frontendModuleIDPattern    = regexp.MustCompile(`(?:^|[,;])\s*d\s*=\s*[A-Za-z_$][\w$]*\((\d+)\)`)
	frontendYPattern           = regexp.MustCompile(`(?:^|[,;])\s*y\s*=\s*"([^"]+)"`)
	webpackModulePattern       = regexp.MustCompile(`(\d+)\s*:\s*function\s*\(([^)]*)\)\s*\{`)
)

type webpackModule struct {
	ID             string
	FunctionSource string
	RequireAlias   string
}

type frontendRuntimeResult struct {
	Plaintext string `json:"plaintext"`
}

func DecryptWithStoredFrontendRuntime(taskID, ciphertext, functionPath, moduleID string) (string, error) {
	if strings.TrimSpace(taskID) == "" {
		return "", fmt.Errorf("missing task id")
	}

	store := database.GetScanDataStore()
	if store == nil {
		return "", fmt.Errorf("scan data store not configured")
	}

	jsResources, err := store.ListJSResources(taskID)
	if err != nil {
		return "", err
	}
	if len(jsResources) == 0 {
		return "", fmt.Errorf("no stored js resources")
	}

	rootModuleID, keySeed, modules, err := extractFrontendDecryptRuntime(jsResources, moduleID)
	if err != nil {
		return "", err
	}

	scriptPath, cleanup, err := buildFrontendRuntimeScript(rootModuleID, keySeed, normalizeCiphertext(ciphertext), functionPath, modules)
	if err != nil {
		return "", err
	}
	defer cleanup()

	cmd := exec.Command("node", scriptPath)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = err.Error()
		}
		return "", fmt.Errorf("frontend runtime decrypt failed: %s", errMsg)
	}

	var result frontendRuntimeResult
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &result); err != nil {
		return "", fmt.Errorf("invalid frontend runtime output: %w", err)
	}
	if strings.TrimSpace(result.Plaintext) == "" {
		return "", fmt.Errorf("frontend runtime returned empty plaintext")
	}
	return result.Plaintext, nil
}

func extractFrontendDecryptRuntime(jsResources []database.JSResource, preferredModuleID string) (string, string, map[string]webpackModule, error) {
	moduleID := ""
	keySeed := ""
	allModules := make(map[string]webpackModule)

	for _, resource := range jsResources {
		content := resource.Content
		for id, mod := range extractWebpackModules(content) {
			if _, exists := allModules[id]; !exists {
				allModules[id] = mod
			}
		}

		if moduleID == "" && frontendDecryptCallPattern.FindStringIndex(content) != nil {
			if matches := frontendModuleIDPattern.FindStringSubmatch(content); len(matches) > 1 {
				moduleID = matches[1]
			}
			if matches := frontendYPattern.FindStringSubmatch(content); len(matches) > 1 {
				keySeed = matches[1]
			}
		}
	}

	if moduleID == "" {
		return "", "", nil, fmt.Errorf("frontend decrypt runtime not found in stored js")
	}
	if strings.TrimSpace(preferredModuleID) != "" {
		trimmedPreferredModuleID := strings.TrimSpace(preferredModuleID)
		if _, exists := allModules[trimmedPreferredModuleID]; exists {
			moduleID = trimmedPreferredModuleID
		}
	}
	if keySeed == "" {
		return "", "", nil, fmt.Errorf("frontend decrypt key seed not found in stored js")
	}
	if _, exists := allModules[moduleID]; !exists {
		return "", "", nil, fmt.Errorf("webpack module %s not found in stored js", moduleID)
	}

	required := collectWebpackDependencies(moduleID, allModules)
	required[moduleID] = struct{}{}

	filtered := make(map[string]webpackModule, len(required))
	for id := range required {
		if mod, exists := allModules[id]; exists {
			filtered[id] = mod
		}
	}
	if len(filtered) == 0 {
		return "", "", nil, fmt.Errorf("no executable webpack modules collected")
	}
	return moduleID, keySeed, filtered, nil
}

func extractWebpackModules(content string) map[string]webpackModule {
	modules := make(map[string]webpackModule)
	matches := webpackModulePattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range matches {
		if len(match) < 6 {
			continue
		}

		moduleID := content[match[2]:match[3]]
		functionOffset := strings.Index(content[match[0]:match[1]], "function")
		if functionOffset < 0 {
			continue
		}
		functionStart := match[0] + functionOffset
		openBrace := match[1] - 1
		functionEnd := findMatchingBrace(content, openBrace)
		if functionEnd <= openBrace {
			continue
		}

		params := strings.Split(content[match[4]:match[5]], ",")
		requireAlias := ""
		if len(params) >= 3 {
			requireAlias = strings.TrimSpace(params[2])
		}

		modules[moduleID] = webpackModule{
			ID:             moduleID,
			FunctionSource: content[functionStart : functionEnd+1],
			RequireAlias:   requireAlias,
		}
	}
	return modules
}

func findMatchingBrace(source string, openBrace int) int {
	depth := 0
	inSingle := false
	inDouble := false
	inTemplate := false
	inLineComment := false
	inBlockComment := false
	escaped := false

	for i := openBrace; i < len(source); i++ {
		ch := source[i]
		var next byte
		if i+1 < len(source) {
			next = source[i+1]
		}

		if inLineComment {
			if ch == '\n' {
				inLineComment = false
			}
			continue
		}
		if inBlockComment {
			if ch == '*' && next == '/' {
				inBlockComment = false
				i++
			}
			continue
		}
		if inSingle {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '\'' {
				inSingle = false
			}
			continue
		}
		if inDouble {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		if inTemplate {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '`' {
				inTemplate = false
			}
			continue
		}

		if ch == '/' && next == '/' {
			inLineComment = true
			i++
			continue
		}
		if ch == '/' && next == '*' {
			inBlockComment = true
			i++
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '`':
			inTemplate = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func collectWebpackDependencies(rootID string, modules map[string]webpackModule) map[string]struct{} {
	required := make(map[string]struct{})
	queue := []string{rootID}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if _, exists := required[current]; exists {
			continue
		}
		required[current] = struct{}{}

		mod, exists := modules[current]
		if !exists || mod.RequireAlias == "" {
			continue
		}
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(mod.RequireAlias) + `\((\d+)\)`)
		matches := re.FindAllStringSubmatch(mod.FunctionSource, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			depID := match[1]
			if _, exists := modules[depID]; exists {
				queue = append(queue, depID)
			}
		}
	}

	return required
}

func buildFrontendRuntimeScript(rootModuleID, keySeed, ciphertext, functionPath string, modules map[string]webpackModule) (string, func(), error) {
	moduleIDs := make([]string, 0, len(modules))
	for id := range modules {
		moduleIDs = append(moduleIDs, id)
	}
	slices.Sort(moduleIDs)

	dir, err := os.MkdirTemp("", "trailblazer-frontend-runtime-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() {
		_ = os.RemoveAll(dir)
	}

	scriptPath := filepath.Join(dir, "decrypt.js")
	var builder strings.Builder
	builder.WriteString(`globalThis.window = globalThis;
globalThis.self = globalThis;
globalThis.global = globalThis;
globalThis.navigator = globalThis.navigator || {};
globalThis.atob = globalThis.atob || function(value) { return Buffer.from(String(value), 'base64').toString('binary'); };
globalThis.btoa = globalThis.btoa || function(value) { return Buffer.from(String(value), 'binary').toString('base64'); };
const modules = {
`)
	for _, id := range moduleIDs {
		builder.WriteString(id)
		builder.WriteString(":")
		builder.WriteString(modules[id].FunctionSource)
		builder.WriteString(",\n")
	}
	builder.WriteString(`};
const cache = {};
function __webpack_require__(id) {
  if (cache[id]) {
    return cache[id].exports;
  }
  if (!modules[id]) {
    throw new Error("missing webpack module: " + id);
  }
  const module = { exports: {} };
  cache[id] = module;
  modules[id](module, module.exports, __webpack_require__);
  return module.exports;
}
__webpack_require__.d = function(exports, definition) {
  for (const key in definition) {
    if (__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
      Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
    }
  }
};
__webpack_require__.o = function(obj, prop) { return Object.prototype.hasOwnProperty.call(obj, prop); };
__webpack_require__.r = function(exports) {
  if (typeof Symbol !== "undefined" && Symbol.toStringTag) {
    Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
  }
  Object.defineProperty(exports, "__esModule", { value: true });
};
__webpack_require__.n = function(module) {
  const getter = module && module.__esModule ? function() { return module.default; } : function() { return module; };
  __webpack_require__.d(getter, { a: getter });
  return getter;
};
__webpack_require__.g = globalThis;
const mod = __webpack_require__(`)
	builder.WriteString(rootModuleID)
	builder.WriteString(`);
const seed = `)
	builder.WriteString(strconvQuote(keySeed))
	builder.WriteString(`;
const ciphertext = `)
	builder.WriteString(strconvQuote(ciphertext))
	builder.WriteString(`;
const functionPath = `)
	builder.WriteString(strconvQuote(normalizeRuntimeFunctionPath(functionPath)))
	builder.WriteString(`;
const key = atob(atob(seed));
function resolveRuntimeFn(root, path) {
  const candidates = [];
  if (path) {
    candidates.push(path);
  }
  candidates.push("sd", "default.sd");
  for (const candidate of candidates) {
    const segments = String(candidate).split(".").filter(Boolean);
    let current = root;
    let ok = true;
    for (const segment of segments) {
      if (segment === "mod" || segment === "exports" || segment === "module" || segment === "module.exports") {
        continue;
      }
      if (current == null || (typeof current !== "object" && typeof current !== "function")) {
        ok = false;
        break;
      }
      current = current[segment];
    }
    if (ok && typeof current === "function") {
      return current;
    }
  }
  throw new Error("decrypt function not found: " + (path || "sd"));
}
const decryptFn = resolveRuntimeFn(mod, functionPath);
const plaintext = decryptFn(ciphertext, key);
process.stdout.write(JSON.stringify({ plaintext }));
`)

	if err := os.WriteFile(scriptPath, []byte(builder.String()), 0o600); err != nil {
		cleanup()
		return "", nil, err
	}

	return scriptPath, cleanup, nil
}

func strconvQuote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func normalizeRuntimeFunctionPath(functionPath string) string {
	trimmed := strings.TrimSpace(functionPath)
	trimmed = strings.TrimPrefix(trimmed, "window.")
	trimmed = strings.TrimPrefix(trimmed, "globalThis.")
	trimmed = strings.TrimPrefix(trimmed, "global.")
	trimmed = strings.TrimPrefix(trimmed, "module.exports.")
	trimmed = strings.TrimPrefix(trimmed, "exports.")
	return strings.TrimSpace(trimmed)
}
