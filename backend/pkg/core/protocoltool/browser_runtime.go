package protocoltool

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"trailblazer/pkg/core/database"

	cdruntime "github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

type browserRuntimeSession struct {
	ctx      context.Context
	cancel   context.CancelFunc
	pageURL  string
	lastUsed time.Time
	mu       sync.Mutex
}

var browserRuntimeSessions sync.Map

func DecryptWithStoredFrontendBrowserRuntime(taskID, pageURL, requestURL, ciphertext, functionPath, moduleID string) (string, error) {
	if strings.TrimSpace(taskID) == "" {
		return "", fmt.Errorf("missing task id")
	}

	jsResources, err := database.QueryJSByTaskID(taskID)
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

	targetPageURL := resolveBrowserRuntimePageURL(pageURL, requestURL)
	if targetPageURL == "" {
		return "", fmt.Errorf("missing browser runtime page url")
	}

	session, err := getBrowserRuntimeSession(taskID, targetPageURL)
	if err != nil {
		return "", err
	}

	script := buildWebpackBrowserExpression(rootModuleID, keySeed, normalizeCiphertext(ciphertext), functionPath, modules)

	session.mu.Lock()
	defer session.mu.Unlock()
	session.lastUsed = time.Now()

	var plaintext string
	if err := chromedp.Run(session.ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		result, exp, err := cdruntime.Evaluate(script).
			WithAwaitPromise(true).
			WithReturnByValue(true).
			Do(ctx)
		if err != nil {
			if exp != nil {
				return fmt.Errorf("browser runtime evaluate failed: %s", exp.Text)
			}
			return err
		}
		if result == nil {
			return fmt.Errorf("browser runtime returned nil")
		}
		if err := json.Unmarshal(result.Value, &plaintext); err != nil {
			return fmt.Errorf("browser runtime decode failed: %w", err)
		}
		return nil
	})); err != nil {
		return "", err
	}

	if strings.TrimSpace(plaintext) == "" {
		return "", fmt.Errorf("browser runtime returned empty plaintext")
	}
	return plaintext, nil
}

func getBrowserRuntimeSession(taskID, pageURL string) (*browserRuntimeSession, error) {
	if existing, ok := browserRuntimeSessions.Load(taskID); ok {
		session := existing.(*browserRuntimeSession)
		if session.pageURL == pageURL {
			return session, nil
		}
		session.cancel()
		browserRuntimeSessions.Delete(taskID)
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	tabCtx, tabCancel := chromedp.NewContext(allocCtx)

	cleanup := func() {
		tabCancel()
		allocCancel()
	}

	if err := chromedp.Run(tabCtx,
		chromedp.Navigate(pageURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(8*time.Second),
	); err != nil {
		cleanup()
		return nil, fmt.Errorf("init browser runtime page failed: %w", err)
	}

	session := &browserRuntimeSession{
		ctx:      tabCtx,
		cancel:   cleanup,
		pageURL:  pageURL,
		lastUsed: time.Now(),
	}
	browserRuntimeSessions.Store(taskID, session)
	return session, nil
}

func resolveBrowserRuntimePageURL(pageURL, requestURL string) string {
	if strings.TrimSpace(pageURL) != "" {
		return strings.TrimSpace(pageURL)
	}
	raw := strings.TrimSpace(requestURL)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	parsed.Path = "/"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func buildWebpackBrowserExpression(rootModuleID, keySeed, ciphertext, functionPath string, modules map[string]webpackModule) string {
	var builder strings.Builder
	builder.WriteString("(async function(){")
	builder.WriteString("const modules={")

	moduleIDs := make([]string, 0, len(modules))
	for id := range modules {
		moduleIDs = append(moduleIDs, id)
	}
	slices.Sort(moduleIDs)
	for _, id := range moduleIDs {
		builder.WriteString(id)
		builder.WriteString(":")
		builder.WriteString(modules[id].FunctionSource)
		builder.WriteString(",")
	}
	builder.WriteString("};")
	builder.WriteString(`const cache={};
function __webpack_require__(id){
 if(cache[id]) return cache[id].exports;
 if(!modules[id]) throw new Error("missing webpack module: "+id);
 const module={exports:{}};
 cache[id]=module;
 modules[id](module,module.exports,__webpack_require__);
 return module.exports;
}
__webpack_require__.d=function(exports,definition){
 for(const key in definition){
  if(Object.prototype.hasOwnProperty.call(definition,key) && !Object.prototype.hasOwnProperty.call(exports,key)){
   Object.defineProperty(exports,key,{enumerable:true,get:definition[key]});
  }
 }
};
__webpack_require__.o=function(obj,prop){ return Object.prototype.hasOwnProperty.call(obj,prop); };
__webpack_require__.r=function(exports){
 if(typeof Symbol!=="undefined" && Symbol.toStringTag){
  Object.defineProperty(exports,Symbol.toStringTag,{value:"Module"});
 }
 Object.defineProperty(exports,"__esModule",{value:true});
};
__webpack_require__.n=function(module){
 const getter = module && module.__esModule ? function(){ return module.default; } : function(){ return module; };
 __webpack_require__.d(getter,{a:function(){ return getter(); }});
 return getter;
};
const mod=__webpack_require__(`)
	builder.WriteString(rootModuleID)
	builder.WriteString(`);
const seed=`)
	builder.WriteString(strconvQuote(keySeed))
	builder.WriteString(`;
const ciphertext=`)
	builder.WriteString(strconvQuote(ciphertext))
	builder.WriteString(`;
const functionPath=`)
	builder.WriteString(strconvQuote(normalizeRuntimeFunctionPath(functionPath)))
	builder.WriteString(`;
const key=atob(atob(seed));
function resolveRuntimeFn(root,path){
 const candidates=[];
 if(path){ candidates.push(path); }
 candidates.push("sd","default.sd");
 for(const candidate of candidates){
  const segments=String(candidate).split(".").filter(Boolean);
  let current=root;
  let ok=true;
  for(const segment of segments){
   if(segment==="mod" || segment==="exports" || segment==="module" || segment==="module.exports"){ continue; }
   if(current==null || typeof current!=="object" && typeof current!=="function"){ ok=false; break; }
   current=current[segment];
  }
  if(ok && typeof current==="function"){ return current; }
 }
 throw new Error("decrypt function not found: " + (path || "sd"));
}
const decryptFn=resolveRuntimeFn(mod,functionPath);
const plaintext = await decryptFn(ciphertext,key);
return String(plaintext);
})()`)
	return builder.String()
}
