# JZSC SDK Scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 `https://jzsc.mohurd.gov.cn/` 新增一套与 `yqq-sdk` 对齐的 SDK 扫描示例，并生成 JSON 与 HTML 报告产物。

**Architecture:** 复用 `trailblazer/pkg/lib` 的 SDK 扫描入口，在 `backend/example/jzsc-sdk/` 中提供独立运行程序。扫描后将结果压缩为摘要 JSON，再把摘要和精选明细内嵌进单文件 HTML 报告，形成可直接交付的证据包。

**Tech Stack:** Go 1.24、Trailblazer SDK、Node.js 内置 `assert/fs/vm`

---

### Task 1: 建立示例目录与测试骨架

**Files:**
- Create: `backend/example/jzsc-sdk/jzsc_sdk_run.go`
- Create: `backend/example/jzsc-sdk/jzsc_sdk_run_test.go`
- Create: `backend/example/jzsc-sdk/report_script_test.mjs`

- [ ] **Step 1: 写一个失败的 Go 测试，验证新示例能归纳站点结论**

```go
func TestBuildConclusionsMarksNoDecryptPath(t *testing.T) {
	summary := map[string]interface{}{
		"decryptionSummaries": []map[string]interface{}{
			{
				"hasResponseCiphertext":  false,
				"hasResponsePlaintext":   false,
				"hasResponseDecryptStep": false,
			},
		},
	}

	conclusions := buildConclusions(summary)
	if conclusions["coreFinding"] == "" {
		t.Fatalf("expected core finding to be populated")
	}
}
```

- [ ] **Step 2: 运行测试，确认它因缺少实现而失败**

Run: `go test ./example/jzsc-sdk -run TestBuildConclusionsMarksNoDecryptPath -v`
Expected: FAIL，提示 `undefined: buildConclusions`

- [ ] **Step 3: 写最小实现与 Node 报告测试**

```go
func buildConclusions(summary map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"coreFinding": "站点以常规页面与接口暴露为主，当前扫描未命中可执行的响应解密链路",
	}
}
```

```js
assert.ok(match, "report.html must define collapseCryptoSteps");
```

- [ ] **Step 4: 再次运行测试，确认通过**

Run: `go test ./example/jzsc-sdk -run TestBuildConclusionsMarksNoDecryptPath -v`
Expected: PASS

### Task 2: 实现 JZSC 扫描入口

**Files:**
- Modify: `backend/example/jzsc-sdk/jzsc_sdk_run.go`
- Test: `backend/example/jzsc-sdk/jzsc_sdk_run_test.go`

- [ ] **Step 1: 写失败测试，验证摘要统计会输出目标与轨迹计数**

```go
func TestBuildSummaryCountsTargetsAndTraces(t *testing.T) {
	result := lib.ScanResult{
		Summary: lib.Summary{
			TotalTargets:   1,
			TotalTreeNodes: 3,
		},
		Targets: []lib.TargetResult{
			{
				Target:         "https://jzsc.mohurd.gov.cn/",
				APIRecords:     []lib.APIRecord{{URL: "https://jzsc.mohurd.gov.cn/api"}},
				ProtocolTraces: []lib.ProtocolTrace{{TraceID: "trace-1"}},
			},
		},
	}

	summary := buildRunSummary(result)
	if summary["targets"] != 1 {
		t.Fatalf("expected targets=1, got %#v", summary["targets"])
	}
}
```

- [ ] **Step 2: 运行测试，确认失败**

Run: `go test ./example/jzsc-sdk -run TestBuildSummaryCountsTargetsAndTraces -v`
Expected: FAIL，提示 `undefined: buildRunSummary`

- [ ] **Step 3: 实现最小扫描摘要逻辑**

```go
func buildRunSummary(result lib.ScanResult) map[string]interface{} {
	return map[string]interface{}{
		"targets":   result.Summary.TotalTargets,
		"treeNodes": result.Summary.TotalTreeNodes,
	}
}
```

- [ ] **Step 4: 运行测试，确认通过**

Run: `go test ./example/jzsc-sdk -run TestBuildSummaryCountsTargetsAndTraces -v`
Expected: PASS

### Task 3: 生成 HTML 报告并执行扫描

**Files:**
- Create: `backend/example/jzsc-sdk/report.html`
- Create: `backend/example/jzsc-sdk/jzsc_sdk_summary.json`
- Create: `backend/example/jzsc-sdk/jzsc_sdk_scan_result.json`

- [ ] **Step 1: 编写报告模板与脚本测试**

```js
const collapsed = collapseCryptoSteps([
  { source: "JSON.stringify", algorithm: "json.stringify" },
  { source: "JSON.stringify", algorithm: "json.stringify" }
]);

assert.equal(collapsed[0].repeatCount, 2);
```

- [ ] **Step 2: 运行 Node 测试，确认报告脚本可用**

Run: `node backend/example/jzsc-sdk/report_script_test.mjs`
Expected: exit 0

- [ ] **Step 3: 执行 SDK 扫描并生成 `/tmp` 产物**

Run: `go run backend/example/jzsc-sdk/jzsc_sdk_run.go`
Expected: exit 0，生成 `/tmp/jzsc_sdk_scan_result.json` 与 `/tmp/jzsc_sdk_summary.json`

- [ ] **Step 4: 将运行产物同步到示例目录并生成最终 `report.html`**

Run: `cp /tmp/jzsc_sdk_scan_result.json backend/example/jzsc-sdk/jzsc_sdk_scan_result.json`
Expected: 文件存在

Run: `cp /tmp/jzsc_sdk_summary.json backend/example/jzsc-sdk/jzsc_sdk_summary.json`
Expected: 文件存在
