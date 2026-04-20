package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"trailblazer/pkg/lib"
)

const (
	targetURL      = "https://jzsc.mohurd.gov.cn/"
	scanOutputPath = "/tmp/jzsc_sdk_scan_result.json"
	summaryPath    = "/tmp/jzsc_sdk_summary.json"
	reportPath     = "/tmp/jzsc_sdk_report.html"
)

func preview(value string, limit int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func materialHexFromRaw(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	return hex.EncodeToString([]byte(raw))
}

func materialHexFromBase64(encoded string) string {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return ""
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(data)
}

func buildMaterialSummary(trace lib.ProtocolTrace) map[string]interface{} {
	materials := trace.SessionMaterials
	keyBase64 := firstNonEmpty(materials["crypto_key_base64"], materials["aes_key_base64"], materials["sm4_key_base64"])
	keyRaw := firstNonEmpty(materials["crypto_key_raw"], materials["aes_key_raw"], materials["sm4_key_raw"])
	keyHex := firstNonEmpty(materials["crypto_key_hex"], materials["aes_key_hex"], materials["sm4_key_hex"], materialHexFromBase64(keyBase64), materialHexFromRaw(keyRaw))
	ivBase64 := firstNonEmpty(materials["crypto_iv_base64"], materials["aes_iv_base64"], materials["sm4_iv_base64"])
	ivRaw := firstNonEmpty(materials["crypto_iv_raw"], materials["aes_iv_raw"], materials["sm4_iv_raw"])
	ivHex := firstNonEmpty(materials["crypto_iv_hex"], materials["aes_iv_hex"], materials["sm4_iv_hex"], materialHexFromBase64(ivBase64), materialHexFromRaw(ivRaw))
	aadBase64 := firstNonEmpty(materials["crypto_aad_base64"], materials["aes_aad_base64"])
	aadHex := firstNonEmpty(materials["crypto_aad_hex"], materials["aes_aad_hex"], materialHexFromBase64(aadBase64))

	summary := map[string]interface{}{
		"hasKeyMaterial": keyBase64 != "" || keyRaw != "" || keyHex != "",
		"hasIVMaterial":  ivBase64 != "" || ivRaw != "" || ivHex != "",
	}

	if keyBase64 != "" {
		summary["keyBase64"] = keyBase64
	}
	if keyRaw != "" {
		summary["keyRawPreview"] = preview(keyRaw, 80)
	}
	if keyHex != "" {
		summary["keyHex"] = keyHex
	}
	if ivBase64 != "" {
		summary["ivBase64"] = ivBase64
	}
	if ivRaw != "" {
		summary["ivRawPreview"] = preview(ivRaw, 80)
	}
	if ivHex != "" {
		summary["ivHex"] = ivHex
	}
	if aadBase64 != "" {
		summary["aadBase64"] = aadBase64
	}
	if aadHex != "" {
		summary["aadHex"] = aadHex
	}

	return summary
}

func buildTraceSummary(trace lib.ProtocolTrace) map[string]interface{} {
	ciphertext := strings.TrimSpace(trace.SessionMaterials["latest_response_ciphertext"])
	evidence := lib.AnalyzeProtocolTrace(trace)
	entry := map[string]interface{}{
		"traceId":                trace.TraceID,
		"requestURL":             trace.RequestURL,
		"method":                 trace.Method,
		"algorithms":             trace.Algorithms,
		"evidenceStatus":         evidence.Status,
		"evidenceSummary":        evidence.Summary,
		"variantSuggestions":     evidence.VariantSuggestions,
		"hasResponseDecryptStep": evidence.HasResponseDecryptStep,
		"hasResponseDecodeStep":  evidence.HasResponseDecodeStep,
		"hasResponseCiphertext":  ciphertext != "",
		"hasResponsePlaintext":   strings.TrimSpace(trace.SessionMaterials["latest_response_plaintext"]) != "",
		"capturedPlaintextPreview": preview(
			trace.SessionMaterials["latest_response_plaintext"],
			160,
		),
		"materialSummary": buildMaterialSummary(trace),
	}

	if ciphertext == "" {
		entry["decryptStatus"] = "skipped"
		entry["decryptError"] = "no response ciphertext captured"
		return entry
	}

	decryptResult, decryptErr := lib.DecryptProtocolTrace(trace, "", ciphertext)
	if decryptErr != nil {
		entry["decryptStatus"] = "error"
		entry["decryptError"] = decryptErr.Error()
		return entry
	}

	entry["decryptStatus"] = "ok"
	entry["decryptPreview"] = preview(decryptResult.Plaintext, 160)
	return entry
}

func buildRunSummary(result *lib.ScanResult) map[string]interface{} {
	summary := map[string]interface{}{
		"scanTime":            result.ScanTime,
		"targets":             result.Summary.TotalTargets,
		"treeNodes":           result.Summary.TotalTreeNodes,
		"vulnerabilities":     result.Summary.TotalVulnerabilities,
		"risks":               result.Summary.TotalRisks,
		"targetSummaries":     []map[string]interface{}{},
		"decryptionSummaries": []map[string]interface{}{},
	}

	for _, target := range result.Targets {
		targetSummary := map[string]interface{}{
			"target":         target.Target,
			"apiRecords":     len(target.APIRecords),
			"protocolTraces": len(target.ProtocolTraces),
			"apiRoutes":      len(target.Assets.APIRoutes),
			"apiRoots":       len(target.Assets.APIRoots),
		}
		summary["targetSummaries"] = append(summary["targetSummaries"].([]map[string]interface{}), targetSummary)

		for i, trace := range target.ProtocolTraces {
			if i >= 8 {
				break
			}
			summary["decryptionSummaries"] = append(summary["decryptionSummaries"].([]map[string]interface{}), buildTraceSummary(trace))
		}
	}

	return summary
}

func asBool(value interface{}) bool {
	typed, ok := value.(bool)
	return ok && typed
}

func buildConclusions(summary map[string]interface{}) map[string]interface{} {
	requestChainDetected := false
	responseCiphertextCaptured := 0
	responsePlaintextCaptured := 0
	responseDecryptStepCaptured := 0

	if entries, ok := summary["decryptionSummaries"].([]map[string]interface{}); ok {
		for _, entry := range entries {
			if len(entry) > 0 {
				requestChainDetected = true
			}
			if asBool(entry["hasResponseCiphertext"]) {
				responseCiphertextCaptured++
			}
			if asBool(entry["hasResponsePlaintext"]) {
				responsePlaintextCaptured++
			}
			if asBool(entry["hasResponseDecryptStep"]) {
				responseDecryptStepCaptured++
			}
		}
	}

	coreFinding := "站点以常规页面与接口暴露为主，当前扫描未命中可执行的响应解密链路"
	if !requestChainDetected {
		coreFinding = "本次扫描未观测到明确的协议解密轨迹，输出以页面结构、接口记录和风险结果为主"
	} else if responsePlaintextCaptured > 0 {
		coreFinding = "已在协议轨迹中捕获响应明文，说明站点至少部分接口未形成额外的响应解密障碍"
	} else if responseCiphertextCaptured > 0 && responseDecryptStepCaptured == 0 {
		coreFinding = "已捕获响应密文或二进制响应，但当前轨迹未命中可直接复算的响应解密步骤"
	}

	return map[string]interface{}{
		"requestChainDetected":        requestChainDetected,
		"responseCiphertextCaptured":  responseCiphertextCaptured,
		"responsePlaintextCaptured":   responsePlaintextCaptured,
		"responseDecryptStepCaptured": responseDecryptStepCaptured,
		"coreFinding":                 coreFinding,
	}
}

func buildDetailBundle(result *lib.ScanResult) map[string]interface{} {
	if len(result.Targets) == 0 {
		return map[string]interface{}{
			"target":         targetURL,
			"apiRecords":     []map[string]interface{}{},
			"protocolTraces": []map[string]interface{}{},
		}
	}

	target := result.Targets[0]
	apiRecords := make([]map[string]interface{}, 0, min(len(target.APIRecords), 12))
	for i, record := range target.APIRecords {
		if i >= 12 {
			break
		}
		apiRecords = append(apiRecords, map[string]interface{}{
			"url":             record.URL,
			"method":          record.Method,
			"mimeType":        record.MIMEType,
			"responseCode":    record.ResponseCode,
			"responsePreview": preview(record.ResponseBody, 320),
		})
	}

	protocolTraces := make([]map[string]interface{}, 0, min(len(target.ProtocolTraces), 8))
	for i, trace := range target.ProtocolTraces {
		if i >= 8 {
			break
		}

		sessionMaterials := map[string]string{}
		for _, key := range []string{
			"latest_request_plaintext",
			"latest_request_ciphertext",
			"latest_response_plaintext",
			"latest_response_ciphertext",
			"crypto_key_hex",
			"aes_key_hex",
			"sm4_key_hex",
			"crypto_iv_hex",
			"aes_iv_hex",
			"sm4_iv_hex",
		} {
			if value := strings.TrimSpace(trace.SessionMaterials[key]); value != "" {
				sessionMaterials[key] = preview(value, 320)
			}
		}

		protocolTraces = append(protocolTraces, map[string]interface{}{
			"traceId":               trace.TraceID,
			"requestUrl":            trace.RequestURL,
			"method":                trace.Method,
			"algorithms":            trace.Algorithms,
			"hasResponseCiphertext": strings.TrimSpace(trace.SessionMaterials["latest_response_ciphertext"]) != "",
			"hasResponsePlaintext":  strings.TrimSpace(trace.SessionMaterials["latest_response_plaintext"]) != "",
			"cryptoSteps":           append(append([]lib.ProtocolCryptoStep{}, trace.RequestSteps...), trace.ResponseSteps...),
			"sessionMaterials":      sessionMaterials,
		})
	}

	return map[string]interface{}{
		"target":         target.Target,
		"apiRecords":     apiRecords,
		"protocolTraces": protocolTraces,
	}
}

func mustJSON(value interface{}) string {
	data, err := json.Marshal(value)
	if err != nil {
		log.Fatalf("marshal report bundle failed: %v", err)
	}
	return string(data)
}

func buildReportHTML(summaryBundle, detailBundle map[string]interface{}) string {
	return fmt.Sprintf(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>JZSC SDK 扫描报告</title>
  <style>
    :root {
      --bg: #f3f5f7;
      --panel: #ffffff;
      --line: rgba(15, 23, 42, 0.10);
      --text: #10233f;
      --muted: #5f7088;
      --accent: #0e7490;
      --accent-soft: rgba(14, 116, 144, 0.10);
      --warn: #b45309;
      --warn-soft: rgba(180, 83, 9, 0.12);
      --danger: #b42318;
      --danger-soft: rgba(180, 35, 24, 0.10);
      --shadow: 0 18px 48px rgba(15, 23, 42, 0.08);
      --radius: 20px;
      --mono: "SFMono-Regular", "JetBrains Mono", "Menlo", monospace;
      --sans: "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: var(--sans);
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(14,116,144,0.18), transparent 30%%),
        linear-gradient(180deg, #f8fbfd 0%%, var(--bg) 100%%);
    }
    .wrap { width: min(1180px, calc(100%% - 32px)); margin: 28px auto 48px; }
    .hero, .section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
    }
    .hero { padding: 28px; }
    .section { margin-top: 20px; padding: 22px; }
    .eyebrow {
      display: inline-flex;
      padding: 6px 11px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    h1 { margin: 16px 0 10px; font-size: clamp(28px, 5vw, 44px); line-height: 1.05; letter-spacing: -0.03em; }
    h2 { margin: 0 0 16px; font-size: 20px; }
    p { margin: 0; }
    .lead { max-width: 760px; color: var(--muted); line-height: 1.75; }
    .stats, .flags, .trace-grid { display: grid; gap: 14px; }
    .stats { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); margin-top: 22px; }
    .flags { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); margin-top: 18px; }
    .stat, .flag, .trace-card, .meta-block {
      border: 1px solid var(--line);
      border-radius: 16px;
      background: #fff;
    }
    .stat, .flag, .trace-card { padding: 16px; }
    .stat strong { display: block; font-size: 28px; line-height: 1; margin-bottom: 8px; }
    .stat span, .flag p, .footnote { color: var(--muted); font-size: 13px; line-height: 1.65; }
    .flag b { display: block; margin-bottom: 6px; font-size: 14px; }
    .callout {
      padding: 18px;
      border-radius: 16px;
      background: linear-gradient(135deg, rgba(14,116,144,0.08), rgba(255,255,255,0.9));
      border: 1px solid rgba(14,116,144,0.16);
      line-height: 1.75;
    }
    .trace-top {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: flex-start;
      flex-wrap: wrap;
      margin-bottom: 10px;
    }
    .trace-url { font-size: 14px; line-height: 1.6; word-break: break-all; }
    .chips { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0 14px; }
    .chip {
      display: inline-flex;
      align-items: center;
      padding: 6px 10px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: #fff;
      font-size: 12px;
      font-weight: 600;
    }
    .chip.good { color: var(--accent); background: var(--accent-soft); }
    .chip.warn { color: var(--warn); background: var(--warn-soft); }
    .chip.bad { color: var(--danger); background: var(--danger-soft); }
    .trace-meta {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 10px;
    }
    .meta-block { padding: 12px 14px; background: rgba(15, 23, 42, 0.02); }
    .meta-block h3 {
      margin: 0 0 8px;
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    .meta-block p, .meta-block pre { margin: 0; font-size: 13px; line-height: 1.65; white-space: pre-wrap; word-break: break-word; }
    .meta-block pre, .raw pre { font-family: var(--mono); }
    table { width: 100%%; border-collapse: collapse; font-size: 13px; }
    th, td {
      text-align: left;
      padding: 12px 10px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
      line-height: 1.65;
      word-break: break-word;
    }
    th {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    details {
      border: 1px solid var(--line);
      border-radius: 16px;
      background: #fff;
      overflow: hidden;
    }
    details + details { margin-top: 12px; }
    summary { cursor: pointer; padding: 14px 16px; font-weight: 700; list-style: none; }
    summary::-webkit-details-marker { display: none; }
    .raw { padding: 0 16px 16px; }
    .raw pre {
      margin: 0;
      padding: 14px;
      border-radius: 14px;
      background: #0f172a;
      color: #dbe7ff;
      font-size: 12px;
      line-height: 1.7;
      overflow: auto;
    }
    .footnote { margin-top: 18px; }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div class="eyebrow">SDK Report · MOHURD</div>
      <h1>全国建筑市场监管公共服务平台测试报告</h1>
      <p class="lead" id="heroLead"></p>
      <div class="stats" id="stats"></div>
    </section>

    <section class="section">
      <h2>核心结论</h2>
      <div class="callout" id="callout"></div>
      <div class="flags" id="flags"></div>
    </section>

    <section class="section">
      <h2>协议轨迹</h2>
      <div class="trace-grid" id="traceGrid"></div>
    </section>

    <section class="section">
      <h2>接口记录</h2>
      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>URL</th>
            <th>MIME</th>
            <th>Status</th>
            <th>响应预览</th>
          </tr>
        </thead>
        <tbody id="apiTable"></tbody>
      </table>
    </section>

    <section class="section">
      <h2>原始证据</h2>
      <details>
        <summary>查看 summary.json</summary>
        <div class="raw"><pre id="rawSummary"></pre></div>
      </details>
      <details>
        <summary>查看精简后的 trace / api 数据</summary>
        <div class="raw"><pre id="rawDetail"></pre></div>
      </details>
      <p class="footnote">
        这份报告是单文件静态 HTML，直接基于当前 SDK 输出生成，便于归档和复查。
      </p>
    </section>
  </div>

  <script>
    const summaryBundle = %s;
    const detailBundle = %s;

    const summary = summaryBundle.summary || {};
    const conclusions = summaryBundle.conclusions || {};
    const detail = detailBundle || {};

    function escapeHtml(value) {
      return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    }

    function chip(label, kind) {
      return "<span class=\"chip " + (kind || "") + "\">" + escapeHtml(label) + "</span>";
    }

    function collapseCryptoSteps(steps) {
      if (!Array.isArray(steps) || steps.length === 0) {
        return [];
      }

      const collapsed = [];
      for (const step of steps) {
        const previous = collapsed[collapsed.length - 1];
        if (
          previous &&
          previous.source === step.source &&
          previous.algorithm === step.algorithm &&
          previous.inputPreview === step.inputPreview &&
          previous.outputPreview === step.outputPreview
        ) {
          previous.repeatCount += 1;
          continue;
        }

        collapsed.push({
          source: step.source,
          algorithm: step.algorithm,
          inputPreview: step.inputPreview,
          outputPreview: step.outputPreview,
          repeatCount: 1
        });
      }
      return collapsed;
    }

    function formatMaterialSummary(materialSummary) {
      if (!materialSummary || typeof materialSummary !== "object") {
        return "-";
      }

      const lines = [];
      if (materialSummary.hasKeyMaterial != null) {
        lines.push("key material: " + (materialSummary.hasKeyMaterial ? "yes" : "no"));
      }
      if (materialSummary.keyBase64) {
        lines.push("key(base64): " + materialSummary.keyBase64);
      }
      if (materialSummary.keyHex) {
        lines.push("key(hex): " + materialSummary.keyHex);
      }
      if (materialSummary.keyRawPreview) {
        lines.push("key(raw): " + materialSummary.keyRawPreview);
      }
      if (materialSummary.hasIVMaterial != null) {
        lines.push("iv material: " + (materialSummary.hasIVMaterial ? "yes" : "no"));
      }
      if (materialSummary.ivBase64) {
        lines.push("iv(base64): " + materialSummary.ivBase64);
      }
      if (materialSummary.ivHex) {
        lines.push("iv(hex): " + materialSummary.ivHex);
      }
      if (materialSummary.ivRawPreview) {
        lines.push("iv(raw): " + materialSummary.ivRawPreview);
      }
      if (materialSummary.aadBase64) {
        lines.push("aad(base64): " + materialSummary.aadBase64);
      }
      if (materialSummary.aadHex) {
        lines.push("aad(hex): " + materialSummary.aadHex);
      }

      return lines.length > 0 ? lines.join("\n") : "-";
    }

    const stats = [
      { value: summary.scanTime || "-", label: "扫描时间" },
      { value: summary.targets || 0, label: "目标数" },
      { value: summary.treeNodes || 0, label: "站点树节点" },
      { value: summary.targetSummaries?.[0]?.apiRecords ?? 0, label: "API 记录" },
      { value: summary.targetSummaries?.[0]?.protocolTraces ?? 0, label: "协议轨迹" },
      { value: conclusions.responseCiphertextCaptured || 0, label: "响应密文命中" }
    ];

    document.getElementById("heroLead").textContent =
      "目标站点: " + (detail.target || "-") + "。本报告沿用 yqq-sdk 的输出结构，展示本次扫描采集到的接口、风险、协议轨迹和解密证据。";
    document.getElementById("stats").innerHTML = stats
      .map(item => "<div class=\"stat\"><strong>" + escapeHtml(item.value) + "</strong><span>" + escapeHtml(item.label) + "</span></div>")
      .join("");

    document.getElementById("callout").textContent = conclusions.coreFinding || "暂无结论";

    document.getElementById("flags").innerHTML = [
      { title: "风险数量", body: "扫描输出中的风险条目数: " + (summary.risks || 0) },
      { title: "漏洞数量", body: "主动探测关闭后的漏洞条目数: " + (summary.vulnerabilities || 0) },
      { title: "响应明文命中", body: "协议轨迹中直接捕获的响应明文数量: " + (conclusions.responsePlaintextCaptured || 0) },
      { title: "解密步骤命中", body: "协议轨迹中识别出的响应解密步骤数量: " + (conclusions.responseDecryptStepCaptured || 0) }
    ]
      .map(item => "<div class=\"flag\"><b>" + escapeHtml(item.title) + "</b><p>" + escapeHtml(item.body) + "</p></div>")
      .join("");

    document.getElementById("traceGrid").innerHTML = (summary.decryptionSummaries || [])
      .map(item => {
        const kind =
          item.decryptStatus === "ok" ? "good" :
          item.hasResponseCiphertext ? "warn" : "bad";
        const label =
          item.decryptStatus === "ok" ? "可读明文" :
          item.hasResponseCiphertext ? "仅捕获密文/异常" : "未见响应密文";
        const trace = (detail.protocolTraces || []).find(candidate => candidate.traceId === item.traceId) || {};
        const cryptoSteps = collapseCryptoSteps(trace.cryptoSteps || []).map(step =>
          chip((step.algorithm || step.source || "unknown") + (step.repeatCount > 1 ? " ×" + step.repeatCount : ""), "warn")
        ).join("");

        return "<article class=\"trace-card\">" +
          "<div class=\"trace-top\"><div class=\"trace-url\">" + escapeHtml(item.requestURL || "-") + "</div>" +
          "<div>" + chip(item.method || "?", "") + " " + chip(label, kind) + "</div></div>" +
          "<div class=\"chips\">" + (item.algorithms || []).map(algorithm => chip(algorithm, "")).join("") + "</div>" +
          (cryptoSteps ? "<div class=\"chips\">" + cryptoSteps + "</div>" : "") +
          "<div class=\"trace-meta\">" +
            "<div class=\"meta-block\"><h3>证据结论</h3><p>" + escapeHtml(item.evidenceSummary || "-") + "</p></div>" +
            "<div class=\"meta-block\"><h3>解密结果</h3><p>" + escapeHtml(item.decryptPreview || item.decryptError || "-") + "</p></div>" +
            "<div class=\"meta-block\"><h3>材料摘要</h3><pre>" + escapeHtml(formatMaterialSummary(item.materialSummary)) + "</pre></div>" +
          "</div>" +
        "</article>";
      })
      .join("");

    document.getElementById("apiTable").innerHTML = (detail.apiRecords || [])
      .map(item => "<tr>" +
        "<td>" + escapeHtml(item.method || "-") + "</td>" +
        "<td>" + escapeHtml(item.url || "-") + "</td>" +
        "<td>" + escapeHtml(item.mimeType || "-") + "</td>" +
        "<td>" + escapeHtml(item.responseCode ?? "-") + "</td>" +
        "<td>" + escapeHtml(item.responsePreview || "-") + "</td>" +
      "</tr>")
      .join("");

    document.getElementById("rawSummary").textContent = JSON.stringify(summaryBundle, null, 2);
    document.getElementById("rawDetail").textContent = JSON.stringify(detailBundle, null, 2);
  </script>
</body>
</html>`, mustJSON(summaryBundle), mustJSON(detailBundle))
}

func writeJSON(path string, value interface{}) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		log.Fatalf("marshal json failed for %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Fatalf("write file failed for %s: %v", path, err)
	}
}

func main() {
	options := lib.NewScanOptions()
	options.OutputPath = scanOutputPath
	options.VulnDetection.SQLInjection.Enabled = false
	options.VulnDetection.LFI.Enabled = false
	options.VulnDetection.SSRF.Enabled = false
	options.VulnDetection.Redirect.Enabled = false
	options.VulnDetection.XSS.Enabled = false
	options.VulnDetection.Upload.Enabled = false

	result, err := lib.PerformScan([]string{targetURL}, options)
	if err != nil {
		log.Fatalf("sdk scan failed: %v", err)
	}

	summary := buildRunSummary(result)
	summaryBundle := map[string]interface{}{
		"summary":     summary,
		"conclusions": buildConclusions(summary),
	}
	detailBundle := buildDetailBundle(result)

	writeJSON(summaryPath, summary)

	reportHTML := buildReportHTML(summaryBundle, detailBundle)
	if err := os.WriteFile(reportPath, []byte(reportHTML), 0644); err != nil {
		log.Fatalf("write report failed: %v", err)
	}

	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		log.Fatalf("marshal summary failed: %v", err)
	}

	fmt.Println(string(data))
}
