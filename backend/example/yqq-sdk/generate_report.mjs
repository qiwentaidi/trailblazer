import fs from "node:fs";
import path from "node:path";

const dir = path.resolve("backend/example/yqq-sdk");
const reportPath = path.join(dir, "report.html");
const summaryPath = path.join(dir, "yqq_sdk_summary.json");
const scanResultPath = path.join(dir, "yqq_sdk_scan_result.json");

function encodeJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64");
}

function preview(value, limit = 200) {
  const normalized = String(value ?? "").trim();
  if (!normalized) {
    return "";
  }
  if (normalized.length <= limit) {
    return normalized;
  }
  return `${normalized.slice(0, limit)}...`;
}

function buildConclusions(summary) {
  const decryptionSummaries = Array.isArray(summary.decryptionSummaries) ? summary.decryptionSummaries : [];
  const responseCiphertextCaptured = decryptionSummaries.filter(item => item?.hasResponseCiphertext).length;
  const responsePlaintextCaptured = decryptionSummaries.filter(item => item?.hasResponsePlaintext).length;

  return {
    requestChainDetected: decryptionSummaries.length > 0,
    responseCiphertextCaptured,
    responsePlaintextCaptured,
    coreFinding: "请求侧 AES-GCM 已识别，响应密文已绑定回 trace，但响应侧真实解密步骤仍未命中。"
  };
}

function buildDetailBundle(scanResult) {
  const target = Array.isArray(scanResult?.targets) ? scanResult.targets[0] : null;
  const apiRecords = Array.isArray(target?.apiRecords) ? target.apiRecords : [];
  const protocolTraces = Array.isArray(target?.protocolTraces) ? target.protocolTraces : [];

  return {
    target: target?.target || "",
    apiRecords: apiRecords.map(record => ({
      url: record?.url || "",
      method: record?.method || "",
      mimeType: record?.mimeType || "",
      responseCode: record?.responseCode ?? "",
      responsePreview: preview(record?.responseBody || record?.responsePreview || "", 360)
    })),
    protocolTraces: protocolTraces.map(trace => ({
      traceId: trace?.traceId || "",
      requestUrl: trace?.requestUrl || "",
      method: trace?.method || "",
      algorithms: Array.isArray(trace?.algorithms) ? trace.algorithms : [],
      requestPlaintextPreview: preview(trace?.requestBeforeTransform || trace?.requestPlaintextPreview || trace?.sessionMaterials?.latest_plaintext || "", 420),
      responseCiphertextPreview: preview(trace?.sessionMaterials?.latest_response_ciphertext || trace?.responseCiphertextPreview || "", 420),
      responsePlaintextPreview: preview(trace?.sessionMaterials?.latest_response_plaintext || trace?.responsePlaintextPreview || "", 420),
      hasResponseCiphertext: !!trace?.hasResponseCiphertext || !!String(trace?.sessionMaterials?.latest_response_ciphertext || "").trim(),
      hasResponsePlaintext: !!trace?.hasResponsePlaintext || !!String(trace?.sessionMaterials?.latest_response_plaintext || "").trim(),
      sessionMaterials: trace?.sessionMaterials || {},
      cryptoSteps: Array.isArray(trace?.cryptoSteps) ? trace.cryptoSteps.map(step => ({
        source: step?.source || "",
        algorithm: step?.algorithm || "",
        inputPreview: step?.inputPreview || "",
        outputPreview: step?.outputPreview || ""
      })) : []
    }))
  };
}

function extractMainScriptBody(html) {
  const marker = "const summary = summaryBundle.summary;";
  const start = html.indexOf(marker);
  if (start === -1) {
    throw new Error("report.html 缺少主脚本标记");
  }

  const scriptStart = html.lastIndexOf("<script>", start);
  const scriptEnd = html.indexOf("</script>", start);
  if (scriptStart === -1 || scriptEnd === -1) {
    throw new Error("report.html 缺少可替换的脚本区块");
  }

  return {
    before: html.slice(0, scriptStart),
    body: html.slice(start, scriptEnd).trim(),
    after: html.slice(scriptEnd + "</script>".length)
  };
}

const summary = JSON.parse(fs.readFileSync(summaryPath, "utf8"));
const scanResult = JSON.parse(fs.readFileSync(scanResultPath, "utf8"));
const currentReport = fs.readFileSync(reportPath, "utf8");
const { before, body, after } = extractMainScriptBody(currentReport);

const summaryBundle = {
  summary,
  conclusions: buildConclusions(summary)
};
const detailBundle = buildDetailBundle(scanResult);

const rebuilt = `${before}  <script id="summaryData" type="text/plain">${encodeJson(summaryBundle)}</script>
  <script id="detailData" type="text/plain">${encodeJson(detailBundle)}</script>
  <script>
    function decodeBase64Json(value) {
      return JSON.parse(atob(value));
    }

    const summaryBundle = decodeBase64Json(document.getElementById("summaryData").textContent.trim());
    const detailBundle = decodeBase64Json(document.getElementById("detailData").textContent.trim());

    ${body}
  </script>${after}`;

fs.writeFileSync(reportPath, rebuilt, "utf8");
console.log(`rewrote ${reportPath}`);
