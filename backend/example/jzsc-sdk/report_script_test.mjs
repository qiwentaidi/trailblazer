import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const html = fs.readFileSync(new URL("./report.html", import.meta.url), "utf8");
const match = html.match(/function collapseCryptoSteps\(steps\) \{[\s\S]*?\n    \}/);

assert.ok(match, "report.html must define collapseCryptoSteps");

const context = {};
vm.createContext(context);
vm.runInContext(`${match[0]}; this.collapseCryptoSteps = collapseCryptoSteps;`, context);

const collapseCryptoSteps = context.collapseCryptoSteps;

const collapsed = collapseCryptoSteps([
  { source: "JSON.stringify", algorithm: "json.stringify", inputPreview: "[]", outputPreview: "[]" },
  { source: "JSON.stringify", algorithm: "json.stringify", inputPreview: "[]", outputPreview: "[]" },
  { source: "TextEncoder.encode", algorithm: "text.encode", inputPreview: "{\"a\":1}", outputPreview: "[97]" }
]);

assert.equal(collapsed.length, 2, "adjacent duplicate steps should collapse");
assert.equal(collapsed[0].repeatCount, 2, "first duplicate group should have repeatCount=2");
assert.equal(collapsed[1].repeatCount, 1, "unique step should keep repeatCount=1");
