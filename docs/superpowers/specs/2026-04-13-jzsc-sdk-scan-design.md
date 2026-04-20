# JZSC SDK 扫描设计

**目标**

按 `backend/example/yqq-sdk/` 的模式，为 `https://jzsc.mohurd.gov.cn/` 产出一套可复跑的 SDK 示例，包括运行入口、扫描结果 JSON、摘要 JSON 与单文件 HTML 报告。

**范围**

- 新增 `backend/example/jzsc-sdk/` 目录。
- 运行入口沿用 `lib.PerformScan`，默认只扫描 `https://jzsc.mohurd.gov.cn/`。
- 输出文件命名对齐 `yqq-sdk`：
  - `/tmp/jzsc_sdk_scan_result.json`
  - `/tmp/jzsc_sdk_summary.json`
  - 仓库内保留 `jzsc_sdk_scan_result.json`
  - 仓库内保留 `jzsc_sdk_summary.json`
  - 仓库内保留 `report.html`
- 漏洞主动探测开关先沿用 `yqq-sdk` 示例策略，默认关闭 SQLi、LFI、SSRF、Redirect、XSS、Upload，重点观察资产、接口记录、协议轨迹与风险输出。

**实现方式**

- 复制并调整 `yqq_sdk_run.go` 的摘要构建逻辑，使其适配住建部站点。
- HTML 报告继续采用单文件静态页面，内嵌本次运行得到的摘要与明细数据。
- 报告内容聚焦：
  - 扫描时间、目标数、站点树节点数、接口记录数、协议轨迹数
  - 风险与漏洞数量
  - 关键接口记录
  - 协议轨迹证据与是否存在解密链路
  - 对站点行为的结论性说明

**验证**

- `go test` 至少覆盖新示例中的可复用辅助逻辑。
- `node backend/example/jzsc-sdk/report_script_test.mjs` 验证报告脚本中关键辅助函数存在且行为符合预期。
- `go run backend/example/jzsc-sdk/jzsc_sdk_run.go` 产出 `/tmp` 文件。
- 将 `/tmp` 产物同步到 `backend/example/jzsc-sdk/`，确保仓库内存在结果文件与报告文件。
