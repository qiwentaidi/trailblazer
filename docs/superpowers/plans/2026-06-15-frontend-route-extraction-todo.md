# 前端路由提取与守卫绕过待办

日期: 2026-06-15

## 已确认现状

- 当前前端路由提取主链路是浏览器运行时 Hook，不是静态逆向完整 Vue 路由表。
- 当前能从 `history.pushState`、`history.replaceState`、`hashchange`、`popstate`、`window` 上疑似 router/menu/nav 对象、以及数组变更中提取候选路由。
- 当前已经接入前端守卫绕过的最小可用实现：
  - patch 疑似 router 实例的 `beforeEach` / `beforeResolve`
  - 清理常见守卫集合
  - 拦截 `/login?redirect=...` 并尝试回跳原目标路由
  - patch `push` / `replace` / `addRoutes` / `addRoute`
- 当前主扫描结果只保留归一化后的前端路径字符串，未保留足够完整的守卫绕过过程证据。

## 当前问题总结

### 1. 前端路由候选误报率高

- `scanWindowForRoutes()` 扫描范围过大，只要 `window` 变量名命中 `route|router|menu|nav` 就递归分析。
- `inspectRouteCandidate()` 的路由对象判定过宽，只要带 `path`、`children`、`routes` 就可能被当成路由。
- `Array.prototype.push/unshift/splice` 的 Hook 会把大量非路由对象带入候选集。
- 最终归一化只做格式过滤，没有做“真实页面路由”的语义过滤。

### 2. 当前结果更像“候选路径集”，不是“真实可访问前端页面集”

- 结果里会混入 React 组件名、UI 属性名、方法名、样式片段、第三方库模块路径、数字模块 ID。
- 目前无法稳定区分：
  - 真正的前端页面路由
  - 路由相关配置碎片
  - 组件树或第三方库运行时对象

### 3. 守卫绕过已接入，但效果还不稳定

- 现有实现能绕过一部分基于 Vue Router 的全局前置守卫。
- 对组件内登录判断、页面初始化自定义跳转、token 判空后手动跳转等场景，效果有限。
- 目前还缺少明确的命中日志，无法快速判断：
  - 哪条跳转被改写
  - 哪个 router 实例被 patch
  - 守卫绕过后是否真的停留在目标页面

### 4. 路由结果缺少足够的上下文与证据

- 当前主结果里只有归一化后的 `path`，丢失了很多原始上下文。
- `FrontendRouteRecord` 虽然有 `SourceKind`、`Source`、`PageURL`，但资产汇总结果里没有完整保留。
- 目前缺少“该路径是自然访问得到，还是守卫绕过得到”的区分。

### 5. 当前实现还不具备文章级别的静态逆向能力

- 还没有从打包 JS 中稳定恢复完整 Vue 动态路由表。
- 还没有静态提取权限菜单到路由的映射关系。
- 还没有专门分析 `watchMenuList`、`addRoutes`、路径字典函数、`__webpack_require__` 动态组件映射的能力。

## 后续待办

- [ ] 收紧 `scanWindowForRoutes()` 的扫描范围，只优先深挖疑似真实 router 实例，降低泛扫描噪声。
- [ ] 提高 `looksLikeRouteRecord()` 的判定门槛，至少结合 `path + component/element/meta/name/children` 等多字段判断。
- [ ] 为数组变更 Hook 增加更严格的过滤条件，减少 UI 库与组件树对象进入候选集。
- [ ] 在最终 `buildFrontendRoutes()` 结果链路里增加页面语义过滤，剔除组件名、Hook 名、样式类名、方法名、数字模块 ID。
- [ ] 在 `FrontendRouteRecord` 或等价输出中增加守卫绕过相关字段，例如 `guardBypassed`、`originalBlockedURL`、`recoveredTarget`。
- [ ] 增加守卫绕过调试日志，明确记录 router patch 命中、登录重定向改写、目标页面停留结果。
- [ ] 针对 hash 路由站点输出完整访问地址，而不仅是归一化 path，例如 `http://host/app/#/login`。
- [ ] 增加“高可信前端页面路由”与“低可信候选路径”的分层输出，避免把候选集直接当页面清单使用。
- [ ] 评估并实现对组件内登录跳转、token 判空跳转、`location.hash` / `location.href` 手动改写的进一步拦截。
- [ ] 为守卫绕过后的二次页面探索增加结果标记，明确哪些运行时接口请求是在绕过后新增出现的。
- [ ] 单独设计静态 Vue 动态路由逆向模块，目标是从打包 JS / SourceMap 中恢复完整路由表，而不是只依赖运行时观察。
- [ ] 设计权限菜单驱动型站点的专用分析链，补足“菜单 API -> 路由构造器 -> 组件映射 -> 页面访问地址”的静态恢复能力。

## 结论

- 当前实现已经具备“运行时前端路由候选提取 + 初步守卫绕过”的能力。
- 当前最大的短板不是“完全抓不到路由”，而是“误报太多、证据不够、静态逆向能力缺失”。
- 后续优先级应先放在“降噪 + 证据化 + 守卫绕过可观测性”，再推进“静态逆向完整动态路由表”。

## 2026-06-16 最新结论

### 1. `history` 模式的通用补全问题，本质是“部署前缀丢失”

- 这类站点的 Vue / React 路由表里，经常只存 `/login`、`/welcome`、`/register` 这样的前端路由路径。
- 但真实访问地址可能部署在二级前缀下，例如：
  - `/web/login`
  - `/console/login`
  - `/back/login`
- 因此自动化测试阶段如果只按 `origin + route` 去补全，就会把很多真实页面误测成根路径版本，导致：
  - 页面打开为空
  - 没有可点击元素
  - 没有接口触发
- 这个问题不应按单站点写死，而应作为 `history` 模式通用规则处理。

### 2. 当前采取的通用标准

- 自动化测试阶段，对 `history` 模式路由统一做“部署前缀推断”：
  - 从入口 URL 自身提取候选前缀，例如 `/web/login` 推断 `/web`
  - 从运行时已知路径与静态路由路径的重叠关系反推前缀，例如同时观察到 `/web/login` 与 `/login`，则推断 `/web`
- 在生成测试候选地址时，同时尝试：
  - `origin + route`
  - `origin + basePrefix + route`
- 这样可以通用覆盖 `/web`、`/console`、`/back` 一类 history 部署前缀，而不是只修补某一个目标站点。

### 3. 为什么暂时没有对 `hash` 模式做同类修补

- `hash` 模式下，部署前缀天然保留在 `#` 之前，前端路由位于 fragment 中，例如：
  - `https://host/back/#/login`
- 在这种结构下：
  - 页面壳路径负责部署前缀
  - `#/...` 负责前端路由
- 两者天然分层，通常不会出现 `history` 模式那种“部署前缀丢失到 pathname 中”的问题。
- 因此本轮补丁只针对 `history` 模式的候选地址补全，不对 `hash` 模式做同等强度的前缀推断。
- 当前结论是：`hash` 模式暂未观察到同类普遍性问题，后续如果出现混合场景，再单独补强。

### 4. 自动化拦截与路由提取是两层问题

- 对 `https://xhtgfw.gongshu.gov.cn/` 这类站点，早期“抓不到路由”并不完全是提取逻辑缺陷。
- 实际诊断表明，自动化窗口在未做规避时会被站点/WAF 拦截到 `502` 异常页，业务 SPA 根本没有正常挂载。
- 已接入的基础反自动化规避包括：
  - 启动参数规避 `AutomationControlled`
  - 覆盖 `User-Agent` / `language` / `platform`
  - 在 `document-start` 注入基础 stealth，隐藏 `navigator.webdriver`，补充 `chrome/runtime`、plugins、permissions、WebGL 常见指纹
- 在规避生效后，自动化浏览器才能正常进入业务登录页，此时 Vue Router 运行时提取才恢复正常。

### 5. 自动化测试阶段的补充约束

- 带参数占位符的静态路由，例如：
  - `:id`
  - `:route*`
- 仍然会保留在路由提取结果中，但在自动化测试阶段会被默认跳过，不再进入导航与点击测试队列。
- 原因是这类路由在缺少真实参数的情况下，自动访问价值低，且容易引入噪音或误导结果。
