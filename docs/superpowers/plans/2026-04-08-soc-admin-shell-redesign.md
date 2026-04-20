# SOC Admin Shell Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the frontend shell and global visual system so the authenticated product reads as a dark SOC console instead of a default Element Plus admin.

**Architecture:** Keep business pages functionally intact and push the redesign through the shared shell layer: global theme tokens, shell layout, navigation, and Element Plus overrides. Use one optional theme stylesheet to centralize SOC tokens and apply only light page-level touch-ups needed for the shell to fit cleanly.

**Tech Stack:** Vue 3, Vite, TypeScript, Element Plus, Tailwind utility classes, global CSS

---

## File Map

### Shell and theme

- Modify: `frontend/src/main.ts`
  - Wire in the new SOC theme stylesheet after the base stylesheet and before mounting the app.
- Modify: `frontend/src/style.css`
  - Replace the current minimal defaults with app-wide layout, background, typography, scrollbar, and content-canvas rules.
- Create: `frontend/src/styles/theme-soc.css`
  - Centralize CSS variables and Element Plus overrides for colors, borders, cards, tables, forms, tabs, dialogs, drawers, buttons, tags, and pagination.
- Modify: `frontend/src/App.vue`
  - Rebuild the authenticated shell structure into a dark command-center layout with top control bar, shell chrome, and consistent content canvas.
- Modify: `frontend/src/components/Sidebar.vue`
  - Rework navigation visuals to match the new shell, including active state, collapse behavior, and lower-noise menu styling.

### Light page-level fit checks

- Modify: `frontend/src/views/Dashboard.vue`
  - Only if needed to fit the new shell spacing or inherit new section wrappers cleanly.
- Modify: `frontend/src/views/Task.vue`
  - Only if needed to inherit shell-level page padding or wrapper classes.
- Modify: `frontend/src/views/Search.vue`
  - Only if needed to align with the new shell page header / form spacing.
- Modify: `frontend/src/views/Settings.vue`
  - Only if needed to align with the new shell page header / form spacing.

### Verification

- Verify: `frontend/package.json`
  - Use the existing `npm run build` as the required regression gate.

---

### Task 1: Add Failing Shell Theme Import Check

**Files:**
- Modify: `frontend/src/main.ts`
- Test/Verify: `frontend`

- [ ] **Step 1: Record the current shell import baseline**

Inspect the current import order in `frontend/src/main.ts` and confirm it only pulls:

```ts
import './style.css'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
```

This is the baseline proving there is no dedicated SOC theme layer yet.

- [ ] **Step 2: Run the frontend build before any shell changes**

Run: `npm run build`
Expected: PASS. This is the pre-change baseline checkpoint for the shell redesign.

- [ ] **Step 3: Add the new theme import target**

Update `frontend/src/main.ts` so the style imports become:

```ts
import './style.css'
import 'element-plus/dist/index.css'
import './styles/theme-soc.css'
```

Keep `ElementPlus` registration behavior unchanged.

- [ ] **Step 4: Run the frontend build to verify the missing file fails**

Run: `npm run build`
Expected: FAIL with a Vite module resolution error for `./styles/theme-soc.css`.

- [ ] **Step 5: Commit after the failure is observed**

```bash
git add frontend/src/main.ts
git commit -m "test: wire missing soc theme import"
```

### Task 2: Build Global SOC Tokens and Element Overrides

**Files:**
- Create: `frontend/src/styles/theme-soc.css`
- Modify: `frontend/src/style.css`
- Verify: `frontend`

- [ ] **Step 1: Write the new theme file with shell tokens**

Create `frontend/src/styles/theme-soc.css` with the initial token structure:

```css
:root {
  --soc-bg: #071018;
  --soc-bg-elevated: #0b1620;
  --soc-bg-panel: #0d1a24;
  --soc-bg-panel-2: #101f2a;
  --soc-border: #183446;
  --soc-border-strong: #24536b;
  --soc-text: #e4f3fb;
  --soc-text-muted: #8ea9b8;
  --soc-text-soft: #6f8896;
  --soc-accent: #35c2f4;
  --soc-accent-strong: #58d5ff;
  --soc-success: #27c39f;
  --soc-warning: #d9a441;
  --soc-danger: #d15b6a;
  --soc-radius-sm: 10px;
  --soc-radius-md: 14px;
  --soc-radius-lg: 18px;
  --soc-shadow-panel: 0 18px 48px rgba(0, 0, 0, 0.28);
}
```

Then add Element Plus overrides for:

```css
:root {
  --el-bg-color: var(--soc-bg-panel);
  --el-bg-color-page: var(--soc-bg);
  --el-bg-color-overlay: var(--soc-bg-panel-2);
  --el-text-color-primary: var(--soc-text);
  --el-text-color-regular: #bfd2de;
  --el-text-color-secondary: var(--soc-text-muted);
  --el-border-color: var(--soc-border);
  --el-border-color-light: #132b39;
  --el-fill-color: #0f1d27;
  --el-fill-color-light: #13212b;
  --el-color-primary: var(--soc-accent);
  --el-color-success: var(--soc-success);
  --el-color-warning: var(--soc-warning);
  --el-color-danger: var(--soc-danger);
  --el-mask-color: rgba(3, 10, 16, 0.72);
  --el-box-shadow-light: 0 12px 32px rgba(0, 0, 0, 0.24);
}
```

- [ ] **Step 2: Add concrete Element component overrides**

In `frontend/src/styles/theme-soc.css`, add override blocks for the current component set:

```css
.el-card,
.el-dialog,
.el-drawer,
.el-table,
.el-input__wrapper,
.el-textarea__inner,
.el-select__wrapper,
.el-tabs__nav-wrap::after,
.el-pagination button,
.el-tag,
.el-button {
  /* shell-aligned surfaces and borders */
}
```

Implement these exact visual rules:

- cards and overlays use dark elevated surfaces with crisp borders
- tables use transparent dark rows with stronger header separation
- input/select/textarea wrappers use dark fill plus accent-colored focus ring
- buttons use restrained fills; primary button gets cyan emphasis, default button stays dark
- tags inherit shell tone and keep status/risk colors readable on dark backgrounds
- tabs and pagination lose the default bright-light appearance

- [ ] **Step 3: Replace the current global base stylesheet**

Rewrite `frontend/src/style.css` around the shell baseline:

```css
@import "tailwindcss";

:root {
  font-family: "IBM Plex Sans", "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
  line-height: 1.5;
  font-weight: 400;
  color: #e4f3fb;
  background:
    radial-gradient(circle at top left, rgba(53, 194, 244, 0.12), transparent 26%),
    radial-gradient(circle at top right, rgba(88, 213, 255, 0.06), transparent 24%),
    #071018;
  font-synthesis: none;
  text-rendering: optimizeLegibility;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  -webkit-text-size-adjust: 100%;
}

html, body, #app {
  min-width: 100%;
  min-height: 100vh;
  margin: 0;
}
```

Also add:

- dark body background lock
- global `box-sizing: border-box`
- shell-friendly scrollbar styling
- reusable classes such as `.app-page`, `.page-shell`, `.page-header`, `.page-title`, `.page-subtitle`

- [ ] **Step 4: Run the frontend build after the theme layer exists**

Run: `npm run build`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/main.ts frontend/src/style.css frontend/src/styles/theme-soc.css
git commit -m "feat: add soc shell theme tokens"
```

### Task 3: Rebuild the Authenticated App Shell

**Files:**
- Modify: `frontend/src/App.vue`
- Verify: `frontend`

- [ ] **Step 1: Use the current authenticated shell as the failing structural baseline**

Confirm the current shell still uses:

- a white `el-header`
- a basic `el-aside`
- raw `el-main` with no inner content canvas

That is the behavior this task replaces.

- [ ] **Step 2: Restructure the authenticated shell markup**

Update the authenticated branch of `frontend/src/App.vue` to a shell like:

```vue
<el-container v-else class="soc-shell">
  <el-header class="soc-topbar">
    <div class="soc-topbar__left">...</div>
    <div class="soc-topbar__right">...</div>
  </el-header>
  <el-container class="soc-shell__body">
    <el-aside class="soc-sidebar" :style="{ width: collapsed ? '88px' : '248px' }">
      <Sidebar v-model:collapsed="collapsed" />
    </el-aside>
    <el-main class="soc-main">
      <div class="soc-main__canvas">
        <el-config-provider :locale="locale">
          <router-view v-slot="{ Component, route }">
            <keep-alive :exclude="['TaskDetail']">
              <component :is="Component" :key="route.path + JSON.stringify(route.query)" class="app-page" />
            </keep-alive>
          </router-view>
        </el-config-provider>
      </div>
    </el-main>
  </el-container>
</el-container>
```

Preserve the login route split, auth initialization, logout flow, and `keep-alive` behavior.

- [ ] **Step 3: Replace the shell-scoped styles in `App.vue`**

Add styles for:

- `soc-shell`
- `soc-topbar`
- `soc-topbar__left`
- `soc-brand`
- `soc-brand__mark`
- `soc-brand__text`
- `soc-shell__body`
- `soc-sidebar`
- `soc-main`
- `soc-main__canvas`
- `soc-user-entry`

Use these exact directional rules:

- topbar is dark, slim, bordered, and slightly translucent
- brand mark reads as platform chrome, not playful iconography
- main canvas is an inset elevated surface inside the darker app background
- sidebar and topbar visually belong to the same shell system

- [ ] **Step 4: Run the frontend build**

Run: `npm run build`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/App.vue
git commit -m "feat: rebuild soc admin shell layout"
```

### Task 4: Redesign Sidebar Navigation for the SOC Shell

**Files:**
- Modify: `frontend/src/components/Sidebar.vue`
- Verify: `frontend`

- [ ] **Step 1: Establish the old menu look as the baseline**

Confirm the current sidebar still uses default Element menu presentation with only a floating collapse button. This is the baseline behavior being replaced.

- [ ] **Step 2: Update the sidebar markup for shell structure**

Restructure `frontend/src/components/Sidebar.vue` around:

```vue
<div class="soc-nav">
  <div class="soc-nav__scroll">
    <el-menu ... class="soc-nav__menu">
      <el-menu-item ... class="soc-nav__item">
        ...
      </el-menu-item>
    </el-menu>
  </div>
  <div class="soc-nav__footer">
    <el-button class="soc-nav__collapse" circle size="small" @click="toggleCollapse">
      ...
    </el-button>
  </div>
</div>
```

- [ ] **Step 3: Add navigation-specific styling**

Implement styles that enforce:

- stronger vertical rhythm
- dark equipment-rack background
- active item with cyan edge bar plus dark active fill
- hover state with restrained contrast increase
- icon and label alignment that still reads well in collapsed mode
- collapse control that feels docked to the shell instead of floating awkwardly

Use concrete classes:

```css
.soc-nav {}
.soc-nav__menu {}
.soc-nav__menu :deep(.el-menu-item.is-active) {}
.soc-nav__menu :deep(.el-menu-item:hover) {}
.soc-nav__collapse {}
```

- [ ] **Step 4: Run the frontend build**

Run: `npm run build`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/Sidebar.vue
git commit -m "feat: redesign soc sidebar navigation"
```

### Task 5: Apply Light Page-Level Fit Adjustments

**Files:**
- Modify: `frontend/src/views/Dashboard.vue`
- Modify: `frontend/src/views/Search.vue`
- Modify: `frontend/src/views/Task.vue`
- Modify: `frontend/src/views/Settings.vue`
- Verify: `frontend`

- [ ] **Step 1: Identify which top-level views need shell wrapper alignment**

Inspect the top-level templates and only touch pages whose root markup fights the new shell spacing, card radius, or page-header classes.

- [ ] **Step 2: Add the minimum page-level wrapper classes**

Where needed, update the page roots to use the shell helpers from `style.css`, such as:

```vue
<div class="page-shell">
  <div class="page-header">
    <div>
      <div class="page-title">...</div>
      <div class="page-subtitle">...</div>
    </div>
  </div>
  ...
</div>
```

Do not redesign the page internals. Only align them to the shell baseline.

- [ ] **Step 3: Run the frontend build**

Run: `npm run build`
Expected: PASS

- [ ] **Step 4: Spot-check the authenticated routes visually**

Check the following routes in the running app if a preview environment is available:

- dashboard
- task list
- search
- settings

Expected: the shell reads consistently as one SOC system even if each page still uses its existing content layout.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/views/Dashboard.vue frontend/src/views/Search.vue frontend/src/views/Task.vue frontend/src/views/Settings.vue
git commit -m "feat: align pages to soc shell"
```

### Task 6: Final Regression Verification

**Files:**
- Verify only

- [ ] **Step 1: Run the final frontend build**

Run: `npm run build`
Expected: PASS

- [ ] **Step 2: Verify shell scope stayed within bounds**

Manually confirm the diff only includes:

- shell layout
- sidebar
- global styles
- minimal page wrappers

And does not include:

- backend changes
- business logic changes
- page-specific IA redesigns

- [ ] **Step 3: Summarize residual follow-up work**

Record the next-phase pages for deeper redesign:

- `frontend/src/views/Dashboard.vue`
- `frontend/src/views/task/TaskList.vue`
- `frontend/src/views/task/TaskDetail.vue`
- `frontend/src/views/Search.vue`
- `frontend/src/views/Settings.vue`

- [ ] **Step 4: Commit if needed**

```bash
git status
```

Expected: clean working tree for the planned shell scope, or only intentional uncommitted changes if final integration still needs review.
