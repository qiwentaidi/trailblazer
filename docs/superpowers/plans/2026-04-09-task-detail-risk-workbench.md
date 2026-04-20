# Task Detail Risk Workbench Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the task detail page into a risk-first workbench with a three-column layout, default risk selection, and in-page evidence review.

**Architecture:** Keep `TaskDetail.vue` as the data/state orchestrator, but replace the current tab-first experience with a risk-first workbench layout. Extract the center risk queue and right evidence panel into focused child components, demote tree/assets/protocol/static analysis into support areas, and preserve existing version-aware data loading APIs.

**Tech Stack:** Vue 3, TypeScript, Element Plus, axios

---

## File Map

### Main page orchestration

- Modify: `frontend/src/views/task/TaskDetail.vue`
  - Replace the tab-first IA with the risk workbench structure, keep data loading/version handling here, and coordinate risk selection plus support panels.

### New focused workbench components

- Create: `frontend/src/components/task/TaskRiskQueue.vue`
  - Own filtering, sorting, selection UI, and risk-list rendering for the center column.
- Create: `frontend/src/components/task/TaskRiskEvidencePanel.vue`
  - Own selected-risk summary, request/response evidence, protocol context, and local actions for the right column.
- Optionally create: `frontend/src/components/task/TaskRiskContextRail.vue`
  - If the left column becomes too large for `TaskDetail.vue`, extract filters/version metadata/support entry points here.

### Existing support components

- Modify: `frontend/src/components/task/RiskDetailDrawer.vue`
  - Remove it from the primary flow or reduce it to a legacy/support role if still referenced elsewhere.
- Modify: `frontend/src/components/task/SiteTreeView.vue`
  - Only if the support-analysis presentation needs minor prop or styling alignment.
- Modify: `frontend/src/components/task/AssetListView.vue`
  - Only if the support-analysis presentation needs minor styling alignment.
- Modify: `frontend/src/components/task/ExportReportDialog.vue`
  - Only if the top control bar integration needs a small contract tweak.

### Verification

- Verify: `frontend/package.json`
  - Use the existing `npm run build` as the required regression gate.

---

### Task 1: Add a Failing Workbench Component Import

**Files:**
- Modify: `frontend/src/views/task/TaskDetail.vue`
- Verify: `frontend`

- [ ] **Step 1: Confirm the current page is still tab-first**

Inspect `frontend/src/views/task/TaskDetail.vue` and confirm:

- `activeTab` defaults to `"overview"`
- the page renders several `el-tab-pane` sections
- `RiskDetailDrawer.vue` is still the primary detailed risk-reading surface

This is the baseline behavior being replaced.

- [ ] **Step 2: Run the frontend build before changes**

Run: `npm run build`
Expected: PASS. This is the baseline checkpoint before the IA redesign.

- [ ] **Step 3: Add the first new workbench import target**

Update the imports in `frontend/src/views/task/TaskDetail.vue` to add:

```ts
import TaskRiskQueue from '@/components/task/TaskRiskQueue.vue'
```

Do not create the file yet.

- [ ] **Step 4: Run the frontend build to verify the missing component fails**

Run: `npm run build`
Expected: FAIL with a Vite or TypeScript module resolution error for `TaskRiskQueue.vue`.

- [ ] **Step 5: Commit after the failure is observed**

```bash
git add frontend/src/views/task/TaskDetail.vue
git commit -m "test: wire missing task risk workbench component"
```

### Task 2: Build the Center Risk Queue Component

**Files:**
- Create: `frontend/src/components/task/TaskRiskQueue.vue`
- Verify: `frontend`

- [ ] **Step 1: Create the typed component contract**

Create `frontend/src/components/task/TaskRiskQueue.vue` with props/emits shaped like:

```ts
interface Risk {
  id: string
  title: string
  level: 'high' | 'medium' | 'low' | 'info'
  type: string
  url: string
  method?: string
  request?: string
  response?: string
  responseLength?: number
  description: string
  createdAt: string
  aiVerified?: boolean
}

interface Props {
  risks: Risk[]
  selectedRiskId?: string | null
  loading?: boolean
}

interface Emits {
  (e: 'select-risk', risk: Risk): void
}
```

- [ ] **Step 2: Implement filtering, sorting, and default list logic**

Inside `TaskRiskQueue.vue`, implement:

- risk-level weighting
- keyword filter
- optional quick toggles for high-only and AI-only
- default sort order: level desc, createdAt desc, AI verified as tiebreaker

The computed pipeline should look like:

```ts
const filteredRisks = computed(() => { ... })
const sortedRisks = computed(() => { ... })
```

Use a local selection highlight driven by `selectedRiskId`.

- [ ] **Step 3: Render the risk queue work surface**

Render:

- a compact toolbar with result count, keyword input, quick toggles, and sort selector
- a high-density list or table optimized for scanning
- row content including level, title, type, URL, method, time, and AI marker
- a visible selected state
- an empty state when no risks match

The component must emit `select-risk` on row click, without opening any drawer.

- [ ] **Step 4: Run the frontend build**

Run: `npm run build`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/task/TaskRiskQueue.vue frontend/src/views/task/TaskDetail.vue
git commit -m "feat: add task risk queue workbench component"
```

### Task 3: Build the Right Evidence Panel Component

**Files:**
- Create: `frontend/src/components/task/TaskRiskEvidencePanel.vue`
- Verify: `frontend`

- [ ] **Step 1: Create the typed evidence-panel contract**

Create `frontend/src/components/task/TaskRiskEvidencePanel.vue` with props/emits shaped like:

```ts
interface Risk { ...same as queue... }

interface ProtocolTrace {
  trace_id: string
  request_before_transform?: string
  final_request_body?: string
  session_materials?: Record<string, string>
  algorithms?: string[]
  created_at?: string
}

interface Props {
  risk: Risk | null
  taskId: string
  protocolTrace?: ProtocolTrace | null
}

interface Emits {
  (e: 'delete-risk', risk: Risk): void
}
```

- [ ] **Step 2: Implement evidence formatting helpers**

Inside the component, add:

- timestamp formatting
- response-length formatting
- JSON response detection and pretty-printing
- request/response empty-state handling

- [ ] **Step 3: Render the evidence panel in priority order**

Render these sections in order:

1. selected risk summary
2. raw request packet
3. raw response packet
4. vulnerability description / hit basis
5. protocol trace summary when available
6. local actions including delete

If no risk is selected, render an explicit empty state rather than stale content.

Do not make this a drawer. It must be a persistent panel surface.

- [ ] **Step 4: Reuse protocol tooling only as a subordinate section**

If `ProtocolToolPanel.vue` is retained, embed it as a lower-priority module within the evidence panel instead of preserving `RiskDetailDrawer.vue` as the main container.

- [ ] **Step 5: Run the frontend build**

Run: `npm run build`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/task/TaskRiskEvidencePanel.vue
git commit -m "feat: add task risk evidence panel"
```

### Task 4: Rebuild `TaskDetail.vue` Around the Workbench

**Files:**
- Modify: `frontend/src/views/task/TaskDetail.vue`
- Modify: `frontend/src/components/task/RiskDetailDrawer.vue` (only if still referenced)
- Verify: `frontend`

- [ ] **Step 1: Add the new workbench state**

Inside `frontend/src/views/task/TaskDetail.vue`, add state for:

```ts
const selectedRiskId = ref<string | null>(null)
const riskKeyword = ref('')
const activeSupportPanel = ref<'tree' | 'assets' | 'protocol' | 'static' | null>('tree')
```

Keep version loading, polling, and shared fetched data in `TaskDetail.vue`.

- [ ] **Step 2: Implement default selected-risk behavior**

Add a helper:

```ts
const riskPriorityWeight = { high: 4, medium: 3, low: 2, info: 1 }

const getPrioritizedRisks = (items: Risk[]) => { ... }
const selectDefaultRisk = (items: Risk[]) => { ... }
```

Rules:

- higher severity first
- newer `createdAt` next
- `aiVerified` wins ties

Call this logic:

- after vuln load completes
- after version changes
- after risk deletion

- [ ] **Step 3: Replace the top-level template structure**

Replace the current tabs-first body with:

```vue
<div class="task-detail-workbench page-shell">
  <div class="task-detail-topbar">...</div>
  <div class="task-detail-grid">
    <aside class="task-detail-rail">...</aside>
    <section class="task-detail-primary">
      <TaskRiskQueue ... />
    </section>
    <aside class="task-detail-evidence">
      <TaskRiskEvidencePanel ... />
    </aside>
  </div>
  <div class="task-detail-support">...</div>
</div>
```

Keep:

- back navigation
- version selector
- export dialog trigger
- existing version-aware fetches

Remove the current `overview` default as the first interaction surface.

- [ ] **Step 4: Demote support analysis areas**

Move these existing views into the support-analysis area:

- `SiteTreeView`
- `AssetListView`
- protocol traces
- static protocol analysis

They may be presented as secondary tabs, segmented panels, or collapsible sections, but they must no longer be the default landing plane.

- [ ] **Step 5: Stop using `RiskDetailDrawer` as the primary flow**

Either:

- remove the drawer from `TaskDetail.vue`, or
- leave it only as a non-default support path

The selected risk must now be read primarily through `TaskRiskEvidencePanel.vue`.

- [ ] **Step 6: Run the frontend build**

Run: `npm run build`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add frontend/src/views/task/TaskDetail.vue frontend/src/components/task/RiskDetailDrawer.vue
git commit -m "feat: redesign task detail as risk workbench"
```

### Task 5: Align Support Components to the New Flow

**Files:**
- Modify: `frontend/src/components/task/SiteTreeView.vue` (only if needed)
- Modify: `frontend/src/components/task/AssetListView.vue` (only if needed)
- Modify: `frontend/src/components/task/ExportReportDialog.vue` (only if needed)
- Verify: `frontend`

- [ ] **Step 1: Verify support components still fit the new layout**

Check whether:

- `SiteTreeView.vue` fits within the new support-analysis surface
- `AssetListView.vue` spacing/density fits the new workbench shell
- `ExportReportDialog.vue` still works cleanly from the top control bar

- [ ] **Step 2: Make only minimal alignment changes**

Apply only styling or small prop-level changes needed to fit the redesigned detail page. Do not expand scope into page-wide redesigns for these components.

- [ ] **Step 3: Run the frontend build**

Run: `npm run build`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add frontend/src/components/task/SiteTreeView.vue frontend/src/components/task/AssetListView.vue frontend/src/components/task/ExportReportDialog.vue
git commit -m "feat: align task detail support panels"
```

### Task 6: Final Verification and Behavior Check

**Files:**
- Verify only

- [ ] **Step 1: Run the final frontend build**

Run: `npm run build`
Expected: PASS

- [ ] **Step 2: Manually verify the core workbench flow**

Confirm in the running UI if available:

- the page lands in risk-first mode
- a risk is auto-selected when risks exist
- request/response evidence is visible without opening a drawer
- version changes do not leak stale evidence
- support-analysis sections remain available but secondary

- [ ] **Step 3: Confirm scope stayed contained**

Manually confirm the diff is restricted to:

- `TaskDetail.vue`
- new workbench child components
- minimal support-component alignment

And does not include:

- backend changes
- dashboard/task-list redesign
- unrelated shell work

- [ ] **Step 4: Commit if needed**

```bash
git status
```

Expected: clean task-detail workbench scope, or only intentional pending changes awaiting review.
