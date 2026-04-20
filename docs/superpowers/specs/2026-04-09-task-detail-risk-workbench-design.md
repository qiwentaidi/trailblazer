# Task Detail Risk Workbench Redesign

## Goal

Redesign the task detail page into a risk-first disposition workbench. The default experience should help an operator move from scan version selection to risk triage to raw evidence review without tab-hopping.

## Scope

This redesign covers:

- the information architecture of `frontend/src/views/task/TaskDetail.vue`
- the main task detail layout and interaction flow
- the role of existing child components under the new layout
- extraction of new risk-list and evidence-panel components if needed
- version switching behavior inside the redesigned detail page

This redesign does not cover:

- backend API changes
- dashboard redesign
- task list redesign
- global shell/theme redesign beyond what already exists

## Product Direction

Approved direction:

- default viewpoint: risk disposition
- primary work surface: risk list
- primary evidence: raw request/response packets
- selected layout direction: three-column workbench

Interpretation:

- risk handling takes precedence over reconnaissance views
- the user should never need to choose a tab before they can start triaging
- evidence should stay visible alongside the selected risk

## Core UX Model

The current page behaves like a multi-tab data hub. The redesign changes it into an operator workbench with one clear default flow:

1. choose scan version
2. narrow risk set with filters
3. scan prioritized risk list
4. inspect raw request/response evidence
5. use protocol/site/asset analysis as supporting context only when needed

This means website tree, static protocol analysis, assets, and broader protocol exploration stop competing for first-screen priority.

## Layout

The page becomes a four-layer structure.

### 1. Top Control Bar

Purpose:

- anchor the task identity
- expose version selection
- summarize the active version’s risk posture
- provide return/export actions

Required content:

- back action
- task name
- active scan version selector
- compact risk summary
- task status for the active version
- export action

Rules:

- compact vertical footprint
- no oversized KPI cards here
- this should feel like a control strip, not a dashboard header

### 2. Left Context Rail

Purpose:

- hold decision-support context and filters
- avoid heavy content that distracts from risk triage

Required modules:

- scan version selector or version history summary
- risk level filter
- vulnerability type filter
- optional keyword or target-scope filter
- active version/task metadata
- compact statistics
- entry points to auxiliary analysis areas

Rules:

- narrow and stable
- optimized for filtering and context, not reading long records

### 3. Center Risk List

Purpose:

- be the primary work surface
- present the risk queue for the current scan version

Required row information:

- risk level
- title
- type
- URL
- HTTP method when present
- time
- AI verification mark when present
- selected state

Required controls:

- sort selector
- keyword filter
- quick toggles such as “high only” and “AI verified only” if feasible

Rules:

- high-density but readable
- optimized for fast scanning
- selection must update the evidence panel immediately without opening a drawer

### 4. Right Evidence Panel

Purpose:

- show the currently selected risk’s disposition context
- keep the operator inside one continuous workflow

Required module priority:

1. risk summary
2. raw request packet
3. raw response packet
4. vulnerability description / hit basis
5. matched protocol trace summary when available
6. local actions such as delete or jump-to-analysis

Rules:

- request/response are the default evidence, not hidden behind a secondary click
- protocol evidence is secondary unless the raw packet is missing
- empty state must be explicit when no risk is selected

## Information Priority

Primary:

- selected version
- risk filters
- risk queue
- request/response evidence

Secondary:

- protocol trace
- static protocol analysis
- site tree
- assets

Supporting analysis areas should remain available but lose first-screen dominance.

## Auxiliary Analysis Areas

The following existing data views stay in the page, but move to a secondary role:

- site tree
- assets
- protocol traces
- static protocol analysis

Recommended presentation:

- collapsed support sections in the left or right rail, or
- secondary tabs below/alongside the main workbench, but not the default visible plane

They should be reachable without leaving the detail page, but they should not replace the risk workbench as the default landing view.

## Default Behaviors

### Initial Selection

When the page loads, it should auto-select the highest-priority risk from the active version.

Default priority order:

1. higher risk level first
2. newer time first
3. AI-verified before unverified when all else is equal

Result:

- center list always has a meaningful initial selection
- right evidence panel is populated immediately when risks exist

### Version Switching

When the scan version changes:

- current filters remain active
- the risk list reloads for the selected version
- the selected risk resets to the highest-priority risk that still matches filters
- right evidence panel must never show stale evidence from the previous version

If the selected version has no risks:

- risk list shows an empty state
- evidence panel shows a no-risk state
- the page should suggest using site tree or protocol analysis for further review

### Risk Switching

When the user selects another risk in the center list:

- the right panel updates in place
- there is no drawer or modal transition
- protocol evidence and request/response should remain synchronized to the selected risk

### Risk Deletion

After deleting a risk:

- the current list position should stay stable
- the next adjacent risk becomes selected when possible
- if the list becomes empty, the evidence panel transitions to empty state

## Component Strategy

### Keep `TaskDetail.vue` as the page orchestrator

`frontend/src/views/task/TaskDetail.vue` should continue to own:

- route/task/version loading
- shared page state
- risk selection state
- coordination between workbench and support panels

### New components

Recommended new focused components:

- `TaskRiskWorkbench.vue` or equivalent layout wrapper
- `TaskRiskQueue.vue` for the center risk list
- `TaskRiskEvidencePanel.vue` for the right evidence panel
- optional compact filter/context component for the left rail

### Existing components

- `RiskDetailDrawer.vue` should no longer be the primary risk-reading container
- `SiteTreeView.vue` remains useful in the support-analysis area
- `AssetListView.vue` remains useful in the support-analysis area
- `ExportReportDialog.vue` remains part of the top control flow

`RiskDetailDrawer.vue` may either be absorbed into the evidence panel logic or reduced to a legacy/support role, but it should not remain the primary interaction model.

## Data and API Assumptions

The redesign assumes the existing version-aware detail APIs remain unchanged:

- task detail
- versions
- vulns
- site map
- assets
- APIs
- protocol traces
- static protocol analysis
- report export

The redesign is a frontend-only architectural change. Backend response contracts should not be changed as part of this work unless a clear UI blocker is discovered.

## Visual Language

This page should inherit the new SOC shell rather than inventing a different style.

Detail-page-specific guidance:

- center risk queue uses sharper row selection states and stronger severity cues
- right evidence panel uses code/evidence surfaces that read like an analyst console
- the page should feel focused and operational, not dashboard-like
- avoid oversized summary cards that push the real work below the fold

## Success Criteria

The redesign is successful when:

- the task detail page opens into a meaningful risk triage workflow by default
- the user can switch versions and keep context without stale evidence leaks
- a selected risk’s request/response is visible without opening a drawer
- support-analysis data remains accessible but clearly secondary
- the page feels like a disposition workbench rather than a tabbed data dump

## Implementation Notes

Expected primary files:

- `/Users/qwtd/WorkManageCode/trailblazer/frontend/src/views/task/TaskDetail.vue`
- new task-detail child components under `/Users/qwtd/WorkManageCode/trailblazer/frontend/src/components/task/`

Potentially touched support files:

- `RiskDetailDrawer.vue`
- `SiteTreeView.vue`
- `AssetListView.vue`
- `ExportReportDialog.vue`

Changes should stay tightly focused on the task detail experience.
