# Antd Admin Frontend Migration

## Goal

Replace the current Vue 3 + Element Plus frontend template with a new React-based frontend built on `zuiidea/antd-admin`, while preserving the existing backend APIs and the core operator workflow.

This phase is intended to retire the old frontend template as the active product shell. The new frontend becomes the primary and only evolving UI surface.

## Scope

This phase covers:

- adopting `antd-admin` as the new frontend foundation
- replacing the current frontend shell and route structure
- rebuilding login, task list, task detail, and settings in the new stack
- preserving the existing backend API contracts where feasible
- carrying forward the current business terminology and operator workflow
- dropping dashboard and search from phase-one implementation

This phase does not cover:

- backend feature changes
- backend API redesign unless a small compatibility shim is required
- full parity for dashboard and search before launch
- mixed Vue/React coexistence as a long-term architecture

## Product Direction

Approved direction:

- foundation: `antd-admin`
- migration style: keep the `antd-admin` shell and infrastructure, then rebuild business pages on top of it
- core release scope: login, task flow, settings
- non-critical pages: defer dashboard and search

Interpretation:

- this is a frontend re-platform, not a theme swap
- the new product should feel like a coherent enterprise console built on Ant Design rather than a ported Vue app
- the first release should optimize for the operator path from login to task review to configuration

## Why This Approach

The approved approach is to use `antd-admin` as the base, but strip it down to the shell and core infrastructure before rebuilding product-specific pages.

This is preferred over:

- a full template copy with all demo pages preserved, because that carries unrelated structure and cleanup cost
- visual imitation inside the old Vue app, because that would keep the old template and fail the replacement goal
- temporary Vue/React hybrid rendering, because that raises maintenance cost and weakens the end-state architecture

## New Frontend Architecture

The new frontend will be a standalone `antd-admin` application.

### Stack

- React
- Ant Design 6
- Umi 4
- TypeScript
- `zustand` or the template’s default lightweight state approach for local/global UI state
- a dedicated service layer for backend API integration

### Application Boundaries

- the new frontend becomes the only active UI shell
- the current `frontend` Vue project becomes reference material during migration, not the ongoing delivery target
- backend endpoints remain the system of record for data and behavior

### Template Strategy

Keep:

- shell layout
- route framework
- login wiring
- theme tokens
- request/service conventions
- shared page scaffolding patterns from `antd-admin`

Remove or replace:

- demo dashboards
- user-management examples
- AI chat examples
- sample menus and mock-only business pages

## Phase-One Information Architecture

The first phase should expose a simplified navigation with only the primary operator routes.

### Primary Navigation

- `任务中心`
- `配置中心`
- user/account actions

### Default Landing Route

The default authenticated route should be `任务中心`, not a dashboard.

Reason:

- task review is the primary business action
- dashboard metrics are useful but not on the critical path
- this keeps the first release tighter and more production-oriented

## Page Design

## 1. Login

The login page should align visually with the new Ant Design shell and should remain operationally simple.

Requirements:

- support the existing authentication flow
- preserve current token/session behavior or provide a compatible replacement
- hand off into the authenticated shell without requiring backend auth changes

## 2. Task Center

Task Center is the default first screen after login.

### Task List

The page should use an `antd-admin` style data table and a compact top action area.

Required controls:

- task name keyword search
- status filter
- create task action

Required table columns:

- task name
- target or target summary
- status
- risk count
- created time
- primary actions

Primary row action:

- view task detail

Optional deferred actions:

- resume or continue scan
- delete
- export

Rules:

- optimize for fast scanning and task entry
- avoid overloading the table with low-value columns in phase one
- keep the task detail route as the natural next step

## 3. Task Detail

Task Detail is the core work surface in phase one.

The page should be rebuilt as a single detail experience with clear internal sections rather than a scattered collection of legacy page fragments.

### Top Section

Required content:

- task identity
- task status
- key counts or summary chips
- export report action
- optional refresh state

### Internal Structure

Use tabs for the four primary views:

- `概览`
- `站点树`
- `风险`
- `资产`

### Overview

Purpose:

- summarize the task state
- provide quick counts and recent highlights
- orient the user before drilling deeper

### Site Tree

Purpose:

- preserve the current tree-browsing capability
- keep a structured exploration view for scanned nodes

### Risks

This is the most important detail tab.

Required capabilities:

- risk list with level, title, type, URL, time, and AI-assisted marker
- risk filtering and sorting
- detail side panel or drawer for the selected risk
- request/response evidence visibility
- compatibility with current vulnerability payload returned by the backend

Interaction model:

- list is the primary navigation within the tab
- selecting a row updates the risk detail surface immediately
- the user should not need route changes to inspect each risk

### Assets

Purpose:

- present aggregated asset findings such as email, phone, ID card, IP or URL, API roots, and routes

Rules:

- group results by asset type
- prefer compact structured sections over long raw lists

### Refresh Behavior

Automatic refresh should remain in the task detail page only.

Rules:

- keep refresh behavior explicit
- show clear auto-refresh state when active
- do not introduce silent global polling across the whole app
- ensure that refreshed data never leaves stale selected risk content on screen

## 4. Settings

Settings should be reorganized around business meaning rather than a long technical menu.

### Primary Groups

- `AI 配置`
- `漏洞检测规则`
- `系统状态`

### AI Configuration

Required fields:

- AI enable toggle
- API key
- base URL
- model

### Vulnerability Detection Rules

Required coverage:

- SQL injection rules
- file read or local file inclusion related rules where currently supported
- placeholder configuration

Recommended presentation:

- structured forms
- collapsible rule sections
- modal or drawer editing where it reduces page overload

### System Status

Required content:

- Elasticsearch connection status
- concise operational guidance when the backend dependency is unavailable

Rules:

- separate read-only system health from editable configuration
- keep save actions clear and localized to the edited configuration set

## Design Principles

The migration should follow these principles:

- preserve business capability before expanding feature scope
- keep terminology familiar to current users
- let the new UI feel native to Ant Design instead of visually mimicking Element Plus
- reduce information sprawl on high-density screens
- prioritize task execution and review over dashboard decoration

## Data Integration

The backend API should be retained where possible.

### Service Layer Rules

- create a dedicated service module for tasks, task detail, assets, risks, auth, and settings
- map legacy response fields into UI-friendly typed structures
- keep API adaptation in the service layer rather than scattering field translation across components

### Compatibility Goal

- frontend migration should not force unnecessary backend changes
- if field naming inconsistencies exist, resolve them in adapters first

## Implementation Boundaries

Allowed:

- create a new frontend app structure based on `antd-admin`
- remove template demo pages and menus
- rebuild the core business routes
- add typed adapters for existing API payloads
- redesign page layout and interaction patterns

Not allowed in phase one:

- rebuilding dashboard and search for parity before the main flow works
- preserving the old Vue shell as a permanent fallback layer
- introducing broad backend contract changes without clear need

## File Strategy

Expected new work areas:

- new frontend app root based on `antd-admin`
- route definitions for task center and settings
- service modules for auth, tasks, task detail, risks, assets, and settings
- page modules for login, task list, task detail, and settings
- shared business components for risk panels, task summary blocks, and settings sections

The exact directory layout should follow the selected `antd-admin` project structure after scaffold selection.

## Verification

Phase-one success criteria:

- user can log in through the new frontend
- default authenticated route opens task list
- user can open task detail from the list
- task detail exposes overview, site tree, risks, and assets
- settings can read and write the approved core configuration groups
- the old Vue template is no longer the active frontend path for normal usage
- the new frontend production build passes

## Risks

Primary delivery risks:

- hidden coupling between the current Vue pages and backend response shapes
- underestimating task detail complexity, especially risk evidence and polling behavior
- configuration forms carrying legacy assumptions that are not obvious from the UI alone

Mitigations:

- implement API adapters early
- build task detail before spending time on non-core screens
- keep settings grouped and typed instead of directly porting the old structure one-to-one

## Recommended Execution Order

1. scaffold or import the `antd-admin` base and remove unrelated demos
2. establish shell, auth, route skeleton, and service layer
3. implement task list
4. implement task detail with overview, site tree, risks, and assets
5. implement settings
6. verify build and key operator flows

## Deferred Work

Explicitly deferred after phase one:

- dashboard rebuild
- search rebuild
- broader visual polish beyond the main flow
- secondary workflow enhancements not required for task execution
