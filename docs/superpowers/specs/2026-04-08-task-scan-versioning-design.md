# Task Scan Versioning Design

Date: 2026-04-08

## Goal

Replace the current "delete historical records, then rescan" behavior with versioned scan history:

- A task remains a stable business object.
- Every rescan creates a new scan version under the same task.
- All scan outputs are isolated by `task_id + version`.
- The frontend can switch between historical scan versions from the task detail view.
- Rescans always use the latest current system configuration.

## Why Change

The current rescan flow deletes the previous results before running again. This causes three product problems:

1. Historical scan evidence is lost.
2. Users cannot compare changes across runs.
3. A failed or partial rescan can leave the task in a degraded state after historical data has already been removed.

The design should make rescans additive instead of destructive.

## Recommended Model

Use a two-level model:

- `Task`: long-lived logical object. Represents "what is being scanned".
- `ScanVersion`: one concrete execution of that task. Represents "the Nth run of this task".

Under this model:

- `Task` owns stable metadata such as task name and base identity.
- `ScanVersion` owns status, progress, timestamps, config snapshot, target snapshot, and all produced results.
- Frontend task list still shows one row per task.
- Frontend task detail adds a version switcher to view any historical scan version.

## Version Semantics

`version` is an integer scoped to a single `task_id`.

Examples:

- first execution of task `abc` => `version = 1`
- first rescan => `version = 2`
- second rescan => `version = 3`

Rules:

- `version` is monotonically increasing within one task.
- New scans never reuse old version numbers.
- The latest completed or running version is the default version shown in the UI.

## Data Model

### SQLite

Keep `tasks` as the stable parent record and add a new `task_versions` table.

Suggested `tasks` responsibility:

- `task_id`
- `name`
- `created_at`
- `updated_at`
- optional stable ownership / creator fields if already present

Suggested `task_versions` fields:

- `id` or composite key of `task_id + version`
- `task_id`
- `version`
- `targets_snapshot`
- `config_snapshot`
- `status`
- `progress`
- `highest_risk_level`
- `started_at`
- `finished_at`
- `created_at`
- `updated_at`
- optional `trigger_type` such as `initial` or `rescan`

Design decision:

- Status and progress move from the task-level runtime view to the version-level runtime view.
- `highest_risk_level` is version-scoped, not task-scoped.
- `targets_snapshot` and `config_snapshot` are persisted so historical versions remain explainable.

### Elasticsearch

All result documents must include:

- `task_id`
- `version`

This applies to every scan artifact:

- site tree
- JS resources
- API resources
- protocol traces
- vulnerabilities
- assets
- static protocol analysis results
- any future scan-derived records

Design decision:

- History isolation is enforced by query dimension, not by deleting old data.
- Existing indices can remain the same initially; add `version` as a field and filter on it.

## Execution Flow

### Initial Scan

1. Create the `Task` if it does not exist.
2. Read current system configuration.
3. Allocate `version = 1` for that task.
4. Create a `task_versions` record with status `pending` or `running`.
5. Run the scan and write all outputs with `task_id + version`.
6. Update that version's status, progress, and highest risk level.

### Rescan

1. User triggers rescan on an existing task.
2. Backend reads the latest current system configuration.
3. Backend allocates the next version number for the task.
4. Backend creates a new `task_versions` row with fresh target and config snapshots.
5. Scan writes all outputs into the new version only.
6. Historical versions are not deleted.

### Failure Behavior

If a rescan fails:

- old versions remain queryable
- the failed version remains visible in history with its failure status
- latest successful version is still available for viewing

This is a core improvement over the current destructive workflow.

## Query and API Changes

### Task List

Task list stays task-oriented, not version-oriented.

Recommended list response includes:

- `taskId`
- `name`
- `latestVersion`
- `latestStatus`
- `latestProgress`
- `latestHighestRiskLevel`
- `versionCount`
- `createdAt`
- `updatedAt`

Task list should summarize the latest version only.

### Task Version List

Add a version history endpoint for one task, for example:

- `GET /api/task/:taskId/versions`

Suggested response:

- `version`
- `status`
- `progress`
- `highestRiskLevel`
- `startedAt`
- `finishedAt`
- `createdAt`
- `isLatest`

### Version-Scoped Detail APIs

All task detail queries must become version-aware.

Recommended shape:

- `GET /api/task/:taskId?version=N`
- `GET /api/task/:taskId/tree?version=N`
- `GET /api/task/:taskId/site-map?version=N`
- `GET /api/task/:taskId/vulns?version=N`
- `GET /api/task/:taskId/js?version=N`
- `GET /api/task/:taskId/apis?version=N`
- `GET /api/task/:taskId/protocol-traces?version=N`
- `GET /api/task/:taskId/static-protocol-analysis?version=N`
- `GET /api/task/:taskId/assets?version=N`
- `GET /api/task/:taskId/report?version=N`

Rules:

- when `version` is omitted, backend serves the latest version
- when `version` is provided, every module must resolve against that exact version

## Frontend Design

### Task List

Still show one task row only.

Recommended additions:

- current latest risk level
- latest status
- scan count or latest version number

Do not expand the task list into one row per version.

### Task Detail

Add a version switcher near the page header.

Suggested UX:

- default selected version = latest
- label examples: `第 3 次扫描（最新）`, `第 2 次扫描`, `第 1 次扫描`
- switching version reloads all modules on the page against the chosen version

The following views must switch together:

- site map / tree
- risks
- vulnerabilities
- assets
- JS / API records
- protocol traces
- static protocol analysis
- exported report

This must behave as a complete historical snapshot, not a mixed view.

## Configuration Semantics

Rescan uses the latest current system configuration at the moment the rescan starts.

That means:

- user edits global config
- user clicks rescan
- backend snapshots the current config into the new version

Historical versions must continue to display the snapshot they used at execution time.

Design decision:

- historical results are immutable
- configuration for a finished version is not recomputed later

## Compatibility and Migration

Existing tasks and ES documents need a compatibility path.

Recommended migration strategy:

1. Treat legacy records as `version = 1`.
2. Add `task_versions` rows for historical tasks where possible.
3. For old ES documents with no version field, query compatibility may map them to version 1.
4. All new scans must write explicit version fields.

This avoids a destructive full reindex requirement on day one.

## Concurrency and Consistency

Version allocation must be serialized per task.

Required guarantees:

- two rescan requests for the same task cannot receive the same version
- version creation and scan start must be atomic enough to avoid orphan execution state

Recommended rule:

- if one version is already running for a task, either reject the new rescan or queue it explicitly

The first implementation should prefer rejection over queuing because it is simpler and clearer.

## Reporting

Report export must be version-aware.

Rules:

- exporting a report from task detail uses the currently selected version
- report metadata should include task id, version, started time, finished time, and config snapshot summary

## Error Handling

If the selected version has partial data:

- UI should render available modules
- modules with no data should show an empty state, not silently fall back to the latest version

If the user requests a non-existent version:

- backend returns 404
- frontend prompts the user to switch back to latest or refresh version history

## Testing Strategy

Minimum backend coverage:

- version allocation increments correctly per task
- rescans no longer delete previous ES data
- version-scoped queries return only the selected version's data
- omitted `version` resolves to latest
- legacy version-less data can still be read as version 1 during migration

Minimum frontend coverage:

- task detail loads latest version by default
- switching versions reloads all panels consistently
- version list shows historical runs in correct order
- report export uses selected version

## Scope Boundaries

Included in this design:

- data model split between task and scan version
- version-scoped storage and querying
- frontend version switcher
- compatibility path for old data

Not included in the first implementation:

- version diff UI
- rollback / restore old version as latest
- concurrent rescan queueing
- full ES historical backfill if old documents cannot be mapped cheaply

## Recommendation

Implement the first production version in phases:

1. Add `task_versions` and version-aware backend writes.
2. Make all detail APIs version-aware with latest fallback.
3. Add frontend version switcher and historical views.
4. Add migration compatibility for legacy records.

This keeps the rollout controlled while moving the product from destructive rescans to durable scan history.
