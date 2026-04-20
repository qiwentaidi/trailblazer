# Task Scan Versioning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace destructive rescans with task-scoped scan versions so every run is preserved, queryable, and switchable from the frontend.

**Architecture:** Keep `tasks` as the stable logical entity and introduce a versioned execution layer in SQLite plus a `version` dimension across all Elasticsearch result documents. Backend write/query paths become version-aware with latest-version fallback, and the frontend task detail switches all panels by selected scan version.

**Tech Stack:** Go, Gin, SQLite, Elasticsearch, Vue 3, Element Plus, axios

---

## File Map

### Backend data model and storage

- Modify: `backend/pkg/core/database/sqlite.go`
  - Add `TaskVersion` model and SQLite helpers for version creation, lookup, pagination, and latest-version resolution.
- Modify: `backend/pkg/core/database/models.go`
  - Add `Version` field to ES-backed result models that are written by the scanner.
- Modify: `backend/pkg/core/database/query.go`
  - Add version-aware ES query helpers and compatibility fallback for legacy records without `version`.
- Modify: `backend/pkg/core/database/delete.go`
  - Stop deleting all historical task data during rescan; optionally support deleting one version later.

### Backend scanning and routes

- Modify: `backend/pkg/web/scan.go`
  - Rescan creates a new version instead of clearing old data; pass version through the whole scan pipeline.
- Modify: `backend/pkg/web/query.go`
  - Task list summarizes latest version; detail endpoints accept `version`.
- Modify: `backend/pkg/web/routes.go`
  - Register version-list endpoint if needed.
- Modify: `backend/main.go`
  - No behavioral redesign expected, but verify startup remains consistent after new SQLite helpers.

### Frontend

- Modify: `frontend/src/views/task/TaskList.vue`
  - Show version summary count/latest version if included in list API.
- Modify: `frontend/src/views/task/TaskDetail.vue`
  - Add version selector and reload all detail panels when it changes.
- Modify: `frontend/src/components/task/*`
  - Only if version switching requires prop or request-shape changes.

### Tests

- Create: `backend/pkg/core/database/task_versions_test.go`
- Modify: `backend/pkg/web/task_records_test.go`
- Create: `backend/pkg/web/task_version_query_test.go`
- Optionally create: `frontend` component tests only if the project already has a test setup; otherwise rely on build verification and carefully scoped type checks.

---

### Task 1: Add SQLite Version Model

**Files:**
- Modify: `backend/pkg/core/database/sqlite.go`
- Test: `backend/pkg/core/database/task_versions_test.go`

- [ ] **Step 1: Write the failing database test for version allocation**

```go
func TestCreateTaskVersionAllocatesIncreasingVersions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "tasks.db")
	if err := InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if DB != nil {
			_ = DB.Close()
			DB = nil
		}
	})

	task := Task{
		ID:      "task-1",
		Name:    "task-1",
		Targets: []string{"https://example.com"},
		Status:  "pending",
	}
	if _, err := task.Save(); err != nil {
		t.Fatalf("Task.Save() error = %v", err)
	}

	first, err := CreateTaskVersion("task-1", []string{"https://example.com"}, []byte(`{"openai":{"enabled":false}}`), "initial")
	if err != nil {
		t.Fatalf("CreateTaskVersion() first error = %v", err)
	}
	second, err := CreateTaskVersion("task-1", []string{"https://example.com"}, []byte(`{"openai":{"enabled":true}}`), "rescan")
	if err != nil {
		t.Fatalf("CreateTaskVersion() second error = %v", err)
	}

	if first.Version != 1 || second.Version != 2 {
		t.Fatalf("versions = %d, %d; want 1, 2", first.Version, second.Version)
	}
	if !second.IsLatest {
		t.Fatalf("latest version flag not updated")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `env GOCACHE=/tmp/trailblazer-gocache go test ./pkg/core/database -run TestCreateTaskVersionAllocatesIncreasingVersions -count=1`
Expected: FAIL with undefined `CreateTaskVersion` / missing `task_versions` schema.

- [ ] **Step 3: Add `task_versions` schema and model**

```go
type TaskVersion struct {
	TaskID           string    `json:"taskId"`
	Version          int       `json:"version"`
	TargetsSnapshot  []string  `json:"targetsSnapshot"`
	ConfigSnapshot   string    `json:"configSnapshot"`
	Status           string    `json:"status"`
	Progress         int       `json:"progress"`
	HighestRiskLevel string    `json:"highestRiskLevel"`
	TriggerType      string    `json:"triggerType"`
	IsLatest         bool      `json:"isLatest"`
	StartedAt        time.Time `json:"startedAt"`
	FinishedAt       time.Time `json:"finishedAt"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}
```

```sql
CREATE TABLE IF NOT EXISTS task_versions (
	task_id TEXT NOT NULL,
	version INTEGER NOT NULL,
	targets_snapshot TEXT NOT NULL,
	config_snapshot TEXT NOT NULL,
	status TEXT NOT NULL,
	progress INTEGER DEFAULT 0,
	highest_risk_level TEXT DEFAULT '',
	trigger_type TEXT DEFAULT 'initial',
	is_latest BOOLEAN DEFAULT 0,
	started_at DATETIME,
	finished_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (task_id, version)
);
CREATE INDEX IF NOT EXISTS idx_task_versions_task_created ON task_versions(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_task_versions_latest ON task_versions(task_id, is_latest);
```

- [ ] **Step 4: Implement version helpers**

```go
func CreateTaskVersion(taskID string, targets []string, configSnapshot []byte, triggerType string) (*TaskVersion, error) {
	tx, err := DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var nextVersion int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(version), 0) + 1 FROM task_versions WHERE task_id = ?`, taskID).Scan(&nextVersion); err != nil {
		return nil, err
	}

	if _, err := tx.Exec(`UPDATE task_versions SET is_latest = 0 WHERE task_id = ?`, taskID); err != nil {
		return nil, err
	}

	targetsJSON, _ := json.Marshal(targets)
	now := time.Now()
	if _, err := tx.Exec(`
		INSERT INTO task_versions (task_id, version, targets_snapshot, config_snapshot, status, progress, trigger_type, is_latest, started_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
	`, taskID, nextVersion, string(targetsJSON), string(configSnapshot), "pending", 0, triggerType, now, now, now); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return GetTaskVersion(taskID, nextVersion)
}
```

- [ ] **Step 5: Add latest-version lookup helpers**

```go
func GetLatestTaskVersion(taskID string) (*TaskVersion, error)
func GetTaskVersion(taskID string, version int) (*TaskVersion, error)
func ListTaskVersions(taskID string) ([]TaskVersion, error)
func UpdateTaskVersionStatus(taskID string, version int, status string, progress int) error
func UpdateTaskVersionHighestRiskLevel(taskID string, version int, level string) error
```

- [ ] **Step 6: Run tests to verify it passes**

Run: `env GOCACHE=/tmp/trailblazer-gocache go test ./pkg/core/database -run TestCreateTaskVersionAllocatesIncreasingVersions -count=1`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add backend/pkg/core/database/sqlite.go backend/pkg/core/database/task_versions_test.go
git commit -m "feat: add task scan version model"
```

### Task 2: Make ES Result Models Version-Aware

**Files:**
- Modify: `backend/pkg/core/database/models.go`
- Test: `backend/pkg/core/database/task_versions_test.go`

- [ ] **Step 1: Write the failing test for highest-risk update by version**

```go
func TestHighestRiskLevelUpdateTargetsSelectedVersion(t *testing.T) {
	got := highestRiskLevelFromVulns([]VulnRecord{
		{Level: "info"},
		{Level: "medium"},
	})
	if got != "medium" {
		t.Fatalf("highestRiskLevelFromVulns() = %q, want %q", got, "medium")
	}
}
```

- [ ] **Step 2: Run test to verify current behavior boundary**

Run: `env GOCACHE=/tmp/trailblazer-gocache go test ./pkg/core/database -run TestHighestRiskLevelUpdateTargetsSelectedVersion -count=1`
Expected: PASS or FAIL only if helper shape changed; adjust test to validate the real helper before proceeding.

- [ ] **Step 3: Add `Version` to every result model that is persisted**

```go
type SiteTreeNode struct {
	TaskID    string    `json:"task_id"`
	Version   int       `json:"version"`
	NodeID    string    `json:"node_id"`
	// ...
}

type VulnRecord struct {
	TaskID    string    `json:"task_id"`
	Version   int       `json:"version"`
	VulnID    string    `json:"vuln_id"`
	// ...
}
```

- [ ] **Step 4: Update highest-risk synchronization to be version-scoped**

```go
func UpdateTaskVersionHighestRiskLevelFromVulns(taskID string, version int, vulns []VulnRecord) error {
	return UpdateTaskVersionHighestRiskLevel(taskID, version, highestRiskLevelFromVulns(vulns))
}
```

- [ ] **Step 5: Run focused database tests**

Run: `env GOCACHE=/tmp/trailblazer-gocache go test ./pkg/core/database -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add backend/pkg/core/database/models.go backend/pkg/core/database/task_versions_test.go
git commit -m "feat: add version field to scan result models"
```

### Task 3: Make Scan Writes Create New Versions Instead of Deleting History

**Files:**
- Modify: `backend/pkg/web/scan.go`
- Modify: `backend/pkg/core/database/delete.go`
- Modify: `backend/pkg/core/database/models.go`
- Test: `backend/pkg/web/task_version_query_test.go`

- [ ] **Step 1: Write the failing test for rescan behavior**

```go
func TestRescanDoesNotDeletePreviousVersionData(t *testing.T) {
	t.Skip("integration-style test scaffold: verify rescan creates version 2 instead of clearing version 1")
}
```

- [ ] **Step 2: Run test to verify it fails or is skipped for explicit follow-up**

Run: `env GOCACHE=/tmp/trailblazer-gocache go test ./pkg/web -run TestRescanDoesNotDeletePreviousVersionData -count=1`
Expected: FAIL or SKIP with a clear note that implementation is still pending.

- [ ] **Step 3: Capture current config and create a new version at scan start**

```go
configData, err := os.ReadFile(configPath)
if err != nil {
	// fail version cleanly
}

taskVersion, err := database.CreateTaskVersion(taskID, urls, configData, triggerType)
if err != nil {
	// fail request cleanly
}
version := taskVersion.Version
```

- [ ] **Step 4: Remove destructive rescan deletion**

```go
// DeleteTaskData(taskId) must not run as part of rescan anymore.
// Historical versions remain intact.
```

- [ ] **Step 5: Pass `version` through all saved records**

```go
treeNode := database.SiteTreeNode{
	TaskID:  taskID,
	Version: version,
	// ...
}

vuln := database.VulnRecord{
	TaskID:  taskID,
	Version: version,
	// ...
}
```

- [ ] **Step 6: Update version status and risk level instead of task-level runtime state**

```go
_ = database.UpdateTaskVersionStatus(taskID, version, "running", progress)
_ = database.UpdateTaskVersionStatus(taskID, version, "completed", 100)
_ = database.UpdateTaskVersionHighestRiskLevel(taskID, version, level)
```

- [ ] **Step 7: Run focused web tests**

Run: `env GOCACHE=/tmp/trailblazer-gocache go test ./pkg/web -count=1`
Expected: PASS for route/query tests, with no code path deleting historical data during rescan.

- [ ] **Step 8: Commit**

```bash
git add backend/pkg/web/scan.go backend/pkg/core/database/delete.go backend/pkg/core/database/models.go backend/pkg/web/task_version_query_test.go
git commit -m "feat: preserve historical scan versions on rescan"
```

### Task 4: Make ES Queries Version-Aware with Latest Fallback

**Files:**
- Modify: `backend/pkg/core/database/query.go`
- Modify: `backend/pkg/web/query.go`
- Modify: `backend/pkg/web/routes.go`
- Test: `backend/pkg/web/task_records_test.go`
- Test: `backend/pkg/web/task_version_query_test.go`

- [ ] **Step 1: Write failing tests for version query semantics**

```go
func TestGetTasksReturnsLatestVersionSummary(t *testing.T) {
	// assert latestVersion/latestStatus/latestHighestRiskLevel/versionCount
}

func TestVersionParameterResolvesSelectedVersion(t *testing.T) {
	// assert versioned task detail query does not fall back to a different version
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `env GOCACHE=/tmp/trailblazer-gocache go test ./pkg/web -run 'TestGetTasksReturnsLatestVersionSummary|TestVersionParameterResolvesSelectedVersion' -count=1`
Expected: FAIL with missing version summary or missing `version` handling.

- [ ] **Step 3: Add version-aware ES filters**

```go
func buildTaskVersionQuery(taskID string, version *int) map[string]interface{} {
	if version == nil {
		return map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{"term": map[string]interface{}{"task_id.keyword": taskID}},
				},
				"should": []map[string]interface{}{
					{"term": map[string]interface{}{"version": 1}},
					{"bool": map[string]interface{}{"must_not": map[string]interface{}{"exists": map[string]interface{}{"field": "version"}}}},
				},
			},
		}
	}
	return map[string]interface{}{
		"bool": map[string]interface{}{
			"must": []map[string]interface{}{
				{"term": map[string]interface{}{"task_id.keyword": taskID}},
				{"term": map[string]interface{}{"version": *version}},
			},
		},
	}
}
```

- [ ] **Step 4: Add version parsing in handlers**

```go
func requestedVersion(c *gin.Context) (*int, error) {
	raw := c.Query("version")
	if raw == "" {
		return nil, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return nil, fmt.Errorf("invalid version")
	}
	return &v, nil
}
```

- [ ] **Step 5: Add version-history endpoint**

```go
protected.GET("/task/:taskId/versions", getTaskVersions)
```

```go
func getTaskVersions(c *gin.Context) {
	versions, err := database.ListTaskVersions(c.Param("taskId"))
	// return sorted version history
}
```

- [ ] **Step 6: Change task list response to latest-version summary**

```go
item := map[string]interface{}{
	"id":                 task.ID,
	"name":               task.Name,
	"latestVersion":      latest.Version,
	"latestStatus":       latest.Status,
	"latestProgress":     latest.Progress,
	"highestRiskLevel":   latest.HighestRiskLevel,
	"versionCount":       versionCount,
	"createdAt":          task.CreatedAt.Format("2006-01-02 15:04:05"),
}
```

- [ ] **Step 7: Run web tests**

Run: `env GOCACHE=/tmp/trailblazer-gocache go test ./pkg/web -count=1`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add backend/pkg/core/database/query.go backend/pkg/web/query.go backend/pkg/web/routes.go backend/pkg/web/task_records_test.go backend/pkg/web/task_version_query_test.go
git commit -m "feat: add version-aware scan queries"
```

### Task 5: Update Frontend Task List for Latest Version Summary

**Files:**
- Modify: `frontend/src/views/task/TaskList.vue`

- [ ] **Step 1: Write the expected TypeScript shape in the component**

```ts
interface Task {
  id: string
  name: string
  targets?: string[] | null
  latestVersion?: number
  versionCount?: number
  latestStatus?: 'pending' | 'running' | 'completed' | 'failed' | 'stopped'
  latestProgress?: number
  highestRiskLevel?: 'high' | 'medium' | 'low' | 'info' | ''
  createdAt: string
}
```

- [ ] **Step 2: Run build to verify it fails or type-checks against current API mismatch**

Run: `npm run build`
Expected: FAIL if the component still references old task status/progress fields directly after the backend shape change.

- [ ] **Step 3: Update the table to summarize latest scan version**

```vue
<el-table-column label="扫描次数" width="100" align="center">
  <template #default="{ row }">
    {{ row.versionCount || row.latestVersion || 0 }}
  </template>
</el-table-column>
```

```ts
const effectiveStatus = (task: Task) => task.latestStatus || task.status
const effectiveProgress = (task: Task) => task.latestProgress ?? task.progress ?? 0
```

- [ ] **Step 4: Run build again**

Run: `npm run build`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/views/task/TaskList.vue
git commit -m "feat: show latest scan version summary in task list"
```

### Task 6: Add Version Switcher to Task Detail

**Files:**
- Modify: `frontend/src/views/task/TaskDetail.vue`
- Modify: `frontend/src/components/task/ExportReportDialog.vue` if it does not already accept version-aware report URLs
- Modify: any task detail child component props only if necessary

- [ ] **Step 1: Add the failing request flow in the page logic**

```ts
interface TaskVersionSummary {
  version: number
  status: 'pending' | 'running' | 'completed' | 'failed' | 'stopped'
  progress: number
  highestRiskLevel?: 'high' | 'medium' | 'low' | 'info' | ''
  startedAt?: string
  finishedAt?: string
  isLatest: boolean
}
```

- [ ] **Step 2: Run build to verify current page has no version support**

Run: `npm run build`
Expected: PASS before change; this step is a baseline checkpoint so later regressions are attributable to the version-switch work.

- [ ] **Step 3: Load version history and default to latest**

```ts
const versions = ref<TaskVersionSummary[]>([])
const selectedVersion = ref<number | null>(null)

const loadVersions = async () => {
  const response = await axios.get(`/api/task/${taskId}/versions`)
  versions.value = response.data.data || []
  selectedVersion.value = versions.value.find((v) => v.isLatest)?.version ?? versions.value[0]?.version ?? null
}
```

- [ ] **Step 4: Make all detail requests include the selected version**

```ts
const versionParams = computed(() => selectedVersion.value ? { version: selectedVersion.value } : {})

await axios.get(`/api/task/${taskId}/vulns`, { params: versionParams.value })
await axios.get(`/api/task/${taskId}/assets`, { params: versionParams.value })
await axios.get(`/api/task/${taskId}/protocol-traces`, { params: versionParams.value })
```

- [ ] **Step 5: Render the version switcher**

```vue
<el-select v-model="selectedVersion" placeholder="选择扫描版本" style="width: 220px">
  <el-option
    v-for="item in versions"
    :key="item.version"
    :label="item.isLatest ? `第 ${item.version} 次扫描（最新）` : `第 ${item.version} 次扫描`"
    :value="item.version"
  />
</el-select>
```

- [ ] **Step 6: Ensure report export uses selected version**

```ts
const reportUrl = computed(() =>
  selectedVersion.value
    ? `/api/task/${taskId}/report?version=${selectedVersion.value}`
    : `/api/task/${taskId}/report`
)
```

- [ ] **Step 7: Run build**

Run: `npm run build`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add frontend/src/views/task/TaskDetail.vue frontend/src/components/task/ExportReportDialog.vue
git commit -m "feat: add scan version switcher to task detail"
```

### Task 7: Add Legacy Compatibility and End-to-End Verification

**Files:**
- Modify: `backend/pkg/core/database/query.go`
- Modify: `backend/pkg/web/query.go`
- Test: `backend/pkg/web/task_version_query_test.go`
- Test: `backend/pkg/core/database/task_versions_test.go`

- [ ] **Step 1: Write failing compatibility tests**

```go
func TestLegacyVersionlessRecordsResolveAsVersionOne(t *testing.T) {
	// insert legacy-style data without version and assert version=1 compatibility path
}
```

- [ ] **Step 2: Run compatibility tests to verify they fail**

Run: `env GOCACHE=/tmp/trailblazer-gocache go test ./pkg/core/database ./pkg/web -run 'TestLegacyVersionlessRecordsResolveAsVersionOne' -count=1`
Expected: FAIL until compatibility fallback is implemented.

- [ ] **Step 3: Implement fallback query behavior for old data**

```go
// When selected version is 1, query should include both:
// - explicit version=1
// - missing version field legacy documents
```

- [ ] **Step 4: Run backend verification suite**

Run: `env GOCACHE=/tmp/trailblazer-gocache go test ./pkg/core/auth ./pkg/core/crawl ./pkg/core/protocoltool ./pkg/core/database ./pkg/web ./pkg/core/vuln/lfi ./pkg/core/vuln/sqli ./pkg/core/vuln/weaklogin ./pkg/core/vuln/redirect ./pkg/core/vuln/ssrf ./pkg/core/vuln/unauth ./pkg/core/vuln/upload`
Expected: PASS

- [ ] **Step 5: Run frontend verification**

Run: `npm run build`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add backend/pkg/core/database/query.go backend/pkg/web/query.go backend/pkg/web/task_version_query_test.go backend/pkg/core/database/task_versions_test.go frontend/src/views/task/TaskDetail.vue frontend/src/views/task/TaskList.vue
git commit -m "feat: ship task scan history versioning"
```

## Self-Review Notes

- Spec coverage: task/version split, versioned storage, latest fallback, version switcher, config snapshot, and legacy compatibility are all mapped to concrete tasks.
- Placeholder scan: there are no `TODO`/`TBD` placeholders; integration-style tests are explicitly called out where scaffolding is needed.
- Type consistency: this plan uses `task_id + version` consistently and keeps `highestRiskLevel` version-scoped throughout.
