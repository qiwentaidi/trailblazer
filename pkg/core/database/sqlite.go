package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

// InitSQLite 初始化SQLite数据库
func InitSQLite(dbPath string) error {
	var err error
	DB, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open sqlite: %w", err)
	}

	// 创建表
	schema := `
	CREATE TABLE IF NOT EXISTS tasks (
		task_id TEXT PRIMARY KEY NOT NULL,
		name TEXT NOT NULL,
		targets TEXT NOT NULL,
		status TEXT NOT NULL,
		progress INTEGER DEFAULT 0,
		highest_risk_level TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT DEFAULT 'user',
		is_active BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
	CREATE INDEX IF NOT EXISTS idx_tasks_created ON tasks(created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);

	CREATE TABLE IF NOT EXISTS js_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		label TEXT NOT NULL,
		value TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_js_rules_created ON js_rules(created_at DESC);

	CREATE TABLE IF NOT EXISTS learned_auth_patterns (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		pattern TEXT NOT NULL UNIQUE,
		source TEXT DEFAULT '',
		hit_count INTEGER DEFAULT 1,
		enabled BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_learned_auth_patterns_enabled ON learned_auth_patterns(enabled, updated_at DESC);

	CREATE TABLE IF NOT EXISTS task_versions (
		task_id TEXT NOT NULL,
		version INTEGER NOT NULL,
		targets_snapshot TEXT NOT NULL,
		config_snapshot TEXT NOT NULL,
		status TEXT NOT NULL,
		progress INTEGER DEFAULT 0,
		highest_risk_level TEXT DEFAULT '',
		trigger_type TEXT NOT NULL,
		is_latest BOOLEAN DEFAULT 1,
		started_at DATETIME NOT NULL,
		finished_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (task_id, version)
	);
	CREATE INDEX IF NOT EXISTS idx_task_versions_task_created ON task_versions(task_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_task_versions_task_latest ON task_versions(task_id, is_latest);

	CREATE TABLE IF NOT EXISTS browser_sessions (
		session_id TEXT PRIMARY KEY NOT NULL,
		site_host TEXT NOT NULL,
		entry_url TEXT NOT NULL,
		status TEXT NOT NULL,
		mode TEXT NOT NULL,
		browser_mode TEXT DEFAULT '',
		proxy_type TEXT DEFAULT '',
		proxy_address TEXT DEFAULT '',
		browser_visible BOOLEAN DEFAULT 1,
		page_count INTEGER DEFAULT 0,
		request_count INTEGER DEFAULT 0,
		suspicious_crypto_count INTEGER DEFAULT 0,
		started_at DATETIME NOT NULL,
		ended_at DATETIME,
		last_activity_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_browser_sessions_started ON browser_sessions(started_at DESC);
	CREATE INDEX IF NOT EXISTS idx_browser_sessions_site_host ON browser_sessions(site_host, started_at DESC);
	CREATE INDEX IF NOT EXISTS idx_browser_sessions_status ON browser_sessions(status, started_at DESC);

	CREATE TABLE IF NOT EXISTS browser_pages (
		page_id TEXT PRIMARY KEY NOT NULL,
		session_id TEXT NOT NULL,
		url TEXT NOT NULL,
		title TEXT DEFAULT '',
		is_entry BOOLEAN DEFAULT 0,
		created_at DATETIME NOT NULL,
		last_seen_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_browser_pages_session_created ON browser_pages(session_id, created_at ASC);

	CREATE TABLE IF NOT EXISTS browser_session_requests (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL,
		trace_id TEXT DEFAULT '',
		url TEXT NOT NULL,
		method TEXT NOT NULL,
		resource_type TEXT DEFAULT '',
		request_headers TEXT DEFAULT '{}',
		request_body TEXT DEFAULT '',
		response_headers TEXT DEFAULT '{}',
		response_body TEXT DEFAULT '',
		response_code INTEGER DEFAULT 0,
		mime_type TEXT DEFAULT '',
		has_protocol_trace BOOLEAN DEFAULT 0,
		is_suspicious BOOLEAN DEFAULT 0,
		suspicious_trace TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_browser_session_requests_session_created ON browser_session_requests(session_id, created_at DESC, id DESC);

	CREATE TABLE IF NOT EXISTS browser_session_traces (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL,
		trace_id TEXT NOT NULL,
		request_url TEXT NOT NULL,
		method TEXT NOT NULL,
		algorithms TEXT NOT NULL,
		request_before_transform TEXT DEFAULT '',
		final_request_body TEXT DEFAULT '',
		request_steps TEXT DEFAULT '[]',
		response_steps TEXT DEFAULT '[]',
		session_materials TEXT DEFAULT '{}',
		response_plaintext TEXT DEFAULT '',
		response_ciphertext TEXT DEFAULT '',
		suspicious_reason TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_browser_session_traces_session_created ON browser_session_traces(session_id, created_at DESC);

	-- 扫描结果使用统一的文档表保留原有 JSON 结构，同时将常用过滤字段拆出并建立索引。
	CREATE TABLE IF NOT EXISTS scan_documents (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		kind TEXT NOT NULL,
		task_id TEXT NOT NULL,
		version INTEGER NOT NULL DEFAULT 0,
		identity TEXT DEFAULT '',
		parent_id TEXT DEFAULT '',
		level INTEGER DEFAULT 0,
		url TEXT DEFAULT '',
		trace_id TEXT DEFAULT '',
		created_at DATETIME,
		fetched_at DATETIME,
		body TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_scan_documents_task_kind_version ON scan_documents(task_id, kind, version);
	CREATE INDEX IF NOT EXISTS idx_scan_documents_kind_identity ON scan_documents(kind, identity);
	CREATE INDEX IF NOT EXISTS idx_scan_documents_task_url ON scan_documents(task_id, kind, url);
	CREATE INDEX IF NOT EXISTS idx_scan_documents_task_trace ON scan_documents(task_id, kind, trace_id);
	CREATE INDEX IF NOT EXISTS idx_scan_documents_tree_parent ON scan_documents(task_id, version, parent_id, level);
	`

	if _, err := DB.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	// 数据库迁移：确保 tasks 表包含 highest_risk_level 列
	if err := migrateTasksTable(); err != nil {
		log.Printf("警告: 迁移 tasks 表失败: %v", err)
	}
	if err := migrateBrowserSessionTracesTable(); err != nil {
		log.Printf("警告: 迁移 browser_session_traces 表失败: %v", err)
	}
	if err := migrateBrowserSessionRequestsTable(); err != nil {
		log.Printf("警告: 迁移 browser_session_requests 表失败: %v", err)
	}

	// 预置 JS 示例规则（仅在表为空时）
	var cnt int
	if err := DB.QueryRow("SELECT COUNT(1) FROM js_rules").Scan(&cnt); err == nil && cnt == 0 {
		samples := []struct{ label, value string }{
			{"JWT Token", `eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`},
			{"敏感Key/Token", `(access_?key|api_?key|secret_?key|token|access_?token)\s*[:=]\s*["']([^"'\s]{8,})["']`},
			{"手机号", `(^|[^0-9a-zA-Z.])(13[0-9]|14[01456879]|15[0-35-9]|16[2567]|17[0-8]|18[0-9]|19[0-35-9])\d{8}([^0-9a-zA-Z]|$)`},
			{"身份证号", `(^|[^0-9a-zA-Z])((\d{8}(0\d|10|11|12)([0-2]\d|30|31)\d{3}$)|(\d{6}(18|19|20)\d{2}(0[1-9]|10|11|12)([0-2]\d|30|31)\d{3}(\d|X|x)))([^0-9a-zA-Z]|$)`},
			{"邮箱地址", `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`},
			{"IP地址", `\b((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)\b`},
			{"URL(http/https)", `https?://[^\s"'<>]+`},
		}
		for _, s := range samples {
			_, _ = DB.Exec("INSERT INTO js_rules(label, value, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)", s.label, s.value)
		}
	}

	// WAL 能避免读取扫描结果时阻塞写入；busy_timeout 让并发采集更稳定。
	if _, err := DB.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON"); err != nil {
		return fmt.Errorf("failed to configure sqlite: %w", err)
	}

	log.Println("SQLite 初始化成功")
	return nil
}

// migrateTasksTable 迁移 tasks 表，确保最高风险等级列存在
func migrateTasksTable() error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	columns := []struct {
		name string
		sql  string
	}{
		{"highest_risk_level", "ALTER TABLE tasks ADD COLUMN highest_risk_level TEXT DEFAULT ''"},
	}

	for _, col := range columns {
		var count int
		err := DB.QueryRow(`
			SELECT COUNT(*) FROM pragma_table_info('tasks') WHERE name=?
		`, col.name).Scan(&count)
		if err != nil {
			log.Printf("警告: 检查字段 %s 失败: %v\n", col.name, err)
			continue
		}

		// 如果列不存在，则添加
		if count == 0 {
			_, err := DB.Exec(col.sql)
			if err != nil {
				log.Printf("警告: 新增字段 %s 失败: %v\n", col.name, err)
				continue
			}
			log.Printf("已向 tasks 表新增字段: %s\n", col.name)
		}
	}

	return nil
}

func migrateBrowserSessionTracesTable() error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	columns := []struct {
		name string
		sql  string
	}{
		{"request_steps", "ALTER TABLE browser_session_traces ADD COLUMN request_steps TEXT DEFAULT '[]'"},
		{"response_steps", "ALTER TABLE browser_session_traces ADD COLUMN response_steps TEXT DEFAULT '[]'"},
		{"session_materials", "ALTER TABLE browser_session_traces ADD COLUMN session_materials TEXT DEFAULT '{}'"},
	}

	for _, col := range columns {
		var count int
		err := DB.QueryRow(`
			SELECT COUNT(*) FROM pragma_table_info('browser_session_traces') WHERE name=?
		`, col.name).Scan(&count)
		if err != nil {
			log.Printf("警告: 检查 browser_session_traces 字段 %s 失败: %v\n", col.name, err)
			continue
		}

		if count == 0 {
			if _, err := DB.Exec(col.sql); err != nil {
				log.Printf("警告: 新增 browser_session_traces 字段 %s 失败: %v\n", col.name, err)
				continue
			}
			log.Printf("已向 browser_session_traces 表新增字段: %s\n", col.name)
		}
	}

	return nil
}

func migrateBrowserSessionRequestsTable() error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	columns := []struct {
		name string
		sql  string
	}{
		{"trace_id", "ALTER TABLE browser_session_requests ADD COLUMN trace_id TEXT DEFAULT ''"},
		{"resource_type", "ALTER TABLE browser_session_requests ADD COLUMN resource_type TEXT DEFAULT ''"},
		{"request_headers", "ALTER TABLE browser_session_requests ADD COLUMN request_headers TEXT DEFAULT '{}'"},
		{"request_body", "ALTER TABLE browser_session_requests ADD COLUMN request_body TEXT DEFAULT ''"},
		{"response_headers", "ALTER TABLE browser_session_requests ADD COLUMN response_headers TEXT DEFAULT '{}'"},
		{"response_body", "ALTER TABLE browser_session_requests ADD COLUMN response_body TEXT DEFAULT ''"},
		{"response_code", "ALTER TABLE browser_session_requests ADD COLUMN response_code INTEGER DEFAULT 0"},
		{"mime_type", "ALTER TABLE browser_session_requests ADD COLUMN mime_type TEXT DEFAULT ''"},
		{"has_protocol_trace", "ALTER TABLE browser_session_requests ADD COLUMN has_protocol_trace BOOLEAN DEFAULT 0"},
		{"is_suspicious", "ALTER TABLE browser_session_requests ADD COLUMN is_suspicious BOOLEAN DEFAULT 0"},
		{"suspicious_trace", "ALTER TABLE browser_session_requests ADD COLUMN suspicious_trace TEXT DEFAULT ''"},
	}

	for _, col := range columns {
		var count int
		err := DB.QueryRow(`
			SELECT COUNT(*) FROM pragma_table_info('browser_session_requests') WHERE name=?
		`, col.name).Scan(&count)
		if err != nil {
			log.Printf("警告: 检查 browser_session_requests 字段 %s 失败: %v\n", col.name, err)
			continue
		}

		if count == 0 {
			if _, err := DB.Exec(col.sql); err != nil {
				log.Printf("警告: 新增 browser_session_requests 字段 %s 失败: %v\n", col.name, err)
				continue
			}
			log.Printf("已向 browser_session_requests 表新增字段: %s\n", col.name)
		}
	}

	return nil
}

// JSRule 自定义JS搜索规则
type JSRule struct {
	ID        int64     `json:"id"`
	Label     string    `json:"label"`
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
}

// SaveJSRule 保存规则（新增）
func SaveJSRule(rule JSRule) (int64, error) {
	if DB == nil {
		return 0, fmt.Errorf("database not initialized")
	}
	res, err := DB.Exec(`INSERT INTO js_rules (label, value, created_at) VALUES (?, ?, ?)`, rule.Label, rule.Value, time.Now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetAllJSRules 获取全部规则
func GetAllJSRules() ([]JSRule, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	rows, err := DB.Query(`SELECT id, label, value, created_at FROM js_rules ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []JSRule
	for rows.Next() {
		var r JSRule
		if err := rows.Scan(&r.ID, &r.Label, &r.Value, &r.CreatedAt); err == nil {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

// DeleteJSRule 删除规则
func DeleteJSRule(id int64) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(`DELETE FROM js_rules WHERE id = ?`, id)
	return err
}

func ListEnabledLearnedAuthPatterns() ([]string, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := DB.Query(`SELECT pattern FROM learned_auth_patterns WHERE enabled = 1 ORDER BY hit_count DESC, updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var patterns []string
	for rows.Next() {
		var pattern string
		if err := rows.Scan(&pattern); err == nil {
			patterns = append(patterns, pattern)
		}
	}
	return patterns, nil
}

func UpsertLearnedAuthPattern(pattern, source string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	pattern = strings.TrimSpace(pattern)
	source = strings.TrimSpace(source)
	if pattern == "" {
		return nil
	}

	_, err := DB.Exec(`
		INSERT INTO learned_auth_patterns(pattern, source, hit_count, enabled, created_at, updated_at)
		VALUES (?, ?, 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(pattern) DO UPDATE SET
			source = CASE
				WHEN excluded.source <> '' THEN excluded.source
				ELSE learned_auth_patterns.source
			END,
			hit_count = learned_auth_patterns.hit_count + 1,
			enabled = 1,
			updated_at = CURRENT_TIMESTAMP
	`, pattern, source)
	return err
}

// SQLite 本地任务结构
type Task struct {
	ID               string    `json:"task_id"`
	Name             string    `json:"name"`
	Targets          []string  `json:"targets"`
	Status           string    `json:"status"`
	Progress         int       `json:"progress"`
	HighestRiskLevel string    `json:"highestRiskLevel"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

// TaskVersion SQLite中的任务版本快照
type TaskVersion struct {
	TaskID           string    `json:"task_id"`
	Version          int       `json:"version"`
	TargetsSnapshot  []string  `json:"targets_snapshot"`
	ConfigSnapshot   string    `json:"config_snapshot"`
	Status           string    `json:"status"`
	Progress         int       `json:"progress"`
	HighestRiskLevel string    `json:"highest_risk_level"`
	TriggerType      string    `json:"trigger_type"`
	IsLatest         bool      `json:"is_latest"`
	StartedAt        time.Time `json:"started_at"`
	FinishedAt       time.Time `json:"finished_at"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type taskVersionRowScanner interface {
	Scan(dest ...any) error
}

func scanTaskVersion(scanner taskVersionRowScanner) (*TaskVersion, error) {
	var version TaskVersion
	var targetsJSON string

	if err := scanner.Scan(
		&version.TaskID,
		&version.Version,
		&targetsJSON,
		&version.ConfigSnapshot,
		&version.Status,
		&version.Progress,
		&version.HighestRiskLevel,
		&version.TriggerType,
		&version.IsLatest,
		&version.StartedAt,
		&version.FinishedAt,
		&version.CreatedAt,
		&version.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if targetsJSON != "" {
		if err := json.Unmarshal([]byte(targetsJSON), &version.TargetsSnapshot); err != nil {
			return nil, err
		}
	}

	return &version, nil
}

func taskVersionTargetsJSON(targets []string) string {
	targetsJSON, _ := json.Marshal(targets)
	return string(targetsJSON)
}

// CreateTaskVersion 为任务创建一个新的版本快照
func CreateTaskVersion(taskID string, targets []string, configSnapshot []byte, triggerType string) (*TaskVersion, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	now := time.Now()
	finishedAt := time.Time{}
	tx, err := DB.Begin()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	var nextVersion int
	if err = tx.QueryRow(`
		SELECT COALESCE(MAX(version), 0) + 1
		FROM task_versions
		WHERE task_id=?
	`, taskID).Scan(&nextVersion); err != nil {
		return nil, err
	}

	if _, err = tx.Exec(`
		UPDATE task_versions
		SET is_latest=0, updated_at=?
		WHERE task_id=? AND is_latest=1
	`, now, taskID); err != nil {
		return nil, err
	}

	if _, err = tx.Exec(`
		INSERT INTO task_versions (
			task_id, version, targets_snapshot, config_snapshot, status, progress,
			highest_risk_level, trigger_type, is_latest, started_at, finished_at,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
	`, taskID, nextVersion, taskVersionTargetsJSON(targets), string(configSnapshot), "pending", 0, "", triggerType, now, finishedAt, now, now); err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	return GetTaskVersion(taskID, nextVersion)
}

// GetLatestTaskVersion 获取任务最新版本
func GetLatestTaskVersion(taskID string) (*TaskVersion, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	row := DB.QueryRow(`
		SELECT task_id, version, targets_snapshot, config_snapshot, status, progress,
		       highest_risk_level, trigger_type, is_latest, started_at, finished_at,
		       created_at, updated_at
		FROM task_versions
		WHERE task_id=?
		ORDER BY is_latest DESC, version DESC
		LIMIT 1
	`, taskID)

	version, err := scanTaskVersion(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return version, nil
}

// GetTaskVersion 获取指定版本
func GetTaskVersion(taskID string, version int) (*TaskVersion, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	row := DB.QueryRow(`
		SELECT task_id, version, targets_snapshot, config_snapshot, status, progress,
		       highest_risk_level, trigger_type, is_latest, started_at, finished_at,
		       created_at, updated_at
		FROM task_versions
		WHERE task_id=? AND version=?
	`, taskID, version)

	versionRow, err := scanTaskVersion(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return versionRow, nil
}

// ListTaskVersions 列出任务所有版本
func ListTaskVersions(taskID string) ([]TaskVersion, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := DB.Query(`
		SELECT task_id, version, targets_snapshot, config_snapshot, status, progress,
		       highest_risk_level, trigger_type, is_latest, started_at, finished_at,
		       created_at, updated_at
		FROM task_versions
		WHERE task_id=?
		ORDER BY created_at DESC, version DESC
	`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []TaskVersion
	for rows.Next() {
		version, err := scanTaskVersion(rows)
		if err != nil {
			continue
		}
		versions = append(versions, *version)
	}

	return versions, nil
}

// UpdateTaskVersionStatus 更新任务版本状态和进度
func UpdateTaskVersionStatus(taskID string, version int, status string, progress int) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := DB.Exec(`
		UPDATE task_versions
		SET status=?, progress=?, updated_at=?
		WHERE task_id=? AND version=?
	`, status, progress, time.Now(), taskID, version)
	return err
}

// UpdateTaskVersionHighestRiskLevel 更新任务版本最高风险等级
func UpdateTaskVersionHighestRiskLevel(taskID string, version int, level string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := DB.Exec(`
		UPDATE task_versions
		SET highest_risk_level=?, updated_at=?
		WHERE task_id=? AND version=?
	`, level, time.Now(), taskID, version)
	return err
}

// 更新任务记录
func (task *Task) Update() (string, error) {
	if DB == nil {
		return "", fmt.Errorf("database not initialized")
	}

	targetsJSON, _ := json.Marshal(task.Targets)
	_, err := DB.Exec(`
		UPDATE tasks 
		SET name=?, targets=?, status=?, progress=?, highest_risk_level=?, updated_at=?
		WHERE task_id=?
	`, task.Name, string(targetsJSON), task.Status, task.Progress, task.HighestRiskLevel, time.Now(), task.ID)

	if err != nil {
		fmt.Printf("[错误] 更新任务 \"%s\" 失败: %v\n", task.ID, err)
		return task.ID, err
	}

	fmt.Printf("[信息] 更新任务成功: ID=%s, Name=%s, Status=%s, Progress=%d\n", task.ID, task.Name, task.Status, task.Progress)
	return task.ID, err
}

// 只更新任务状态和进度（不覆盖其他字段）
func (task *Task) UpdateStatus(status string, progress int) (string, error) {
	if DB == nil {
		return "", fmt.Errorf("database not initialized")
	}

	_, err := DB.Exec(`
		UPDATE tasks 
		SET status=?, progress=?, updated_at=?
		WHERE task_id=?
	`, status, progress, time.Now(), task.ID)

	if err != nil {
		fmt.Printf("[错误] 更新任务状态 \"%s\" 失败: %v\n", task.ID, err)
		return task.ID, err
	}

	fmt.Printf("[信息] 更新任务状态成功: ID=%s, Status=%s, Progress=%d\n", task.ID, status, progress)
	return task.ID, nil
}

func highestRiskLevelFromVulns(vulns []VulnRecord) string {
	for _, level := range []string{"high", "medium", "low", "info"} {
		for _, vuln := range vulns {
			if vuln.Level == level {
				return level
			}
		}
	}
	return ""
}

// UpdateTaskHighestRiskLevel 仅同步任务的最高风险等级，不再维护漏洞计数。
func UpdateTaskHighestRiskLevel(taskID string) error {
	if DB == nil {
		return nil
	}

	vulns, err := QueryVulnsByTaskID(taskID)
	if err != nil {
		return nil
	}

	_, err = DB.Exec(`
		UPDATE tasks
		SET highest_risk_level=?, updated_at=?
		WHERE task_id=?
	`, highestRiskLevelFromVulns(vulns), time.Now(), taskID)
	if err != nil {
		fmt.Printf("[错误] 更新任务最高风险等级 \"%s\" 失败: %v\n", taskID, err)
		return err
	}

	return nil
}

// 保存任务，仅用于创建
func (task *Task) Save() (string, error) {
	if DB == nil {
		return "", fmt.Errorf("database not initialized")
	}

	targetsJSON, _ := json.Marshal(task.Targets)

	// 插入新任务
	_, err := DB.Exec(`
		INSERT INTO tasks (task_id, name, targets, status, progress, highest_risk_level, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, task.ID, task.Name, string(targetsJSON), task.Status, task.Progress, task.HighestRiskLevel, time.Now(), time.Now())

	if err != nil {
		fmt.Printf("[错误] 插入任务 \"%s\" 失败: %v\n", task.ID, err)
		return "", err
	}

	fmt.Printf("[信息] 插入新任务: ID=%s, Name=%s, Status=%s\n", task.ID, task.Name, task.Status)
	return task.ID, nil
}

// 删除SQLite中的任务记录
func (task *Task) Delete() error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := DB.Exec("DELETE FROM tasks WHERE task_id = ?", task.ID)
	if err != nil {
		fmt.Printf("[错误] 删除任务 \"%s\" 失败: %v\n", task.ID, err)
		return err
	}

	fmt.Printf("[信息] 删除任务成功: ID=%s\n", task.ID)
	return nil
}

// 获取所有任务
func GetAllTasks() ([]Task, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := DB.Query(`
		SELECT task_id, name, targets, status, progress, highest_risk_level, created_at, updated_at
		FROM tasks ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		var task Task
		var targetsJSON string

		err := rows.Scan(&task.ID, &task.Name, &targetsJSON, &task.Status, &task.Progress,
			&task.HighestRiskLevel, &task.CreatedAt, &task.UpdatedAt)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(targetsJSON), &task.Targets)
		tasks = append(tasks, task)
	}

	return tasks, nil
}

// GetTaskByID 根据任务 ID 获取单个任务
func GetTaskByID(taskID string) (*Task, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	row := DB.QueryRow(`
		SELECT task_id, name, targets, status, progress, highest_risk_level, created_at, updated_at
		FROM tasks
		WHERE task_id=?
		LIMIT 1
	`, taskID)

	var task Task
	var targetsJSON string
	if err := row.Scan(&task.ID, &task.Name, &targetsJSON, &task.Status, &task.Progress,
		&task.HighestRiskLevel, &task.CreatedAt, &task.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if targetsJSON != "" {
		if err := json.Unmarshal([]byte(targetsJSON), &task.Targets); err != nil {
			return nil, err
		}
	}

	return &task, nil
}

// GetTasksWithPagination 分页获取任务列表
func GetTasksWithPagination(offset, limit int) ([]Task, int, error) {
	if DB == nil {
		return nil, 0, fmt.Errorf("database not initialized")
	}

	// 获取总数
	var total int
	err := DB.QueryRow("SELECT COUNT(*) FROM tasks").Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// 获取分页数据
	rows, err := DB.Query(`
		SELECT task_id, name, targets, status, progress, highest_risk_level, created_at, updated_at
		FROM tasks ORDER BY created_at DESC LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		var task Task
		var targetsJSON string

		err := rows.Scan(&task.ID, &task.Name, &targetsJSON, &task.Status, &task.Progress,
			&task.HighestRiskLevel, &task.CreatedAt, &task.UpdatedAt)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(targetsJSON), &task.Targets)
		tasks = append(tasks, task)
	}

	return tasks, total, nil
}

// GetTasksByKeyword 根据关键词获取任务列表（不分页）
func GetTasksByKeyword(keyword string) ([]Task, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	trimmedKeyword := strings.TrimSpace(keyword)
	query := `
		SELECT task_id, name, targets, status, progress, highest_risk_level, created_at, updated_at
		FROM tasks
	`
	args := []any{}
	if trimmedKeyword != "" {
		pattern := "%" + strings.ToLower(trimmedKeyword) + "%"
		query += `
			WHERE lower(task_id) LIKE ? OR lower(name) LIKE ? OR lower(targets) LIKE ?
		`
		args = append(args, pattern, pattern, pattern)
	}
	query += " ORDER BY created_at DESC"

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		var task Task
		var targetsJSON string

		err := rows.Scan(&task.ID, &task.Name, &targetsJSON, &task.Status, &task.Progress,
			&task.HighestRiskLevel, &task.CreatedAt, &task.UpdatedAt)
		if err != nil {
			continue
		}

		_ = json.Unmarshal([]byte(targetsJSON), &task.Targets)
		tasks = append(tasks, task)
	}

	return tasks, nil
}

// SaveUser 保存用户到SQLite
func SaveUser(user User) (int64, error) {
	if DB == nil {
		return 0, fmt.Errorf("database not initialized")
	}

	if user.ID > 0 {
		// 更新
		_, err := DB.Exec(`
			UPDATE users 
			SET username=?, password=?, role=?, is_active=?, updated_at=?
			WHERE id=?
		`, user.Username, user.Password, user.Role, user.IsActive, time.Now(), user.ID)
		return user.ID, err
	}

	// 插入
	result, err := DB.Exec(`
		INSERT INTO users (username, password, role, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, user.Username, user.Password, user.Role, user.IsActive, time.Now(), time.Now())

	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// CountUsers 统计用户总数
func CountUsers() (int64, error) {
	if DB == nil {
		return 0, fmt.Errorf("database not initialized")
	}

	var count int64
	if err := DB.QueryRow(`SELECT COUNT(1) FROM users`).Scan(&count); err != nil {
		return 0, err
	}

	return count, nil
}

// GetUserByUsername 根据用户名获取用户
func GetUserByUsername(username string) (*User, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	var user User
	err := DB.QueryRow(`
		SELECT id, username, password, role, is_active, created_at, updated_at
		FROM users WHERE username = ? AND is_active = 1
	`, username).Scan(&user.ID, &user.Username, &user.Password, &user.Role, &user.IsActive, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // 用户不存在
		}
		return nil, err
	}

	return &user, nil
}

// UpdateUserPasswordByUsername 按用户名更新密码
func UpdateUserPasswordByUsername(username, hashedPassword string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := DB.Exec(`
		UPDATE users
		SET password=?, updated_at=?
		WHERE username=?
	`, hashedPassword, time.Now(), username)

	return err
}

// GetAllUsers 获取所有用户
func GetAllUsers() ([]User, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := DB.Query(`
		SELECT id, username, password, role, is_active, created_at, updated_at
		FROM users ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Password, &user.Role, &user.IsActive, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			continue
		}
		users = append(users, user)
	}

	return users, nil
}

// DeleteUser 删除用户
func DeleteUser(id int64) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := DB.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}
