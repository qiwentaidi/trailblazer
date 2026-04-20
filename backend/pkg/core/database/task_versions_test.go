package database

import "testing"

func TestCreateTaskVersionAllocatesIncreasingVersions(t *testing.T) {
	dbPath := t.TempDir() + "/task_versions.db"
	if err := InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if DB != nil {
			_ = DB.Close()
			DB = nil
		}
	})

	task := &Task{
		ID:       "task-version-test",
		Name:     "Versioned task",
		Targets:  []string{"https://example.com"},
		Status:   "pending",
		Progress: 0,
	}
	if _, err := task.Save(); err != nil {
		t.Fatalf("Task.Save() error = %v", err)
	}

	first, err := CreateTaskVersion(task.ID, task.Targets, []byte(`{"scan":"first"}`), "manual")
	if err != nil {
		t.Fatalf("CreateTaskVersion() first error = %v", err)
	}
	if first.Version != 1 {
		t.Fatalf("first version = %d, want 1", first.Version)
	}
	if !first.IsLatest {
		t.Fatalf("first version IsLatest = false, want true")
	}

	second, err := CreateTaskVersion(task.ID, task.Targets, []byte(`{"scan":"second"}`), "manual")
	if err != nil {
		t.Fatalf("CreateTaskVersion() second error = %v", err)
	}
	if second.Version != 2 {
		t.Fatalf("second version = %d, want 2", second.Version)
	}
	if !second.IsLatest {
		t.Fatalf("second version IsLatest = false, want true")
	}

	latest, err := GetLatestTaskVersion(task.ID)
	if err != nil {
		t.Fatalf("GetLatestTaskVersion() error = %v", err)
	}
	if latest == nil {
		t.Fatal("GetLatestTaskVersion() = nil, want version")
	}
	if latest.Version != 2 {
		t.Fatalf("latest version = %d, want 2", latest.Version)
	}
	if latest.TaskID != task.ID {
		t.Fatalf("latest TaskID = %q, want %q", latest.TaskID, task.ID)
	}
}

func TestHighestRiskLevelUpdateTargetsSelectedVersion(t *testing.T) {
	dbPath := t.TempDir() + "/task_versions.db"
	if err := InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if DB != nil {
			_ = DB.Close()
			DB = nil
		}
	})

	task := &Task{
		ID:       "task-version-risk-test",
		Name:     "Risk versioned task",
		Targets:  []string{"https://example.com"},
		Status:   "pending",
		Progress: 0,
	}
	if _, err := task.Save(); err != nil {
		t.Fatalf("Task.Save() error = %v", err)
	}

	first, err := CreateTaskVersion(task.ID, task.Targets, []byte(`{"scan":"first"}`), "manual")
	if err != nil {
		t.Fatalf("CreateTaskVersion() first error = %v", err)
	}
	second, err := CreateTaskVersion(task.ID, task.Targets, []byte(`{"scan":"second"}`), "manual")
	if err != nil {
		t.Fatalf("CreateTaskVersion() second error = %v", err)
	}

	if got := highestRiskLevelFromVulns([]VulnRecord{{Level: "info"}, {Level: "medium"}}); got != "medium" {
		t.Fatalf("highestRiskLevelFromVulns() = %q, want %q", got, "medium")
	}

	if err := UpdateTaskVersionHighestRiskLevelFromVulns(task.ID, first.Version, []VulnRecord{{Level: "info"}, {Level: "medium"}}); err != nil {
		t.Fatalf("UpdateTaskVersionHighestRiskLevelFromVulns() error = %v", err)
	}

	updatedFirst, err := GetTaskVersion(task.ID, first.Version)
	if err != nil {
		t.Fatalf("GetTaskVersion() first error = %v", err)
	}
	if updatedFirst == nil {
		t.Fatal("GetTaskVersion() first = nil, want version")
	}
	if updatedFirst.HighestRiskLevel != "medium" {
		t.Fatalf("first version highest risk = %q, want %q", updatedFirst.HighestRiskLevel, "medium")
	}

	updatedSecond, err := GetTaskVersion(task.ID, second.Version)
	if err != nil {
		t.Fatalf("GetTaskVersion() second error = %v", err)
	}
	if updatedSecond == nil {
		t.Fatal("GetTaskVersion() second = nil, want version")
	}
	if updatedSecond.HighestRiskLevel != "" {
		t.Fatalf("second version highest risk = %q, want empty", updatedSecond.HighestRiskLevel)
	}
}
