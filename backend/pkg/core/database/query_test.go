package database

import "testing"

func TestQueryTaskByIDFallsBackToSQLiteAndAppliesLatestVersion(t *testing.T) {
	dbPath := t.TempDir() + "/query_task.db"
	if err := InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if DB != nil {
			_ = DB.Close()
			DB = nil
		}
		ESClient = nil
	})

	task := &Task{
		ID:       "task-query-test",
		Name:     "Query task",
		Targets:  []string{"https://example.com"},
		Status:   "pending",
		Progress: 0,
	}
	if _, err := task.Save(); err != nil {
		t.Fatalf("Task.Save() error = %v", err)
	}

	if _, err := CreateTaskVersion(task.ID, []string{"https://version.example.com"}, []byte(`{"k":"v"}`), "manual"); err != nil {
		t.Fatalf("CreateTaskVersion() error = %v", err)
	}
	if err := UpdateTaskVersionStatus(task.ID, 1, "completed", 100); err != nil {
		t.Fatalf("UpdateTaskVersionStatus() error = %v", err)
	}

	got, err := QueryTaskByID(task.ID)
	if err != nil {
		t.Fatalf("QueryTaskByID() error = %v", err)
	}
	if got == nil {
		t.Fatal("QueryTaskByID() = nil, want task")
	}
	if got.TaskID != task.ID {
		t.Fatalf("TaskID = %q, want %q", got.TaskID, task.ID)
	}
	if got.TaskName != task.Name {
		t.Fatalf("TaskName = %q, want %q", got.TaskName, task.Name)
	}
	if got.Status != "completed" {
		t.Fatalf("Status = %q, want completed", got.Status)
	}
	if len(got.Targets) != 1 || got.Targets[0] != "https://version.example.com" {
		t.Fatalf("Targets = %#v, want version snapshot", got.Targets)
	}
}
