package database

import (
	"fmt"
	"strings"
)

// DeleteTaskData removes every SQLite-backed scan document belonging to a task.
func DeleteTaskData(taskID string) error {
	if _, err := deleteScanDocuments("task_id = ?", CleanUTF8Text(taskID)); err != nil {
		return fmt.Errorf("delete task scan data: %w", err)
	}
	return nil
}

func DeleteVulnByID(vulnID string) error {
	var taskID string
	if DB == nil {
		return fmt.Errorf("SQLite database not initialized")
	}
	_ = DB.QueryRow("SELECT task_id FROM scan_documents WHERE kind = ? AND identity = ? LIMIT 1", CollectionVuln, vulnID).Scan(&taskID)
	result, err := deleteScanDocuments("kind = ? AND identity = ?", CollectionVuln, CleanUTF8Text(vulnID))
	if err != nil {
		return err
	}
	deleted, _ := result.RowsAffected()
	if deleted == 0 {
		return fmt.Errorf("vulnerability %s not found", vulnID)
	}
	if taskID != "" {
		go func() { _ = UpdateTaskHighestRiskLevel(taskID) }()
	}
	return nil
}

func DeleteVulnsByIDs(taskID string, vulnIDs []string) error {
	if len(vulnIDs) == 0 {
		return nil
	}
	placeholders := make([]string, len(vulnIDs))
	args := make([]any, 0, len(vulnIDs)+2)
	args = append(args, CollectionVuln, CleanUTF8Text(taskID))
	for i, id := range vulnIDs {
		placeholders[i] = "?"
		args = append(args, CleanUTF8Text(id))
	}
	result, err := deleteScanDocuments("kind = ? AND task_id = ? AND identity IN ("+strings.Join(placeholders, ",")+")", args...)
	if err != nil {
		return err
	}
	deleted, _ := result.RowsAffected()
	if deleted == 0 {
		return fmt.Errorf("no vulnerabilities deleted")
	}
	if taskID != "" {
		go func() { _ = UpdateTaskHighestRiskLevel(taskID) }()
	}
	return nil
}
