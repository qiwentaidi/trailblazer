package database

import (
	"encoding/json"
	"fmt"
	"strings"
)

var allowedVulnStatuses = map[string]struct{}{"open": {}, "resolved": {}, "ignored": {}}

func NormalizeVulnStatus(status string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(status))
	if normalized == "" {
		return "", fmt.Errorf("status is required")
	}
	if _, ok := allowedVulnStatuses[normalized]; !ok {
		return "", fmt.Errorf("unsupported status %q", status)
	}
	return normalized, nil
}

func UpdateVulnStatusByID(vulnID, status string) error {
	normalized, err := NormalizeVulnStatus(status)
	if err != nil {
		return err
	}
	if DB == nil {
		return fmt.Errorf("SQLite database not initialized")
	}
	rows, err := DB.Query("SELECT id, body FROM scan_documents WHERE kind = ? AND identity = ?", CollectionVuln, CleanUTF8Text(vulnID))
	if err != nil {
		return err
	}
	defer rows.Close()
	updated := 0
	for rows.Next() {
		var id int64
		var body string
		if err := rows.Scan(&id, &body); err != nil {
			return err
		}
		var vuln VulnRecord
		if err := json.Unmarshal([]byte(body), &vuln); err != nil {
			return fmt.Errorf("decode vulnerability %s: %w", vulnID, err)
		}
		vuln.Status = normalized
		cleaned, err := marshalUTF8Document(vuln)
		if err != nil {
			return err
		}
		if _, err := DB.Exec("UPDATE scan_documents SET body = ? WHERE id = ?", cleaned, id); err != nil {
			return err
		}
		updated++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if updated == 0 {
		return fmt.Errorf("vulnerability %s not found", vulnID)
	}
	return nil
}
