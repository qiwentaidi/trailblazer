package database

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

var allowedVulnStatuses = map[string]struct{}{
	"open":     {},
	"resolved": {},
	"ignored":  {},
}

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
	if ESClient == nil {
		return fmt.Errorf("ES client not initialized")
	}

	normalizedStatus, err := NormalizeVulnStatus(status)
	if err != nil {
		return err
	}

	body := map[string]interface{}{
		"query": map[string]interface{}{
			"term": map[string]interface{}{
				"vuln_id.keyword": vulnID,
			},
		},
		"script": map[string]interface{}{
			"source": "ctx._source.status = params.status",
			"lang":   "painless",
			"params": map[string]interface{}{
				"status": normalizedStatus,
			},
		},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return fmt.Errorf("failed to encode update query: %v", err)
	}

	res, err := ESClient.UpdateByQuery(
		[]string{IndexVuln},
		ESClient.UpdateByQuery.WithContext(context.Background()),
		ESClient.UpdateByQuery.WithBody(&buf),
		ESClient.UpdateByQuery.WithRefresh(true),
	)
	if err != nil {
		return fmt.Errorf("failed to update vulnerability status: %v", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error response from ES when updating vulnerability status: %s", res.String())
	}

	var result struct {
		Updated int `json:"updated"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode update result: %v", err)
	}
	if result.Updated == 0 {
		return fmt.Errorf("vulnerability %s not found", vulnID)
	}

	return nil
}
