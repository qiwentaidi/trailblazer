package database

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

// DeleteTaskData 删除任务相关的所有ES数据
func DeleteTaskData(taskID string) error {
	if ESClient == nil {
		return fmt.Errorf("ES client not initialized")
	}

	// 删除查询条件
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"term": map[string]interface{}{
				"task_id.keyword": taskID,
			},
		},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return err
	}

	// 删除各个索引中的数据
	indices := []string{
		IndexSiteTree,
		IndexJS,
		IndexVuln,
		IndexAsset,
	}

	for _, index := range indices {
		// 先检查索引是否存在
		existsRes, err := ESClient.Indices.Exists([]string{index})
		if err != nil {
			fmt.Printf("[ERROR] Failed to check index %s: %v\n", index, err)
			continue
		}
		existsRes.Body.Close()

		if existsRes.StatusCode == 404 {
			// 索引不存在，跳过
			continue
		}

		res, err := ESClient.DeleteByQuery(
			[]string{index},
			bytes.NewReader(buf.Bytes()),
			ESClient.DeleteByQuery.WithContext(context.Background()),
		)

		if err != nil {
			fmt.Printf("[ERROR] Failed to delete from %s: %v\n", index, err)
			continue
		}

		defer res.Body.Close()

		if res.IsError() {
			fmt.Printf("[WARNING] Error response from ES when deleting %s: %s\n", index, res.String())
		} else {
			var result map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&result); err == nil {
				deleted := result["deleted"]
				if deleted != nil && deleted != 0 {
					fmt.Printf("[INFO] Deleted %v documents from %s for task %s\n", deleted, index, taskID)
				}
			}
		}
	}

	return nil
}

// DeleteVulnByID 删除指定的漏洞记录
func DeleteVulnByID(vulnID string) error {
	if ESClient == nil {
		return fmt.Errorf("ES client not initialized")
	}

	searchQuery := map[string]interface{}{
		"query": map[string]interface{}{
			"term": map[string]interface{}{
				"vuln_id.keyword": vulnID,
			},
		},
		"size": 1,
	}

	var searchBuf bytes.Buffer
	if err := json.NewEncoder(&searchBuf).Encode(searchQuery); err != nil {
		return fmt.Errorf("failed to encode search query: %v", err)
	}

	searchRes, err := ESClient.Search(
		ESClient.Search.WithContext(context.Background()),
		ESClient.Search.WithIndex(IndexVuln),
		ESClient.Search.WithBody(&searchBuf),
	)
	if err != nil {
		return fmt.Errorf("failed to search vuln %s: %v", vulnID, err)
	}
	defer searchRes.Body.Close()

	taskID := ""
	if !searchRes.IsError() {
		var searchResult struct {
			Hits struct {
				Hits []struct {
					Source VulnRecord `json:"_source"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if err := json.NewDecoder(searchRes.Body).Decode(&searchResult); err == nil && len(searchResult.Hits.Hits) > 0 {
			taskID = searchResult.Hits.Hits[0].Source.TaskID
		}
	}

	// 删除查询条件
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"term": map[string]interface{}{
				"vuln_id.keyword": vulnID,
			},
		},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return err
	}

	// 先检查索引是否存在
	existsRes, err := ESClient.Indices.Exists([]string{IndexVuln})
	if err != nil {
		return fmt.Errorf("failed to check index %s: %v", IndexVuln, err)
	}
	existsRes.Body.Close()

	if existsRes.StatusCode == 404 {
		return fmt.Errorf("index %s does not exist", IndexVuln)
	}

	res, err := ESClient.DeleteByQuery(
		[]string{IndexVuln},
		bytes.NewReader(buf.Bytes()),
		ESClient.DeleteByQuery.WithContext(context.Background()),
	)

	if err != nil {
		return fmt.Errorf("failed to delete vuln %s: %v", vulnID, err)
	}

	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error response from ES when deleting vuln %s: %s", vulnID, res.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode delete result: %v", err)
	}

	deleted := result["deleted"]
	if deleted == nil || deleted == float64(0) {
		return fmt.Errorf("vulnerability %s not found", vulnID)
	}

	if taskID != "" {
		go func() {
			if err := UpdateTaskHighestRiskLevel(taskID); err != nil {
				fmt.Printf("[WARNING] Failed to update highest risk level for task %s after deleting vuln %s: %v\n", taskID, vulnID, err)
			}
		}()
	}

	return nil
}

// DeleteVulnsByIDs 批量删除指定漏洞记录
func DeleteVulnsByIDs(taskID string, vulnIDs []string) error {
	if ESClient == nil {
		return fmt.Errorf("ES client not initialized")
	}
	if len(vulnIDs) == 0 {
		return nil
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"terms": map[string]interface{}{
				"vuln_id.keyword": vulnIDs,
			},
		},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return err
	}

	existsRes, err := ESClient.Indices.Exists([]string{IndexVuln})
	if err != nil {
		return fmt.Errorf("failed to check index %s: %v", IndexVuln, err)
	}
	existsRes.Body.Close()

	if existsRes.StatusCode == 404 {
		return fmt.Errorf("index %s does not exist", IndexVuln)
	}

	res, err := ESClient.DeleteByQuery(
		[]string{IndexVuln},
		bytes.NewReader(buf.Bytes()),
		ESClient.DeleteByQuery.WithContext(context.Background()),
	)
	if err != nil {
		return fmt.Errorf("failed to delete vulns: %v", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error response from ES when deleting vulns: %s", res.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode delete result: %v", err)
	}

	deleted := result["deleted"]
	if deleted == nil || deleted == float64(0) {
		return fmt.Errorf("no vulnerabilities deleted")
	}

	if taskID != "" {
		go func() {
			if err := UpdateTaskHighestRiskLevel(taskID); err != nil {
				fmt.Printf("[WARNING] Failed to update highest risk level for task %s after batch delete: %v\n", taskID, err)
			}
		}()
	}

	return nil
}

// // DeleteTaskDataBatch 批量删除多个任务的ES数据
// func DeleteTaskDataBatch(taskIDs []string) error {
// 	if ESClient == nil {
// 		return fmt.Errorf("ES client not initialized")
// 	}

// 	if len(taskIDs) == 0 {
// 		return nil
// 	}

// 	// 构建批量删除查询
// 	query := map[string]interface{}{
// 		"query": map[string]interface{}{
// 			"terms": map[string]interface{}{
// 				"task_id.keyword": taskIDs,
// 			},
// 		},
// 	}

// 	var buf bytes.Buffer
// 	if err := json.NewEncoder(&buf).Encode(query); err != nil {
// 		return err
// 	}

// 	indices := []string{
// 		IndexSiteTree,
// 		IndexJS,
// 		IndexVuln,
// 	}

// 	for _, index := range indices {
// 		res, err := ESClient.DeleteByQuery(
// 			[]string{index},
// 			bytes.NewReader(buf.Bytes()),
// 			ESClient.DeleteByQuery.WithContext(context.Background()),
// 		)

// 		if err != nil {
// 			fmt.Printf("[ERROR] Failed to batch delete from %s: %v\n", index, err)
// 			continue
// 		}

// 		defer res.Body.Close()

// 		if !res.IsError() {
// 			var result map[string]interface{}
// 			if err := json.NewDecoder(res.Body).Decode(&result); err == nil {
// 				deleted := result["deleted"]
// 				fmt.Printf("[INFO] Batch deleted %v documents from %s\n", deleted, index)
// 			}
// 		}
// 	}

// 	return nil
// }
