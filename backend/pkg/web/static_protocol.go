package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"trailblazer/pkg/core/database"
	"trailblazer/pkg/core/crawl"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/singleflight"
)

type staticProtocolAnalysisDocument struct {
	TaskID      string                        `json:"task_id"`
	Version     int                           `json:"version"`
	JSCount     int                           `json:"js_count"`
	Profiles    []crawl.StaticProtocolProfile `json:"profiles"`
	GeneratedAt time.Time                     `json:"generated_at"`
}

var (
	staticProtocolAnalysisGroup singleflight.Group
	analyzeStoredJSProtocols    = crawl.AnalyzeStoredJSProtocols
	queryStoredStaticProtocol   = queryStoredStaticProtocolAnalysis
	saveStoredStaticProtocol    = saveStaticProtocolAnalysis
)

func buildStaticProtocolAnalysisCacheKey(taskID string, version int) string {
	if version <= 0 {
		return taskID + ":latest-pending"
	}
	return fmt.Sprintf("%s:v%d", taskID, version)
}

func resolveStaticProtocolVersion(taskID string, version *int) (int, error) {
	if version != nil {
		return *version, nil
	}

	if database.DB == nil {
		return 0, nil
	}

	latest, err := database.GetLatestTaskVersion(taskID)
	if err != nil {
		return 0, err
	}
	if latest == nil {
		return 0, nil
	}
	return latest.Version, nil
}

func queryStoredStaticProtocolAnalysis(taskID string, version int) (*crawl.StaticProtocolAnalysisResult, bool, error) {
	if database.ESClient == nil {
		return nil, false, fmt.Errorf("ES client not initialized")
	}

	must := []map[string]interface{}{
		{
			"term": map[string]interface{}{
				"task_id.keyword": taskID,
			},
		},
	}
	if version > 0 {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{
				"version": version,
			},
		})
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": must,
			},
		},
		"size": 1,
		"sort": []map[string]interface{}{
			{"generated_at": map[string]interface{}{"order": "desc", "unmapped_type": "date", "missing": "_last"}},
		},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, false, err
	}

	res, err := database.ESClient.Search(
		database.ESClient.Search.WithContext(context.Background()),
		database.ESClient.Search.WithIndex(database.IndexStaticProtocolAnalysis),
		database.ESClient.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, false, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, false, fmt.Errorf("ES error: %s", res.String())
	}

	var result struct {
		Hits struct {
			Hits []struct {
				Source staticProtocolAnalysisDocument `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, false, err
	}
	if len(result.Hits.Hits) == 0 {
		return nil, false, nil
	}

	doc := result.Hits.Hits[0].Source
	return &crawl.StaticProtocolAnalysisResult{
		TaskID:      doc.TaskID,
		JSCount:     doc.JSCount,
		Profiles:    doc.Profiles,
		GeneratedAt: doc.GeneratedAt,
	}, true, nil
}

func saveStaticProtocolAnalysis(taskID string, version int, result *crawl.StaticProtocolAnalysisResult) error {
	if result == nil {
		return nil
	}
	if database.ESClient == nil {
		return fmt.Errorf("ES client not initialized")
	}

	return database.InsertToES(staticProtocolAnalysisDocument{
		TaskID:      taskID,
		Version:     version,
		JSCount:     result.JSCount,
		Profiles:    result.Profiles,
		GeneratedAt: result.GeneratedAt,
	}, database.IndexStaticProtocolAnalysis, false)
}

// getTaskStaticProtocolAnalysis 基于已存 JS 做静态协议分析
func getTaskStaticProtocolAnalysis(c *gin.Context) {
	taskID := c.Param("taskId")
	version, ok := parseTaskVersionQuery(c)
	if !ok {
		return
	}

	resolvedVersion, err := resolveStaticProtocolVersion(taskID, version)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to resolve task version", "detail": err.Error()})
		return
	}

	if cached, hit, err := queryStoredStaticProtocol(taskID, resolvedVersion); err == nil && hit {
		c.JSON(200, gin.H{"data": cached, "cached": true})
		return
	} else if err != nil &&
		!strings.Contains(err.Error(), "index_not_found_exception") &&
		!strings.Contains(err.Error(), "ES client not initialized") &&
		!strings.Contains(err.Error(), "connection") {
		c.JSON(500, gin.H{"error": "failed to query stored static protocol analysis", "detail": err.Error()})
		return
	}

	cacheKey := buildStaticProtocolAnalysisCacheKey(taskID, resolvedVersion)
	computed, err, _ := staticProtocolAnalysisGroup.Do(cacheKey, func() (interface{}, error) {
		if cached, hit, err := queryStoredStaticProtocol(taskID, resolvedVersion); err == nil && hit {
			return cached, nil
		} else if err != nil &&
			!strings.Contains(err.Error(), "index_not_found_exception") &&
			!strings.Contains(err.Error(), "ES client not initialized") &&
			!strings.Contains(err.Error(), "connection") {
			return nil, err
		}

		result, err := analyzeStoredJSProtocols(taskID, versionArgs(version)...)
		if err != nil {
			return nil, err
		}
		if err := saveStoredStaticProtocol(taskID, resolvedVersion, result); err != nil &&
			!strings.Contains(err.Error(), "ES client not initialized") &&
			!strings.Contains(err.Error(), "index_not_found_exception") &&
			!strings.Contains(err.Error(), "connection") {
			return nil, err
		}
		return result, nil
	})
	if err != nil {
		if strings.Contains(err.Error(), "index_not_found_exception") ||
			strings.Contains(err.Error(), "ES client not initialized") ||
			strings.Contains(err.Error(), "connection") {
			c.JSON(200, gin.H{"data": gin.H{
				"task_id":      taskID,
				"js_count":     0,
				"profiles":     []interface{}{},
				"generated_at": nil,
			}})
			return
		}
		c.JSON(500, gin.H{"error": "failed to analyze stored JS", "detail": err.Error()})
		return
	}

	result, _ := computed.(*crawl.StaticProtocolAnalysisResult)
	c.JSON(200, gin.H{"data": result, "cached": false})
}
