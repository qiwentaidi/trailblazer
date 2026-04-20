package web

import (
	"strings"
	"trailblazer/pkg/core/crawl"

	"github.com/gin-gonic/gin"
)

// getTaskStaticProtocolAnalysis 基于已存 JS 做静态协议分析
func getTaskStaticProtocolAnalysis(c *gin.Context) {
	taskID := c.Param("taskId")
	version, ok := parseTaskVersionQuery(c)
	if !ok {
		return
	}

	result, err := crawl.AnalyzeStoredJSProtocols(taskID, versionArgs(version)...)
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

	c.JSON(200, gin.H{"data": result})
}
