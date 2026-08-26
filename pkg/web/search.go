package web

import (
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type SearchMatch struct {
	Line         int    `json:"line"`
	Content      string `json:"content"`
	MatchStart   int    `json:"matchStart"`
	MatchEnd     int    `json:"matchEnd"`
	OriginalText string `json:"originalText"` // 原始匹配的文本
}

type SearchResult struct {
	ID           string        `json:"id"`
	URL          string        `json:"url"`
	TaskID       string        `json:"taskId"`
	Matches      []SearchMatch `json:"matches"`
	TotalMatches int           `json:"totalMatches"`
}

// searchJSContent 在JS内容中搜索
func searchJSContent(c *gin.Context) {
	var body struct {
		Pattern       string `json:"pattern"`
		IsRegex       bool   `json:"isRegex"`
		CaseSensitive bool   `json:"caseSensitive"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}

	if body.Pattern == "" {
		c.JSON(400, gin.H{"error": "pattern is required"})
		return
	}

	if database.DB == nil {
		c.JSON(500, gin.H{"error": "SQLite database not initialized"})
		return
	}

	var results []SearchResult
	seenResultURLs := make(map[string]struct{})

	// 编译搜索模式
	var re *regexp.Regexp
	var err error
	if body.IsRegex {
		flags := ""
		if !body.CaseSensitive {
			flags = "(?i)"
		}
		pattern := flags + body.Pattern
		re, err = regexp.Compile(pattern)
		if err != nil {
			c.JSON(400, gin.H{"error": "invalid regex pattern", "detail": err.Error()})
			return
		}
	}

	const batchSize = 25
	const maxScanDocs = 1000
	for offset := 0; offset < maxScanDocs; offset += batchSize {
		jsResources, queryErr := database.QueryJSBatch(offset, batchSize)
		if queryErr != nil {
			c.JSON(500, gin.H{"error": "failed to query JS resources", "detail": queryErr.Error()})
			return
		}
		if len(jsResources) == 0 {
			break
		}

		// 遍历当前批次的 JS 文件进行搜索
		for _, js := range jsResources {
			if _, exists := seenResultURLs[js.URL]; exists {
				continue
			}

			matches := []SearchMatch{}

			// 先对整个内容进行匹配（获取所有匹配位置）
			var allMatchIndices [][]int

			if body.IsRegex {
				allMatchIndices = re.FindAllStringIndex(js.Content, -1)
			} else {
				// 简单字符串搜索
				searchStr := body.Pattern
				compareStr := js.Content
				if !body.CaseSensitive {
					searchStr = strings.ToLower(searchStr)
					compareStr = strings.ToLower(js.Content)
				}

				startIdx := 0
				for {
					idx := strings.Index(compareStr[startIdx:], searchStr)
					if idx == -1 {
						break
					}
					actualIdx := startIdx + idx
					allMatchIndices = append(allMatchIndices, []int{actualIdx, actualIdx + len(searchStr)})
					startIdx = actualIdx + len(searchStr)
				}
			}

			// 如果有匹配，计算每个匹配所在的行号和行内容
			if len(allMatchIndices) > 0 {
				lines := strings.Split(js.Content, "\n")

				// 计算每行的起始位置
				lineStarts := make([]int, len(lines))
				pos := 0
				for i, line := range lines {
					lineStarts[i] = pos
					pos += len(line) + 1 // +1 for newline
				}

				// 限制返回数量，避免前端性能问题
				maxMatches := 30
				if len(allMatchIndices) > maxMatches {
					allMatchIndices = allMatchIndices[:maxMatches]
				}

				// 为每个匹配找到对应的行
				for _, indices := range allMatchIndices {
					matchStart := indices[0]
					matchEnd := indices[1]

					// 找到匹配所在的行
					lineNum := 0
					for i, start := range lineStarts {
						if i+1 < len(lineStarts) && matchStart >= start && matchStart < lineStarts[i+1] {
							lineNum = i + 1
							break
						} else if i+1 >= len(lineStarts) && matchStart >= start {
							lineNum = i + 1
							break
						}
					}

					if lineNum == 0 {
						continue
					}

					if lineNum > 0 && lineNum <= len(lines) {
						line := lines[lineNum-1]
						lineStart := lineStarts[lineNum-1]

						// 计算匹配在行内的相对位置
						relativeStart := matchStart - lineStart
						relativeEnd := matchEnd - lineStart

						// 如果匹配跨行，只显示第一行
						if relativeEnd > len(line) {
							relativeEnd = len(line)
						}

						// 验证相对位置是否合法
						if relativeStart < 0 || relativeStart >= len(line) {
							continue // 跳过无效的匹配
						}
						if relativeEnd < 0 || relativeEnd > len(line) {
							relativeEnd = len(line)
						}
						if relativeEnd <= relativeStart {
							continue // 跳过无效的匹配
						}

						// 验证匹配内容是否正确
						actualMatch := line[relativeStart:relativeEnd]
						expectedMatch := js.Content[matchStart:matchEnd]
						if actualMatch != expectedMatch {
							// 如果匹配内容不一致，尝试重新计算位置
							// 在行内直接搜索匹配的文本
							lineMatchStart := strings.Index(line, expectedMatch)
							if lineMatchStart >= 0 {
								relativeStart = lineMatchStart
								relativeEnd = lineMatchStart + len(expectedMatch)
							}
						}

						// 对于超长行，直接从原始内容中截取匹配周围的内容
						maxContextLength := 100 // 匹配前后各显示100个字符

						// 直接从原始JS内容中截取
						displayStart := matchStart - maxContextLength
						if displayStart < 0 {
							displayStart = 0
						}
						displayEnd := matchEnd + maxContextLength
						if displayEnd > len(js.Content) {
							displayEnd = len(js.Content)
						}

						// 构建显示内容
						before := js.Content[displayStart:matchStart]
						match := js.Content[matchStart:matchEnd]
						after := js.Content[matchEnd:displayEnd]

						content := ""
						if displayStart > 0 {
							content += "..."
						}
						content += before + match + after
						if displayEnd < len(js.Content) {
							content += "..."
						}

						// 计算在截断后内容中的正确位置
						adjustedStart := len(before)
						if displayStart > 0 {
							adjustedStart += 3 // "..." 的长度
						}
						adjustedEnd := adjustedStart + len(match)

						matches = append(matches, SearchMatch{
							Line:         lineNum,
							Content:      content,
							MatchStart:   adjustedStart,
							MatchEnd:     adjustedEnd,
							OriginalText: js.Content[matchStart:matchEnd], // 原始匹配文本
						})
					}
				}
			}

			if len(matches) > 0 {
				seenResultURLs[js.URL] = struct{}{}
				results = append(results, SearchResult{
					ID:           fmt.Sprintf("%s-%s", js.TaskID, js.URL),
					URL:          js.URL,
					TaskID:       js.TaskID,
					Matches:      matches,
					TotalMatches: len(matches),
				})
			}
		}

		if len(jsResources) < batchSize {
			break
		}
	}

	c.JSON(200, gin.H{"data": results})
}

// 自定义JS搜索规则 API（SQLite 持久化）
func getJSRules(c *gin.Context) {
	rules, err := database.GetAllJSRules()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"data": rules})
}

func createJSRule(c *gin.Context) {
	var body struct {
		Label string `json:"label"`
		Value string `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Label) == "" || strings.TrimSpace(body.Value) == "" {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}
	id, err := database.SaveJSRule(database.JSRule{Label: body.Label, Value: body.Value})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"data": gin.H{"id": id}})
}

func deleteJSRule(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id"})
		return
	}
	if err := database.DeleteJSRule(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"data": true})
}
