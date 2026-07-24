package crawl

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	httputil "github.com/qiwentaidi/utils/http"

	"github.com/qiwentaidi/clients"
)

// SourceMap 是 .map 文件的结构（只关心需要的部分）
type SourceMap struct {
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

var outputPath = "./sourceMap"

func RestoreWebpack(sourceMapURL string) (string, error) {
	// 正确逻辑：必须以 .js.map 结尾
	if !strings.HasSuffix(sourceMapURL, ".js.map") {
		return "", fmt.Errorf("source map url must end with .js.map")
	}

	// 请求 map 文件
	data, err := clients.SimpleGet(sourceMapURL, clients.NewRestyClient(nil, true))
	if err != nil {
		return "", fmt.Errorf("读取 .map 文件失败: %w", err)
	}

	// 解析JSON
	var sm SourceMap
	if err := json.Unmarshal(data.Body(), &sm); err != nil {
		return "", fmt.Errorf("解析 .map JSON失败: %w", err)
	}

	if len(sm.Sources) != len(sm.SourcesContent) {
		return "", errors.New("sources 和 sourcesContent 长度不匹配")
	}

	// 恢复源码文件
	for i, sourcePath := range sm.Sources {
		content := sm.SourcesContent[i]

		// 去掉开头的 webpack://
		sourcePath = removeWebpackPrefix(sourcePath)

		// 最终的输出路径
		fullOutputPath := filepath.Join(outputPath, RenameOutput(httputil.GetBasicURL(sourceMapURL)), sourcePath)

		// 创建中间目录
		if err := os.MkdirAll(filepath.Dir(fullOutputPath), 0755); err != nil {
			fmt.Printf("[错误] 创建目录失败: %s，错误: %v\n", fullOutputPath, err)
			continue
		}

		// 写入文件
		if err := os.WriteFile(fullOutputPath, []byte(content), 0644); err != nil {
			fmt.Printf("[错误] 写入文件失败: %s，错误: %v\n", fullOutputPath, err)
			continue
		}
	}
	return outputPath, nil
}

// 移除路径前缀，例如 webpack://
func removeWebpackPrefix(path string) string {
	const prefix = "webpack://"
	if strings.HasPrefix(path, prefix) {
		return path[len(prefix):]
	}
	return path
}

// renameOutput 用于清理URL中的非法字符，以生成合法的文件名。
func RenameOutput(filename string) string {
	filename = strings.ReplaceAll(filename, ":", "_")
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "___", "_")
	return filename
}
