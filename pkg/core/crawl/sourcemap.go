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

	mapOutputRoot, err := filepath.Abs(filepath.Join(outputPath, RenameOutput(httputil.GetBasicURL(sourceMapURL))))
	if err != nil {
		return "", fmt.Errorf("解析 source map 输出目录失败: %w", err)
	}

	// 恢复源码文件
	for i, sourcePath := range sm.Sources {
		content := sm.SourcesContent[i]

		// 去掉开头的 webpack://
		fullOutputPath, err := resolveSourceMapOutputPath(mapOutputRoot, sourcePath)
		if err != nil {
			fmt.Printf("[警告] 忽略越界 source map 路径: %q，错误: %v\n", sourcePath, err)
			continue
		}

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

func resolveSourceMapOutputPath(outputRoot, sourcePath string) (string, error) {
	sourcePath = removeWebpackPrefix(sourcePath)
	if strings.TrimSpace(sourcePath) == "" {
		return "", errors.New("source map 路径为空")
	}

	sourcePath = filepath.FromSlash(sourcePath)
	if filepath.IsAbs(sourcePath) {
		return "", errors.New("source map 路径不能是绝对路径")
	}

	root, err := filepath.Abs(outputRoot)
	if err != nil {
		return "", fmt.Errorf("解析 source map 根目录失败: %w", err)
	}
	candidate, err := filepath.Abs(filepath.Join(root, filepath.Clean(sourcePath)))
	if err != nil {
		return "", fmt.Errorf("解析 source map 文件路径失败: %w", err)
	}

	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return "", fmt.Errorf("校验 source map 文件路径失败: %w", err)
	}
	if relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("source map 路径超出输出目录")
	}

	return candidate, nil
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
