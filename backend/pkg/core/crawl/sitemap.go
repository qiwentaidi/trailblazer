package crawl

import (
	"fmt"
	"net/url"
	"strings"
)

type SiteNode struct {
	Name     string               `json:"name"`
	Children map[string]*SiteNode `json:"children,omitempty"`
}

type ElTreeNode struct {
	ID       string       `json:"id"`
	Label    string       `json:"label"`
	Children []ElTreeNode `json:"children,omitempty"`
}

// 生成 Burp 样式树
func BuildSiteMap(urls []string) *SiteNode {
	root := &SiteNode{
		Name:     "root",
		Children: make(map[string]*SiteNode),
	}

	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}

		host := u.Scheme + "://" + u.Host
		if _, ok := root.Children[host]; !ok {
			root.Children[host] = &SiteNode{
				Name:     host,
				Children: make(map[string]*SiteNode),
			}
		}
		current := root.Children[host]

		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		for _, p := range parts {
			if p == "" {
				continue
			}
			if _, ok := current.Children[p]; !ok {
				current.Children[p] = &SiteNode{
					Name:     p,
					Children: make(map[string]*SiteNode),
				}
			}
			current = current.Children[p]
		}

		// 如果URL包含查询参数，将其作为子节点添加
		if u.RawQuery != "" {
			queryLabel := "?" + u.RawQuery
			if _, ok := current.Children[queryLabel]; !ok {
				current.Children[queryLabel] = &SiteNode{
					Name:     queryLabel,
					Children: make(map[string]*SiteNode),
				}
			}
		}
	}
	return root
}

// 转换为 el-tree-v2 数据结构
func toElTree(node *SiteNode, prefix string) []ElTreeNode {
	var result []ElTreeNode
	i := 0
	for _, child := range node.Children {
		id := fmt.Sprintf("%s/%d", prefix, i)
		elNode := ElTreeNode{
			ID:    id,
			Label: child.Name,
		}
		if len(child.Children) > 0 {
			elNode.Children = toElTree(child, id)
		}
		result = append(result, elNode)
		i++
	}
	return result
}

// BuildElTree 从 URL 列表构建 el-tree 所需的数据
func BuildElTree(urls []string) []ElTreeNode {
	root := BuildSiteMap(urls)
	return toElTree(root, "0")
}
