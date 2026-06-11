package web

import (
	"testing"
	"trailblazer/pkg/core/database"
)

func TestRebuildTreeWithURLsKeepsUniqueRootKeys(t *testing.T) {
	nodes := []database.SiteTreeNode{
		{
			NodeID:   "http_akso.caocaokeji.cn_0/0",
			ParentID: "0",
			Label:    "https://akso.caocaokeji.cn",
			URL:      "https://akso.caocaokeji.cn",
			Level:    1,
		},
		{
			NodeID:   "http_akso.caocaokeji.cn_0/0/1",
			ParentID: "0/0",
			Label:    "/login",
			URL:      "https://akso.caocaokeji.cn/login",
			Level:    2,
		},
		{
			NodeID:   "http_aq.caocaoglobal.com_0/0",
			ParentID: "0",
			Label:    "https://aq.caocaoglobal.com",
			URL:      "https://aq.caocaoglobal.com",
			Level:    1,
		},
		{
			NodeID:   "http_aq.caocaoglobal.com_0/0/1",
			ParentID: "0/0",
			Label:    "/dashboard",
			URL:      "https://aq.caocaoglobal.com/dashboard",
			Level:    2,
		},
	}

	tree := rebuildTreeWithURLs(nodes)
	if len(tree) != 2 {
		t.Fatalf("expected 2 roots, got %d", len(tree))
	}

	if tree[0].ID != "http_akso.caocaokeji.cn_0/0" {
		t.Fatalf("unexpected first root id: %s", tree[0].ID)
	}
	if len(tree[0].Children) != 1 || tree[0].Children[0].ID != "http_akso.caocaokeji.cn_0/0/1" {
		t.Fatalf("unexpected first root children: %#v", tree[0].Children)
	}

	if tree[1].ID != "http_aq.caocaoglobal.com_0/0" {
		t.Fatalf("unexpected second root id: %s", tree[1].ID)
	}
	if len(tree[1].Children) != 1 || tree[1].Children[0].ID != "http_aq.caocaoglobal.com_0/0/1" {
		t.Fatalf("unexpected second root children: %#v", tree[1].Children)
	}
}
