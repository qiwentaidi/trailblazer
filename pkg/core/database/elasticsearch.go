package database

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/config"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
)

// ESClient 全局客户端
var ESClient *elasticsearch.Client

func InitESClient(db config.Elasticsearch) {
	address := strings.TrimSpace(db.Address)
	transport, err := buildESTransport(address)
	if err != nil {
		log.Fatalf("创建 ES 网络传输失败: %v", err)
	}

	ESClient, err = elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{address}, // 如果启用了安全认证，加上 Username 和 Password
		Username:  db.Username,
		Password:  db.Password,
		Transport: transport,
	})
	if err != nil {
		log.Fatalf("创建 ES 客户端失败: %v", err)
	}

	// 确保所有必要的索引存在
	ensureAllIndices()
}

func buildESTransport(address string) (*http.Transport, error) {
	parsed, err := url.Parse(strings.TrimSpace(address))
	if err != nil {
		return nil, fmt.Errorf("无效的 ES 地址 %q: %w", address, err)
	}

	switch strings.ToLower(parsed.Scheme) {
	case "http":
		return &http.Transport{}, nil
	case "https":
		return &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}, nil
	default:
		return nil, fmt.Errorf("ES 地址必须使用 http 或 https scheme: %q", address)
	}
}

// ensureIndex 确保指定索引存在，如果不存在则创建
func ensureIndex(indexName string) error {
	res, err := ESClient.Indices.Exists([]string{indexName})
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode == 404 {
		// 索引不存在，创建索引
		createRes, err := ESClient.Indices.Create(indexName)
		if err != nil {
			return err
		}
		defer createRes.Body.Close()
		if createRes.IsError() {
			return fmt.Errorf("failed to create index %s: %s", indexName, createRes.String())
		}
		log.Printf("已创建索引: %s", indexName)
	}
	return nil
}

// ensureAllIndices 确保所有必要的索引都存在
func ensureAllIndices() {
	indices := []string{
		IndexSiteTree,               // trailblazer-sitetree
		IndexJS,                     // trailblazer-js
		IndexAPI,                    // trailblazer-api
		IndexProtocol,               // trailblazer-protocol
		IndexStaticProtocolAnalysis, // trailblazer-static-protocol
		IndexVuln,                   // trailblazer-vuln
		IndexAsset,                  // trailblazer-asset
	}

	for _, indexName := range indices {
		if err := ensureIndex(indexName); err != nil {
			log.Printf("确保索引 %s 存在失败: %v", indexName, err)
		}
	}
}

// InsertToES 插入结构体到 ES
// doc: 任意结构体
// indexPrefix: 索引前缀，例如 "logs" 或 "users"
// useDateSuffix: 是否在索引名加上日期，例如 logs-2025-09-26
func InsertToES(doc interface{}, indexPrefix string, useDateSuffix bool) error {
	indexName := indexPrefix
	if useDateSuffix {
		indexName = fmt.Sprintf("%s-%s", indexPrefix, time.Now().Format("2006-01-02"))
	}

	// 将结构体转为 JSON
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal doc: %w", err)
	}

	// 插入数据，不指定 ID，ES 会自动生成 UUID
	res, err := ESClient.Index(
		indexName,
		bytes.NewReader(data),
		ESClient.Index.WithContext(context.Background()),
	)
	if err != nil {
		return fmt.Errorf("failed to index document: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error response from ES: %s", res.String())
	}

	return nil
}
