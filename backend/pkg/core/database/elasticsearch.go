package database

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"trailblazer/pkg/config"

	"github.com/elastic/go-elasticsearch/v8"
)

// ESClient 全局客户端
var ESClient *elasticsearch.Client

func InitESClient(db config.Elasticsearch) {
	var err error
	ESClient, err = elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{db.Address}, // 如果启用了安全认证，加上 Username 和 Password
		Username:  db.Username,
		Password:  db.Password,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 忽略自签名证书验证
			},
		},
	})
	if err != nil {
		log.Fatalf("Failed to create ES client: %v", err)
	}

	// 确保所有必要的索引存在
	ensureAllIndices()
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
		log.Printf("Index created: %s", indexName)
	}
	return nil
}

// ensureAllIndices 确保所有必要的索引都存在
func ensureAllIndices() {
	indices := []string{
		IndexSiteTree, // trailblazer-sitetree
		IndexJS,       // trailblazer-js
		IndexAPI,      // trailblazer-api
		IndexProtocol, // trailblazer-protocol
		IndexStaticProtocolAnalysis, // trailblazer-static-protocol
		IndexVuln,     // trailblazer-vuln
		IndexAsset,    // trailblazer-asset
	}

	for _, indexName := range indices {
		if err := ensureIndex(indexName); err != nil {
			log.Printf("Failed to ensure index %s: %v", indexName, err)
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
