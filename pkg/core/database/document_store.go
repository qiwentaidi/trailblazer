package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	CollectionSiteTree = "site_tree"
	CollectionJS       = "js"
	CollectionAPI      = "api"
	CollectionProtocol = "protocol"
	CollectionVuln     = "vuln"
	CollectionAsset    = "asset"
)

// CleanUTF8Text converts malformed byte sequences to the Unicode replacement
// character, removes an accidental BOM, and normalizes line endings. SQLite
// stores TEXT as UTF-8, so applying it before every document write keeps both
// JSON decoding and subsequent LIKE searches deterministic.
func CleanUTF8Text(value string) string {
	value = strings.TrimPrefix(value, "\ufeff")
	value = strings.ToValidUTF8(value, "\uFFFD")
	return strings.ReplaceAll(strings.ReplaceAll(value, "\r\n", "\n"), "\r", "\n")
}

func cleanUTF8JSON(value any) any {
	switch current := value.(type) {
	case string:
		return CleanUTF8Text(current)
	case []any:
		for i := range current {
			current[i] = cleanUTF8JSON(current[i])
		}
	case map[string]any:
		cleaned := make(map[string]any, len(current))
		for key, item := range current {
			cleaned[CleanUTF8Text(key)] = cleanUTF8JSON(item)
		}
		return cleaned
	}
	return value
}

func marshalUTF8Document(document any) (string, error) {
	raw, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return "", err
	}
	cleaned, err := json.Marshal(cleanUTF8JSON(decoded))
	if err != nil {
		return "", err
	}
	if !utf8.Valid(cleaned) {
		return "", fmt.Errorf("failed to produce valid UTF-8 JSON")
	}
	return string(cleaned), nil
}

type scanDocumentFields struct {
	kind, taskID, identity, parentID, url, traceID string
	version, level                                 int
	createdAt, fetchedAt                           time.Time
}

func saveScanDocument(fields scanDocumentFields, document any) error {
	if DB == nil {
		return fmt.Errorf("SQLite database not initialized")
	}
	if strings.TrimSpace(fields.taskID) == "" {
		return fmt.Errorf("task_id is required")
	}
	body, err := marshalUTF8Document(document)
	if err != nil {
		return fmt.Errorf("marshal scan document: %w", err)
	}
	_, err = DB.Exec(`INSERT INTO scan_documents
		(kind, task_id, version, identity, parent_id, level, url, trace_id, created_at, fetched_at, body)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fields.kind, CleanUTF8Text(fields.taskID), fields.version,
		CleanUTF8Text(fields.identity), CleanUTF8Text(fields.parentID), fields.level,
		CleanUTF8Text(fields.url), CleanUTF8Text(fields.traceID), fields.createdAt, fields.fetchedAt, body)
	return err
}

func versionPredicate(version *int, args *[]any) string {
	if version == nil {
		return ""
	}
	if *version == 1 {
		*args = append(*args, 1)
		return " AND version IN (?, 0)"
	}
	*args = append(*args, *version)
	return " AND version = ?"
}

func queryDocumentBodies(kind, taskID string, version *int, orderBy string, limit, offset int) ([]string, error) {
	if DB == nil {
		return nil, fmt.Errorf("SQLite database not initialized")
	}
	args := []any{kind}
	query := "SELECT body FROM scan_documents WHERE kind = ?"
	if taskID != "" {
		query += " AND task_id = ?"
		args = append(args, taskID)
	}
	query += versionPredicate(version, &args)
	if orderBy != "" {
		query += " ORDER BY " + orderBy
	}
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
		if offset > 0 {
			query += " OFFSET ?"
			args = append(args, offset)
		}
	}
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bodies := make([]string, 0)
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		bodies = append(bodies, body)
	}
	return bodies, rows.Err()
}

func loadScanDocuments[T any](kind, taskID string, version *int, orderBy string, limit, offset int) ([]T, error) {
	bodies, err := queryDocumentBodies(kind, taskID, version, orderBy, limit, offset)
	if err != nil {
		return nil, err
	}
	items := make([]T, 0, len(bodies))
	for _, body := range bodies {
		var item T
		if err := json.Unmarshal([]byte(body), &item); err != nil {
			return nil, fmt.Errorf("decode stored %s document: %w", kind, err)
		}
		items = append(items, item)
	}
	return items, nil
}

func deleteScanDocuments(where string, args ...any) (sql.Result, error) {
	if DB == nil {
		return nil, fmt.Errorf("SQLite database not initialized")
	}
	return DB.Exec("DELETE FROM scan_documents WHERE "+where, args...)
}

// SaveJSONDocument is for feature-specific cached results that do not warrant a
// dedicated relational table. The common task/version metadata remains indexed.
func SaveJSONDocument(kind, taskID string, version int, identity string, createdAt time.Time, document any) error {
	return saveScanDocument(scanDocumentFields{
		kind: kind, taskID: taskID, version: version, identity: identity, createdAt: createdAt,
	}, document)
}

// LoadJSONDocuments returns cleaned JSON documents for a collection. Callers
// decode into their feature-local type, avoiding a database-to-feature import.
func LoadJSONDocuments(kind, taskID string, version *int, limit int) ([]json.RawMessage, error) {
	bodies, err := queryDocumentBodies(kind, taskID, version, "created_at DESC, id DESC", limit, 0)
	if err != nil { return nil, err }
	result := make([]json.RawMessage, 0, len(bodies))
	for _, body := range bodies { result = append(result, json.RawMessage(body)) }
	return result, nil
}
