package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type BrowserSessionListFilters struct {
	Keyword  string
	Status   string
	SiteHost string
}

func normalizeBrowserSessionSiteHost(siteHost, entryURL string) string {
	trimmed := strings.TrimSpace(siteHost)
	if trimmed != "" {
		return trimmed
	}

	parsed, err := url.Parse(strings.TrimSpace(entryURL))
	if err != nil || parsed.Host == "" {
		return ""
	}
	return parsed.Host
}

func CreateBrowserSession(record BrowserSessionRecord) (*BrowserSessionRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	now := time.Now()
	record.SessionID = strings.TrimSpace(record.SessionID)
	record.SiteHost = normalizeBrowserSessionSiteHost(record.SiteHost, record.EntryURL)
	record.EntryURL = strings.TrimSpace(record.EntryURL)
	record.Status = strings.TrimSpace(record.Status)
	record.Mode = strings.TrimSpace(record.Mode)
	record.BrowserMode = strings.TrimSpace(record.BrowserMode)
	record.ProxyType = strings.TrimSpace(record.ProxyType)
	record.ProxyAddress = strings.TrimSpace(record.ProxyAddress)

	if record.SessionID == "" {
		return nil, fmt.Errorf("session_id is required")
	}
	if record.SiteHost == "" {
		return nil, fmt.Errorf("site_host is required")
	}
	if record.EntryURL == "" {
		return nil, fmt.Errorf("entry_url is required")
	}
	if record.Status == "" {
		record.Status = "running"
	}
	if record.Mode == "" {
		record.Mode = "manual"
	}
	if record.StartedAt.IsZero() {
		record.StartedAt = now
	}
	if record.LastActivityAt.IsZero() {
		record.LastActivityAt = record.StartedAt
	}

	_, err := DB.Exec(`
		INSERT INTO browser_sessions (
			session_id, site_host, entry_url, status, mode, browser_mode,
			proxy_type, proxy_address, browser_visible, page_count, request_count,
			suspicious_crypto_count, started_at, ended_at, last_activity_at,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		record.SessionID,
		record.SiteHost,
		record.EntryURL,
		record.Status,
		record.Mode,
		record.BrowserMode,
		record.ProxyType,
		record.ProxyAddress,
		record.BrowserVisible,
		record.PageCount,
		record.RequestCount,
		record.SuspiciousCryptoCount,
		record.StartedAt,
		nullTime(record.EndedAt),
		record.LastActivityAt,
		now,
		now,
	)
	if err != nil {
		return nil, err
	}

	return GetBrowserSessionByID(record.SessionID)
}

func UpsertBrowserPage(record BrowserPageRecord) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	now := time.Now()
	record.PageID = strings.TrimSpace(record.PageID)
	record.SessionID = strings.TrimSpace(record.SessionID)
	record.URL = strings.TrimSpace(record.URL)
	record.Title = strings.TrimSpace(record.Title)
	if record.PageID == "" {
		return fmt.Errorf("page_id is required")
	}
	if record.SessionID == "" {
		return fmt.Errorf("session_id is required")
	}
	if record.URL == "" {
		return fmt.Errorf("url is required")
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	if record.LastSeenAt.IsZero() {
		record.LastSeenAt = record.CreatedAt
	}

	_, err := DB.Exec(`
		INSERT INTO browser_pages (
			page_id, session_id, url, title, is_entry, created_at, last_seen_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(page_id) DO UPDATE SET
			session_id=excluded.session_id,
			url=excluded.url,
			title=excluded.title,
			is_entry=excluded.is_entry,
			last_seen_at=excluded.last_seen_at
	`, record.PageID, record.SessionID, record.URL, record.Title, record.IsEntry, record.CreatedAt, record.LastSeenAt)
	return err
}

func UpdateBrowserSessionMetrics(sessionID string, pageCount, requestCount, suspiciousCryptoCount int, status string, lastActivityAt, endedAt time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return fmt.Errorf("session_id is required")
	}
	if lastActivityAt.IsZero() {
		lastActivityAt = time.Now()
	}
	status = strings.TrimSpace(status)
	if status == "" {
		status = "running"
	}

	_, err := DB.Exec(`
		UPDATE browser_sessions
		SET page_count=?, request_count=?, suspicious_crypto_count=?, status=?,
		    last_activity_at=?, ended_at=?, updated_at=?
		WHERE session_id=?
	`, pageCount, requestCount, suspiciousCryptoCount, status, lastActivityAt, nullTime(endedAt), time.Now(), sessionID)
	return err
}

func GetBrowserSessionByID(sessionID string) (*BrowserSessionRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	row := DB.QueryRow(`
		SELECT session_id, site_host, entry_url, status, mode, browser_mode,
		       proxy_type, proxy_address, browser_visible, page_count, request_count,
		       suspicious_crypto_count, started_at, ended_at, last_activity_at,
		       created_at, updated_at
		FROM browser_sessions
		WHERE session_id=?
	`, strings.TrimSpace(sessionID))

	record, err := scanBrowserSession(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return record, nil
}

func ListBrowserPagesBySessionID(sessionID string) ([]BrowserPageRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := DB.Query(`
		SELECT page_id, session_id, url, title, is_entry, created_at, last_seen_at
		FROM browser_pages
		WHERE session_id=?
		ORDER BY created_at ASC, page_id ASC
	`, strings.TrimSpace(sessionID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	pages := make([]BrowserPageRecord, 0)
	for rows.Next() {
		page, err := scanBrowserPage(rows)
		if err != nil {
			return nil, err
		}
		pages = append(pages, *page)
	}
	return pages, nil
}

func ReplaceBrowserSessionRequests(sessionID string, requests []BrowserSessionRequestRecord) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return fmt.Errorf("session_id is required")
	}

	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.Exec(`DELETE FROM browser_session_requests WHERE session_id=?`, sessionID); err != nil {
		return err
	}

	for _, record := range requests {
		requestHeadersJSON, marshalErr := json.Marshal(record.RequestHeaders)
		if marshalErr != nil {
			return marshalErr
		}
		responseHeadersJSON, marshalErr := json.Marshal(record.ResponseHeaders)
		if marshalErr != nil {
			return marshalErr
		}
		createdAt := record.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now()
		}
		if _, err = tx.Exec(`
			INSERT INTO browser_session_requests (
				session_id, trace_id, url, method, resource_type,
				request_headers, request_body, response_headers, response_body,
				response_code, mime_type, has_protocol_trace, is_suspicious,
				suspicious_trace, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			sessionID,
			strings.TrimSpace(record.TraceID),
			strings.TrimSpace(record.URL),
			strings.TrimSpace(record.Method),
			strings.TrimSpace(record.ResourceType),
			string(requestHeadersJSON),
			strings.TrimSpace(record.RequestBody),
			string(responseHeadersJSON),
			strings.TrimSpace(record.ResponseBody),
			record.ResponseCode,
			strings.TrimSpace(record.MIMEType),
			record.HasProtocolTrace,
			record.IsSuspicious,
			strings.TrimSpace(record.SuspiciousTrace),
			createdAt,
		); err != nil {
			return err
		}
	}

	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func ListBrowserSessionRequests(sessionID string) ([]BrowserSessionRequestRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := DB.Query(`
		SELECT id, session_id, trace_id, url, method, resource_type,
		       request_headers, request_body, response_headers, response_body,
		       response_code, mime_type, has_protocol_trace, is_suspicious,
		       suspicious_trace, created_at
		FROM browser_session_requests
		WHERE session_id=?
		ORDER BY created_at DESC, id DESC
	`, strings.TrimSpace(sessionID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]BrowserSessionRequestRecord, 0)
	for rows.Next() {
		record, scanErr := scanBrowserSessionRequest(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, *record)
	}
	return records, nil
}

func ReplaceBrowserSessionTraces(sessionID string, traces []BrowserSessionTraceRecord) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return fmt.Errorf("session_id is required")
	}

	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.Exec(`DELETE FROM browser_session_traces WHERE session_id=?`, sessionID); err != nil {
		return err
	}

	for _, trace := range traces {
		algorithmsJSON, marshalErr := json.Marshal(trace.Algorithms)
		if marshalErr != nil {
			return marshalErr
		}
		requestStepsJSON, marshalErr := json.Marshal(trace.RequestSteps)
		if marshalErr != nil {
			return marshalErr
		}
		responseStepsJSON, marshalErr := json.Marshal(trace.ResponseSteps)
		if marshalErr != nil {
			return marshalErr
		}
		sessionMaterialsJSON, marshalErr := json.Marshal(trace.SessionMaterials)
		if marshalErr != nil {
			return marshalErr
		}
		createdAt := trace.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now()
		}
		if _, err = tx.Exec(`
			INSERT INTO browser_session_traces (
				session_id, trace_id, request_url, method, algorithms,
				request_before_transform, final_request_body, request_steps,
				response_steps, session_materials, response_plaintext,
				response_ciphertext, suspicious_reason, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			sessionID,
			strings.TrimSpace(trace.TraceID),
			strings.TrimSpace(trace.RequestURL),
			strings.TrimSpace(trace.Method),
			string(algorithmsJSON),
			strings.TrimSpace(trace.RequestBeforeTransform),
			strings.TrimSpace(trace.FinalRequestBody),
			string(requestStepsJSON),
			string(responseStepsJSON),
			string(sessionMaterialsJSON),
			strings.TrimSpace(trace.ResponsePlaintext),
			strings.TrimSpace(trace.ResponseCiphertext),
			strings.TrimSpace(trace.SuspiciousReason),
			createdAt,
		); err != nil {
			return err
		}
	}

	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func ListBrowserSessionTraces(sessionID string) ([]BrowserSessionTraceRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := DB.Query(`
		SELECT id, session_id, trace_id, request_url, method, algorithms,
		       request_before_transform, final_request_body, request_steps,
		       response_steps, session_materials, response_plaintext,
		       response_ciphertext, suspicious_reason, created_at
		FROM browser_session_traces
		WHERE session_id=?
		ORDER BY created_at DESC, id DESC
	`, strings.TrimSpace(sessionID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]BrowserSessionTraceRecord, 0)
	for rows.Next() {
		record, scanErr := scanBrowserSessionTrace(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, *record)
	}
	return records, nil
}

func DeleteBrowserSession(sessionID string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return fmt.Errorf("session_id is required")
	}

	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.Exec(`DELETE FROM browser_session_traces WHERE session_id=?`, sessionID); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM browser_session_requests WHERE session_id=?`, sessionID); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM browser_pages WHERE session_id=?`, sessionID); err != nil {
		return err
	}
	result, err := tx.Exec(`DELETE FROM browser_sessions WHERE session_id=?`, sessionID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func ListBrowserSessions(page, size int, filters BrowserSessionListFilters) ([]BrowserSessionRecord, int, error) {
	if DB == nil {
		return nil, 0, fmt.Errorf("database not initialized")
	}

	if page <= 0 {
		page = 1
	}
	if size <= 0 {
		size = 10
	}

	conditions := make([]string, 0, 3)
	args := make([]any, 0, 6)

	if keyword := strings.TrimSpace(filters.Keyword); keyword != "" {
		conditions = append(conditions, "(session_id LIKE ? OR site_host LIKE ? OR entry_url LIKE ?)")
		like := "%" + keyword + "%"
		args = append(args, like, like, like)
	}
	if status := strings.TrimSpace(filters.Status); status != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, status)
	}
	if siteHost := strings.TrimSpace(filters.SiteHost); siteHost != "" {
		conditions = append(conditions, "site_host = ?")
		args = append(args, siteHost)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	var total int
	countQuery := `SELECT COUNT(1) FROM browser_sessions` + whereClause
	if err := DB.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * size
	listQuery := `
		SELECT session_id, site_host, entry_url, status, mode, browser_mode,
		       proxy_type, proxy_address, browser_visible, page_count, request_count,
		       suspicious_crypto_count, started_at, ended_at, last_activity_at,
		       created_at, updated_at
		FROM browser_sessions` + whereClause + `
		ORDER BY started_at DESC, created_at DESC
		LIMIT ? OFFSET ?`
	listArgs := append(append([]any{}, args...), size, offset)

	rows, err := DB.Query(listQuery, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	records := make([]BrowserSessionRecord, 0)
	for rows.Next() {
		record, err := scanBrowserSession(rows)
		if err != nil {
			return nil, 0, err
		}
		records = append(records, *record)
	}
	return records, total, nil
}

type browserSessionRowScanner interface {
	Scan(dest ...any) error
}

func scanBrowserSession(scanner browserSessionRowScanner) (*BrowserSessionRecord, error) {
	var record BrowserSessionRecord
	var endedAt sql.NullTime
	if err := scanner.Scan(
		&record.SessionID,
		&record.SiteHost,
		&record.EntryURL,
		&record.Status,
		&record.Mode,
		&record.BrowserMode,
		&record.ProxyType,
		&record.ProxyAddress,
		&record.BrowserVisible,
		&record.PageCount,
		&record.RequestCount,
		&record.SuspiciousCryptoCount,
		&record.StartedAt,
		&endedAt,
		&record.LastActivityAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if endedAt.Valid {
		record.EndedAt = endedAt.Time
	}
	return &record, nil
}

type browserPageRowScanner interface {
	Scan(dest ...any) error
}

func scanBrowserPage(scanner browserPageRowScanner) (*BrowserPageRecord, error) {
	var record BrowserPageRecord
	if err := scanner.Scan(
		&record.PageID,
		&record.SessionID,
		&record.URL,
		&record.Title,
		&record.IsEntry,
		&record.CreatedAt,
		&record.LastSeenAt,
	); err != nil {
		return nil, err
	}
	return &record, nil
}

type browserSessionTraceRowScanner interface {
	Scan(dest ...any) error
}

type browserSessionRequestRowScanner interface {
	Scan(dest ...any) error
}

func scanBrowserSessionRequest(scanner browserSessionRequestRowScanner) (*BrowserSessionRequestRecord, error) {
	var record BrowserSessionRequestRecord
	var requestHeadersJSON string
	var responseHeadersJSON string
	if err := scanner.Scan(
		&record.ID,
		&record.SessionID,
		&record.TraceID,
		&record.URL,
		&record.Method,
		&record.ResourceType,
		&requestHeadersJSON,
		&record.RequestBody,
		&responseHeadersJSON,
		&record.ResponseBody,
		&record.ResponseCode,
		&record.MIMEType,
		&record.HasProtocolTrace,
		&record.IsSuspicious,
		&record.SuspiciousTrace,
		&record.CreatedAt,
	); err != nil {
		return nil, err
	}
	if strings.TrimSpace(requestHeadersJSON) != "" {
		if err := json.Unmarshal([]byte(requestHeadersJSON), &record.RequestHeaders); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(responseHeadersJSON) != "" {
		if err := json.Unmarshal([]byte(responseHeadersJSON), &record.ResponseHeaders); err != nil {
			return nil, err
		}
	}
	return &record, nil
}

func scanBrowserSessionTrace(scanner browserSessionTraceRowScanner) (*BrowserSessionTraceRecord, error) {
	var record BrowserSessionTraceRecord
	var algorithmsJSON string
	var requestStepsJSON string
	var responseStepsJSON string
	var sessionMaterialsJSON string
	if err := scanner.Scan(
		&record.ID,
		&record.SessionID,
		&record.TraceID,
		&record.RequestURL,
		&record.Method,
		&algorithmsJSON,
		&record.RequestBeforeTransform,
		&record.FinalRequestBody,
		&requestStepsJSON,
		&responseStepsJSON,
		&sessionMaterialsJSON,
		&record.ResponsePlaintext,
		&record.ResponseCiphertext,
		&record.SuspiciousReason,
		&record.CreatedAt,
	); err != nil {
		return nil, err
	}
	if strings.TrimSpace(algorithmsJSON) != "" {
		if err := json.Unmarshal([]byte(algorithmsJSON), &record.Algorithms); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(requestStepsJSON) != "" {
		if err := json.Unmarshal([]byte(requestStepsJSON), &record.RequestSteps); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(responseStepsJSON) != "" {
		if err := json.Unmarshal([]byte(responseStepsJSON), &record.ResponseSteps); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(sessionMaterialsJSON) != "" {
		if err := json.Unmarshal([]byte(sessionMaterialsJSON), &record.SessionMaterials); err != nil {
			return nil, err
		}
	}
	return &record, nil
}

func nullTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}
