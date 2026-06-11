package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type response struct {
	Mode    string      `json:"mode"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func main() {
	addr := envOrDefault("SQLI_LAB_ADDR", ":18082")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/sqli/error", handleErrorBased)
	mux.HandleFunc("/api/sqli/boolean", handleBooleanBased)
	mux.HandleFunc("/api/sqli/time", handleTimeBased)
	mux.HandleFunc("/api/sqli/false-positive", handleFalsePositive)
	mux.HandleFunc("/api/sqli/dynamic", handleDynamic)

	server := &http.Server{
		Addr:              addr,
		Handler:           accessLog(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("sqli-lab listening on %s", addr)
	log.Fatal(server.ListenAndServe())
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, response{
		Mode:    "health",
		Message: "ok",
	})
}

func handleErrorBased(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if strings.Contains(user, "'") {
		http.Error(w, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, response{
		Mode:    "error-based",
		Message: "query ok",
		Data: []map[string]any{
			{"id": 1, "user": "alice"},
		},
	})
}

func handleBooleanBased(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")

	switch user {
	case "'":
		writeJSON(w, http.StatusOK, response{
			Mode:    "boolean-based",
			Message: "query ok",
			Data: []map[string]any{},
		})
		return
	case "''", "":
		writeJSON(w, http.StatusOK, response{
			Mode:    "boolean-based",
			Message: "query ok",
			Data: []map[string]any{
				{"id": 1, "user": "alice"},
				{"id": 2, "user": "bob"},
			},
		})
		return
	default:
		writeJSON(w, http.StatusOK, response{
			Mode:    "boolean-based",
			Message: "query ok",
			Data: []map[string]any{
				{"id": 3, "user": user},
			},
		})
	}
}

func handleTimeBased(w http.ResponseWriter, r *http.Request) {
	user := strings.ToLower(r.URL.Query().Get("user"))
	time.Sleep(150 * time.Millisecond)
	if strings.Contains(user, "sleep") || strings.Contains(user, "pg_sleep") || strings.Contains(user, "waitfor") {
		time.Sleep(2200 * time.Millisecond)
	}

	writeJSON(w, http.StatusOK, response{
		Mode:    "time-based",
		Message: "query ok",
		Data: map[string]any{
			"elapsedMs": 150,
		},
	})
}

func handleFalsePositive(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if strings.Contains(user, "'") {
		http.Error(w, "invalid input", http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, response{
		Mode:    "false-positive",
		Message: "accepted",
	})
}

func handleDynamic(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	now := strconv.FormatInt(time.Now().UnixMilli(), 10)
	requestID := "550e8400-e29b-41d4-a716-446655440000"

	if user == "'" {
		http.Error(w, "query failed trace="+now, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, response{
		Mode:    "dynamic",
		Message: "query ok",
		Data: map[string]any{
			"trace":     now,
			"requestId": requestID,
			"user":      user,
		},
	})
}

func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
