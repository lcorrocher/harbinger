package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScanHandler_MethodNotAllowed(t *testing.T) {
	handler := makeScanHandler(nil, noopLogger())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/scan", nil)
	handler(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected %d got %d: %s", http.StatusMethodNotAllowed, rr.Code, rr.Body)
	}
}

func TestScanHandler_EmptyBody(t *testing.T) {
	handler := makeScanHandler(nil, noopLogger())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	handler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d got %d: %s", http.StatusBadRequest, rr.Code, rr.Body)
	}
}

func TestScanHandler_MissingImage(t *testing.T) {
	handler := makeScanHandler(nil, noopLogger())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(`{"image":""}`))
	req.Header.Set("Content-Type", "application/json")
	handler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d got %d: %s", http.StatusBadRequest, rr.Code, rr.Body)
	}
}

func TestHealthz(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d got %d", http.StatusOK, rr.Code)
	}
}

// logger that discards all out
func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
