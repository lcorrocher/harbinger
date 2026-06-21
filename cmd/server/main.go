package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lcorrocher/harbinger/core/image"
	"github.com/lcorrocher/harbinger/core/report"
	"github.com/lcorrocher/harbinger/core/sbom"
	"github.com/lcorrocher/harbinger/core/scan"
)

type scanRequest struct {
	Image string `json:"image"`
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	rulesDir, err := getRulesDir()
	if err != nil {
		logger.Error("rules dir", "err", err)
		os.Exit(1)
	}

	yaraScanner, err := scan.NewYARAScanner(rulesDir)
	if err != nil {
		logger.Error("load yara rules", "err", err, "dir", rulesDir)
		os.Exit(1)
	}
	logger.Info("loaded YARA rules", "dir", rulesDir)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/scan", makeScanHandler(yaraScanner, logger))

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("listen error", "err", err)
			os.Exit(1)
		}
	}()

	<-stop
	logger.Info("shutting down server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func makeScanHandler(yaraScanner *scan.YARAScanner, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req scanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if req.Image == "" {
			http.Error(w, "image required", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
		defer cancel()

		img, err := image.Pull(req.Image)
		if err != nil {
			logger.Error("pull image", "err", err, "image", req.Image)
			http.Error(w, fmt.Sprintf("pull image: %v", err), http.StatusBadRequest)
			return
		}

		extracted, err := img.Extract()
		if err != nil {
			logger.Error("extract image", "err", err)
			http.Error(w, fmt.Sprintf("extract image: %v", err), http.StatusInternalServerError)
			return
		}
		defer func() { _ = extracted.Cleanup() }()

		sbomDoc, err := sbom.Generate(ctx, extracted.RootPath)
		if err != nil {
			logger.Error("generate sbom", "err", err)
			http.Error(w, fmt.Sprintf("generate sbom: %v", err), http.StatusInternalServerError)
			return
		}

		pkgs, err := sbom.Parse(sbomDoc)
		if err != nil {
			logger.Error("parse sbom", "err", err)
			http.Error(w, fmt.Sprintf("parse sbom: %v", err), http.StatusInternalServerError)
			return
		}

		cveScanner := scan.NewCVEScanner()
		cveCh := cveScanner.Scan(ctx, pkgs)
		yaraCh := yaraScanner.ScanDir(ctx, extracted.RootPath)

		rep, err := report.Assemble(ctx, img.Ref, img.Digest, sbomDoc, yaraCh, cveCh)
		if err != nil {
			logger.Error("assemble report", "err", err)
			http.Error(w, fmt.Sprintf("assemble report: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(rep); err != nil {
			logger.Error("encode response", "err", err)
			return
		}

		logger.Info("scan complete", "image", req.Image, "findings", len(rep.Findings))
	}
}

func getRulesDir() (string, error) {
	if dir := os.Getenv("HARBINGER_RULES_DIR"); dir != "" {
		return dir, nil
	}

	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	if dir := filepath.Join(filepath.Dir(exe), "..", "app", "core", "scan"); dirExists(dir) {
		return dir, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve working directory: %w", err)
	}
	if dir := filepath.Join(cwd, "core", "scan"); dirExists(dir) {
		return dir, nil
	}

	return "", fmt.Errorf(
		"YARA rules directory not found: set HARBINGER_RULES_DIR or run from repo root",
	)
}

func dirExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
