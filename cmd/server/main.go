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

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/scan", scanHandler)

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

func scanHandler(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, fmt.Sprintf("pull image: %v", err), http.StatusBadRequest)
		return
	}

	extracted, err := img.Extract()
	if err != nil {
		http.Error(w, fmt.Sprintf("extract image: %v", err), http.StatusInternalServerError)
		return
	}
	defer func() {
		_ = extracted.Cleanup()
	}()

	sbomDoc, err := sbom.Generate(ctx, extracted.RootPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("generate sbom: %v", err), http.StatusInternalServerError)
		return
	}

	pkgs, err := sbom.Parse(sbomDoc)
	if err != nil {
		http.Error(w, fmt.Sprintf("parse sbom: %v", err), http.StatusInternalServerError)
		return
	}

	cveScanner := scan.NewCVEScanner()
	cveCh := cveScanner.Scan(ctx, pkgs)

	cwd, _ := os.Getwd()
	rulesDir := filepath.Join(cwd, "core", "scan")
	yaraScanner, err := scan.NewYARAScanner(rulesDir)
	if err != nil {
		http.Error(w, fmt.Sprintf("create yara scanner: %v", err), http.StatusInternalServerError)
		return
	}
	yaraCh := yaraScanner.ScanDir(ctx, extracted.RootPath)

	rep, err := report.Assemble(ctx, img.Ref, img.Digest, sbomDoc, yaraCh, cveCh)
	if err != nil {
		http.Error(w, fmt.Sprintf("assemble report: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rep); err != nil {
		http.Error(w, fmt.Sprintf("encode response: %v", err), http.StatusInternalServerError)
		return
	}
}
