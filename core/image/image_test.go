package image

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPullImage(t *testing.T) {
	img, err := Pull("alpine:latest")
	if err != nil {
		t.Fatalf("Pull() error = %v", err)
	}

	if img.Ref == "" {
		t.Error("Pull() returned empty Ref")
	}
	if img.Digest == "" {
		t.Error("Pull() returned empty Digest")
	}
	if img.img == nil {
		t.Error("Pull() returned nil underlying image")
	}

	t.Logf("pulled %s@%s", img.Ref, img.Digest)
}

func TestExtract(t *testing.T) {
	img, err := Pull("alpine:latest")
	if err != nil {
		t.Fatalf("Pull() error = %v", err)
	}

	extracted, err := img.Extract()
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	defer func() {
		if err := extracted.Cleanup(); err != nil {
			t.Errorf("Cleanup() error = %v", err)
		}
	}()

	if extracted.RootPath == "" {
		t.Fatal("Extract() returned empty RootPath")
	}

	if _, err := os.Stat(extracted.RootPath); err != nil {
		t.Fatalf("extracted root dir does not exist: %v", err)
	}

	expectedPaths := []string{
		"bin/sh",
		"etc/os-release",
	}
	for _, p := range expectedPaths {
		full := filepath.Join(extracted.RootPath, p)
		if _, err := os.Lstat(full); err != nil {
			t.Errorf("expected path %s not found in extracted image: %v", p, err)
		}
	}

	t.Logf("extracted to %s", extracted.RootPath)
}

func TestExtractCleanup(t *testing.T) {
	img, err := Pull("alpine:latest")
	if err != nil {
		t.Fatalf("Pulle() error = %v", err)
	}

	extracted, err := img.Extract()
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	root := extracted.RootPath

	if err := extracted.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("expected temp dir %s to be removed after Cleanup(), got err = %v", root, err)
	}
}

func TestPullInvalidRef(t *testing.T) {
	_, err := Pull(":::not-a-valid-ref:::")
	if err == nil {
		t.Error("Pull() expected error for invalid ref, got nil")
	}
}
