package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lcorrocher/harbinger/core/sbom"
)

// ── YARA tests ────────────────────────────────────────────────────────────────

// writeRule writes YARA rule
func writeRule(t *testing.T, dir, filename, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0o644); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
}

// syntheticRulesDir creates a temp directory with a test YARA rule.
func syntheticRulesDir(t *testing.T) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "harbinger-rules-*")
	if err != nil {
		t.Fatalf("create rules dir: %v", err)
	}

	// Simple rule that matches the ASCII string "EICAR" — safe test string
	// that won't trigger real AV but proves the YARA engine fires
	writeRule(t, dir, "test.yar", `
rule TestMalwareString : HIGH {
    meta:
        description = "Matches test malware string"
    strings:
        $s1 = "EICAR-STANDARD-ANTIVIRUS-TEST"
    condition:
        $s1
}
`)
	return dir, func() { os.RemoveAll(dir) }
}

// syntheticScanDir creates a temp directory with one clean and one matching file
func syntheticScanDir(t *testing.T) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "harbinger-scan-*")
	if err != nil {
		t.Fatalf("create scan dir: %v", err)
	}

	// should not match
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("hello world"), 0o644); err != nil {
		t.Fatalf("write clean file: %v", err)
	}

	// matches TestMalwareString rule
	if err := os.WriteFile(
		filepath.Join(dir, "suspicious.bin"),
		[]byte("prefix EICAR-STANDARD-ANTIVIRUS-TEST suffix"),
		0o644,
	); err != nil {
		t.Fatalf("write suspicious file: %v", err)
	}

	return dir, func() { os.RemoveAll(dir) }
}

func TestNewYARAScanner(t *testing.T) {
	rulesDir, cleanup := syntheticRulesDir(t)
	defer cleanup()

	scanner, err := NewYARAScanner(rulesDir)
	if err != nil {
		t.Fatalf("NewYARAScanner() error = %v", err)
	}
	if scanner == nil {
		t.Fatal("NewYARAScanner() returned nil scanner")
	}
}

func TestNewYARAScannerEmptyDir(t *testing.T) {
	dir, err := os.MkdirTemp("", "harbinger-empty-rules-*")
	if err != nil {
		t.Fatalf("create dir: %v", err)
	}
	defer os.RemoveAll(dir)

	_, err = NewYARAScanner(dir)
	if err == nil {
		t.Error("NewYARAScanner() expected error for empty rules dir, got nil")
	}
}

func TestYARAScanDir(t *testing.T) {
	rulesDir, rulesCleanup := syntheticRulesDir(t)
	defer rulesCleanup()

	scanDir, scanCleanup := syntheticScanDir(t)
	defer scanCleanup()

	scanner, err := NewYARAScanner(rulesDir)
	if err != nil {
		t.Fatalf("NewYARAScanner() error = %v", err)
	}

	var findings []YARAFinding
	for f := range scanner.ScanDir(context.Background(), scanDir) {
		findings = append(findings, f)
		t.Logf("finding: rule=%s file=%s severity=%s", f.RuleName, f.FilePath, f.Severity)
	}

	if len(findings) == 0 {
		t.Error("ScanDir() expected at least one finding from suspicious.bin, got none")
	}

	// Verify finding points at right file
	found := false
	for _, f := range findings {
		if f.FilePath == "/suspicious.bin" {
			found = true
			if f.RuleName != "TestMalwareString" {
				t.Errorf("expected rule TestMalwareString, got %s", f.RuleName)
			}
			if f.Severity != "HIGH" {
				t.Errorf("expected severity HIGH, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("ScanDir() did not produce a finding for /suspicious.bin")
	}
}

func TestYARAScanDirCancelledContext(t *testing.T) {
	rulesDir, rulesCleanup := syntheticRulesDir(t)
	defer rulesCleanup()

	scanDir, scanCleanup := syntheticScanDir(t)
	defer scanCleanup()

	scanner, err := NewYARAScanner(rulesDir)
	if err != nil {
		t.Fatalf("NewYARAScanner() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Must drain the channel even if cancelled
	// Use timeout
	done := make(chan bool, 1)
	go func() {
		for range scanner.ScanDir(ctx, scanDir) {
		}
		done <- true
	}()

	select {
	case <-done: // Channel drained
	case <-time.After(5 * time.Second):
		t.Fatal("ScanDir with cancelled context took too long to complete")
	}
}

func TestSeverityFromTags(t *testing.T) {
	tests := []struct {
		tags     []string
		expected string
	}{
		{[]string{"CRITICAL", "malware"}, "CRITICAL"},
		{[]string{"HIGH"}, "HIGH"},
		{[]string{"LOW", "MEDIUM"}, "MEDIUM"},
		{[]string{"unknown_tag"}, "MEDIUM"},
		{[]string{}, "MEDIUM"},
	}

	for _, tt := range tests {
		got := tagSeverity(tt.tags)
		if got != tt.expected {
			t.Errorf("severityFromTags(%v) = %q, want %q", tt.tags, got, tt.expected)
		}
	}
}

// ── CVE tests ─────────────────────────────────────────────────────────────────

func TestChunk(t *testing.T) {
	tests := []struct {
		input    []int
		size     int
		expected [][]int
	}{
		{[]int{1, 2, 3, 4, 5}, 2, [][]int{{1, 2}, {3, 4}, {5}}},
		{[]int{1, 2, 3}, 3, [][]int{{1, 2, 3}}},
		{[]int{1, 2, 3}, 5, [][]int{{1, 2, 3}}},
		{[]int{}, 2, [][]int{{}}},
	}

	for _, tt := range tests {
		got := chunk(tt.input, tt.size)
		if len(got) != len(tt.expected) {
			t.Errorf("chunk(%v, %d) = %v, want %v", tt.input, tt.size, got, tt.expected)
		}
	}
}

func TestCVEScannerLiveOSV(t *testing.T) {
	// Integration test — queries the real OSV API
	// Uses curl 7.68.0 which has known CVEs at time of writing
	// Skip in offline environments
	if os.Getenv("HARBINGER_INTEGRATION") == "" {
		t.Skip("skipping OSV integration test; set HARBINGER_INTEGRATION=1 to run")
	}

	packages := []sbom.Package{
		{
			Name:    "curl",
			Version: "7.68.0",
			PURL:    "pkg:deb/debian/curl@7.68.0",
			Type:    "deb",
		},
	}

	scanner := NewCVEScanner()
	var findings []CVEFinding
	for f := range scanner.Scan(context.Background(), packages) {
		findings = append(findings, f)
		t.Logf("CVE: %s (%s) severity=%s", f.CVEID, f.PackageName, f.Severity)
	}

	if len(findings) == 0 {
		t.Error("Scan() expected CVE findings for curl@7.68.0, got none")
	}
}

func TestCVEScannerEmptyPackages(t *testing.T) {
	scanner := NewCVEScanner()

	var count int
	for range scanner.Scan(context.Background(), nil) {
		count++
	}

	if count != 0 {
		t.Errorf("Scan(nil) expected 0 findings, got %d", count)
	}
}

func TestParseCVSSScore(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"9.8", 9.8},
		{"7.5", 7.5},
		{"4.0", 4.0},
		{"0.0", 0.0},
		{"not-a-score", 0.0},
	}

	for _, tt := range tests {
		got := parseCVSSScore(tt.input)
		if got != tt.expected {
			t.Errorf("parseCVSSScore(%q) = %f, want %f", tt.input, got, tt.expected)
		}
	}
}
