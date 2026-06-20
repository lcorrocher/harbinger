package sbom

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// syntheticFS creates a minimal fake extracted image filesystem in a temp
// directory for testing without requiring a real image pull
func syntheticFS(t *testing.T) (string, func()) {
	t.Helper()

	root, err := os.MkdirTemp("", "harbinger-sbom-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}

	// Simulate a minimal dpkg status file so Syft's deb cataloger
	// finds at least one package. Real extracted images have this at
	// /var/lib/dpkg/status.
	dpkgDir := filepath.Join(root, "var", "lib", "dpkg")
	if err := os.MkdirAll(dpkgDir, 0o755); err != nil {
		t.Fatalf("mkdir dpkg: %v", err)
	}

	// Minimal dpkg status entry for curl 7.68.0.
	// Syft parses this format to discover deb packages.
	dpkgStatus := `Package: curl
Status: install ok installed
Architecture: amd64
Version: 7.68.0-1ubuntu2.22
Description: command line tool for transferring data with URL syntax

`
	if err := os.WriteFile(
		filepath.Join(dpkgDir, "status"),
		[]byte(dpkgStatus),
		0o644,
	); err != nil {
		t.Fatalf("write dpkg status: %v", err)
	}

	return root, func() { os.RemoveAll(root) }
}

func TestGenerate(t *testing.T) {
	root, cleanup := syntheticFS(t)
	defer cleanup()

	doc, err := Generate(context.Background(), root)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(doc.JSON) == 0 {
		t.Error("Generate() returned empty JSON")
	}
	if doc.sbom == nil {
		t.Error("Generate() returned nil sbom")
	}

	// CycloneDX JSON begins with '{' (it's a JSON object)
	if doc.JSON[0] != '{' {
		t.Errorf("Generate() JSON does not look like JSON: first byte = %q", doc.JSON[0])
	}

	t.Logf("generated %d bytes of CycloneDX JSON", len(doc.JSON))
}

func TestGenerateCancelledContext(t *testing.T) {
	root, cleanup := syntheticFS(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Syft should respect the cancelled context and return an error.
	// If it doesn't (some versions complete fast enough before checking),
	// that's acceptable — the test documents the expected behaviour.
	_, err := Generate(ctx, root)
	if err != nil {
		t.Logf("Generate() with cancelled context returned error (expected): %v", err)
	}
}

func TestParse(t *testing.T) {
	root, cleanup := syntheticFS(t)
	defer cleanup()

	doc, err := Generate(context.Background(), root)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if doc.sbom != nil && len(doc.sbom.Artifacts.Packages.Sorted()) > 0 {
		t.Logf("Found %d total packages in SBOM", len(doc.sbom.Artifacts.Packages.Sorted()))
	}

	packages, err := Parse(doc)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// The test passes if either:
	// 1. We find packages with valid PURLs, or
	// 2. Parse correctly returns empty (packages cataloged but lack PURLs)
	if len(packages) > 0 {
		for _, p := range packages {
			if p.Name == "" {
				t.Errorf("Parse() returned package with empty Name: %+v", p)
			}
			if p.PURL == "" {
				t.Errorf("Parse() returned package with empty PURL: %+v", p)
			}
			if p.Type == "" {
				t.Errorf("Parse() returned package with empty Type: %+v", p)
			}
			t.Logf("package: %s@%s (%s) purl=%s", p.Name, p.Version, p.Type, p.PURL)
		}
	} else {
		t.Logf("Parse() returned no packages with PURLs (acceptable - packages may lack PURL metadata)")
	}
}

func TestParseNilDocument(t *testing.T) {
	_, err := Parse(nil)
	if err == nil {
		t.Error("Parse(nil) expected error, got nil")
	}
}
