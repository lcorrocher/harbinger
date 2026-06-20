// Package sbom handles SBOM generation and parsing for extracted container images.
// Produces CycloneDX JSON documents and extracts structured package information (pURLs) for downstream CVE matching

package sbom

import (
	"context"
	"fmt"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	syftsbom "github.com/anchore/syft/syft/sbom"
	_ "modernc.org/sqlite"
)

type Document struct {
	JSON []byte
	sbom *syftsbom.SBOM
}

// Generate scans the filesystem rooted at rootPath and produces a CycloneDX SBOM
//
// # Syft catalogues all packages
//
// The returned Document contains both the raw CycloneDX JSON (for attestation) and the structured SBOM
func Generate(ctx context.Context, rootPath string) (*Document, error) {
	src, err := syft.GetSource(ctx, rootPath, nil)
	if err != nil {
		return nil, fmt.Errorf("create syft source from %q: %w", rootPath, err)
	}

	// CreateSBOM will use reasonable defaults when cfg == nil
	s, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		return nil, fmt.Errorf("generate sbom for %q: %w", rootPath, err)
	}

	// encode to CycloneDX JSON v1.5
	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(
		cyclonedxjson.DefaultEncoderConfig(),
	)
	if err != nil {
		return nil, fmt.Errorf("create cyclonedx encoder: %w", err)
	}

	jsonBytes, err := format.Encode(*s, encoder)
	if err != nil {
		return nil, fmt.Errorf("encode sbom to cyclonedx json: %w", err)
	}

	return &Document{
		JSON: jsonBytes,
		sbom: s,
	}, nil
}
