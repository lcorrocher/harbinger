package report

import (
	"context"
	"fmt"
	"time"

	"github.com/lcorrocher/harbinger/core/sbom"
	"github.com/lcorrocher/harbinger/core/scan"
)

// Finding types
const (
	FindingTypeYARA = "YARA_MATCH"
	FindingTypeCVE  = "CVE"
)

type Finding struct {
	Type     string `json:"type"`
	FilePath string `json:"file_path,omitempty"`
	Package  string `json:"package,omitempty"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
}

type Report struct {
	Image          string    `json:"image"`
	Digest         string    `json:"digest,omitempty"`
	ScannedAt      time.Time `json:"scanned_at"`
	SBOMComponents int       `json:"sbom_components"`
	Findings       []Finding `json:"findings"`
}

// Assemble consumes YARA and CVE findings channels and produces a unified Report.
// This function blocks until both input channels are closed or the context is done.
func Assemble(ctx context.Context, imageRef, digest string, doc *sbom.Document, yaraCh <-chan scan.YARAFinding, cveCh <-chan scan.CVEFinding) (*Report, error) {
	if doc == nil {
		return nil, fmt.Errorf("nil sbom document")
	}

	pkgs, err := sbom.Parse(doc)
	if err != nil {
		return nil, fmt.Errorf("parse sbom: %w", err)
	}

	rep := &Report{
		Image:          imageRef,
		Digest:         digest,
		ScannedAt:      time.Now().UTC(),
		SBOMComponents: len(pkgs),
		Findings:       make([]Finding, 0),
	}

	yaraClosed := false
	cveClosed := false

	for {
		if yaraClosed && cveClosed {
			break
		}

		select {
		case <-ctx.Done():
			return rep, ctx.Err()
		case yf, ok := <-yaraCh:
			if !ok {
				yaraClosed = true
				continue
			}
			rep.Findings = append(rep.Findings, Finding{
				Type:     FindingTypeYARA,
				FilePath: yf.FilePath,
				Detail:   fmt.Sprintf("rule: %s", yf.RuleName),
				Severity: yf.Severity,
			})
		case cf, ok := <-cveCh:
			if !ok {
				cveClosed = true
				continue
			}
			rep.Findings = append(rep.Findings, Finding{
				Type:     FindingTypeCVE,
				Package:  cf.Package,
				Detail:   cf.CVEID,
				Severity: cf.Severity,
			})
		}
	}

	return rep, nil
}
