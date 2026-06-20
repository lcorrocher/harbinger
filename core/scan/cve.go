package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/lcorrocher/harbinger/core/sbom"
)

const (
	osvBatchURL  = "https://api.osv.dev/v1/querybatch"
	osvBatchSize = 500
	httpTimeout  = 30 * time.Second
)

type CVEFinding struct {
	Package     string // pURL
	PackageName string
	CVEID       string
	Summary     string
	Severity    string
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	PURL string `json:"purl"`
}

type osvBatchResponse struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Severity []osvSeverity `json:"severity"`
	Aliases  []string      `json:"aliases"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type CVEScanner struct {
	client *http.Client
}

func NewCVEScanner() *CVEScanner {
	return &CVEScanner{
		client: &http.Client{Timeout: httpTimeout},
	}
}

// Scan queries OSV for packages in slice
func (s *CVEScanner) Scan(ctx context.Context, packages []sbom.Package) <-chan CVEFinding {
	out := make(chan CVEFinding, 64)

	go func() {
		defer close(out)

		batches := chunk(packages, osvBatchSize)
		var wg sync.WaitGroup
		sem := make(chan struct{}, 4)

		for _, batch := range batches {
			batch := batch // iteration specific variable goroutine loop

			wg.Add(1)
			sem <- struct{}{} // acquire
			go func() {
				defer wg.Done()
				defer func() { <-sem }() // release

				findings, err := s.queryBatch(ctx, batch)
				if err != nil {
					return
				}

				for _, f := range findings {
					select {
					case out <- f:
					case <-ctx.Done():
						return
					}
				}
			}()
		}

		wg.Wait()
	}()

	return out
}

// queryBatch sends POST request for packages and returns CVEFindings
func (s *CVEScanner) queryBatch(ctx context.Context, packages []sbom.Package) ([]CVEFinding, error) {
	queries := make([]osvQuery, len(packages))
	for i, p := range packages {
		queries[i] = osvQuery{Package: osvPackage{PURL: p.PURL}}
	}

	body, err := json.Marshal(osvBatchRequest{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("marchal osv batch request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvBatchURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build osv request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv batch request: %w", err)
	}
	defer resp.Body.Close() // error ignored - best effort close

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv returned status %d", resp.StatusCode)
	}

	var result osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode osv response: %w", err)
	}

	var findings []CVEFinding
	for i, res := range result.Results {
		if i >= len(packages) {
			break
		}
		pkg := packages[i]

		for _, vuln := range res.Vulns {
			findings = append(findings, CVEFinding{
				Package:     pkg.PURL,
				PackageName: pkg.Name,
				CVEID:       cveID(vuln),
				Summary:     vuln.Summary,
				Severity:    cvssToSeverity(vuln.Severity),
			})
		}
	}

	return findings, nil
}

// OSV uses its own IDS but also stores CVE IDs in Aliases field, preferred
func cveID(v osvVuln) string {
	for _, alias := range v.Aliases {
		if len(alias) > 4 && alias[:4] == "CVE-" {
			return alias
		}
	}
	return v.ID
}

// CVSS v3 severity bands (NIST)
func cvssToSeverity(severities []osvSeverity) string {
	for _, s := range severities {
		if s.Type == "CVSS_V3" {
			score := parseCVSSScore(s.Score)
			switch {
			case score >= 9.0:
				return "CRITICAL"
			case score >= 7.0:
				return "HIGH"
			case score >= 4.0:
				return "MEDIUM"
			default:
				return "LOW"
			}
		}
	}
	return "UNKNOWN"
}

func parseCVSSScore(vector string) float64 {
	var score float64
	_, err := fmt.Sscanf(vector, "%f", &score)
	if err != nil {
		return 0.0
	}
	return score
}

func chunk[T any](s []T, size int) [][]T {
	if size <= 0 {
		return nil
	}
	chunks := make([][]T, 0, (len(s)+size-1)/size)
	for size < len(s) {
		s, chunks = s[size:], append(chunks, s[:size])
	}
	return append(chunks, s)
}
