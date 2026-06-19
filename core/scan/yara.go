package scan

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/hillu/go-yara/v4"
)

type YARAFinding struct {
	FilePath      string
	RuleName      string
	RuleNamespace string
	Tags          []string
	Severity      string
}

type YARAScanner struct {
	rules *yara.Rules
}

func NewYARAScanner(rulesDir string) (*YARAScanner, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("create yara compiler: %w", err)
	}

	var ruleCount int
	err = filepath.WalkDir(rulesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yar" && ext != ".yara" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open rule file %s: %w", path, err)
		}
		defer f.Close()

		namespace := filepath.Base(path)
		if err := compiler.AddFile(f, namespace); err != nil {
			return fmt.Errorf("compile rule file %s: %w", path, err)
		}
		ruleCount++
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk rules dir %q: %w", rulesDir, err)
	}

	if ruleCount == 0 {
		return nil, fmt.Errorf("no YARA rules found in %q", rulesDir)
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("compile yara rules: %w", err)
	}

	return &YARAScanner{rules: rules}, nil
}

// ScanDir collects paths, then distributes to workers to scan - memory overhead (stores all paths)
// Alternative approach (future) - collect paths and distribute to workers concurrently....
// Context used for cancellations/timeouts
func (s *YARAScanner) ScanDir(ctx context.Context, rootPath string) <-chan YARAFinding {
	out := make(chan YARAFinding, 64)

	go func() {
		defer close(out)

		// get all paths
		var paths []string
		_ = filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if d.Type()&fs.ModeSymlink != 0 {
				return nil
			}
			paths = append(paths, path)
			return nil
		})

		// worker pool
		workers := runtime.NumCPU()
		work := make(chan string, workers)

		// distribute paths to workers
		go func() {
			for _, path := range paths {
				select {
				case work <- path: // send
				case <-ctx.Done():
					return
				}
			}
			close(work) // sender closes
		}()

		var wg sync.WaitGroup // tracks how many goroutines are running
		for range workers {
			wg.Add(1) // add one to wg - tracked, the rm'd with wg.Done()
			go func() {
				defer wg.Done()
				for path := range work {
					findings, err := s.scanFile(path, rootPath)
					if err != nil {
						continue
					}
					for _, f := range findings {
						select {
						case out <- f:
						case <-ctx.Done(): // checks if context cancelled
							return
						}
					}
				}
			}()
		}

		wg.Wait() // wait for all workers to finish scanning

	}()

	return out
}

// scanFile reads single file and runs full YARA ruleset against it.
// File limit of 32MB
func (s *YARAScanner) scanFile(filePath, rootPath string) ([]YARAFinding, error) {
	const maxScanSize = 32 << 20 // 32MB

	info, err := os.Lstat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", filePath, err)
	}
	if info.Size() > maxScanSize {
		return nil, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filePath, err)
	}

	var matches yara.MatchRules
	if err := s.rules.ScanMem(data, 0, 0, &matches); err != nil {
		return nil, fmt.Errorf("yara scan %s: %w", filePath, err)
	}

	if len(matches) == 0 {
		return nil, nil
	}

	rel, err := filepath.Rel(rootPath, filePath)
	if err != nil {
		rel = filePath
	}

	findings := make([]YARAFinding, 0, len(matches))
	for _, m := range matches {
		findings = append(findings, YARAFinding{
			FilePath:      "/" + rel,
			RuleName:      m.Rule,
			RuleNamespace: m.Namespace,
			Tags:          m.Tags,
			Severity:      tagSeverity(m.Tags),
		})
	}

	return findings, nil
}

// tagSeverity extracts a severity level from YARA rule tags
func tagSeverity(tags []string) string {
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	tagSet := make(map[string]bool, len(tags))
	for _, t := range tags {
		tagSet[t] = true
	}
	for _, sev := range order {
		if tagSet[sev] {
			return sev
		}
	}
	return "MEDIUM"
}
