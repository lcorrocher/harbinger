package image

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type ExtractedImage struct {
	RootPath string
	cleanup  func() error
}

// Cleanup removes extracted filesystem from disk
func (e *ExtractedImage) Cleanup() error {
	if e.cleanup != nil {
		return e.cleanup()
	}
	return nil
}

// Extract unpack image layers into temp dir
// handles whiteout files (.wh.*)
func (image *Image) Extract() (*ExtractedImage, error) {
	root, err := os.MkdirTemp("", "harbinger-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(root)
		}
	}()

	layers, err := image.img.Layers()
	if err != nil {
		return nil, fmt.Errorf("get layers: %w", err)
	}

	for i, layer := range layers {
		//each layer is gzip-compressed tar archive
		rc, err := layer.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("open layer %d: %w", i, err)
		}

		if err := extractTar(rc, root); err != nil {
			rc.Close()
			return nil, fmt.Errorf("extract layer %d: %w", i, err)
		}
		rc.Close()
	}

	ok = true
	return &ExtractedImage{
		RootPath: root,
		cleanup:  func() error { return os.RemoveAll(root) },
	}, nil
}

// extractTar unpacks a single tar stream into destDir
// considers
// - path traversal: rejects malware whose resolved path escapes destDir ("../../etc/passwd"")
// - whiteout files: skipped. OCI layers ".wh." to mark deletions
// - symlinks: written as symlinks, not followed
// - hard links: checked for path traversal
func extractTar(r io.Reader, destDir string) error {
	tr := tar.NewReader(r)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		cleanName := filepath.Clean(hdr.Name)
		if cleanName == "." {
			continue
		}

		destPath := filepath.Join(destDir, cleanName)
		if !strings.HasPrefix(destPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue
		}

		base := filepath.Base(cleanName)
		if strings.HasPrefix(base, ".wh.") {
			// opaque whiteout (.wh..wh..opq) marks entire dir as replaced
			// regular whiteout (.wh.*) marks specific file as deleted
			if base == ".wh..wh..opq" {
				dir := filepath.Dir(destPath)
				if err := removeContents(dir); err != nil {
					return fmt.Errorf("apply opaque whiteout %s: %w", cleanName, err)
				}
			} else {
				target := filepath.Join(filepath.Dir(destPath), strings.TrimPrefix(base, ".wh."))
				os.Remove(target)
			}
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destPath, hdr.FileInfo().Mode()); err != nil {
				return fmt.Errorf("mkdir %s: %w", destPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
				return fmt.Errorf("mkdir parent for %s: %w", destPath, err)
			}

			f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, hdr.FileInfo().Mode())
			if err != nil {
				return fmt.Errorf("create file %s: %w", destPath, err)
			}

			// limit file copy size to 512MB - prevents zip bombs in malware
			const maxFileSize = 512 << 20
			if _, err := io.Copy(f, io.LimitReader(tr, maxFileSize)); err != nil {
				f.Close()
				return fmt.Errorf("write file %s: %w", destPath, err)
			}
			f.Close()

		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
				return fmt.Errorf("mkdir parent for symlink %s: %w", destPath, err)
			}
			os.Remove(destPath)
			if err := os.Symlink(hdr.Linkname, destPath); err != nil {
				return fmt.Errorf("symlink %s → %s: %w", destPath, hdr.Linkname, err)
			}

		case tar.TypeLink:
			linkTarget := filepath.Join(destDir, filepath.Clean(hdr.Linkname))
			if !strings.HasPrefix(linkTarget, filepath.Clean(destDir)+string(os.PathSeparator)) {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
				return fmt.Errorf("mkdir parent for hardlink %s: %w", destPath, err)
			}
			os.Remove(destPath)
			if err := os.Link(linkTarget, destPath); err != nil {
				return fmt.Errorf("hardlink %s → %s: %w", destPath, linkTarget, err)
			}
		default:
			continue
		}
	}

	return nil
}

// removeContents removes all entries inside dir without removing dir itself
func removeContents(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}
