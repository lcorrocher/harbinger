package sbom

import (
	"fmt"

	"github.com/anchore/syft/syft/pkg"
)

type Package struct {
	Name    string
	Version string
	// package URL — standardised id accepted by OSV and other vulnerability DBs e.g. pkg:deb/debian/curl@7.68.0
	PURL string
	Type string
}

// Parse extracts all packages from a generated SBOM document, returning
// a slice of Package values ready for OSV CVE querying
//
// OSV requires a pURL to identify a package. Syft assigns pURLs to all packages it recognises
func Parse(doc *Document) ([]Package, error) {
	if doc == nil || doc.sbom == nil {
		return nil, fmt.Errorf("parse: nil document")
	}

	all := doc.sbom.Artifacts.Packages.Sorted()
	packages := make([]Package, 0, len(all))

	for _, p := range all {
		purl := p.PURL
		if purl == "" {
			// skip
			continue
		}

		packages = append(packages, Package{
			Name:    p.Name,
			Version: p.Version,
			PURL:    purl,
			Type:    ecosystemFromType(p.Type),
		})
	}

	return packages, nil
}

func ecosystemFromType(t pkg.Type) string {
	switch t {
	case pkg.DebPkg:
		return "deb"
	case pkg.ApkPkg:
		return "apk"
	case pkg.RpmPkg:
		return "rpm"
	case pkg.NpmPkg:
		return "npm"
	case pkg.PythonPkg:
		return "pypi"
	case pkg.GemPkg:
		return "gem"
	case pkg.GoModulePkg:
		return "golang"
	case pkg.JavaPkg:
		return "maven"
	default:
		return string(t)
	}
}
