# harbinger

Container image malware scanner. 
Pulls OCI images, generates a CycloneDX SBOM, and concurrently runs YARA pattern matching and CVE detection across all image contents. Returns a unified JSON findings report.

---

## What it does

Harbinger accepts an image reference via HTTP, pulls and unpacks the image layers, and runs two detection engines concurrently across every file:

- **YARA scanner** — matches file bytes against bundled rules for known malware patterns, suspicious strings, and embedded scripts
- **CVE scanner** — generates a CycloneDX SBOM via Syft, extracts package URLs (pURLs), and queries the OSV API for known vulnerabilities

Results are normalised into a single findings report typed by severity. The scanner runs as an HTTP server, deployed to Kubernetes, and can be triggered manually or later on a schedule via a CronJob.
