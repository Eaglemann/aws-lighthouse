# Changelog

All notable changes are documented here. The project follows Semantic
Versioning while acknowledging that pre-1.0 releases may change interfaces.

## Unreleased

### Fixed

- Degraded scans no longer emit false resolved findings, overwrite trusted
  baselines with incomplete absence, or resolve opportunities outside successful
  source/region coverage.
- Cost forecasts use AWS prediction interval fields and the API-required current
  start date instead of min/max mean values.
- Security-group blast-radius enrichment is region-aware even when IDs repeat.
- SARIF now reports the installed package version and canonical repository URL.

### Security

- Removed the dormant MCP client that auto-downloaded an unpinned npm package
  while inheriting the process environment.
- Removed generic shell execution from the model's tool list and narrowed the
  internal command allowlist to static diagnostics.
- Approval-gated Terraform reads, drift reads, and local opportunity mutations.
- Added per-resource confirmations for CLI remediation.
- Removed unused dependency trees, upgraded the lockfile, removed the final audit
  exception, and made release security gates match CI.
- Expanded credential/state ignore patterns and checksum-verified Gitleaks.

### Changed

- Extracted reconciliation, scan orchestration, output/SARIF rendering, approval
  policy, remediation execution, and database schema/migrations from hotspot
  modules.
- Added guarded AWS/Ollama live qualification and full project documentation.

## 0.3.0

- Current alpha baseline before the unreleased reliability and hardening work.
