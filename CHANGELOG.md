# Changelog

All notable changes to CodexLens are documented in this file.

The project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-07-20

### Added

- Three-pass Python security-auditing pipeline: local static analysis,
  model-assisted business-logic review, and confirmation-gated auto-fix.
- Model-neutral OpenAI Responses API integration selected with `--model` or
  `CODEXLENS_MODEL`.
- Locally validated, single-source-unit patch proposals with an explicit
  `y`/`n` decision and atomic application safeguards.
- Source-free JSON reporting for CI and a GitHub Actions quality workflow.
- An owned ExpenseFlow IDOR demonstration, exploit proof, hardened reference,
  regression test, and credential-free offline replay.
- `codexlens --version` for release verification and support workflows.

### Security

- Heuristic redaction before optional model-assisted analysis.
- Strict local validation of model output and patch bindings before a file can
  be changed.
