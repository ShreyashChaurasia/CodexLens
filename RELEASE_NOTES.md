# CodexLens v0.2.0

CodexLens v0.2.0 focuses the project on its production security-review
workflow: local static analysis, optional OpenAI business-logic review, and
human-approved patching.

## Highlights

- Removed the legacy non-production walkthrough command and temporary project
  planning material.
- Kept ExpenseFlow as a focused, intentionally vulnerable integration example
  with exploit proof, hardened-reference behavior, and a live patch regression
  path.
- Added the ANSI Shadow CodexLens mark to the README, root help, and version
  output.
- Retained JSON reporting, confirmation-gated patches, strict local patch
  validation, and model-neutral OpenAI Responses API support.

## Upgrade notes

- `codexlens demo` has been removed. Use `codexlens scan` for local static
  analysis or a configured `--model` review instead.
- `codexlens --version` is now human-readable branded output. Tools that need
  only the installed version should use Python package metadata.

## Verification

This release is built from the `v0.2.0` tag after locked dependency install,
Ruff checks, the full test suite, and source/wheel builds. The attached
artifacts are the release source distribution and universal Python wheel.

## Getting started

See the [README](https://github.com/ShreyashChaurasia/CodexLens#readme) for
installation and the optional live OpenAI review workflow. Review the
[security policy](https://github.com/ShreyashChaurasia/CodexLens/security/policy)
before scanning code that may contain sensitive material.
