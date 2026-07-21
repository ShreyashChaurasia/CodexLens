# CodexLens v0.2.1

CodexLens v0.2.1 is a compatibility patch for the production security-review
workflow: local static analysis, optional OpenAI business-logic review, and
human-approved patching.

## Highlights

- Replaced the Unicode banner used by root help and `codexlens --version` with
  an ASCII-only wordmark, so the command works in Windows terminals using a
  legacy code page.
- Kept package metadata, lockfiles, the PyPI workflow default, and the owned
  ExpenseFlow example on the same `0.2.1` version.

## Upgrade notes

- `codexlens --version` remains human-readable branded output and is now safe
  to run in standard Windows consoles. Tools that need only the installed
  version should use Python package metadata.

## Verification

This release is built from the `v0.2.1` tag after locked dependency install,
Ruff checks, the full test suite, and source/wheel builds. The attached
artifacts are the release source distribution and universal Python wheel.

## Getting started

See the [README](https://github.com/ShreyashChaurasia/CodexLens#readme) for
installation and the optional live OpenAI review workflow. Review the
[security policy](https://github.com/ShreyashChaurasia/CodexLens/security/policy)
before scanning code that may contain sensitive material.
