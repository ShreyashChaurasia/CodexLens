# CodexLens v0.1.0

This is the first public release of CodexLens: a Python CLI security auditor
for reviews that need more than pattern matching.

## Highlights

- A three-pass workflow combines local static checks, optional AI-assisted
  business-logic review, and confirmation-gated patch proposals.
- Any compatible OpenAI model can be selected with `--model` or
  `CODEXLENS_MODEL`; CodexLens does not hard-code a model family.
- Proposed fixes are constrained to a reviewed source unit, shown as a local
  unified diff, and applied only when the user enters `y`.
- The repository includes JSON reporting for automation and an owned
  ExpenseFlow IDOR demonstration with exploit and hardened-reference tests.

## Verification

This release was built from the `v0.1.0` tag after locked dependency install,
Ruff checks, the full test suite, and source/wheel builds. The attached
artifacts are the release source distribution and universal Python wheel.

## Getting started

See the [README](https://github.com/ShreyashChaurasia/CodexLens#readme) for
installation, the credential-free offline replay, and the optional live
OpenAI evaluation path. Review the
[security policy](https://github.com/ShreyashChaurasia/CodexLens/security/policy)
before scanning code that may contain sensitive material.
