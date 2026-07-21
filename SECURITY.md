# Security Policy

## Supported versions

CodexLens is in its `0.2.x` release series. Security fixes are applied to the
latest `0.2.x` release.

| Version | Supported |
| --- | --- |
| 0.2.x | Yes |
| Earlier versions | No |

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities, bypasses, or sensitive
reproduction material in a public GitHub issue.

Use GitHub's private vulnerability reporting feature when it is available for
this repository. If it is unavailable, contact
[@ShreyashChaurasia](https://github.com/ShreyashChaurasia) privately through
GitHub with:

- a concise description of the issue and its impact;
- a safe reproduction path that contains no real credentials or customer code;
- the affected CodexLens version and operating system; and
- any proposed mitigation, if available.

Reports receive an acknowledgement as soon as practical. A fix is validated,
released in the latest supported version, and credited when requested.

## Handling scanned code

CodexLens operates locally for static analysis. Optional AI passes send bounded
source context to OpenAI after heuristic redaction; no redaction strategy can
guarantee removal of every sensitive detail. Only code authorized for sharing
with the selected service should be scanned.
