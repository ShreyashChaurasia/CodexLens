"""Line-oriented local checks for likely hardcoded credentials."""

import re
from collections import Counter
from math import log2
from pathlib import Path

from codexlens.models import Finding, FindingConfidence, Severity

MIN_ENTROPY_LENGTH = 32
MIN_SHANNON_ENTROPY = 3.5
REDACTED_SECRET = "[REDACTED_SECRET]"

_KNOWN_SECRET_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "AWS access key ID",
        "A credential matching an AWS access-key format is present in source code.",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "GitHub token",
        "A credential matching a GitHub-token format is present in source code.",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    ),
    (
        "OpenAI-style API key",
        "A credential matching an API-key format is present in source code.",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "Slack token",
        "A credential matching a Slack-token format is present in source code.",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    ),
    (
        "Private-key header",
        "A private-key header is present in source code.",
        re.compile(r"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----"),
    ),
)
_ASSIGNMENT_PATTERN = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(?P<quote>['\"])(?P<value>[^'\"]+)(?P=quote)"
)
_MAPPING_PATTERN = re.compile(
    r"(?P<key_quote>['\"])(?P<name>[A-Za-z_][A-Za-z0-9_-]*)(?P=key_quote)"
    r"\s*:\s*(?P<value_quote>['\"])(?P<value>[^'\"]+)(?P=value_quote)"
)
_STRING_LITERAL_PATTERN = re.compile(
    r"(?P<quote>['\"])(?P<value>[A-Za-z0-9_+/=.!@#$%^&*()\-]{1,})(?P=quote)"
)
_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{32,}$")


def find_secret_findings(path: Path, source: str) -> tuple[Finding, ...]:
    """Find credentials without returning a secret value or source snippet."""

    findings: list[Finding] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        known_secret = _known_secret_on_line(line)
        if known_secret is not None:
            title, description = known_secret
            findings.append(
                Finding(
                    rule_id="CL002",
                    title=title,
                    severity=Severity.CRITICAL,
                    confidence=FindingConfidence.CONFIRMED,
                    description=description,
                    path=path,
                    line=line_number,
                    cwe="CWE-798",
                )
            )
            continue

        assignment = _sensitive_assignment_on_line(line)
        if assignment is not None:
            name = assignment
            findings.append(
                Finding(
                    rule_id="CL001",
                    title="Hardcoded sensitive value",
                    severity=Severity.HIGH,
                    confidence=FindingConfidence.CONFIRMED,
                    description=f"A hardcoded value is assigned to `{name}`.",
                    path=path,
                    line=line_number,
                    cwe="CWE-798",
                )
            )
            continue

        if _has_high_entropy_literal(line):
            findings.append(
                Finding(
                    rule_id="CL003",
                    title="High-entropy secret candidate",
                    severity=Severity.MEDIUM,
                    confidence=FindingConfidence.CANDIDATE,
                    description="A high-entropy string literal may be a hardcoded credential.",
                    path=path,
                    line=line_number,
                    cwe="CWE-798",
                )
            )

    return tuple(findings)


def redact_sensitive_source(source: str) -> str:
    """Replace likely credentials before source code leaves the local machine.

    Replacements deliberately preserve newlines so source-line references remain
    meaningful to downstream analysis.
    """

    redacted = source
    for _, _, pattern in _KNOWN_SECRET_PATTERNS:
        redacted = pattern.sub(REDACTED_SECRET, redacted)

    redacted = _ASSIGNMENT_PATTERN.sub(_redact_sensitive_assignment, redacted)
    redacted = _MAPPING_PATTERN.sub(_redact_sensitive_mapping, redacted)
    return _STRING_LITERAL_PATTERN.sub(_redact_high_entropy_literal, redacted)


def _known_secret_on_line(line: str) -> tuple[str, str] | None:
    for title, description, pattern in _KNOWN_SECRET_PATTERNS:
        if pattern.search(line):
            return title, description
    return None


def _sensitive_assignment_on_line(line: str) -> str | None:
    for pattern in (_ASSIGNMENT_PATTERN, _MAPPING_PATTERN):
        match = pattern.search(line)
        if match is None:
            continue

        name = match.group("name")
        value = match.group("value")
        if _is_sensitive_name(name) and not _is_placeholder(value):
            return name
    return None


def _redact_sensitive_assignment(match: re.Match[str]) -> str:
    if not _is_sensitive_name(match.group("name")) or _is_placeholder(match.group("value")):
        return match.group(0)
    return _replace_match_value(match)


def _redact_sensitive_mapping(match: re.Match[str]) -> str:
    if not _is_sensitive_name(match.group("name")) or _is_placeholder(match.group("value")):
        return match.group(0)
    return _replace_match_value(match)


def _replace_match_value(match: re.Match[str]) -> str:
    return (
        match.string[match.start() : match.start("value")]
        + REDACTED_SECRET
        + match.string[match.end("value") : match.end()]
    )


def _redact_high_entropy_literal(match: re.Match[str]) -> str:
    value = match.group("value")
    if not _is_high_entropy_literal(value):
        return match.group(0)
    quote = match.group("quote")
    return f"{quote}{REDACTED_SECRET}{quote}"


def _is_sensitive_name(name: str) -> bool:
    normalized = name.rsplit(".", maxsplit=1)[-1].replace("-", "_").lower()
    direct_names = {
        "api_key",
        "api_secret",
        "auth_token",
        "credential",
        "credentials",
        "password",
        "passwd",
        "private_key",
        "pwd",
        "secret",
        "secret_key",
        "token",
    }
    sensitive_suffixes = ("_key", "_secret", "_token", "_password", "_passwd", "_pwd")
    return normalized in direct_names or normalized.endswith(sensitive_suffixes)


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    if not normalized:
        return True
    if normalized.startswith(("${", "{{", "<")):
        return True
    placeholders = {
        "changeme",
        "change_me",
        "example",
        "placeholder",
        "replace_me",
        "[redacted_secret]",
        "your_api_key",
        "your_secret",
    }
    return normalized in placeholders


def _has_high_entropy_literal(line: str) -> bool:
    for match in _STRING_LITERAL_PATTERN.finditer(line):
        if _is_high_entropy_literal(match.group("value")):
            return True
    return False


def _is_high_entropy_literal(value: str) -> bool:
    return (
        not _is_placeholder(value)
        and not _looks_non_secret(value)
        and len(value) >= MIN_ENTROPY_LENGTH
        and _character_groups(value) >= 3
        and _shannon_entropy(value) >= MIN_SHANNON_ENTROPY
    )


def _looks_non_secret(value: str) -> bool:
    return (
        value.startswith(("http://", "https://", "./", "../", "/"))
        or bool(_UUID_PATTERN.fullmatch(value))
        or bool(_HEX_HASH_PATTERN.fullmatch(value))
    )


def _character_groups(value: str) -> int:
    groups = (
        any(character.islower() for character in value),
        any(character.isupper() for character in value),
        any(character.isdigit() for character in value),
        any(not character.isalnum() for character in value),
    )
    return sum(groups)


def _shannon_entropy(value: str) -> float:
    length = len(value)
    return -sum((count / length) * log2(count / length) for count in Counter(value).values())
