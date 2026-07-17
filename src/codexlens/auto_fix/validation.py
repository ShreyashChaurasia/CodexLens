"""Local, fail-closed validation for Pass 3 source-unit replacements."""

import ast
import difflib
import hashlib
import io
import tokenize
from dataclasses import dataclass, field
from pathlib import Path

from codexlens.auto_fix.models import (
    FixCandidate,
    PatchDiagnostic,
    PatchGenerationResult,
    PatchProposal,
)
from codexlens.static_analysis.secrets import REDACTED_SECRET, redact_sensitive_source

MAX_FILE_BYTES = 1_000_000
MAX_SOURCE_UNIT_CHARS = 16_000
MAX_REPLACEMENT_CHARS = 20_000
MAX_CHANGED_LINES = 240
MAX_SUMMARY_CHARS = 1_000
MAX_VERIFICATION_NOTES = 8
MAX_NOTE_CHARS = 500


@dataclass(frozen=True, slots=True)
class PatchSnapshot:
    """An immutable local preimage captured before any model request."""

    candidate: FixCandidate
    target_root: Path
    target_root_device: int
    target_root_inode: int
    path: Path
    relative_path: Path
    original_bytes: bytes = field(repr=False)
    source_text: str = field(repr=False)
    unit_source: str = field(repr=False)
    encoding: str
    newline: str
    base_file_sha256: str


def capture_patch_snapshot(
    target: Path,
    candidate: FixCandidate,
) -> tuple[PatchSnapshot | None, PatchDiagnostic | None]:
    """Read and validate the one source unit that a model may replace."""

    relative_path = _validated_relative_path(candidate.relative_path)
    if relative_path is None:
        return None, _diagnostic(candidate, "patch-path-invalid", "The patch target was invalid.")

    try:
        root, allowed_file = _target_scope(target)
        root_stat = root.stat()
        lexical_path = root.joinpath(*relative_path.parts)
        if _has_symlink_component(root, lexical_path):
            return None, _diagnostic(
                candidate,
                "patch-path-symlink",
                "The patch target could not be safely resolved.",
            )
        resolved_path = lexical_path.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, _diagnostic(
            candidate,
            "patch-path-unavailable",
            "The patch target could not be safely read.",
        )

    if (
        not resolved_path.is_relative_to(root)
        or (allowed_file is not None and resolved_path != allowed_file)
        or resolved_path.suffix.lower() != ".py"
        or not resolved_path.is_file()
        or resolved_path.is_symlink()
    ):
        return None, _diagnostic(
            candidate,
            "patch-path-outside-scope",
            "The patch target is outside the selected Python source scope.",
        )

    try:
        original_bytes = resolved_path.read_bytes()
    except OSError:
        return None, _diagnostic(
            candidate,
            "patch-read-error",
            "The patch target could not be safely read.",
        )

    if len(original_bytes) > MAX_FILE_BYTES:
        return None, _diagnostic(
            candidate,
            "patch-file-limit",
            "The patch target exceeds the safe auto-fix file size limit.",
        )

    decoded = _decode_python_source(original_bytes)
    if decoded is None:
        return None, _diagnostic(
            candidate,
            "patch-decode-error",
            "The patch target could not be decoded safely.",
        )
    source_text, encoding = decoded

    unit_source = _source_unit_from_snapshot(source_text, candidate)
    if unit_source is None:
        return None, _diagnostic(
            candidate,
            "patch-unit-mismatch",
            "The reviewed source unit no longer matches the local file.",
        )

    if (
        REDACTED_SECRET in unit_source
        or redact_sensitive_source(unit_source) != unit_source
    ):
        return None, _diagnostic(
            candidate,
            "patch-source-sensitive",
            "The reviewed source unit contains sensitive data, so no patch was requested.",
        )

    if _has_unsafe_controls(unit_source):
        return None, _diagnostic(
            candidate,
            "patch-source-unsafe",
            "The reviewed source unit contains unsafe control characters.",
        )

    if _unit_sha256(unit_source) != candidate.source_unit_sha256:
        return None, _diagnostic(
            candidate,
            "patch-unit-stale",
            "The reviewed source unit changed after the AI scan; rerun the scan first.",
        )

    if len(unit_source) > MAX_SOURCE_UNIT_CHARS:
        return None, _diagnostic(
            candidate,
            "patch-unit-limit",
            "The reviewed source unit exceeds the safe auto-fix size limit.",
        )

    return (
        PatchSnapshot(
            candidate=candidate,
            target_root=root,
            target_root_device=root_stat.st_dev,
            target_root_inode=root_stat.st_ino,
            path=resolved_path,
            relative_path=relative_path,
            original_bytes=original_bytes,
            source_text=source_text,
            unit_source=unit_source,
            encoding=encoding,
            newline=_preferred_newline(source_text),
            base_file_sha256=hashlib.sha256(original_bytes).hexdigest(),
        ),
        None,
    )


def validate_model_payload(
    snapshot: PatchSnapshot,
    payload: object,
) -> PatchGenerationResult:
    """Validate structured model data and produce a local canonical proposal."""

    if not isinstance(payload, dict) or set(payload) != _EXPECTED_RESPONSE_KEYS:
        return _rejected(snapshot, "patch-response-invalid-shape")

    status = payload.get("status")
    summary = payload.get("summary")
    notes = payload.get("verification_notes")
    replacement = payload.get("replacement_source")
    if (
        payload.get("schema_version") != "codexlens.pass3.v1"
        or status not in {"proposed", "not_applicable"}
        or payload.get("candidate_id") != snapshot.candidate.candidate_id
        or payload.get("source_unit_id") != snapshot.candidate.source_unit_id
        or payload.get("source_unit_sha256") != snapshot.candidate.source_unit_sha256
        or payload.get("base_file_sha256") != snapshot.base_file_sha256
        or not _is_safe_summary(summary)
        or not _is_safe_notes(notes)
        or not isinstance(replacement, str)
    ):
        return _rejected(snapshot, "patch-response-invalid-binding")

    if status == "not_applicable":
        if replacement:
            return _rejected(snapshot, "patch-response-invalid-replacement")
        return PatchGenerationResult(
            diagnostics=(
                _diagnostic(
                    snapshot.candidate,
                    "patch-not-applicable",
                    "The selected model could not produce a safe, precise patch for this finding.",
                ),
            )
        )

    if not replacement or len(replacement) > MAX_REPLACEMENT_CHARS:
        return _rejected(snapshot, "patch-response-invalid-replacement")
    if _has_unsafe_controls(replacement) or REDACTED_SECRET in replacement:
        return _rejected(snapshot, "patch-response-invalid-replacement")
    if redact_sensitive_source(replacement) != replacement:
        return _rejected(snapshot, "patch-response-sensitive")

    normalized_replacement = _with_snapshot_newlines(replacement, snapshot.newline)
    if _ends_with_newline(snapshot.unit_source) and not _ends_with_newline(
        normalized_replacement
    ):
        return _rejected(snapshot, "patch-response-invalid-replacement")

    updated_text = _replace_unit(snapshot, normalized_replacement)
    if updated_text is None:
        return _rejected(snapshot, "patch-unit-mismatch")
    try:
        updated_bytes = updated_text.encode(snapshot.encoding)
    except UnicodeEncodeError:
        return _rejected(snapshot, "patch-encoding-error")

    round_tripped = _decode_python_source(updated_bytes)
    if round_tripped is None or round_tripped[0] != updated_text:
        return _rejected(snapshot, "patch-encoding-error")

    if updated_bytes == snapshot.original_bytes:
        return _rejected(snapshot, "patch-response-noop")
    try:
        ast.parse(updated_text, filename=str(snapshot.path))
    except (SyntaxError, ValueError, TypeError):
        return _rejected(snapshot, "patch-response-syntax-error")

    changed_lines = _changed_line_count(snapshot.source_text, updated_text)
    if changed_lines == 0:
        return _rejected(snapshot, "patch-response-noop")
    if changed_lines > MAX_CHANGED_LINES:
        return _rejected(snapshot, "patch-response-too-large")

    unified_diff = _canonical_diff(snapshot, updated_text)
    if not unified_diff:
        return _rejected(snapshot, "patch-response-noop")

    return PatchGenerationResult(
        proposal=PatchProposal(
            candidate=snapshot.candidate,
            target_root=snapshot.target_root,
            target_root_device=snapshot.target_root_device,
            target_root_inode=snapshot.target_root_inode,
            path=snapshot.path,
            relative_path=snapshot.relative_path,
            base_file_sha256=snapshot.base_file_sha256,
            original_bytes=snapshot.original_bytes,
            updated_bytes=updated_bytes,
            encoding=snapshot.encoding,
            unified_diff=unified_diff,
            summary=_safe_terminal_text(summary, MAX_SUMMARY_CHARS),
            verification_notes=tuple(
                _safe_terminal_text(note, MAX_NOTE_CHARS) for note in notes
            ),
        )
    )


def _target_scope(target: Path) -> tuple[Path, Path | None]:
    resolved_target = target.resolve(strict=True)
    if resolved_target.is_dir():
        return resolved_target, None
    if resolved_target.is_file() and resolved_target.suffix.lower() == ".py":
        return resolved_target.parent, resolved_target
    raise OSError("unsupported target")


def _validated_relative_path(path: Path) -> Path | None:
    if path.is_absolute() or path.drive or path.root or path.suffix.lower() != ".py":
        return None
    if not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return Path(*path.parts)


def _has_symlink_component(root: Path, path: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _decode_python_source(raw_bytes: bytes) -> tuple[str, str] | None:
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw_bytes).readline)
        return raw_bytes.decode(encoding), encoding
    except (LookupError, SyntaxError, UnicodeError):
        return None


def _source_unit_from_snapshot(source_text: str, candidate: FixCandidate) -> str | None:
    start_line = candidate.source_unit_start_line
    end_line = candidate.source_unit_end_line
    if (
        not _is_positive_int(start_line)
        or not _is_positive_int(end_line)
        or start_line > end_line
        or not _is_sha256(candidate.source_unit_sha256)
    ):
        return None
    lines = source_text.splitlines(keepends=True)
    if end_line > len(lines):
        return None
    return "".join(lines[start_line - 1 : end_line])


def _unit_sha256(source: str) -> str:
    return hashlib.sha256(_normalize_newlines(source).encode("utf-8")).hexdigest()


def _normalize_newlines(source: str) -> str:
    return source.replace("\r\n", "\n").replace("\r", "\n")


def _preferred_newline(source: str) -> str:
    if "\r\n" in source:
        return "\r\n"
    if "\r" in source:
        return "\r"
    return "\n"


def _with_snapshot_newlines(source: str, newline: str) -> str:
    return _normalize_newlines(source).replace("\n", newline)


def _replace_unit(snapshot: PatchSnapshot, replacement: str) -> str | None:
    lines = snapshot.source_text.splitlines(keepends=True)
    start_line = snapshot.candidate.source_unit_start_line
    end_line = snapshot.candidate.source_unit_end_line
    if end_line > len(lines):
        return None
    return "".join((*lines[: start_line - 1], replacement, *lines[end_line:]))


def _changed_line_count(original: str, updated: str) -> int:
    matcher = difflib.SequenceMatcher(
        a=original.splitlines(keepends=True),
        b=updated.splitlines(keepends=True),
        autojunk=False,
    )
    return sum(
        (old_end - old_start) + (new_end - new_start)
        for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes()
        if tag != "equal"
    )


def _canonical_diff(snapshot: PatchSnapshot, updated_text: str) -> str:
    relative = snapshot.relative_path.as_posix()
    return "".join(
        difflib.unified_diff(
            _display_diff_lines(snapshot.source_text),
            _display_diff_lines(updated_text),
            fromfile=f"a/{relative}",
            tofile=f"b/{relative}",
            n=0,
        )
    )


def _display_diff_lines(source: str) -> list[str]:
    normalized = _normalize_newlines(source)
    return [
        line if line.endswith("\n") else f"{line}\n"
        for line in normalized.splitlines(keepends=True)
    ]


def _is_safe_summary(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= MAX_SUMMARY_CHARS


def _is_safe_notes(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= MAX_VERIFICATION_NOTES
        and all(
            isinstance(note, str) and note.strip() and len(note) <= MAX_NOTE_CHARS
            for note in value
        )
    )


def _safe_terminal_text(value: str, limit: int) -> str:
    cleaned = "".join(
        character if character in {"\n", "\t"} or character.isprintable() else " "
        for character in value
    )
    return redact_sensitive_source(cleaned).strip()[:limit]


def _has_unsafe_controls(value: str) -> bool:
    return any(
        not (character in {"\n", "\r", "\t"} or character.isprintable())
        for character in value
    )


def _ends_with_newline(value: str) -> bool:
    return value.endswith(("\n", "\r"))


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _diagnostic(candidate: FixCandidate, kind: str, message: str) -> PatchDiagnostic:
    return PatchDiagnostic(kind=kind, message=message, path=candidate.relative_path)


def _rejected(snapshot: PatchSnapshot, kind: str) -> PatchGenerationResult:
    return PatchGenerationResult(
        diagnostics=(
            _diagnostic(
                snapshot.candidate,
                kind,
                "The model response was rejected because it did not meet CodexLens safety checks.",
            ),
        )
    )


_EXPECTED_RESPONSE_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "candidate_id",
        "source_unit_id",
        "source_unit_sha256",
        "base_file_sha256",
        "summary",
        "verification_notes",
        "replacement_source",
    }
)
