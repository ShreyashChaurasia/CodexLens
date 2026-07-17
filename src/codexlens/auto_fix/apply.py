"""Atomic application for already validated CodexLens patch proposals."""

import hashlib
import os
import stat
import tempfile
from pathlib import Path

from codexlens.auto_fix.models import (
    PatchApplyResult,
    PatchDiagnostic,
    PatchProposal,
    PatchStatus,
)


def apply_patch_proposal(proposal: PatchProposal) -> PatchApplyResult:
    """Apply *proposal* only when its local preimage is still byte-for-byte fresh."""

    path = _canonical_target_path(proposal)
    if path is None:
        return _rejected(
            proposal,
            "patch-apply-path-invalid",
            "The patch target is no longer safe.",
        )

    try:
        current_bytes = path.read_bytes()
    except OSError:
        return _rejected(
            proposal,
            "patch-apply-read-error",
            "The patch target could not be read before applying the patch.",
        )
    if (
        current_bytes != proposal.original_bytes
        or hashlib.sha256(current_bytes).hexdigest() != proposal.base_file_sha256
    ):
        return _rejected(
            proposal,
            "patch-apply-stale-file",
            "The target file changed after the patch was proposed; rerun the scan first.",
        )

    try:
        original_mode = stat.S_IMODE(path.stat().st_mode)
        _atomic_replace(proposal, path, original_mode)
    except _StalePatchError:
        return _rejected(
            proposal,
            "patch-apply-stale-file",
            "The target file changed after the patch was proposed; rerun the scan first.",
        )
    except _UnsafePatchTargetError:
        return _rejected(
            proposal,
            "patch-apply-path-invalid",
            "The patch target is no longer safe.",
        )
    except (OSError, RuntimeError):
        return PatchApplyResult(
            status=PatchStatus.FAILED,
            diagnostic=PatchDiagnostic(
                kind="patch-apply-write-error",
                message="The patch could not be applied safely; the original file was preserved.",
                path=proposal.relative_path,
            ),
        )
    return PatchApplyResult(status=PatchStatus.APPLIED)


def _canonical_target_path(proposal: PatchProposal) -> Path | None:
    try:
        relative_path = proposal.relative_path
        target_root = proposal.target_root
        if (
            relative_path.is_absolute()
            or relative_path.drive
            or relative_path.root
            or relative_path.suffix.lower() != ".py"
            or not relative_path.parts
            or any(part in {"", ".", ".."} for part in relative_path.parts)
            or not target_root.is_absolute()
            or target_root.is_symlink()
            or not target_root.is_dir()
            or not proposal.path.is_absolute()
            or proposal.path.suffix.lower() != ".py"
            or proposal.path.is_symlink()
            or not proposal.path.is_file()
            or not proposal.path.is_relative_to(target_root)
        ):
            return None
        resolved_root = target_root.resolve(strict=True)
        if resolved_root != target_root:
            return None
        root_stat = target_root.stat()
        if (
            root_stat.st_dev != proposal.target_root_device
            or root_stat.st_ino != proposal.target_root_inode
        ):
            return None
        expected_path = target_root.joinpath(*relative_path.parts)
        if expected_path != proposal.path:
            return None
        if _has_symlink_component(target_root, expected_path):
            return None
        resolved_path = expected_path.resolve(strict=True)
        if resolved_path != expected_path or not resolved_path.is_relative_to(resolved_root):
            return None
        return expected_path
    except (OSError, RuntimeError):
        return None


def _atomic_replace(proposal: PatchProposal, path: Path, mode: int) -> None:
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=".codexlens-",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    replaced = False
    try:
        with os.fdopen(file_descriptor, "wb") as temporary_file:
            temporary_file.write(proposal.updated_bytes)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.chmod(temporary_path, mode)
        fresh_path = _canonical_target_path(proposal)
        if fresh_path is None or fresh_path != path:
            raise _UnsafePatchTargetError
        current_bytes = fresh_path.read_bytes()
        if (
            current_bytes != proposal.original_bytes
            or hashlib.sha256(current_bytes).hexdigest() != proposal.base_file_sha256
        ):
            raise _StalePatchError
        os.replace(temporary_path, fresh_path)
        replaced = True
    finally:
        if not replaced and _canonical_target_path(proposal) == path:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


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


class _StalePatchError(Exception):
    """Raised when the fresh preimage check fails immediately before replacement."""


class _UnsafePatchTargetError(Exception):
    """Raised when the target path changes safety properties before replacement."""


def _rejected(proposal: PatchProposal, kind: str, message: str) -> PatchApplyResult:
    return PatchApplyResult(
        status=PatchStatus.REJECTED,
        diagnostic=PatchDiagnostic(kind=kind, message=message, path=proposal.relative_path),
    )
