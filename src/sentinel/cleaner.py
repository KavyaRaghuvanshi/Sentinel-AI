"""
Sentinel AI - Safe Temp File Cleaner

Deterministic cleanup engine that safely removes orphaned temporary
files without breaking running programs or deleting protected files.

Safety guarantees:
  - Never deletes files currently locked by a process
  - Never deletes files inside protected system directories
  - Never deletes files with protected extensions
  - Respects a configurable maximum deletion cap (MB)
  - Only targets files older than the configured age threshold
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from pathlib import Path

from sentinel.guardrails import is_extension_protected, is_protected_path


def get_temp_directories(additional_dirs: list[str] | None = None) -> list[Path]:
    """
    Return a de-duplicated list of temp directories to scan.

    Automatically includes the standard Windows TEMP and
    LOCALAPPDATA/Temp directories, plus any user-configured extras.
    """
    candidates: list[str | None] = [
        os.environ.get("TEMP"),
        os.environ.get("TMP"),
    ]

    local_app = os.environ.get("LOCALAPPDATA")
    if local_app:
        candidates.append(os.path.join(local_app, "Temp"))

    if additional_dirs:
        candidates.extend(additional_dirs)

    # De-duplicate and filter to existing directories
    seen: set[str] = set()
    dirs: list[Path] = []
    for c in candidates:
        if c is None:
            continue
        resolved = str(Path(c).resolve())
        if resolved not in seen and Path(resolved).is_dir():
            seen.add(resolved)
            dirs.append(Path(resolved))

    return dirs


def scan_temp_files(
    min_age_hours: int = 24,
    protected_extensions: list[str] | None = None,
    additional_dirs: list[str] | None = None,
) -> list[dict]:
    """
    Scan temporary directories and return a list of deletable file records.

    Each record: ``{"path": str, "size_bytes": int, "age_hours": float}``
    """
    if protected_extensions is None:
        protected_extensions = []

    cutoff = datetime.now() - timedelta(hours=min_age_hours)
    deletable: list[dict] = []

    for temp_dir in get_temp_directories(additional_dirs):
        for root, _dirs, files in os.walk(temp_dir):
            # Skip protected system paths
            if is_protected_path(root):
                continue

            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    stat = os.stat(filepath)
                    mtime = datetime.fromtimestamp(stat.st_mtime)

                    if mtime >= cutoff:
                        continue  # Too new

                    if is_extension_protected(filename, protected_extensions):
                        continue  # Protected extension

                    age_hours = (datetime.now() - mtime).total_seconds() / 3600

                    deletable.append({
                        "path": filepath,
                        "size_bytes": stat.st_size,
                        "age_hours": round(age_hours, 1),
                    })
                except (OSError, ValueError):
                    continue  # File inaccessible; skip

    return deletable


def clean_temp_files(
    min_age_hours: int = 24,
    max_delete_mb: int = 5000,
    protected_extensions: list[str] | None = None,
    additional_dirs: list[str] | None = None,
    dry_run: bool = False,
) -> dict:
    """
    Safely delete orphaned temporary files.

    Parameters
    ----------
    min_age_hours : int
        Minimum file age in hours before it's eligible for deletion.
    max_delete_mb : int
        Safety cap: stop deleting after this many MB have been freed.
    protected_extensions : list[str]
        File extensions that must never be deleted.
    additional_dirs : list[str]
        Extra directories to scan beyond standard TEMP dirs.
    dry_run : bool
        If True, scan and report but do not actually delete anything.

    Returns
    -------
    dict
        Summary: purged_mb, files_deleted, files_skipped, dry_run,
        and scanned_dirs.
    """
    if protected_extensions is None:
        protected_extensions = [".dll", ".sys", ".exe", ".msi", ".log"]

    max_delete_bytes = max_delete_mb * 1024 * 1024
    targets = scan_temp_files(min_age_hours, protected_extensions, additional_dirs)

    deleted_bytes = 0
    deleted_count = 0
    skipped_count = 0
    scanned_dirs = get_temp_directories(additional_dirs)

    for entry in targets:
        if deleted_bytes >= max_delete_bytes:
            break  # Safety cap reached

        if dry_run:
            deleted_bytes += entry["size_bytes"]
            deleted_count += 1
            continue

        try:
            os.remove(entry["path"])
            deleted_bytes += entry["size_bytes"]
            deleted_count += 1
        except (PermissionError, FileNotFoundError, OSError):
            skipped_count += 1  # File is locked by a running process

    return {
        "purged_mb": round(deleted_bytes / (1024 * 1024), 2),
        "files_deleted": deleted_count,
        "files_skipped": skipped_count,
        "total_candidates": len(targets),
        "dry_run": dry_run,
        "scanned_dirs": [str(d) for d in scanned_dirs],
    }
