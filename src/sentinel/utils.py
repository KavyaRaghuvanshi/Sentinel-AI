"""
Sentinel AI - Utility Functions

Common helpers used across all modules.
"""

from __future__ import annotations

import platform
import re
import socket
from datetime import datetime, timezone


def format_bytes(num_bytes: int | float) -> str:
    """Convert bytes to a human-readable string (e.g., '4.21 GB')."""
    if num_bytes < 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"


def format_mb(num_bytes: int | float) -> float:
    """Convert bytes to megabytes, rounded to 2 decimal places."""
    return round(num_bytes / (1024 * 1024), 2)


def format_gb(num_bytes: int | float) -> float:
    """Convert bytes to gigabytes, rounded to 2 decimal places."""
    return round(num_bytes / (1024**3), 2)


def get_hostname() -> str:
    """Return the machine hostname."""
    return socket.gethostname()


def get_timestamp() -> str:
    """Return current local time as an ISO-8601 string."""
    return datetime.now().isoformat(timespec="seconds")


def get_utc_timestamp() -> str:
    """Return current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_os_info() -> dict:
    """Return basic OS version information."""
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "architecture": platform.machine(),
    }


def truncate(text: str, max_length: int = 200) -> str:
    """Truncate text to max_length, appending '…' if truncated."""
    if len(text) <= max_length:
        return text
    return text[: max_length - 1] + "…"


def sanitize_for_filename(text: str) -> str:
    """Remove characters unsafe for filenames."""
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", text)


def seconds_to_human(seconds: float) -> str:
    """Convert seconds to a human-readable duration string."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes = int(seconds // 60)
    rem_seconds = int(seconds % 60)
    if minutes < 60:
        return f"{minutes}m {rem_seconds}s"
    hours = int(minutes // 60)
    rem_minutes = int(minutes % 60)
    return f"{hours}h {rem_minutes}m"
