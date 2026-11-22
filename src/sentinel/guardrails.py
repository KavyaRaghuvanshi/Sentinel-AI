"""
Sentinel AI - Security Guardrails

Sanitization layer that prevents prompt-injection attacks when
untrusted system text (process names, file paths, event log entries)
is passed to the LLM agent.
"""

from __future__ import annotations

import re
from typing import Any


# --- Dangerous patterns that could be prompt-injection attempts ---
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+a", re.IGNORECASE),
    re.compile(r"system\s*:\s*", re.IGNORECASE),
    re.compile(r"<\s*/?\s*(?:script|img|iframe|object|embed|svg)", re.IGNORECASE),
    re.compile(r"\{\{.*?\}\}"),              # Template injection
    re.compile(r"\$\{.*?\}"),                # Template literal injection
    re.compile(r"(?:exec|eval|import)\s*\(", re.IGNORECASE),
]

# --- Paths that must never be deleted or modified ---
_PROTECTED_PATHS: list[str] = [
    "\\windows\\",
    "\\windows\\system32\\",
    "\\program files\\",
    "\\program files (x86)\\",
    "\\programdata\\",
    "\\users\\default\\",
]


def sanitize_text(text: str, max_length: int = 200) -> str:
    """
    Sanitize untrusted text before it reaches the LLM.

    - Strips control characters (keeps printable ASCII + common Unicode).
    - Truncates to *max_length*.
    - Flags (but does not remove) suspicious injection patterns by
      replacing them with ``[REDACTED]``.
    """
    if not isinstance(text, str):
        return str(text)[:max_length]

    # Strip ASCII control characters except newline/tab
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

    # Redact anything that looks like a prompt-injection attempt
    for pattern in _INJECTION_PATTERNS:
        cleaned = pattern.sub("[REDACTED]", cleaned)

    # Truncate
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length - 3] + "..."

    return cleaned


def sanitize_process_name(name: str) -> str:
    """Sanitize a process name to safe printable characters, max 100 chars."""
    if not name:
        return "<unknown>"
    # Allow only alphanumeric, dots, hyphens, underscores, spaces
    safe = re.sub(r"[^a-zA-Z0-9.\-_ ]", "_", name)
    return safe[:100]


def is_protected_path(path: str) -> bool:
    """Return True if *path* falls inside a protected system directory."""
    normalized = path.lower().replace("/", "\\")
    return any(protected in normalized for protected in _PROTECTED_PATHS)


def is_extension_protected(filename: str, protected_extensions: list[str]) -> bool:
    """Return True if the file has a protected extension."""
    lower_name = filename.lower()
    return any(lower_name.endswith(ext.lower()) for ext in protected_extensions)


def sanitize_telemetry(telemetry: dict[str, Any]) -> dict[str, Any]:
    """
    Deep-sanitize a telemetry dictionary before passing it to the LLM.

    Walks all string values and applies sanitize_text; truncates lists
    to prevent context-window abuse.
    """
    return _sanitize_value(telemetry, depth=0)


def _sanitize_value(value: Any, depth: int) -> Any:
    """Recursively sanitize a value. Caps recursion at depth 10."""
    if depth > 10:
        return "[DEPTH_LIMIT]"

    if isinstance(value, str):
        return sanitize_text(value, max_length=300)
    elif isinstance(value, dict):
        return {
            sanitize_text(str(k), max_length=100): _sanitize_value(v, depth + 1)
            for k, v in value.items()
        }
    elif isinstance(value, (list, tuple)):
        # Cap list length to prevent flooding
        items = value[:50]
        return [_sanitize_value(item, depth + 1) for item in items]
    else:
        return value
