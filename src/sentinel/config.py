"""
Sentinel AI - Configuration Loader

Loads and validates YAML configuration with layered overrides:
  1. Built-in defaults (hardcoded)
  2. config.yaml (project root)
  3. config.local.yaml (git-ignored personal overrides)
  4. Environment variable overrides
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Default configuration (used when no config file is present)
# ---------------------------------------------------------------------------
_DEFAULTS: dict[str, Any] = {
    "sentinel": {
        "cleanup": {
            "enabled": True,
            "min_age_hours": 24,
            "max_delete_mb": 5000,
            "protected_extensions": [".dll", ".sys", ".exe", ".msi", ".log"],
            "additional_temp_dirs": [],
        },
        "security": {
            "enabled": True,
            "suspicious_exe_paths": ["\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\"],
            "trusted_processes": [
                "python.exe", "pythonw.exe", "code.exe", "chrome.exe",
                "msedge.exe", "explorer.exe", "svchost.exe",
                "RuntimeBroker.exe", "SearchHost.exe", "WindowsTerminal.exe",
            ],
            "event_log_lookback_hours": 24,
            "max_connections_to_report": 20,
        },
        "agent": {
            "provider": "none",
            "model": "gemini-2.5-flash",
            "api_key_env": "GEMINI_API_KEY",
            "ollama_base_url": "http://localhost:11434",
            "temperature": 0.2,
            "max_output_tokens": 1024,
            "fallback_to_template": True,
        },
        "reporter": {
            "console": True,
            "save_to_file": True,
            "report_dir": "./reports",
            "toast_notification": False,
            "webhook": {"enabled": False, "url": ""},
            "email": {
                "enabled": False,
                "smtp_server": "",
                "smtp_port": 587,
                "use_tls": True,
                "sender": "",
                "password_env": "SENTINEL_EMAIL_PASSWORD",
                "recipient": "",
            },
        },
    }
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base*, returning a new dict."""
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _find_config_dir() -> Path:
    """Walk up from CWD looking for a directory containing config.yaml."""
    current = Path.cwd()
    for parent in [current, *current.parents]:
        if (parent / "config.yaml").exists():
            return parent
    return current


def load_config(config_path: str | Path | None = None) -> dict:
    """
    Load configuration with layered overrides.

    Parameters
    ----------
    config_path : str | Path | None
        Explicit path to the primary config.yaml.  If *None*, searches
        from the current working directory upward.

    Returns
    -------
    dict
        The ``sentinel`` sub-tree of the merged configuration.
    """
    merged = _DEFAULTS.copy()

    if config_path is not None:
        config_file = Path(config_path)
    else:
        config_file = _find_config_dir() / "config.yaml"

    # Layer 1: config.yaml
    if config_file.exists():
        with open(config_file, encoding="utf-8") as f:
            file_config = yaml.safe_load(f) or {}
        merged = _deep_merge(merged, file_config)

    # Layer 2: config.local.yaml  (personal overrides, git-ignored)
    local_file = config_file.parent / "config.local.yaml"
    if local_file.exists():
        with open(local_file, encoding="utf-8") as f:
            local_config = yaml.safe_load(f) or {}
        merged = _deep_merge(merged, local_config)

    return merged.get("sentinel", merged)


@dataclass
class CleanupConfig:
    enabled: bool = True
    min_age_hours: int = 24
    max_delete_mb: int = 5000
    protected_extensions: list[str] = field(default_factory=lambda: [".dll", ".sys", ".exe", ".msi", ".log"])
    additional_temp_dirs: list[str] = field(default_factory=list)


@dataclass
class SecurityConfig:
    enabled: bool = True
    suspicious_exe_paths: list[str] = field(
        default_factory=lambda: ["\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\"]
    )
    trusted_processes: list[str] = field(default_factory=list)
    event_log_lookback_hours: int = 24
    max_connections_to_report: int = 20


@dataclass
class AgentConfig:
    provider: str = "none"
    model: str = "gemini-2.5-flash"
    api_key_env: str = "GEMINI_API_KEY"
    ollama_base_url: str = "http://localhost:11434"
    temperature: float = 0.2
    max_output_tokens: int = 1024
    fallback_to_template: bool = True


@dataclass
class SentinelConfig:
    """Typed accessor for the full configuration tree."""

    cleanup: CleanupConfig = field(default_factory=CleanupConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)

    @classmethod
    def from_dict(cls, data: dict) -> "SentinelConfig":
        return cls(
            cleanup=CleanupConfig(**data.get("cleanup", {})),
            security=SecurityConfig(**data.get("security", {})),
            agent=AgentConfig(**data.get("agent", {})),
        )
