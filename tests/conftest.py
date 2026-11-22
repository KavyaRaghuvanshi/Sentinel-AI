"""
Sentinel AI - Test Fixtures

Shared pytest fixtures and mock data for the entire test suite.
All tests run WITHOUT admin privileges, network access, or a real
LLM API key — everything is mocked.
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Configuration fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_config() -> dict:
    """Return a minimal Sentinel configuration dict for testing."""
    return {
        "cleanup": {
            "enabled": True,
            "min_age_hours": 24,
            "max_delete_mb": 5000,
            "protected_extensions": [".dll", ".sys", ".exe"],
            "additional_temp_dirs": [],
        },
        "security": {
            "enabled": True,
            "suspicious_exe_paths": ["\\temp\\", "\\downloads\\"],
            "trusted_processes": ["python.exe", "explorer.exe"],
            "event_log_lookback_hours": 24,
            "max_connections_to_report": 20,
        },
        "agent": {
            "provider": "none",
            "model": "test-model",
            "api_key_env": "TEST_API_KEY",
            "temperature": 0.2,
            "max_output_tokens": 512,
            "fallback_to_template": True,
        },
        "reporter": {
            "console": False,  # Don't pollute test output
            "save_to_file": False,
            "report_dir": "./test_reports",
            "toast_notification": False,
            "webhook": {"enabled": False, "url": ""},
            "email": {"enabled": False},
        },
    }


@pytest.fixture
def sample_config_yaml(tmp_path: Path, sample_config: dict) -> Path:
    """Write a sample config.yaml to a temp dir and return its path."""
    import yaml

    config_data = {"sentinel": sample_config}
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.dump(config_data), encoding="utf-8")
    return config_file


# ---------------------------------------------------------------------------
# Temp file fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_dir_with_files(tmp_path: Path) -> Path:
    """
    Create a temp directory containing:
      - 3 old files (> 48 hours, eligible for deletion)
      - 2 recent files (< 1 hour, should NOT be deleted)
      - 1 protected extension file (.dll, should NOT be deleted)
    """
    old_time = time.time() - (72 * 3600)  # 72 hours ago

    # Old files (should be deleted)
    for name in ["cache_001.tmp", "session_old.dat", "installer_leftovers.cab"]:
        f = tmp_path / name
        f.write_text(f"old data for {name}", encoding="utf-8")
        os.utime(f, (old_time, old_time))

    # Recent files (should NOT be deleted)
    for name in ["active_session.tmp", "download_in_progress.part"]:
        f = tmp_path / name
        f.write_text(f"recent data for {name}", encoding="utf-8")

    # Protected extension (should NOT be deleted even if old)
    dll_file = tmp_path / "important_cache.dll"
    dll_file.write_text("mock dll content", encoding="utf-8")
    os.utime(dll_file, (old_time, old_time))

    return tmp_path


# ---------------------------------------------------------------------------
# Telemetry fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_telemetry() -> dict:
    """Return a complete mock telemetry snapshot for agent/report testing."""
    return {
        "timestamp": "2026-11-22T10:00:00",
        "hostname": "TEST-PC-01",
        "os": {
            "system": "Windows",
            "release": "10",
            "version": "10.0.22631",
        },
        "disk": {
            "drive": "C:\\",
            "total_gb": 500.0,
            "used_gb": 350.0,
            "free_gb": 150.0,
            "percent_used": 70.0,
            "status": "Healthy",
        },
        "memory": {
            "total_gb": 16.0,
            "available_gb": 8.5,
            "percent_used": 46.9,
            "status": "Healthy",
        },
        "cpu": {
            "physical_cores": 8,
            "logical_cores": 16,
            "current_percent": 15.3,
            "status": "Healthy",
        },
        "boot": {
            "boot_time": "2026-11-22T09:55:00",
            "uptime": "5m 0s",
            "uptime_seconds": 300,
        },
        "top_processes": [
            {"pid": 100, "name": "chrome.exe", "memory_percent": 8.5, "cpu_percent": 3.2},
            {"pid": 200, "name": "code.exe", "memory_percent": 5.1, "cpu_percent": 1.0},
        ],
        "cleanup": {
            "purged_mb": 42.5,
            "files_deleted": 15,
            "files_skipped": 2,
            "total_candidates": 17,
            "dry_run": False,
            "scanned_dirs": ["C:\\Users\\Test\\AppData\\Local\\Temp"],
        },
        "security": {
            "processes": {
                "total_processes": 180,
                "anomalies": [],
                "anomaly_count": 0,
                "high_resource_processes": [],
            },
            "network": {
                "total_connections": 12,
                "connections": [
                    {"pid": 100, "process": "chrome.exe", "remote_ip": "142.250.80.46", "remote_port": 443},
                ],
            },
            "defender": {
                "available": True,
                "real_time_protection": True,
                "antivirus_enabled": True,
                "antispyware_enabled": True,
            },
            "event_log_alerts": [],
        },
    }


@pytest.fixture
def sample_telemetry_with_anomalies(sample_telemetry: dict) -> dict:
    """Return telemetry with security anomalies for testing warning reports."""
    sample_telemetry["security"]["processes"]["anomalies"] = [
        {
            "type": "SUSPICIOUS_EXE_PATH",
            "pid": 9999,
            "name": "suspicious_app.exe",
            "exe": "C:\\Users\\Test\\AppData\\Local\\Temp\\suspicious_app.exe",
            "reason": "Executing from suspicious location matching '\\temp\\'",
        },
    ]
    sample_telemetry["security"]["processes"]["anomaly_count"] = 1
    sample_telemetry["disk"]["percent_used"] = 92.0
    sample_telemetry["disk"]["status"] = "Warning"
    return sample_telemetry
