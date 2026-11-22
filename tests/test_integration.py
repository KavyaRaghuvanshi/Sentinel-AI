"""
Integration tests for the full Sentinel AI pipeline.

These test the end-to-end flow with all system calls mocked,
ensuring the modules connect correctly.
"""

from unittest.mock import MagicMock, patch

import pytest

from sentinel.__main__ import run


class TestFullPipeline:
    """Test the complete pipeline with mocked system calls."""

    @patch("sentinel.__main__.deliver_report")
    @patch("sentinel.__main__.analyze_and_report")
    @patch("sentinel.__main__.run_security_audit")
    @patch("sentinel.__main__.clean_temp_files")
    @patch("sentinel.__main__.collect_system_telemetry")
    @patch("sentinel.__main__.load_config")
    def test_full_run_healthy(
        self, mock_config, mock_telemetry, mock_clean, mock_security, mock_agent, mock_deliver
    ):
        # Setup mocks
        mock_config.return_value = {
            "cleanup": {"enabled": True, "min_age_hours": 24, "max_delete_mb": 5000},
            "security": {"enabled": True},
            "agent": {"provider": "none"},
            "reporter": {"console": False, "save_to_file": False, "toast_notification": False, "webhook": {"enabled": False}, "email": {"enabled": False}},
        }
        mock_telemetry.return_value = {
            "hostname": "INTEGRATION-PC",
            "disk": {"percent_used": 50, "status": "Healthy"},
            "cpu": {"current_percent": 10},
            "memory": {"percent_used": 40},
            "boot": {"uptime": "10m"},
        }
        mock_clean.return_value = {"purged_mb": 10.0, "files_deleted": 5, "files_skipped": 1}
        mock_security.return_value = {
            "processes": {"total_processes": 100, "anomaly_count": 0},
            "network": {"total_connections": 5},
        }
        mock_agent.return_value = "Test report: All systems healthy."
        mock_deliver.return_value = {"console": True}

        result = run(["--skip-security"])

        assert "report" in result
        assert "telemetry" in result
        assert "delivery" in result
        assert result["elapsed_seconds"] >= 0

    @patch("sentinel.__main__.deliver_report")
    @patch("sentinel.__main__.analyze_and_report")
    @patch("sentinel.__main__.run_security_audit")
    @patch("sentinel.__main__.clean_temp_files")
    @patch("sentinel.__main__.collect_system_telemetry")
    @patch("sentinel.__main__.load_config")
    def test_dry_run_mode(
        self, mock_config, mock_telemetry, mock_clean, mock_security, mock_agent, mock_deliver
    ):
        mock_config.return_value = {
            "cleanup": {"enabled": True, "min_age_hours": 24, "max_delete_mb": 5000},
            "security": {"enabled": True},
            "agent": {"provider": "none"},
            "reporter": {"console": False, "save_to_file": False, "toast_notification": False, "webhook": {"enabled": False}, "email": {"enabled": False}},
        }
        mock_telemetry.return_value = {
            "hostname": "DRY-RUN-PC",
            "disk": {"percent_used": 50, "status": "Healthy"},
            "cpu": {"current_percent": 10},
            "memory": {"percent_used": 40},
            "boot": {"uptime": "10m"},
        }
        mock_clean.return_value = {"purged_mb": 5.0, "files_deleted": 3, "files_skipped": 0}
        mock_security.return_value = {
            "processes": {"total_processes": 50, "anomaly_count": 0},
            "network": {"total_connections": 2},
        }
        mock_agent.return_value = "Dry run report."
        mock_deliver.return_value = {}

        result = run(["--dry-run"])

        # Verify dry_run was passed to clean_temp_files
        _, kwargs = mock_clean.call_args
        assert kwargs.get("dry_run") is True

    @patch("sentinel.__main__.deliver_report")
    @patch("sentinel.__main__.analyze_and_report")
    @patch("sentinel.__main__.collect_system_telemetry")
    @patch("sentinel.__main__.load_config")
    def test_skip_cleanup_and_security(
        self, mock_config, mock_telemetry, mock_agent, mock_deliver
    ):
        mock_config.return_value = {
            "cleanup": {"enabled": True},
            "security": {"enabled": True},
            "agent": {"provider": "none"},
            "reporter": {"console": False, "save_to_file": False, "toast_notification": False, "webhook": {"enabled": False}, "email": {"enabled": False}},
        }
        mock_telemetry.return_value = {
            "hostname": "SKIP-PC",
            "disk": {"percent_used": 50, "status": "Healthy"},
            "cpu": {"current_percent": 10},
            "memory": {"percent_used": 40},
            "boot": {"uptime": "10m"},
        }
        mock_agent.return_value = "Minimal report."
        mock_deliver.return_value = {}

        result = run(["--skip-cleanup", "--skip-security"])

        telemetry = result["telemetry"]
        assert telemetry["cleanup"] == {"skipped": True}
        assert telemetry["security"] == {"skipped": True}

    @patch("sentinel.__main__.deliver_report")
    @patch("sentinel.__main__.analyze_and_report")
    @patch("sentinel.__main__.run_security_audit")
    @patch("sentinel.__main__.clean_temp_files")
    @patch("sentinel.__main__.collect_system_telemetry")
    @patch("sentinel.__main__.load_config")
    def test_provider_override(
        self, mock_config, mock_telemetry, mock_clean, mock_security, mock_agent, mock_deliver
    ):
        mock_config.return_value = {
            "cleanup": {"enabled": False},
            "security": {"enabled": False},
            "agent": {"provider": "none"},
            "reporter": {"console": False, "save_to_file": False, "toast_notification": False, "webhook": {"enabled": False}, "email": {"enabled": False}},
        }
        mock_telemetry.return_value = {
            "hostname": "OVERRIDE-PC",
            "disk": {"percent_used": 50, "status": "Healthy"},
            "cpu": {"current_percent": 10},
            "memory": {"percent_used": 40},
            "boot": {"uptime": "10m"},
        }
        mock_agent.return_value = "Override report."
        mock_deliver.return_value = {}

        result = run(["--provider", "ollama"])

        # Verify the agent was called with the overridden provider
        call_args = mock_agent.call_args
        agent_config = call_args[0][1]
        assert agent_config["provider"] == "ollama"
