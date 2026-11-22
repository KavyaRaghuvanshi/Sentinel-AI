"""Tests for sentinel.gui"""

from unittest.mock import MagicMock, patch

from sentinel.gui import get_recommendations_and_precautions


class TestGetRecommendationsAndPrecautions:
    def test_healthy_telemetry(self, sample_telemetry: dict):
        suggestions, precautions = get_recommendations_and_precautions(sample_telemetry)
        assert len(suggestions) > 0
        assert len(precautions) > 0
        # No critical warnings
        assert not any("CRITICAL" in p for p in precautions)

    def test_high_memory_warning(self, sample_telemetry: dict):
        sample_telemetry["memory"]["percent_used"] = 92.0
        suggestions, precautions = get_recommendations_and_precautions(sample_telemetry)
        assert any("Memory is at 92.0%" in s for s in suggestions)
        assert any("High RAM usage" in p for p in precautions)

    def test_low_disk_warning(self, sample_telemetry: dict):
        sample_telemetry["disk"]["percent_used"] = 91.0
        sample_telemetry["disk"]["free_gb"] = 12.0
        suggestions, precautions = get_recommendations_and_precautions(sample_telemetry)
        assert any("Disk free space is low" in s for s in suggestions)
        assert any("Low disk space" in p for p in precautions)

    def test_process_anomalies_flagged(self, sample_telemetry_with_anomalies: dict):
        suggestions, precautions = get_recommendations_and_precautions(sample_telemetry_with_anomalies)
        assert any("Suspicious activity" in p for p in precautions)
        assert any("suspicious_app.exe" in p for p in precautions)

    def test_defender_disabled_critical(self, sample_telemetry: dict):
        sample_telemetry["security"]["defender"]["real_time_protection"] = False
        suggestions, precautions = get_recommendations_and_precautions(sample_telemetry)
        assert any("Real-Time Protection is DISABLED" in p for p in precautions)
        assert any("Windows Defender" in s for s in suggestions)

    def test_cleanup_purged_reported(self, sample_telemetry: dict):
        sample_telemetry["cleanup"]["purged_mb"] = 120.5
        suggestions, precautions = get_recommendations_and_precautions(sample_telemetry)
        assert any("Purged 120.5 MB" in s for s in suggestions)


class TestGUILauncher:
    @patch("sentinel.gui.tk.Tk")
    @patch("sentinel.gui.SentinelHUD")
    def test_launch_gui(self, mock_hud, mock_tk):
        from sentinel.gui import launch_gui

        mock_root = MagicMock()
        mock_tk.return_value = mock_root

        launch_gui({"cleanup": {}})
        mock_tk.assert_called_once()
        mock_hud.assert_called_once_with(mock_root, {"cleanup": {}})
        mock_root.mainloop.assert_called_once()
