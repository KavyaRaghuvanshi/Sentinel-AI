"""Tests for sentinel.agent"""

from unittest.mock import MagicMock, patch

from sentinel.agent import analyze_and_report, generate_report_from_template


class TestGenerateReportFromTemplate:
    def test_healthy_report(self, sample_telemetry: dict):
        report = generate_report_from_template(sample_telemetry)
        assert "Storage & Maintenance" in report
        assert "System Performance" in report
        assert "Security Assessment" in report
        assert "✅" in report or "HEALTHY" in report

    def test_warning_report(self, sample_telemetry_with_anomalies: dict):
        report = generate_report_from_template(sample_telemetry_with_anomalies)
        assert "Warning" in report or "⚠" in report
        assert "suspicious_app.exe" in report

    def test_critical_disk_report(self, sample_telemetry: dict):
        sample_telemetry["disk"]["percent_used"] = 97.0
        sample_telemetry["disk"]["status"] = "Critical"
        report = generate_report_from_template(sample_telemetry)
        assert "Critical" in report

    def test_defender_off_critical(self, sample_telemetry: dict):
        sample_telemetry["security"]["defender"]["real_time_protection"] = False
        report = generate_report_from_template(sample_telemetry)
        assert "OFF" in report

    def test_includes_hostname(self, sample_telemetry: dict):
        report = generate_report_from_template(sample_telemetry)
        assert "TEST-PC-01" in report

    def test_includes_cleanup_info(self, sample_telemetry: dict):
        report = generate_report_from_template(sample_telemetry)
        assert "42.5" in report  # purged_mb
        assert "15" in report    # files_deleted

    def test_handles_missing_sections(self):
        minimal = {"hostname": "MINIMAL-PC", "timestamp": "2026-01-01T00:00:00"}
        report = generate_report_from_template(minimal)
        assert "MINIMAL-PC" in report
        # Should not crash with missing data

    def test_handles_skipped_cleanup(self, sample_telemetry: dict):
        sample_telemetry["cleanup"] = {"skipped": True}
        report = generate_report_from_template(sample_telemetry)
        assert "Storage & Maintenance" in report


class TestAnalyzeAndReport:
    def test_provider_none_uses_template(self, sample_telemetry: dict):
        config = {"provider": "none"}
        report = analyze_and_report(sample_telemetry, config)
        assert "Storage & Maintenance" in report
        assert len(report) > 50

    def test_unknown_provider_falls_back(self, sample_telemetry: dict):
        config = {"provider": "nonexistent_provider", "fallback_to_template": True}
        report = analyze_and_report(sample_telemetry, config)
        assert "Storage & Maintenance" in report

    def test_gemini_provider_calls_api(self, sample_telemetry: dict):
        config = {
            "provider": "gemini",
            "api_key_env": "TEST_KEY",
            "model": "test-model",
            "temperature": 0.2,
            "max_output_tokens": 512,
            "fallback_to_template": True,
        }
        # Gemini SDK won't be importable or the env var won't be set,
        # so it should fall back to template
        report = analyze_and_report(sample_telemetry, config)
        assert len(report) > 50  # Got some report (from fallback)

    def test_fallback_disabled_raises(self, sample_telemetry: dict):
        config = {
            "provider": "gemini",
            "api_key_env": "NONEXISTENT_KEY_12345",
            "fallback_to_template": False,
        }
        import pytest
        with pytest.raises(Exception):
            analyze_and_report(sample_telemetry, config)

    @patch("sentinel.agent._call_gemini")
    def test_successful_gemini_call(self, mock_gemini, sample_telemetry: dict):
        mock_gemini.return_value = "Mocked LLM Report: Everything looks great."
        config = {"provider": "gemini", "fallback_to_template": True}
        report = analyze_and_report(sample_telemetry, config)
        assert report == "Mocked LLM Report: Everything looks great."
        mock_gemini.assert_called_once()

    @patch("sentinel.agent._call_openai")
    def test_successful_openai_call(self, mock_openai, sample_telemetry: dict):
        mock_openai.return_value = "OpenAI Report: Systems nominal."
        config = {"provider": "openai"}
        report = analyze_and_report(sample_telemetry, config)
        assert report == "OpenAI Report: Systems nominal."

    @patch("sentinel.agent._call_ollama")
    def test_successful_ollama_call(self, mock_ollama, sample_telemetry: dict):
        mock_ollama.return_value = "Ollama Report: All clear."
        config = {"provider": "ollama"}
        report = analyze_and_report(sample_telemetry, config)
        assert report == "Ollama Report: All clear."
