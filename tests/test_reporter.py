"""Tests for sentinel.reporter"""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from sentinel.reporter import deliver_report, save_report_to_file, send_webhook


class TestSaveReportToFile:
    def test_creates_file(self, tmp_path: Path):
        report = "Test report content"
        filepath = save_report_to_file(report, report_dir=str(tmp_path), hostname="test-pc")
        assert os.path.exists(filepath)
        content = Path(filepath).read_text(encoding="utf-8")
        assert content == report

    def test_creates_directory_if_missing(self, tmp_path: Path):
        new_dir = tmp_path / "nested" / "reports"
        filepath = save_report_to_file("content", report_dir=str(new_dir), hostname="pc")
        assert os.path.exists(filepath)

    def test_filename_format(self, tmp_path: Path):
        filepath = save_report_to_file("content", report_dir=str(tmp_path), hostname="mypc")
        filename = os.path.basename(filepath)
        assert filename.startswith("sentinel_report_mypc_")
        assert filename.endswith(".txt")


class TestSendWebhook:
    @patch("sentinel.reporter.requests.post")
    def test_discord_webhook(self, mock_post):
        mock_post.return_value = MagicMock(status_code=204)
        mock_post.return_value.raise_for_status = MagicMock()

        result = send_webhook("Test report", "https://discord.com/api/webhooks/123", "test-pc")
        assert result is True
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert "discord" in call_kwargs[0][0].lower() or "discord" in str(call_kwargs)

    @patch("sentinel.reporter.requests.post")
    def test_slack_webhook(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        mock_post.return_value.raise_for_status = MagicMock()

        result = send_webhook("Test", "https://hooks.slack.com/services/T00/B00/xxx", "pc")
        assert result is True

    def test_empty_url_returns_false(self):
        assert send_webhook("Test", "", "pc") is False

    @patch("sentinel.reporter.requests.post", side_effect=Exception("Network error"))
    def test_handles_network_error(self, mock_post):
        result = send_webhook("Test", "https://example.com/webhook", "pc")
        assert result is False


class TestDeliverReport:
    def test_console_only(self, capsys):
        config = {
            "console": True,
            "save_to_file": False,
            "toast_notification": False,
            "webhook": {"enabled": False},
            "email": {"enabled": False},
        }
        results = deliver_report("Console test report", config, "test-pc")
        assert results["console"] is True
        captured = capsys.readouterr()
        assert "Console test report" in captured.out

    def test_file_save(self, tmp_path: Path):
        config = {
            "console": False,
            "save_to_file": True,
            "report_dir": str(tmp_path),
            "toast_notification": False,
            "webhook": {"enabled": False},
            "email": {"enabled": False},
        }
        results = deliver_report("File test report", config, "test-pc")
        assert isinstance(results["file"], str)
        assert os.path.exists(results["file"])

    def test_all_disabled(self):
        config = {
            "console": False,
            "save_to_file": False,
            "toast_notification": False,
            "webhook": {"enabled": False},
            "email": {"enabled": False},
        }
        results = deliver_report("Nothing", config, "test-pc")
        assert len(results) == 0
