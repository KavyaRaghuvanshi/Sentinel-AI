"""Tests for sentinel.utils"""

from sentinel.utils import (
    format_bytes,
    format_gb,
    format_mb,
    get_hostname,
    get_timestamp,
    sanitize_for_filename,
    seconds_to_human,
    truncate,
)


class TestFormatBytes:
    def test_zero(self):
        assert format_bytes(0) == "0.00 B"

    def test_bytes(self):
        assert format_bytes(500) == "500.00 B"

    def test_kilobytes(self):
        result = format_bytes(2048)
        assert "KB" in result

    def test_megabytes(self):
        result = format_bytes(5 * 1024 * 1024)
        assert "MB" in result

    def test_gigabytes(self):
        result = format_bytes(10 * 1024**3)
        assert "10.00 GB" == result

    def test_negative(self):
        assert format_bytes(-100) == "0 B"


class TestFormatMbGb:
    def test_format_mb(self):
        assert format_mb(1024 * 1024) == 1.0

    def test_format_gb(self):
        assert format_gb(1024**3) == 1.0

    def test_format_gb_fractional(self):
        assert format_gb(1.5 * 1024**3) == 1.5


class TestTruncate:
    def test_short_text(self):
        assert truncate("hello", 100) == "hello"

    def test_exact_length(self):
        text = "x" * 200
        assert truncate(text, 200) == text

    def test_truncation(self):
        text = "x" * 300
        result = truncate(text, 200)
        assert len(result) == 200
        assert result.endswith("…")


class TestSecondsToHuman:
    def test_seconds(self):
        assert seconds_to_human(45) == "45s"

    def test_minutes(self):
        result = seconds_to_human(90)
        assert "1m" in result

    def test_hours(self):
        result = seconds_to_human(7200)
        assert "2h" in result


class TestSanitizeForFilename:
    def test_clean_name(self):
        assert sanitize_for_filename("report_2026") == "report_2026"

    def test_special_chars(self):
        result = sanitize_for_filename('file<>:"/\\|?*name')
        assert "<" not in result
        assert ">" not in result


class TestGetters:
    def test_hostname_returns_string(self):
        assert isinstance(get_hostname(), str)
        assert len(get_hostname()) > 0

    def test_timestamp_returns_iso_format(self):
        ts = get_timestamp()
        assert "T" in ts  # ISO format contains T separator
