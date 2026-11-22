"""Tests for sentinel.sensor"""

from unittest.mock import MagicMock, patch

from sentinel.sensor import (
    collect_system_telemetry,
    get_boot_time,
    get_cpu_info,
    get_disk_health,
    get_memory_info,
    get_top_processes,
)


class TestGetDiskHealth:
    @patch("sentinel.sensor.psutil.disk_usage")
    def test_returns_expected_fields(self, mock_usage):
        mock_usage.return_value = MagicMock(
            total=500 * 1024**3,
            used=350 * 1024**3,
            free=150 * 1024**3,
            percent=70.0,
        )
        result = get_disk_health("C:\\")
        assert result["drive"] == "C:\\"
        assert result["total_gb"] == 500.0
        assert result["free_gb"] == 150.0
        assert result["percent_used"] == 70.0
        assert result["status"] == "Healthy"

    @patch("sentinel.sensor.psutil.disk_usage")
    def test_critical_status(self, mock_usage):
        mock_usage.return_value = MagicMock(
            total=500 * 1024**3,
            used=480 * 1024**3,
            free=20 * 1024**3,
            percent=96.0,
        )
        result = get_disk_health()
        assert result["status"] == "Critical"

    @patch("sentinel.sensor.psutil.disk_usage")
    def test_warning_status(self, mock_usage):
        mock_usage.return_value = MagicMock(
            total=500 * 1024**3,
            used=440 * 1024**3,
            free=60 * 1024**3,
            percent=88.0,
        )
        result = get_disk_health()
        assert result["status"] == "Warning"


class TestGetMemoryInfo:
    @patch("sentinel.sensor.psutil.virtual_memory")
    def test_returns_expected_fields(self, mock_mem):
        mock_mem.return_value = MagicMock(
            total=16 * 1024**3,
            available=8 * 1024**3,
            percent=50.0,
        )
        result = get_memory_info()
        assert result["total_gb"] == 16.0
        assert result["available_gb"] == 8.0
        assert result["percent_used"] == 50.0
        assert result["status"] == "Healthy"

    @patch("sentinel.sensor.psutil.virtual_memory")
    def test_critical_memory(self, mock_mem):
        mock_mem.return_value = MagicMock(
            total=16 * 1024**3,
            available=1 * 1024**3,
            percent=93.0,
        )
        result = get_memory_info()
        assert result["status"] == "Critical"


class TestGetCpuInfo:
    @patch("sentinel.sensor.psutil.cpu_percent", return_value=25.0)
    @patch("sentinel.sensor.psutil.cpu_count")
    def test_returns_expected_fields(self, mock_count, mock_percent):
        mock_count.side_effect = lambda logical=True: 16 if logical else 8
        result = get_cpu_info()
        assert result["physical_cores"] == 8
        assert result["logical_cores"] == 16
        assert result["current_percent"] == 25.0
        assert result["status"] == "Healthy"


class TestGetBootTime:
    @patch("sentinel.sensor.psutil.boot_time")
    def test_returns_expected_fields(self, mock_boot):
        import time
        mock_boot.return_value = time.time() - 300  # 5 minutes ago
        result = get_boot_time()
        assert "boot_time" in result
        assert "uptime" in result
        assert result["uptime_seconds"] >= 299  # Allow small delta


class TestGetTopProcesses:
    @patch("sentinel.sensor.psutil.process_iter")
    def test_returns_top_n(self, mock_iter):
        procs = []
        for i in range(10):
            mock_proc = MagicMock()
            mock_proc.info = {
                "pid": i,
                "name": f"proc_{i}.exe",
                "memory_percent": float(10 - i),
                "cpu_percent": float(i),
            }
            procs.append(mock_proc)
        mock_iter.return_value = procs

        result = get_top_processes(n=3)
        assert len(result) == 3
        # Should be sorted by memory_percent descending
        assert result[0]["memory_percent"] >= result[1]["memory_percent"]


class TestCollectSystemTelemetry:
    @patch("sentinel.sensor.get_top_processes", return_value=[])
    @patch("sentinel.sensor.get_boot_time", return_value={"boot_time": "test", "uptime": "1m", "uptime_seconds": 60})
    @patch("sentinel.sensor.get_cpu_info", return_value={"physical_cores": 4, "logical_cores": 8, "current_percent": 10, "status": "Healthy"})
    @patch("sentinel.sensor.get_memory_info", return_value={"total_gb": 16, "available_gb": 10, "percent_used": 37, "status": "Healthy"})
    @patch("sentinel.sensor.get_disk_health", return_value={"drive": "C:\\", "total_gb": 500, "free_gb": 300, "used_gb": 200, "percent_used": 40, "status": "Healthy"})
    def test_full_telemetry(self, mock_disk, mock_mem, mock_cpu, mock_boot, mock_procs):
        result = collect_system_telemetry()
        assert "timestamp" in result
        assert "hostname" in result
        assert "disk" in result
        assert "memory" in result
        assert "cpu" in result
        assert "boot" in result
        assert "top_processes" in result
