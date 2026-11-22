"""Tests for sentinel.security"""

from unittest.mock import MagicMock, patch

import psutil

from sentinel.security import audit_network, audit_processes, run_security_audit


class TestAuditProcesses:
    @patch("sentinel.security.psutil.process_iter")
    def test_flags_suspicious_path(self, mock_iter):
        proc = MagicMock()
        proc.info = {
            "pid": 1234,
            "name": "malware.exe",
            "exe": "C:\\Users\\Test\\AppData\\Local\\Temp\\malware.exe",
            "cpu_percent": 5.0,
            "memory_percent": 2.0,
        }
        mock_iter.return_value = [proc]

        result = audit_processes(
            suspicious_paths=["\\temp\\"],
            trusted_processes=[],
        )
        assert result["anomaly_count"] == 1
        assert result["anomalies"][0]["type"] == "SUSPICIOUS_EXE_PATH"
        assert result["anomalies"][0]["pid"] == 1234

    @patch("sentinel.security.psutil.process_iter")
    def test_skips_trusted_process(self, mock_iter):
        proc = MagicMock()
        proc.info = {
            "pid": 100,
            "name": "python.exe",
            "exe": "C:\\Users\\Test\\AppData\\Local\\Temp\\python.exe",
            "cpu_percent": 1.0,
            "memory_percent": 1.0,
        }
        mock_iter.return_value = [proc]

        result = audit_processes(
            suspicious_paths=["\\temp\\"],
            trusted_processes=["python.exe"],
        )
        assert result["anomaly_count"] == 0

    @patch("sentinel.security.psutil.process_iter")
    def test_flags_no_exe_path(self, mock_iter):
        proc = MagicMock()
        proc.info = {
            "pid": 5678,
            "name": "ghost_process",
            "exe": "",
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
        }
        mock_iter.return_value = [proc]

        result = audit_processes(suspicious_paths=[], trusted_processes=[])
        anomaly_types = [a["type"] for a in result["anomalies"]]
        assert "NO_EXE_PATH" in anomaly_types

    @patch("sentinel.security.psutil.process_iter")
    def test_flags_high_cpu(self, mock_iter):
        proc = MagicMock()
        proc.info = {
            "pid": 999,
            "name": "compute_heavy.exe",
            "exe": "C:\\Apps\\compute_heavy.exe",
            "cpu_percent": 95.0,
            "memory_percent": 2.0,
        }
        mock_iter.return_value = [proc]

        result = audit_processes(suspicious_paths=[], trusted_processes=[])
        assert len(result["high_resource_processes"]) == 1
        assert result["high_resource_processes"][0]["cpu_percent"] == 95.0

    @patch("sentinel.security.psutil.process_iter")
    def test_handles_access_denied(self, mock_iter):
        proc = MagicMock()
        proc.info.__getitem__ = MagicMock(side_effect=psutil.AccessDenied(pid=1))
        # Simulating a process that raises on attribute access
        type(proc).info = property(lambda self: (_ for _ in ()).throw(psutil.AccessDenied(pid=1)))
        mock_iter.return_value = [proc]

        # Should not crash
        result = audit_processes()
        assert result["total_processes"] == 0  # Skipped


class TestAuditNetwork:
    @patch("sentinel.security.psutil.net_connections")
    def test_captures_established_connections(self, mock_net):
        conn = MagicMock()
        conn.status = psutil.CONN_ESTABLISHED
        conn.raddr = MagicMock(ip="142.250.80.46", port=443)
        conn.laddr = MagicMock(port=54321)
        conn.pid = 100
        mock_net.return_value = [conn]

        with patch("sentinel.security.psutil.Process") as mock_proc_cls:
            mock_proc_cls.return_value.name.return_value = "chrome.exe"
            result = audit_network(max_connections=10)

        assert result["total_connections"] == 1
        assert result["connections"][0]["remote_ip"] == "142.250.80.46"

    @patch("sentinel.security.psutil.net_connections")
    def test_respects_max_connections(self, mock_net):
        conns = []
        for i in range(50):
            conn = MagicMock()
            conn.status = psutil.CONN_ESTABLISHED
            conn.raddr = MagicMock(ip=f"10.0.0.{i}", port=80)
            conn.laddr = MagicMock(port=50000 + i)
            conn.pid = 100 + i
            conns.append(conn)
        mock_net.return_value = conns

        with patch("sentinel.security.psutil.Process") as mock_proc_cls:
            mock_proc_cls.return_value.name.return_value = "app.exe"
            result = audit_network(max_connections=5)

        assert result["total_connections"] == 5

    @patch("sentinel.security.psutil.net_connections", side_effect=psutil.AccessDenied(pid=0))
    def test_handles_access_denied(self, mock_net):
        result = audit_network()
        assert result["total_connections"] == 0
        assert "error" in result


class TestRunSecurityAudit:
    @patch("sentinel.security.scan_event_logs", return_value=[])
    @patch("sentinel.security.check_defender_status", return_value={"available": False})
    @patch("sentinel.security.audit_network", return_value={"total_connections": 0, "connections": []})
    @patch("sentinel.security.audit_processes", return_value={"total_processes": 50, "anomalies": [], "anomaly_count": 0, "high_resource_processes": []})
    def test_consolidates_all_checks(self, mock_proc, mock_net, mock_def, mock_evt):
        result = run_security_audit()
        assert "processes" in result
        assert "network" in result
        assert "defender" in result
        assert "event_log_alerts" in result
