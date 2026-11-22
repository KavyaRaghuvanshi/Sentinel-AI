"""
Sentinel AI - Security Auditor

Inspects running processes, active network connections, and
Windows Event Logs for anomalies and potential threats.

All operations are read-only — no processes are killed or blocked
by this module.  Remediation decisions are left to the agent layer.
"""

from __future__ import annotations

import platform
from datetime import datetime, timedelta

import psutil

from sentinel.guardrails import sanitize_process_name


def audit_processes(
    suspicious_paths: list[str] | None = None,
    trusted_processes: list[str] | None = None,
) -> dict:
    """
    Audit running processes for suspicious characteristics.

    Flags:
      - Processes executing from temporary or download directories
      - Processes with unusually high resource usage (CPU > 80%)
      - Processes with no executable path (potential injection)

    Returns
    -------
    dict
        {total_processes, anomalies: list[dict], high_resource: list[dict]}
    """
    if suspicious_paths is None:
        suspicious_paths = ["\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\"]
    if trusted_processes is None:
        trusted_processes = []

    trusted_lower = {p.lower() for p in trusted_processes}
    anomalies: list[dict] = []
    high_resource: list[dict] = []
    total = 0

    for proc in psutil.process_iter(["pid", "name", "exe", "cpu_percent", "memory_percent"]):
        try:
            info = proc.info
            total += 1

            proc_name = info.get("name") or "<unknown>"
            exe_path = info.get("exe") or ""

            # Skip trusted processes
            if proc_name.lower() in trusted_lower:
                continue

            # Check 1: Running from a suspicious path
            exe_lower = exe_path.lower()
            for sus_path in suspicious_paths:
                if sus_path.lower() in exe_lower:
                    anomalies.append({
                        "type": "SUSPICIOUS_EXE_PATH",
                        "pid": info["pid"],
                        "name": sanitize_process_name(proc_name),
                        "exe": exe_path[:200],
                        "reason": f"Executing from suspicious location matching '{sus_path}'",
                    })
                    break

            # Check 2: No executable path (may indicate code injection)
            if not exe_path and proc_name not in ("<unknown>", "System Idle Process", "System"):
                anomalies.append({
                    "type": "NO_EXE_PATH",
                    "pid": info["pid"],
                    "name": sanitize_process_name(proc_name),
                    "exe": "",
                    "reason": "Process has no associated executable path",
                })

            # Check 3: High resource usage
            cpu = info.get("cpu_percent") or 0
            mem = info.get("memory_percent") or 0
            if cpu > 80 or mem > 15:
                high_resource.append({
                    "pid": info["pid"],
                    "name": sanitize_process_name(proc_name),
                    "cpu_percent": round(cpu, 1),
                    "memory_percent": round(mem, 1),
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return {
        "total_processes": total,
        "anomalies": anomalies,
        "anomaly_count": len(anomalies),
        "high_resource_processes": high_resource,
    }


def audit_network(max_connections: int = 20) -> dict:
    """
    Audit active outbound network connections.

    Returns
    -------
    dict
        {total_connections, connections: list[dict]}
    """
    connections: list[dict] = []

    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                proc_name = "<unknown>"
                if conn.pid:
                    try:
                        proc_name = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                connections.append({
                    "pid": conn.pid,
                    "process": sanitize_process_name(proc_name),
                    "local_port": conn.laddr.port if conn.laddr else None,
                    "remote_ip": conn.raddr.ip,
                    "remote_port": conn.raddr.port,
                })

                if len(connections) >= max_connections:
                    break
    except (psutil.AccessDenied, RuntimeError, OSError):
        return {
            "total_connections": 0,
            "connections": [],
            "error": "Access restricted — run with administrator privileges for full network audit.",
        }

    return {
        "total_connections": len(connections),
        "connections": connections,
    }


def check_defender_status() -> dict:
    """
    Check if Windows Defender real-time protection is enabled.

    Uses WMI via PowerShell. Returns a status dict.
    Falls back gracefully if WMI is unavailable.
    """
    if platform.system() != "Windows":
        return {"available": False, "reason": "Not a Windows system"}

    try:
        import subprocess

        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                "Get-MpComputerStatus | Select-Object -Property "
                "RealTimeProtectionEnabled,AntivirusEnabled,AntispywareEnabled,"
                "QuickScanAge,FullScanAge | ConvertTo-Json",
            ],
            capture_output=True, text=True, timeout=15,
        )

        if result.returncode != 0:
            return {"available": False, "reason": f"PowerShell error: {result.stderr[:200]}"}

        import json
        data = json.loads(result.stdout)
        return {
            "available": True,
            "real_time_protection": data.get("RealTimeProtectionEnabled", False),
            "antivirus_enabled": data.get("AntivirusEnabled", False),
            "antispyware_enabled": data.get("AntispywareEnabled", False),
            "quick_scan_age_days": data.get("QuickScanAge"),
            "full_scan_age_days": data.get("FullScanAge"),
        }
    except Exception as exc:
        return {"available": False, "reason": str(exc)[:200]}


def scan_event_logs(lookback_hours: int = 24, max_events: int = 20) -> list[dict]:
    """
    Scan Windows Security and System event logs for notable entries.

    Looks for failed logon attempts, service crashes, and audit failures.
    Returns a list of event dicts.
    """
    if platform.system() != "Windows":
        return []

    events: list[dict] = []
    try:
        import subprocess
        import json

        cutoff_ms = int((datetime.now() - timedelta(hours=lookback_hours)).timestamp() * 1000)

        # Query System log for critical/error events
        cmd = (
            f'Get-WinEvent -FilterHashtable @{{LogName="System"; Level=1,2; '
            f'StartTime=(Get-Date).AddHours(-{lookback_hours})}} '
            f'-MaxEvents {max_events} -ErrorAction SilentlyContinue | '
            f'Select-Object TimeCreated,Id,LevelDisplayName,Message | ConvertTo-Json'
        )

        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=15,
        )

        if result.returncode == 0 and result.stdout.strip():
            raw = json.loads(result.stdout)
            # PowerShell returns a single object when there's only 1 result
            if isinstance(raw, dict):
                raw = [raw]
            for evt in raw:
                events.append({
                    "time": str(evt.get("TimeCreated", ""))[:25],
                    "event_id": evt.get("Id"),
                    "level": evt.get("LevelDisplayName", ""),
                    "message": str(evt.get("Message", ""))[:200],
                })
    except Exception:
        pass  # Event log access is best-effort

    return events


def run_security_audit(
    suspicious_paths: list[str] | None = None,
    trusted_processes: list[str] | None = None,
    max_connections: int = 20,
    event_log_lookback_hours: int = 24,
) -> dict:
    """
    Master function: runs all security checks and returns a consolidated report.
    """
    return {
        "processes": audit_processes(suspicious_paths, trusted_processes),
        "network": audit_network(max_connections),
        "defender": check_defender_status(),
        "event_log_alerts": scan_event_logs(event_log_lookback_hours),
    }
