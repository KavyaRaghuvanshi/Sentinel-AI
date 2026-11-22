"""
Sentinel AI - System Sensor

Deterministic data collection: disk usage, CPU, memory, boot time,
and general system telemetry.  No side-effects — read-only operations.
"""

from __future__ import annotations

import platform
from datetime import datetime

import psutil

from sentinel.utils import format_bytes, format_gb, seconds_to_human


def get_disk_health(drive: str = "C:\\") -> dict:
    """Return disk usage statistics for *drive*."""
    usage = psutil.disk_usage(drive)
    return {
        "drive": drive,
        "total_gb": format_gb(usage.total),
        "used_gb": format_gb(usage.used),
        "free_gb": format_gb(usage.free),
        "percent_used": usage.percent,
        "status": _disk_status(usage.percent),
    }


def get_memory_info() -> dict:
    """Return physical memory usage."""
    mem = psutil.virtual_memory()
    return {
        "total_gb": format_gb(mem.total),
        "available_gb": format_gb(mem.available),
        "percent_used": mem.percent,
        "status": "Critical" if mem.percent > 90 else ("Warning" if mem.percent > 80 else "Healthy"),
    }


def get_cpu_info() -> dict:
    """Return CPU usage snapshot."""
    cpu_percent = psutil.cpu_percent(interval=1)
    return {
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "current_percent": cpu_percent,
        "status": "Critical" if cpu_percent > 90 else ("Warning" if cpu_percent > 70 else "Healthy"),
    }


def get_boot_time() -> dict:
    """Return boot time and uptime information."""
    boot_ts = psutil.boot_time()
    boot_dt = datetime.fromtimestamp(boot_ts)
    uptime_seconds = (datetime.now() - boot_dt).total_seconds()
    return {
        "boot_time": boot_dt.isoformat(timespec="seconds"),
        "uptime": seconds_to_human(uptime_seconds),
        "uptime_seconds": round(uptime_seconds),
    }


def get_top_processes(n: int = 5) -> list[dict]:
    """
    Return the top *n* processes by memory usage.

    Useful for identifying what is consuming the most resources post-boot.
    """
    procs: list[dict] = []
    for proc in psutil.process_iter(["pid", "name", "memory_percent", "cpu_percent"]):
        try:
            info = proc.info
            procs.append({
                "pid": info["pid"],
                "name": info["name"] or "<unknown>",
                "memory_percent": round(info["memory_percent"] or 0, 2),
                "cpu_percent": round(info["cpu_percent"] or 0, 2),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    procs.sort(key=lambda p: p["memory_percent"], reverse=True)
    return procs[:n]


def collect_system_telemetry() -> dict:
    """
    Master function: collects all system sensors into one snapshot.

    Returns
    -------
    dict
        {timestamp, hostname, os, disk, memory, cpu, boot, top_processes}
    """
    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "hostname": platform.node(),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
        },
        "disk": get_disk_health(),
        "memory": get_memory_info(),
        "cpu": get_cpu_info(),
        "boot": get_boot_time(),
        "top_processes": get_top_processes(n=5),
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _disk_status(percent_used: float) -> str:
    if percent_used > 95:
        return "Critical"
    elif percent_used > 85:
        return "Warning"
    return "Healthy"
