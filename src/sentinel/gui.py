"""
Sentinel AI - Modern Desktop GUI / HUD

A sleek Windows-native dashboard displayed on boot or on demand.
Presents:
  - System health & detected problems
  - Security status & process anomalies
  - AI suggestions to improve performance
  - Precautions & security best practices
"""

from __future__ import annotations

import logging
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any

from sentinel.agent import analyze_and_report
from sentinel.cleaner import clean_temp_files
from sentinel.config import load_config
from sentinel.reporter import save_report_to_file
from sentinel.security import run_security_audit
from sentinel.sensor import collect_system_telemetry

logger = logging.getLogger("sentinel.gui")

# Color palette: Modern Fluent Dark Theme
BG_DARK = "#0f172a"      # Slate 900
CARD_BG = "#1e293b"      # Slate 800
CARD_BORDER = "#334155"  # Slate 700
TEXT_MAIN = "#f8fafc"    # Slate 50
TEXT_MUTED = "#94a3b8"   # Slate 400
ACCENT_BLUE = "#38bdf8"  # Sky 400
ACCENT_GREEN = "#10b981" # Emerald 500
ACCENT_AMBER = "#f59e0b" # Amber 500
ACCENT_RED = "#ef4444"   # Red 500


def get_recommendations_and_precautions(telemetry: dict) -> tuple[list[str], list[str]]:
    """Derive smart recommendations and security precautions from telemetry."""
    suggestions: list[str] = []
    precautions: list[str] = []

    # 1. Memory suggestions
    mem = telemetry.get("memory", {})
    mem_used = mem.get("percent_used", 0)
    if mem_used > 85:
        suggestions.append(f"Memory is at {mem_used}%. Close heavy background browser tabs or idle dev tools.")
        precautions.append("High RAM usage can lead to memory paging freezes. Avoid launching memory-heavy apps.")
    elif mem_used > 70:
        suggestions.append(f"Memory usage is moderate ({mem_used}%). Monitor memory-intensive background services.")
    else:
        suggestions.append("Memory footprint is healthy. No action required.")

    # 2. Disk suggestions
    disk = telemetry.get("disk", {})
    disk_used = disk.get("percent_used", 0)
    free_gb = disk.get("free_gb", 0)
    if disk_used > 85:
        suggestions.append(f"Disk free space is low ({free_gb} GB remaining). Run cleanup or move archives.")
        precautions.append("Low disk space can prevent Windows Updates from installing critical security patches.")
    else:
        suggestions.append(f"Disk capacity is optimal with {free_gb} GB available.")

    # 3. Security suggestions & precautions
    security = telemetry.get("security", {})
    proc_audit = security.get("processes", {})
    anomalies = proc_audit.get("anomalies", [])
    defender = security.get("defender", {})

    if anomalies:
        for anom in anomalies[:2]:
            precautions.append(f"Suspicious activity: {anom.get('name')} (PID: {anom.get('pid')}) in temp directory.")
        suggestions.append("Review flagged temporary processes in Task Manager and quarantine if unverified.")
    else:
        suggestions.append("Process audit clean: No unauthorized binaries found running from temporary folders.")

    if defender.get("available") and not defender.get("real_time_protection"):
        precautions.append("CRITICAL: Windows Defender Real-Time Protection is DISABLED!")
        suggestions.append("Turn Windows Defender Real-Time Protection back ON immediately in Windows Security.")
    else:
        precautions.append("Ensure OS updates and antivirus definitions remain up to date.")

    # 4. Cleanup
    cleanup = telemetry.get("cleanup", {})
    purged = cleanup.get("purged_mb", 0)
    if purged > 0:
        suggestions.append(f"Routine maintenance: Purged {purged} MB of orphaned temporary files.")

    return suggestions, precautions


class SentinelHUD:
    """Modern Desktop GUI for Sentinel AI."""

    def __init__(self, root: tk.Tk, config: dict | None = None) -> None:
        self.root = root
        self.config = config or load_config()
        self.telemetry: dict = {}
        self.report_text: str = ""

        # Window styling
        self.root.title("Sentinel AI — Endpoint Health & Security Shield")
        self.root.geometry("960x680")
        self.root.minsize(860, 600)
        self.root.configure(bg=BG_DARK)

        # Configure custom TTK styles
        self._setup_styles()

        # Build UI layout
        self._build_header()
        self._build_main_grid()
        self._build_footer()

        # Start initial scan in background thread so UI doesn't hang
        self.start_scan_async()

    def _setup_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")

        # Custom progressbar style
        style.configure(
            "Health.Horizontal.TProgressbar",
            troughcolor=CARD_BG,
            bordercolor=CARD_BORDER,
            background=ACCENT_BLUE,
            lightcolor=ACCENT_BLUE,
            darkcolor=ACCENT_BLUE,
        )

    def _build_header(self) -> None:
        """Top banner with app name, system info, and overall status badge."""
        header_frame = tk.Frame(self.root, bg=BG_DARK, padx=24, pady=16)
        header_frame.pack(fill=tk.X)

        # Title & subtitle
        title_box = tk.Frame(header_frame, bg=BG_DARK)
        title_box.pack(side=tk.LEFT)

        title_lbl = tk.Label(
            title_box,
            text="🛡️ Sentinel AI Endpoint Shield",
            font=("Segoe UI", 18, "bold"),
            fg=TEXT_MAIN,
            bg=BG_DARK,
        )
        title_lbl.pack(anchor="w")

        self.subtitle_lbl = tk.Label(
            title_box,
            text="Scanning system telemetry...",
            font=("Segoe UI", 10),
            fg=TEXT_MUTED,
            bg=BG_DARK,
        )
        self.subtitle_lbl.pack(anchor="w")

        # Overall Status Badge (Right)
        self.status_badge = tk.Label(
            header_frame,
            text="INITIALIZING",
            font=("Segoe UI", 11, "bold"),
            fg=BG_DARK,
            bg=ACCENT_BLUE,
            padx=14,
            pady=6,
        )
        self.status_badge.pack(side=tk.RIGHT)

    def _build_main_grid(self) -> None:
        """Two-column card layout for stats and AI recommendations."""
        main_container = tk.Frame(self.root, bg=BG_DARK, padx=20, pady=4)
        main_container.pack(fill=tk.BOTH, expand=True)

        # Configure 2 equal columns
        main_container.columnconfigure(0, weight=1, uniform="group1")
        main_container.columnconfigure(1, weight=1, uniform="group1")
        main_container.rowconfigure(0, weight=1)
        main_container.rowconfigure(1, weight=1)

        # --- Card 1: Storage & Maintenance (Row 0, Col 0) ---
        self.storage_card = self._create_card(main_container, "💾 Storage & Cache Health", 0, 0)
        self.disk_metric_lbl = tk.Label(
            self.storage_card, text="Checking disk...", font=("Segoe UI", 11), fg=TEXT_MAIN, bg=CARD_BG
        )
        self.disk_metric_lbl.pack(anchor="w", padx=16, pady=(10, 4))

        self.disk_progress = ttk.Progressbar(
            self.storage_card, style="Health.Horizontal.TProgressbar", length=200, mode="determinate"
        )
        self.disk_progress.pack(fill=tk.X, padx=16, pady=4)

        self.cleanup_lbl = tk.Label(
            self.storage_card,
            text="Clean status: Idle",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=CARD_BG,
            justify=tk.LEFT,
        )
        self.cleanup_lbl.pack(anchor="w", padx=16, pady=(6, 12))

        # --- Card 2: Performance & Hardware (Row 1, Col 0) ---
        self.perf_card = self._create_card(main_container, "⚡ Hardware Performance", 1, 0)
        self.cpu_metric_lbl = tk.Label(
            self.perf_card, text="CPU: --", font=("Segoe UI", 11), fg=TEXT_MAIN, bg=CARD_BG
        )
        self.cpu_metric_lbl.pack(anchor="w", padx=16, pady=(10, 2))

        self.mem_metric_lbl = tk.Label(
            self.perf_card, text="Memory: --", font=("Segoe UI", 11), fg=TEXT_MAIN, bg=CARD_BG
        )
        self.mem_metric_lbl.pack(anchor="w", padx=16, pady=2)

        self.mem_progress = ttk.Progressbar(
            self.perf_card, style="Health.Horizontal.TProgressbar", length=200, mode="determinate"
        )
        self.mem_progress.pack(fill=tk.X, padx=16, pady=4)

        self.uptime_lbl = tk.Label(
            self.perf_card, text="Uptime: --", font=("Segoe UI", 9), fg=TEXT_MUTED, bg=CARD_BG
        )
        self.uptime_lbl.pack(anchor="w", padx=16, pady=(4, 12))

        # --- Card 3: Security & Threat Audit (Row 0, Col 1) ---
        self.security_card = self._create_card(main_container, "🛡️ Security & Integrity", 0, 1)
        self.threat_status_lbl = tk.Label(
            self.security_card, text="Auditing running processes...", font=("Segoe UI", 11), fg=TEXT_MAIN, bg=CARD_BG
        )
        self.threat_status_lbl.pack(anchor="w", padx=16, pady=(10, 4))

        self.threat_detail_lbl = tk.Label(
            self.security_card,
            text="Network connections: --\nDefender status: --",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=CARD_BG,
            justify=tk.LEFT,
        )
        self.threat_detail_lbl.pack(anchor="w", padx=16, pady=(2, 12))

        # --- Card 4: AI Recommendations & Precautions (Row 1, Col 1) ---
        self.ai_card = self._create_card(main_container, "💡 Agentic AI Suggestions & Precautions", 1, 1)
        
        self.ai_text_box = tk.Text(
            self.ai_card,
            font=("Segoe UI", 9),
            fg=TEXT_MAIN,
            bg="#172033",
            bd=0,
            highlightthickness=0,
            wrap=tk.WORD,
            padx=10,
            pady=8,
        )
        self.ai_text_box.pack(fill=tk.BOTH, expand=True, padx=14, pady=10)
        self.ai_text_box.insert(tk.END, "Analyzing system telemetry with AI agent...")
        self.ai_text_box.config(state=tk.DISABLED)

    def _create_card(self, parent: tk.Frame, title: str, row: int, col: int) -> tk.Frame:
        """Create a styled Fluent card container."""
        card = tk.Frame(
            parent,
            bg=CARD_BG,
            highlightbackground=CARD_BORDER,
            highlightthickness=1,
            padx=4,
            pady=4,
        )
        card.grid(row=row, column=col, padx=8, pady=8, sticky="nsew")

        # Card Title Header
        header = tk.Label(
            card,
            text=title,
            font=("Segoe UI", 11, "bold"),
            fg=ACCENT_BLUE,
            bg=CARD_BG,
            padx=12,
            pady=8,
        )
        header.pack(anchor="w")

        # Divider line
        div = tk.Frame(card, height=1, bg=CARD_BORDER)
        div.pack(fill=tk.X, padx=12)

        return card

    def _build_footer(self) -> None:
        """Bottom action bar with Re-Scan, View Report, and Clean buttons."""
        footer_frame = tk.Frame(self.root, bg=BG_DARK, padx=24, pady=14)
        footer_frame.pack(fill=tk.X)

        self.rescan_btn = tk.Button(
            footer_frame,
            text="🔄 Re-Scan Now",
            font=("Segoe UI", 10, "bold"),
            bg="#2563eb",
            fg="white",
            activebackground="#1d4ed8",
            activeforeground="white",
            bd=0,
            padx=16,
            pady=8,
            cursor="hand2",
            command=self.start_scan_async,
        )
        self.rescan_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.clean_btn = tk.Button(
            footer_frame,
            text="🧹 Safe Temp Cleanup",
            font=("Segoe UI", 10),
            bg=CARD_BG,
            fg=TEXT_MAIN,
            activebackground=CARD_BORDER,
            activeforeground=TEXT_MAIN,
            bd=1,
            padx=14,
            pady=7,
            cursor="hand2",
            command=self._run_cleanup_action,
        )
        self.clean_btn.pack(side=tk.LEFT, padx=6)

        self.close_btn = tk.Button(
            footer_frame,
            text="Dismiss",
            font=("Segoe UI", 10),
            bg=CARD_BG,
            fg=TEXT_MUTED,
            bd=0,
            padx=14,
            pady=7,
            cursor="hand2",
            command=self.root.destroy,
        )
        self.close_btn.pack(side=tk.RIGHT)

    def start_scan_async(self) -> None:
        """Run telemetry scan in background thread to avoid freezing the GUI."""
        self.subtitle_lbl.config(text="Scanning endpoint telemetry and evaluating security...")
        self.status_badge.config(text="ANALYZING...", bg=ACCENT_BLUE, fg=BG_DARK)
        self.rescan_btn.config(state=tk.DISABLED)

        thread = threading.Thread(target=self._perform_scan, daemon=True)
        thread.start()

    def _perform_scan(self) -> None:
        """Worker thread logic."""
        try:
            # 1. Collect telemetry
            telemetry = collect_system_telemetry()

            # 2. Dry-run cleanup scan
            cleanup_cfg = self.config.get("cleanup", {})
            cleanup_result = clean_temp_files(
                min_age_hours=cleanup_cfg.get("min_age_hours", 24),
                max_delete_mb=cleanup_cfg.get("max_delete_mb", 5000),
                protected_extensions=cleanup_cfg.get("protected_extensions"),
                dry_run=True,
            )
            telemetry["cleanup"] = cleanup_result

            # 3. Security audit
            sec_cfg = self.config.get("security", {})
            sec_result = run_security_audit(
                suspicious_paths=sec_cfg.get("suspicious_exe_paths"),
                trusted_processes=sec_cfg.get("trusted_processes"),
                max_connections=sec_cfg.get("max_connections_to_report", 20),
            )
            telemetry["security"] = sec_result

            # 4. Generate AI report text
            agent_cfg = self.config.get("agent", {})
            report = analyze_and_report(telemetry, agent_cfg)

            # 5. Derive smart recommendations
            suggestions, precautions = get_recommendations_and_precautions(telemetry)

            # Update UI on main thread
            self.root.after(0, self._update_ui, telemetry, report, suggestions, precautions)

        except Exception as exc:
            logger.error("Scan failed: %s", exc, exc_info=True)
            self.root.after(0, self._handle_scan_error, str(exc))

    def _update_ui(
        self,
        telemetry: dict,
        report: str,
        suggestions: list[str],
        precautions: list[str],
    ) -> None:
        """Update all GUI widgets with fresh scan data."""
        self.telemetry = telemetry
        self.report_text = report
        self.rescan_btn.config(state=tk.NORMAL)

        # Host & Time
        host = telemetry.get("hostname", "Localhost")
        ts = telemetry.get("timestamp", "")
        self.subtitle_lbl.config(text=f"Host: {host}  |  Last Updated: {ts}")

        # Storage Card
        disk = telemetry.get("disk", {})
        disk_pct = disk.get("percent_used", 0)
        self.disk_metric_lbl.config(
            text=f"Drive {disk.get('drive', 'C:')} — {disk_pct}% Used ({disk.get('free_gb', 0)} GB free)"
        )
        self.disk_progress["value"] = disk_pct

        cleanup = telemetry.get("cleanup", {})
        self.cleanup_lbl.config(
            text=f"Orphaned Cache: {cleanup.get('purged_mb', 0)} MB deletable ({cleanup.get('files_deleted', 0)} files found)"
        )

        # Hardware Performance Card
        cpu = telemetry.get("cpu", {})
        mem = telemetry.get("memory", {})
        boot = telemetry.get("boot", {})

        cpu_val = cpu.get("current_percent", 0)
        mem_val = mem.get("percent_used", 0)

        self.cpu_metric_lbl.config(text=f"CPU Activity: {cpu_val}%  ({cpu.get('logical_cores', '?')} Cores)")
        self.mem_metric_lbl.config(text=f"Memory Consumption: {mem_val}%  ({mem.get('available_gb', 0)} GB Available)")
        self.mem_progress["value"] = mem_val
        self.uptime_lbl.config(text=f"System Uptime: {boot.get('uptime', 'Unknown')}")

        # Security Card
        sec = telemetry.get("security", {})
        procs = sec.get("processes", {})
        anomalies = procs.get("anomaly_count", 0)
        defender = sec.get("defender", {})

        if anomalies > 0:
            self.threat_status_lbl.config(text=f"⚠️ {anomalies} Potential Process Anomalies Detected!", fg=ACCENT_AMBER)
        else:
            self.threat_status_lbl.config(text="✅ All Running Processes Verified Clean", fg=ACCENT_GREEN)

        net = sec.get("network", {})
        def_status = "Protected" if defender.get("real_time_protection") else "Unavailable / Disabled"
        self.threat_detail_lbl.config(
            text=f"Audited Processes: {procs.get('total_processes', 0)}\n"
                 f"Active Connections: {net.get('total_connections', 0)}\n"
                 f"Windows Defender: {def_status}"
        )

        # AI Suggestions & Precautions Box
        self.ai_text_box.config(state=tk.NORMAL)
        self.ai_text_box.delete("1.0", tk.END)

        self.ai_text_box.insert(tk.END, "📌 AI RECOMMENDATIONS FOR IMPROVEMENT:\n", "header")
        for idx, sug in enumerate(suggestions, 1):
            self.ai_text_box.insert(tk.END, f"  {idx}. {sug}\n")

        self.ai_text_box.insert(tk.END, "\n🛡️ PRECAUTIONS & SECURITY BEST PRACTICES:\n", "header")
        for idx, prec in enumerate(precautions, 1):
            self.ai_text_box.insert(tk.END, f"  • {prec}\n")

        self.ai_text_box.tag_config("header", font=("Segoe UI", 9, "bold"), foreground=ACCENT_BLUE)
        self.ai_text_box.config(state=tk.DISABLED)

        # Evaluate Overall Status
        if mem_val > 90 or disk_pct > 95 or anomalies > 5:
            self.status_badge.config(text="🚨 CRITICAL", bg=ACCENT_RED, fg="white")
        elif mem_val > 80 or disk_pct > 85 or anomalies > 0:
            self.status_badge.config(text="⚠️ WARNING", bg=ACCENT_AMBER, fg=BG_DARK)
        else:
            self.status_badge.config(text="✅ HEALTHY", bg=ACCENT_GREEN, fg=BG_DARK)

    def _handle_scan_error(self, err_msg: str) -> None:
        self.rescan_btn.config(state=tk.NORMAL)
        self.status_badge.config(text="ERROR", bg=ACCENT_RED, fg="white")
        self.subtitle_lbl.config(text=f"Scan error: {err_msg[:80]}")

    def _run_cleanup_action(self) -> None:
        """Trigger an immediate live safe cleanup."""
        cleanup_cfg = self.config.get("cleanup", {})
        res = clean_temp_files(
            min_age_hours=cleanup_cfg.get("min_age_hours", 24),
            max_delete_mb=cleanup_cfg.get("max_delete_mb", 5000),
            protected_extensions=cleanup_cfg.get("protected_extensions"),
            dry_run=False,
        )
        messagebox.showinfo(
            "Sentinel Cleanup Complete",
            f"Successfully purged {res.get('purged_mb', 0)} MB of temporary files!\n"
            f"Files deleted: {res.get('files_deleted', 0)}\n"
            f"Files skipped (in-use): {res.get('files_skipped', 0)}",
        )
        self.start_scan_async()


def launch_gui(config: dict | None = None) -> None:
    """Launch the Sentinel AI Desktop HUD."""
    root = tk.Tk()
    app = SentinelHUD(root, config)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
