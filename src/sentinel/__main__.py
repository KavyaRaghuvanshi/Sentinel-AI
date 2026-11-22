"""
Sentinel AI - Main Entry Point

Orchestrates the full pipeline:
  1. Load configuration
  2. Collect system telemetry (read-only sensors)
  3. Perform safe temp file cleanup
  4. Run security audit
  5. Analyze with AI agent (or template fallback)
  6. Deliver report through configured channels

Usage:
  python -m sentinel                     # Run with defaults
  python -m sentinel --config my.yaml    # Custom config file
  python -m sentinel --dry-run           # Scan only, no deletions
  python -m sentinel --provider gemini   # Override LLM provider
"""

from __future__ import annotations

import argparse
import logging
import platform
import sys
import time

from sentinel.agent import analyze_and_report
from sentinel.cleaner import clean_temp_files
from sentinel.config import load_config
from sentinel.reporter import deliver_report
from sentinel.security import run_security_audit
from sentinel.sensor import collect_system_telemetry


def _setup_logging(verbose: bool = False) -> None:
    """Configure logging for the application."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel AI — Autonomous Endpoint Health & Cyber-Defense Agent",
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        default=None,
        help="Path to config.yaml (default: auto-detect)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and report without deleting any files",
    )
    parser.add_argument(
        "--provider",
        type=str,
        choices=["gemini", "openai", "ollama", "none"],
        default=None,
        help="Override the LLM provider (default: from config)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--skip-cleanup",
        action="store_true",
        help="Skip the temp file cleanup step",
    )
    parser.add_argument(
        "--skip-security",
        action="store_true",
        help="Skip the security audit step",
    )
    return parser.parse_args(argv)


def run(argv: list[str] | None = None) -> dict:
    """
    Execute the full Sentinel AI pipeline.

    Parameters
    ----------
    argv : list[str] | None
        Command-line arguments. If None, reads from sys.argv.

    Returns
    -------
    dict
        Pipeline results including telemetry, report, and delivery status.
    """
    args = _parse_args(argv)
    _setup_logging(args.verbose)

    logger = logging.getLogger("sentinel")
    logger.info("=" * 50)
    logger.info("Sentinel AI starting on %s", platform.node())
    logger.info("=" * 50)

    start_time = time.time()

    # --- Step 1: Load Configuration ---
    logger.info("Step 1/5: Loading configuration...")
    config = load_config(args.config)
    cleanup_cfg = config.get("cleanup", {})
    security_cfg = config.get("security", {})
    agent_cfg = config.get("agent", {})
    reporter_cfg = config.get("reporter", {})

    # CLI overrides
    if args.provider:
        agent_cfg["provider"] = args.provider

    # --- Step 2: Collect System Telemetry ---
    logger.info("Step 2/5: Collecting system telemetry...")
    telemetry = collect_system_telemetry()
    logger.info(
        "  Disk: %s%% used | CPU: %s%% | Memory: %s%% | Uptime: %s",
        telemetry["disk"]["percent_used"],
        telemetry["cpu"]["current_percent"],
        telemetry["memory"]["percent_used"],
        telemetry["boot"]["uptime"],
    )

    # --- Step 3: Safe Cleanup ---
    if args.skip_cleanup or not cleanup_cfg.get("enabled", True):
        logger.info("Step 3/5: Cleanup skipped.")
        telemetry["cleanup"] = {"skipped": True}
    else:
        logger.info("Step 3/5: Performing safe temp file cleanup...")
        cleanup_result = clean_temp_files(
            min_age_hours=cleanup_cfg.get("min_age_hours", 24),
            max_delete_mb=cleanup_cfg.get("max_delete_mb", 5000),
            protected_extensions=cleanup_cfg.get("protected_extensions"),
            additional_dirs=cleanup_cfg.get("additional_temp_dirs"),
            dry_run=args.dry_run,
        )
        telemetry["cleanup"] = cleanup_result
        mode = "DRY RUN" if args.dry_run else "LIVE"
        logger.info(
            "  [%s] Purged %.2f MB (%d files deleted, %d skipped)",
            mode,
            cleanup_result["purged_mb"],
            cleanup_result["files_deleted"],
            cleanup_result["files_skipped"],
        )

    # --- Step 4: Security Audit ---
    if args.skip_security or not security_cfg.get("enabled", True):
        logger.info("Step 4/5: Security audit skipped.")
        telemetry["security"] = {"skipped": True}
    else:
        logger.info("Step 4/5: Running security audit...")
        security_result = run_security_audit(
            suspicious_paths=security_cfg.get("suspicious_exe_paths"),
            trusted_processes=security_cfg.get("trusted_processes"),
            max_connections=security_cfg.get("max_connections_to_report", 20),
            event_log_lookback_hours=security_cfg.get("event_log_lookback_hours", 24),
        )
        telemetry["security"] = security_result
        anomaly_count = security_result.get("processes", {}).get("anomaly_count", 0)
        logger.info(
            "  Processes: %d total, %d anomalies. Network: %d active connections.",
            security_result["processes"]["total_processes"],
            anomaly_count,
            security_result["network"]["total_connections"],
        )

    # --- Step 5: AI Analysis & Report ---
    logger.info("Step 5/5: Generating admin briefing (provider: %s)...", agent_cfg.get("provider", "none"))
    report = analyze_and_report(telemetry, agent_cfg)

    # --- Deliver Report ---
    logger.info("Delivering report...")
    delivery_results = deliver_report(report, reporter_cfg, hostname=telemetry.get("hostname", "unknown"))

    elapsed = round(time.time() - start_time, 1)
    logger.info("Sentinel AI completed in %.1fs.", elapsed)

    return {
        "telemetry": telemetry,
        "report": report,
        "delivery": delivery_results,
        "elapsed_seconds": elapsed,
    }


def main() -> None:
    """CLI entry point."""
    try:
        result = run()
        sys.exit(0)
    except KeyboardInterrupt:
        print("\nSentinel AI interrupted.")
        sys.exit(130)
    except Exception as exc:
        logging.getLogger("sentinel").critical("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
