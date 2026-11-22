"""
Sentinel AI - Agentic Reasoning Layer

Takes raw telemetry and produces a concise, actionable admin report.

Supports multiple LLM providers:
  - Google Gemini API
  - OpenAI API
  - Ollama (local, offline-capable)
  - Template fallback (no LLM required — always works)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime

from sentinel.guardrails import sanitize_telemetry

logger = logging.getLogger("sentinel.agent")


# ---------------------------------------------------------------------------
# LLM Prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are Sentinel AI, an Endpoint Security & System Administrator Agent.

Your task is to analyze raw computer telemetry data and produce a concise,
professional Admin Briefing.

Rules:
- Output EXACTLY 3 bullet points with these headers:
  1. **Storage & Maintenance** — Disk status and cleanup results.
  2. **System Performance** — CPU, memory, boot time assessment.
  3. **Security Assessment** — Process anomalies, network issues, defender status.
- Keep the entire briefing under 150 words.
- If everything is healthy, state that explicitly — do not invent problems.
- If there are anomalies, be specific: name the process, PID, path, or IP.
- End with a one-line overall status: ✅ Healthy, ⚠️ Warning, or 🚨 Critical.
- Do NOT include any raw JSON, code blocks, or markdown headers.
"""


def _build_user_prompt(telemetry: dict) -> str:
    """Build the user prompt containing sanitized telemetry."""
    safe_telemetry = sanitize_telemetry(telemetry)
    return (
        "Analyze this telemetry and generate the Admin Briefing:\n\n"
        f"```json\n{json.dumps(safe_telemetry, indent=2)}\n```"
    )


# ---------------------------------------------------------------------------
# Provider: Google Gemini
# ---------------------------------------------------------------------------

def _call_gemini(telemetry: dict, config: dict) -> str:
    """Generate report using Google Gemini API."""
    from google import genai
    from google.genai import types

    api_key = os.environ.get(config.get("api_key_env", "GEMINI_API_KEY"), "")
    if not api_key:
        raise EnvironmentError(
            f"Gemini API key not found. Set the {config.get('api_key_env', 'GEMINI_API_KEY')} "
            f"environment variable."
        )

    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=config.get("model", "gemini-2.5-flash"),
        contents=_build_user_prompt(telemetry),
        config=types.GenerateContentConfig(
            system_instruction=_SYSTEM_PROMPT,
            temperature=config.get("temperature", 0.2),
            max_output_tokens=config.get("max_output_tokens", 1024),
        ),
    )
    return response.text


# ---------------------------------------------------------------------------
# Provider: OpenAI
# ---------------------------------------------------------------------------

def _call_openai(telemetry: dict, config: dict) -> str:
    """Generate report using OpenAI API."""
    from openai import OpenAI

    api_key = os.environ.get(config.get("api_key_env", "OPENAI_API_KEY"), "")
    if not api_key:
        raise EnvironmentError(
            f"OpenAI API key not found. Set the {config.get('api_key_env', 'OPENAI_API_KEY')} "
            f"environment variable."
        )

    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=config.get("model", "gpt-4o-mini"),
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(telemetry)},
        ],
        temperature=config.get("temperature", 0.2),
        max_tokens=config.get("max_output_tokens", 1024),
    )
    return response.choices[0].message.content


# ---------------------------------------------------------------------------
# Provider: Ollama (local, offline)
# ---------------------------------------------------------------------------

def _call_ollama(telemetry: dict, config: dict) -> str:
    """Generate report using a local Ollama model."""
    import requests

    base_url = config.get("ollama_base_url", "http://localhost:11434")
    model = config.get("model", "llama3.2:3b")

    response = requests.post(
        f"{base_url}/api/chat",
        json={
            "model": model,
            "stream": False,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(telemetry)},
            ],
            "options": {
                "temperature": config.get("temperature", 0.2),
                "num_predict": config.get("max_output_tokens", 1024),
            },
        },
        timeout=120,
    )
    response.raise_for_status()
    return response.json()["message"]["content"]


# ---------------------------------------------------------------------------
# Template Fallback (No LLM — always works)
# ---------------------------------------------------------------------------

def generate_report_from_template(telemetry: dict) -> str:
    """
    Generate a structured report using deterministic string templates.
    No LLM required. This is the guaranteed-available fallback.
    """
    lines: list[str] = []
    hostname = telemetry.get("hostname", "Unknown")
    timestamp = telemetry.get("timestamp", datetime.now().isoformat(timespec="seconds"))

    lines.append(f"=== Sentinel AI — Endpoint Health Briefing ===")
    lines.append(f"Host: {hostname}  |  Time: {timestamp}")
    lines.append("")

    # --- Storage & Maintenance ---
    disk = telemetry.get("disk", {})
    cleanup = telemetry.get("cleanup", {})
    disk_status = disk.get("status", "Unknown")
    lines.append(f"1. **Storage & Maintenance** [{disk_status}]")
    lines.append(
        f"   Disk {disk.get('drive', 'C:')}: "
        f"{disk.get('used_gb', '?')}/{disk.get('total_gb', '?')} GB used "
        f"({disk.get('percent_used', '?')}%). "
        f"Free: {disk.get('free_gb', '?')} GB."
    )
    if cleanup:
        lines.append(
            f"   Cleanup: Purged {cleanup.get('purged_mb', 0)} MB "
            f"({cleanup.get('files_deleted', 0)} files removed, "
            f"{cleanup.get('files_skipped', 0)} skipped/locked)."
        )
    lines.append("")

    # --- System Performance ---
    cpu = telemetry.get("cpu", {})
    mem = telemetry.get("memory", {})
    boot = telemetry.get("boot", {})
    perf_statuses = [
        cpu.get("status", "Unknown"),
        mem.get("status", "Unknown"),
    ]
    worst_perf = "Critical" if "Critical" in perf_statuses else (
        "Warning" if "Warning" in perf_statuses else "Healthy"
    )
    lines.append(f"2. **System Performance** [{worst_perf}]")
    lines.append(
        f"   CPU: {cpu.get('current_percent', '?')}% "
        f"({cpu.get('logical_cores', '?')} cores). "
        f"Memory: {mem.get('percent_used', '?')}% used "
        f"({mem.get('available_gb', '?')} GB free). "
        f"Uptime: {boot.get('uptime', '?')}."
    )
    lines.append("")

    # --- Security ---
    security = telemetry.get("security", {})
    proc_audit = security.get("processes", {})
    net_audit = security.get("network", {})
    defender = security.get("defender", {})
    events = security.get("event_log_alerts", [])
    anomaly_count = proc_audit.get("anomaly_count", 0)

    sec_status = "Healthy"
    if anomaly_count > 0:
        sec_status = "Warning"
    if anomaly_count > 5 or (defender.get("available") and not defender.get("real_time_protection")):
        sec_status = "Critical"

    lines.append(f"3. **Security Assessment** [{sec_status}]")
    lines.append(
        f"   Processes scanned: {proc_audit.get('total_processes', '?')}. "
        f"Anomalies: {anomaly_count}."
    )

    # Detail anomalies
    for anom in proc_audit.get("anomalies", [])[:3]:
        lines.append(
            f"   ⚠ {anom.get('type', '?')}: {anom.get('name', '?')} "
            f"(PID {anom.get('pid', '?')}) — {anom.get('reason', '')}"
        )

    lines.append(
        f"   Active outbound connections: {net_audit.get('total_connections', '?')}."
    )

    if defender.get("available"):
        rt = "✅ ON" if defender.get("real_time_protection") else "🚨 OFF"
        lines.append(f"   Windows Defender real-time protection: {rt}.")
    else:
        lines.append(f"   Windows Defender: status unavailable.")

    if events:
        lines.append(f"   Event log alerts (last 24h): {len(events)} critical/error events.")

    lines.append("")

    # --- Overall Status ---
    all_statuses = [disk_status, worst_perf, sec_status]
    if "Critical" in all_statuses:
        overall = "🚨 CRITICAL — Immediate attention required."
    elif "Warning" in all_statuses:
        overall = "⚠️ WARNING — Review flagged items."
    else:
        overall = "✅ HEALTHY — All systems nominal."

    lines.append(f"Overall: {overall}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_and_report(telemetry: dict, agent_config: dict) -> str:
    """
    Analyze telemetry and produce a human-readable report.

    Tries the configured LLM provider first; falls back to the
    deterministic template if the LLM is unavailable or fails.

    Parameters
    ----------
    telemetry : dict
        Full telemetry snapshot from the sensor + cleaner + security modules.
    agent_config : dict
        The ``agent`` section of the Sentinel configuration.

    Returns
    -------
    str
        The formatted admin briefing.
    """
    provider = agent_config.get("provider", "none").lower()

    # Provider = "none" means always use template
    if provider == "none":
        logger.info("Agent provider is 'none'; using template report.")
        return generate_report_from_template(telemetry)

    try:
        logger.info("Generating report with provider '%s'...", provider)
        if provider == "gemini":
            return _call_gemini(telemetry, agent_config)
        elif provider == "openai":
            return _call_openai(telemetry, agent_config)
        elif provider == "ollama":
            return _call_ollama(telemetry, agent_config)
        else:
            logger.warning("Unknown provider '%s'; falling back to template.", provider)
            return generate_report_from_template(telemetry)
    except Exception as exc:
        logger.warning("LLM provider '%s' failed: %s", provider, exc)
        if agent_config.get("fallback_to_template", True):
            logger.info("Falling back to template report.")
            return generate_report_from_template(telemetry)
        raise
