# Sentinel AI

**Autonomous Endpoint Health & Cyber-Defense Agent for Windows**

[![CI](https://github.com/YOUR_USERNAME/sentinel-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/sentinel-ai/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Sentinel AI is an agentic AI system that automatically monitors, cleans, secures, and reports on Windows endpoint health. It runs at boot (or on a schedule) and delivers a concise 3-bullet executive briefing to the user or admin.

## What It Does

| Step | Action | Method |
| :--: | :----- | :----- |
| 1 | **Collect System Telemetry** | Disk, CPU, memory, boot time, top processes |
| 2 | **Safe Temp File Cleanup** | Deletes only old, unlocked, non-protected temp files |
| 3 | **Security Audit** | Scans processes, network connections, Windows Defender, event logs |
| 4 | **AI Analysis** | LLM summarizes findings into a concise briefing (or uses a template) |
| 5 | **Report Delivery** | Console, file, Windows toast, webhook (Slack/Discord/Teams), or email |

## Architecture

```
[System Boot / Scheduled Trigger]
         │
         ▼
┌──────────────────────────────────┐
│  Sensor & Cleaner (Deterministic)│  ← No AI, fast, zero-latency
│  • Disk, CPU, memory metrics     │
│  • Safe temp file cleanup        │
│  • Process & network audit       │
└──────────────┬───────────────────┘
               │ Structured telemetry
               ▼
┌──────────────────────────────────┐
│  Agent Reasoning Layer           │  ← LLM or template fallback
│  • Sanitizes inputs (guardrails) │
│  • Generates 3-bullet briefing   │
└──────────────┬───────────────────┘
               │ Report
               ▼
┌──────────────────────────────────┐
│  Reporter (Multi-channel)        │
│  • Console / File / Toast        │
│  • Webhook / Email               │
└──────────────────────────────────┘
```

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/YOUR_USERNAME/sentinel-ai.git
cd sentinel-ai
pip install -e ".[dev]"
```

### 2. Run

```bash
# Basic run (template report, no API key needed)
python -m sentinel

# Dry run (scan only, no deletions)
python -m sentinel --dry-run

# With verbose logging
python -m sentinel --verbose

# Skip cleanup or security
python -m sentinel --skip-cleanup
python -m sentinel --skip-security
```

### 3. Run Tests

```bash
pytest
```

## Configuration

All settings live in [`config.yaml`](config.yaml). Create a `config.local.yaml` for personal overrides (it's git-ignored).

### Key Settings

| Setting | Description | Default |
| :------ | :---------- | :------ |
| `cleanup.min_age_hours` | Minimum file age before deletion | `24` |
| `cleanup.max_delete_mb` | Safety cap (MB) per run | `5000` |
| `security.trusted_processes` | Processes to never flag | `[python.exe, chrome.exe, ...]` |
| `agent.provider` | LLM provider: `gemini`, `openai`, `ollama`, or `none` | `none` |
| `reporter.toast_notification` | Show Windows toast popup | `false` |
| `reporter.webhook.url` | Discord/Slack/Teams webhook URL | `""` |

### LLM Providers

Sentinel works **without any API key** using the built-in template engine. To enable AI-powered analysis:

**Google Gemini:**
```bash
set GEMINI_API_KEY=your-key-here
# In config.yaml: agent.provider: "gemini"
```

**OpenAI:**
```bash
set OPENAI_API_KEY=your-key-here
# In config.yaml: agent.provider: "openai", agent.model: "gpt-4o-mini"
```

**Ollama (Local, Offline):**
```bash
ollama pull llama3.2:3b
# In config.yaml: agent.provider: "ollama", agent.model: "llama3.2:3b"
```

## Auto-Start at Boot

Run the included PowerShell script as Administrator:

```powershell
powershell -ExecutionPolicy Bypass -File setup_task_scheduler.ps1
```

To remove:
```powershell
powershell -ExecutionPolicy Bypass -File setup_task_scheduler.ps1 -Remove
```

## Example Report

```
=== Sentinel AI — Endpoint Health Briefing ===
Host: WORKSTATION-04  |  Time: 2026-11-22T10:42:17

1. **Storage & Maintenance** [Healthy]
   Disk C:\: 350.0/500.0 GB used (70.0%). Free: 150.0 GB.
   Cleanup: Purged 42.5 MB (15 files removed, 2 skipped/locked).

2. **System Performance** [Healthy]
   CPU: 15.3% (16 cores). Memory: 46.9% used (8.5 GB free). Uptime: 5m 0s.

3. **Security Assessment** [Healthy]
   Processes scanned: 180. Anomalies: 0.
   Active outbound connections: 12.
   Windows Defender real-time protection: ✅ ON.

Overall: ✅ HEALTHY — All systems nominal.
```

## Project Structure

```
sentinel-ai/
├── config.yaml                 # Default configuration
├── pyproject.toml              # Project metadata & dependencies
├── setup_task_scheduler.ps1    # Windows Task Scheduler setup
├── src/sentinel/
│   ├── __init__.py             # Package metadata
│   ├── __main__.py             # CLI entry point & pipeline orchestrator
│   ├── agent.py                # LLM integration (Gemini/OpenAI/Ollama/template)
│   ├── cleaner.py              # Safe temp file cleanup engine
│   ├── config.py               # YAML config loader with layered overrides
│   ├── guardrails.py           # Prompt-injection defense & sanitization
│   ├── reporter.py             # Multi-channel report delivery
│   ├── security.py             # Process, network & event log auditor
│   ├── sensor.py               # System telemetry collector
│   └── utils.py                # Shared utilities
├── tests/
│   ├── conftest.py             # Shared test fixtures
│   ├── test_agent.py
│   ├── test_cleaner.py
│   ├── test_config.py
│   ├── test_guardrails.py
│   ├── test_integration.py
│   ├── test_reporter.py
│   ├── test_security.py
│   └── test_utils.py
├── .github/workflows/ci.yml   # GitHub Actions CI pipeline
├── reports/                    # Generated reports (git-ignored)
└── LICENSE
```

## Security Design

Sentinel is built with defense-in-depth:

- **No raw shell access for the LLM** — The agent can only call typed Python functions, never arbitrary commands.
- **Prompt injection guardrails** — All system text (process names, file paths, event logs) is sanitized before reaching the LLM.
- **Protected paths & extensions** — System directories and critical file types are never touched.
- **Safety caps** — Maximum deletion limits prevent runaway cleanup.
- **Locked file protection** — Files currently in use by running processes are automatically skipped.
- **Graceful fallback** — If the LLM is unavailable, a deterministic template produces the report.

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Install dev dependencies: `pip install -e ".[dev]"`
4. Write tests and ensure they pass: `pytest`
5. Submit a pull request

## License

[MIT](LICENSE) — free for personal and commercial use.
