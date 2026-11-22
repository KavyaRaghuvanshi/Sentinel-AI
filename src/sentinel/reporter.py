"""
Sentinel AI - Report Delivery

Delivers the generated admin briefing through multiple channels:
  - Console (stdout)
  - Saved text/JSON file in the reports directory
  - Windows toast notification
  - Webhook (Discord / Slack / Teams)
  - Email (SMTP)
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import requests

logger = logging.getLogger("sentinel.reporter")


def save_report_to_file(report: str, report_dir: str = "./reports", hostname: str = "unknown") -> str:
    """
    Save the report to a timestamped text file.

    Returns the absolute path of the saved file.
    """
    dir_path = Path(report_dir)
    dir_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"sentinel_report_{hostname}_{timestamp}.txt"
    filepath = dir_path / filename

    filepath.write_text(report, encoding="utf-8")
    logger.info("Report saved to %s", filepath.resolve())
    return str(filepath.resolve())


def send_toast_notification(title: str, message: str) -> bool:
    """
    Show a Windows toast notification.

    Requires the ``winotify`` package (pip install winotify).
    Returns True if successful, False otherwise.
    """
    try:
        from winotify import Notification

        toast = Notification(
            app_id="Sentinel AI",
            title=title,
            msg=message[:256],  # Toast messages have a character limit
            duration="long",
        )
        toast.show()
        logger.info("Toast notification sent.")
        return True
    except ImportError:
        logger.warning("winotify not installed; skipping toast notification.")
        return False
    except Exception as exc:
        logger.warning("Toast notification failed: %s", exc)
        return False


def send_webhook(report: str, url: str, hostname: str = "unknown") -> bool:
    """
    POST the report to a webhook URL (Discord, Slack, or Teams).

    Returns True if the request succeeds (2xx status).
    """
    if not url:
        return False

    try:
        import requests

        # Detect platform and format accordingly
        if "discord" in url.lower():
            payload = {"content": f"**Sentinel AI — {hostname}**\n```\n{report[:1900]}\n```"}
        elif "slack" in url.lower() or "hooks.slack.com" in url.lower():
            payload = {"text": f"*Sentinel AI — {hostname}*\n```\n{report[:3000]}\n```"}
        else:
            # Generic / MS Teams format
            payload = {"text": f"Sentinel AI — {hostname}\n\n{report[:5000]}"}

        resp = requests.post(url, json=payload, timeout=15)
        resp.raise_for_status()
        logger.info("Webhook delivered to %s", url[:50])
        return True
    except Exception as exc:
        logger.warning("Webhook delivery failed: %s", exc)
        return False


def send_email(
    report: str,
    smtp_server: str,
    smtp_port: int,
    sender: str,
    recipient: str,
    password_env: str = "SENTINEL_EMAIL_PASSWORD",
    use_tls: bool = True,
    hostname: str = "unknown",
) -> bool:
    """
    Send the report via email (SMTP).

    The SMTP password is read from the environment variable named
    by *password_env*.  Returns True if successful.
    """
    password = os.environ.get(password_env, "")
    if not all([smtp_server, sender, recipient, password]):
        logger.warning("Email configuration incomplete; skipping.")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"Sentinel AI Report — {hostname} — {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        msg["From"] = sender
        msg["To"] = recipient
        msg.attach(MIMEText(report, "plain", "utf-8"))

        with smtplib.SMTP(smtp_server, smtp_port, timeout=15) as server:
            if use_tls:
                server.starttls()
            server.login(sender, password)
            server.sendmail(sender, [recipient], msg.as_string())

        logger.info("Email sent to %s", recipient)
        return True
    except Exception as exc:
        logger.warning("Email delivery failed: %s", exc)
        return False


def deliver_report(report: str, reporter_config: dict, hostname: str = "unknown") -> dict:
    """
    Deliver the report through all enabled channels.

    Parameters
    ----------
    report : str
        The formatted admin briefing text.
    reporter_config : dict
        The ``reporter`` section of the Sentinel configuration.
    hostname : str
        Machine hostname (used in subject lines and file names).

    Returns
    -------
    dict
        Results for each delivery channel: {channel: bool}.
    """
    results: dict[str, bool | str] = {}

    # 1. Console
    if reporter_config.get("console", True):
        print("\n" + "=" * 60)
        print(report)
        print("=" * 60 + "\n")
        results["console"] = True

    # 2. File
    if reporter_config.get("save_to_file", True):
        try:
            filepath = save_report_to_file(
                report,
                report_dir=reporter_config.get("report_dir", "./reports"),
                hostname=hostname,
            )
            results["file"] = filepath
        except Exception as exc:
            logger.warning("File save failed: %s", exc)
            results["file"] = False

    # 3. Toast notification
    if reporter_config.get("toast_notification", False):
        # Extract first line or overall status for the toast
        first_line = report.split("\n")[0][:100] if report else "Report generated."
        results["toast"] = send_toast_notification("Sentinel AI", first_line)

    # 4. Webhook
    webhook_config = reporter_config.get("webhook", {})
    if webhook_config.get("enabled", False):
        results["webhook"] = send_webhook(
            report, webhook_config.get("url", ""), hostname=hostname
        )

    # 5. Email
    email_config = reporter_config.get("email", {})
    if email_config.get("enabled", False):
        results["email"] = send_email(
            report,
            smtp_server=email_config.get("smtp_server", ""),
            smtp_port=email_config.get("smtp_port", 587),
            sender=email_config.get("sender", ""),
            recipient=email_config.get("recipient", ""),
            password_env=email_config.get("password_env", "SENTINEL_EMAIL_PASSWORD"),
            use_tls=email_config.get("use_tls", True),
            hostname=hostname,
        )

    return results
