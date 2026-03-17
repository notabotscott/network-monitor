"""Cloud Function: forward network-monitor change events to Slack."""
from __future__ import annotations

import base64
import json
import logging
import os
import urllib.request

import functions_framework
from google.cloud import secretmanager

logger = logging.getLogger(__name__)


def _get_webhook_url() -> str:
    client = secretmanager.SecretManagerServiceClient()
    name = "projects/internal-automation-385014/secrets/network-monitor-slack-webhook/versions/latest"
    return client.access_secret_version(name=name).payload.data.decode()


def _severity_emoji(severity: str) -> str:
    return {"critical": ":red_circle:", "warning": ":yellow_circle:"}.get(
        severity.lower(), ":blue_circle:"
    )


def _format_message(payload: dict) -> dict:
    change_type = payload.get("change_type", "UNKNOWN")
    host_ip = payload.get("host_ip", "?")
    client_id = payload.get("client_id", "?")
    severity = payload.get("severity", "info")
    port = payload.get("port")
    previous = payload.get("previous")
    current = payload.get("current")
    target = payload.get("target", "?")

    emoji = _severity_emoji(severity)
    header = f"{emoji} *{change_type}*"

    lines = [
        f"*Client:* {client_id}",
        f"*Target:* {target} ({host_ip})",
    ]
    if port:
        lines.append(f"*Port:* {port}")
    if previous is not None:
        lines.append(f"*Was:* `{previous}`")
    if current is not None:
        lines.append(f"*Now:* `{current}`")

    return {
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": header}},
            {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
        ]
    }


@functions_framework.cloud_event
def notify_slack(cloud_event):
    raw_data = cloud_event.data["message"].get("data", "")
    logger.info("Received message, data length: %d", len(raw_data))

    if not raw_data:
        logger.warning("Empty message data — skipping")
        return

    decoded = base64.b64decode(raw_data).decode()
    logger.info("Decoded: %s", decoded[:200])

    log_entry = json.loads(decoded)

    # Real log sink messages have jsonPayload; direct publishes may not
    payload = log_entry.get("jsonPayload") or log_entry

    change_type = payload.get("change_type")
    if not change_type:
        logger.info("No change_type in payload — skipping")
        return

    logger.info("Processing change_type=%s", change_type)

    message = _format_message(payload)
    webhook_url = _get_webhook_url()

    body = json.dumps(message).encode()
    req = urllib.request.Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        status = resp.status
        logger.info("Slack webhook response: %d", status)
        if status != 200:
            raise RuntimeError(f"Slack webhook returned {status}")
