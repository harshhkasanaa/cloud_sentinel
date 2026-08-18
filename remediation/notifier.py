# remediation/notifier.py

import json
import logging
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CloudSentinelNotifier")


class IncidentNotifier:
    """Dispatches real-time security incident alerts to Webhook endpoints (Slack/Discord/Teams)."""

    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url

    def send_alert(self, title, severity, details):
        """Constructs a structured security alert card and dispatches payload."""
        
        # Color coding by severity
        color_map = {
            "CRITICAL": "#FF0000",
            "HIGH": "#FFA500",
            "MEDIUM": "#FFFF00",
            "INFO": "#00FF00"
        }
        
        payload = {
            "text": f"🚨 *[CLOUD SENTINEL AUTO-REMEDIATION]* {title}",
            "attachments": [
                {
                    "color": color_map.get(severity, "#FF0000"),
                    "fields": [
                        {"title": "Severity", "value": severity, "short": True},
                        {"title": "Action Taken", "value": details.get("action", "AUTO_REMEDIATED"), "short": True},
                        {"title": "Target Resource", "value": details.get("resource_id", "N/A"), "short": False},
                        {"title": "Violating Identity", "value": details.get("user_arn", "Unknown"), "short": False},
                        {"title": "Rule ID", "value": details.get("rule_id", "CS-RT-001"), "short": True},
                        {"title": "Timestamp", "value": details.get("timestamp", "N/A"), "short": True}
                    ],
                    "footer": "Cloud Sentinel Zero-Trust Guardrail Engine"
                }
            ]
        }

        # If a valid Webhook URL is provided, send HTTP POST request
        if self.webhook_url:
            try:
                response = requests.post(
                    self.webhook_url,
                    data=json.dumps(payload),
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                logger.info(f"[+] Webhook alert sent successfully. Status code: {response.status_code}")
                return response.status_code
            except Exception as e:
                logger.error(f"[-] Failed to dispatch Webhook alert: {e}")
                return None
        else:
            # Fallback for local console output if no live Webhook URL is set
            logger.info("\n📢 [LOCAL ALERT NOTIFICATION DISPLAY]")
            logger.info(json.dumps(payload, indent=2))
            return 200