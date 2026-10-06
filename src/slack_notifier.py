"""Slack notifications for Claude's triage verdicts."""
import logging

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

logger = logging.getLogger(__name__)

_VERDICT_EMOJI = {
    "malicious": "🚨",
    "suspicious": "⚠️",
    "likely_benign": "✅",
    "unknown": "❓",
}

_VERDICT_LABEL = {
    "malicious": "Phishing",
    "suspicious": "Suspicious",
    "likely_benign": "Legitimate",
    "unknown": "Unknown",
}


class SlackNotifier:
    def __init__(self, bot_token: str, channel_id: str):
        self._client = WebClient(token=bot_token)
        self._channel_id = channel_id

    def notify(self, email, analysis: dict) -> None:
        """Post one triage result to Slack. Never raises -- a Slack outage
        shouldn't take down the enrichment pipeline, so failures are logged
        and swallowed."""
        verdict = analysis.get("verdict", "unknown")
        emoji = _VERDICT_EMOJI.get(verdict, "❓")
        label = _VERDICT_LABEL.get(verdict, verdict.replace("_", " ").title())
        confidence = analysis.get("confidence", "unknown")

        text = (
            f"{emoji} *{label}* (confidence: {confidence})\n"
            f"*From:* {email.sender}\n"
            f"*Subject:* {email.subject}\n"
            f"*Summary:* {analysis.get('summary', 'No summary provided.')}\n"
            f"*Recommended action:* {analysis.get('recommended_action', '-')}"
        )

        try:
            self._client.chat_postMessage(channel=self._channel_id, text=text)
        except SlackApiError as exc:
            error = exc.response.get("error") if exc.response else str(exc)
            logger.warning("Slack notification failed: %s", error)
        except Exception:
            logger.exception("Slack notification failed unexpectedly")
