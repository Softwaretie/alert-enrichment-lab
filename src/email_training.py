"""Train the mail provider's spam filter from Claude's verdict, without moving mail.

malicious -> mark as spam; likely_benign -> mark as not spam; suspicious/unknown
-> leave alone for the user to review. Emails stay where they are so every
analyzed message remains visible for comparing Claude's verdict to your own.
"""
import logging

from src import gmail_client

logger = logging.getLogger(__name__)

_SPAM_VERDICTS = {"malicious"}
_NOT_SPAM_VERDICTS = {"likely_benign"}


def apply_email_training(email, verdict: str, gmail_service=None, yahoo_listener=None) -> dict:
    result = {"email_id": email.id, "source": email.source, "verdict": verdict,
              "action": None, "success": False}

    if verdict in _SPAM_VERDICTS:
        action = "marked_as_spam"
    elif verdict in _NOT_SPAM_VERDICTS:
        action = "marked_as_not_spam"
    else:
        result.update(action="skipped", success=True)
        logger.info("[training] Skipping %s (verdict=%s; left for user review)", email.id, verdict)
        return result

    try:
        if email.source == "gmail" and gmail_service is not None:
            if action == "marked_as_spam":
                gmail_client.mark_as_spam(gmail_service, email.id)
            else:
                gmail_client.mark_as_not_spam(gmail_service, email.id)
        elif email.source == "yahoo" and yahoo_listener is not None:
            if action == "marked_as_spam":
                yahoo_listener.mark_as_spam(email.id)
            else:
                yahoo_listener.mark_as_not_spam(email.id)
        else:
            result["error"] = f"no {email.source} client available"
            return result

        result.update(action=action, success=True)
        logger.info("[training] %s %s in %s", email.id, action, email.source)
    except Exception as exc:
        logger.warning("[training] Failed for %s: %s", email.id, exc)
        result["error"] = str(exc)

    return result
