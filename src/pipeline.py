"""Orchestrates: fetch from Gmail/Yahoo -> extract IOCs -> enrich -> Claude triage -> log."""
import dataclasses
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src import attachments, database, gmail_client, ioc_extractor
from src.mail_actions import MailActor
from src.claude_analyzer import ClaudeAnalyzer
from src.config import Config
from src.email_message import EmailMessage
from src.enrichment import enrich
from src.enrichment.abuseipdb import AbuseIPDBClient
from src.enrichment.urlscan import UrlscanClient
from src.enrichment.virustotal import VirusTotalClient
from src.yahoo_client import YahooListener

logger = logging.getLogger(__name__)

LOGS_DIR = "logs"


@dataclass
class RunResult:
    written_paths: list = field(default_factory=list)
    failures: list = field(default_factory=list)  # [{"message_id", "source", "error"}, ...]
    total: int = 0


def _write_result(email: EmailMessage, result: dict) -> str:
    os.makedirs(LOGS_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(LOGS_DIR, f"{timestamp}_{email.source}_{email.id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    return path


def _process_email(email: EmailMessage, vt: VirusTotalClient, abuseipdb: AbuseIPDBClient,
                    analyzer: ClaudeAnalyzer, db_conn, notifier, urlscan: UrlscanClient = None,
                    mail_actor: MailActor = None) -> str:
    """Run one email through IOC extraction -> enrichment -> Claude -> persistence
    -> Slack -> mail actions. Shared by every mail source so Gmail and Yahoo get
    identical treatment."""
    iocs = ioc_extractor.extract(email.body_text, email.sender)

    # Attachments: hash + static analysis of the downloaded bytes (in memory only).
    # URLs found inside the files join the email's own, so the VirusTotal/urlscan.io
    # checks below cover them too. Only the report is kept; the file bytes are dropped.
    attachment_report = None
    if email.attachments:
        attachment_report = attachments.analyze_attachments(email.attachments, email.body_text)
        email.attachments = []
        added = attachments.merge_into_iocs(iocs, attachment_report)
        logger.info("[%s] %s: analysed %d attachment(s), static risk %s, %d URL(s) found inside",
                    email.source, email.id, attachment_report["count"], attachment_report["static_risk"], added)

    if iocs.is_empty():
        logger.info("No IOCs found in [%s] %s; skipping enrichment.", email.source, email.id)
        enrichment_results = {}
    else:
        enrichment_results = enrich(iocs, vt, abuseipdb, urlscan)

    if attachment_report is not None:
        attachments.lookup_hashes(attachment_report, vt)
        enrichment_results["attachments"] = attachment_report

    # Sender authentication doesn't depend on IOCs being present, so it's
    # always recorded, not gated behind iocs.is_empty().
    enrichment_results["sender_authentication"] = email.auth_results

    analysis = analyzer.analyze(email, iocs, enrichment_results)

    finding = {
        "source": email.source,
        "mailbox": email.mailbox,
        "email_id": email.id,
        "thread_id": email.thread_id,
        "subject": email.subject,
        "sender": email.sender,
        "date": email.date,
        "attachment_names": email.attachment_names,
        "extracted_iocs": dataclasses.asdict(iocs),
        "enrichment": enrichment_results,
        "claude_analysis": analysis,
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "message_id": email.message_id,
        "mail_folder": email.folder,
        "uidvalidity": email.uidvalidity,
    }

    path = _write_result(email, finding)
    finding_id = database.insert_finding(db_conn, finding)
    logger.info(
        "[%s] Wrote result to %s (verdict=%s)", email.source, path, analysis.get("verdict")
    )

    if notifier:
        notifier.notify(email, analysis)

    # High-confidence spam -> spam folder; phishing/malicious -> Trash + block sender.
    # A failed action is logged on the dashboard; it never fails the email.
    if mail_actor is not None:
        mail_actor.auto_act(database.get_finding(db_conn, finding_id))

    return path


def _handle_blocked_sender(email: EmailMessage, db_conn, mail_actor: MailActor) -> str:
    """Mail from a sender you blocked: trash it without spending Claude/VirusTotal calls,
    and record it so it still shows on the dashboard (with Undo)."""
    finding = {
        "source": email.source,
        "mailbox": email.mailbox,
        "email_id": email.id,
        "thread_id": email.thread_id,
        "subject": email.subject,
        "sender": email.sender,
        "date": email.date,
        "attachment_names": email.attachment_names,
        "extracted_iocs": {},
        "enrichment": {"sender_authentication": email.auth_results},
        "claude_analysis": {
            "verdict": "malicious",
            "category": "blocked_sender",
            "confidence": "high",
            "summary": "This sender is on your block list, so the email was moved to Trash without being analysed.",
            "key_indicators": ["Sender previously blocked"],
            "recommended_action": "None needed. If this was a mistake, Undo it here and unblock the sender on the Blocked page.",
        },
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "message_id": email.message_id,
        "mail_folder": email.folder,
        "uidvalidity": email.uidvalidity,
    }
    path = _write_result(email, finding)
    finding_id = database.insert_finding(db_conn, finding)
    mail_actor.move_to_trash(database.get_finding(db_conn, finding_id), trigger="blocklist")
    logger.info("[%s] %s is from blocked sender %r; moved to Trash without analysis.",
                email.source, email.id, email.sender)
    return path

def _run_gmail(config: Config, vt, abuseipdb, analyzer, db_conn, notifier, urlscan,
                max_results: int, mark_read: bool, result: RunResult, attachment_bytes: int = 0,
                mail_actor: MailActor = None) -> None:
    service = gmail_client.authenticate(config.gmail_credentials_path, config.gmail_token_path)
    if mail_actor is not None:
        mail_actor.set_gmail(service)
    mailbox = gmail_client.get_profile_email(service)
    message_ids = gmail_client.list_message_ids(service, config.gmail_query, max_results)
    total = len(message_ids)
    result.total += total
    logger.info("Gmail: found %d message(s) matching query %r", total, config.gmail_query)

    for i, message_id in enumerate(message_ids, start=1):
        try:
            email = gmail_client.get_message(service, message_id, mailbox=mailbox,
                                             max_attachment_bytes=attachment_bytes)
            logger.info("[gmail %d/%d] Processing %s: %r from %r", i, total, email.id, email.subject, email.sender)

            if mail_actor is not None and mail_actor.is_blocked(email.sender):
                path = _handle_blocked_sender(email, db_conn, mail_actor)
            else:
                path = _process_email(email, vt, abuseipdb, analyzer, db_conn, notifier, urlscan, mail_actor)
            result.written_paths.append(path)

            if mark_read:
                gmail_client.mark_processed(service, email.id)

        except Exception as exc:
            logger.exception("[gmail %d/%d] Failed to process message %s: %s", i, total, message_id, exc)
            result.failures.append({"source": "gmail", "message_id": message_id, "error": str(exc)})
            continue


def _run_yahoo(config: Config, vt, abuseipdb, analyzer, db_conn, notifier, urlscan,
                max_results: int, mark_read: bool, result: RunResult, attachment_bytes: int = 0,
                mail_actor: MailActor = None) -> None:
    listener = YahooListener(
        config.yahoo_email, config.yahoo_app_password,
        folder=config.yahoo_folder, search_criteria=config.yahoo_search_criteria,
    )
    if mail_actor is not None:
        mail_actor.set_yahoo(listener)
    try:
        message_ids = listener.list_message_ids(max_results)
        total = len(message_ids)
        result.total += total
        logger.info("Yahoo: found %d message(s) in %r matching %r",
                    total, config.yahoo_folder, config.yahoo_search_criteria)

        for i, message_id in enumerate(message_ids, start=1):
            try:
                email = listener.get_message(message_id, max_attachment_bytes=attachment_bytes)
                logger.info("[yahoo %d/%d] Processing %s: %r from %r", i, total, email.id, email.subject, email.sender)

                if mail_actor is not None and mail_actor.is_blocked(email.sender):
                    path = _handle_blocked_sender(email, db_conn, mail_actor)
                else:
                    path = _process_email(email, vt, abuseipdb, analyzer, db_conn, notifier, urlscan, mail_actor)
                result.written_paths.append(path)

                if mark_read:
                    listener.mark_processed(message_id)

            except Exception as exc:
                logger.exception("[yahoo %d/%d] Failed to process message %s: %s", i, total, message_id, exc)
                result.failures.append({"source": "yahoo", "message_id": message_id, "error": str(exc)})
                continue
    finally:
        listener.close()


def run(config: Config, max_results: int = 25, mark_read: bool = True, notifier=None,
        use_yahoo: bool = None, use_gmail: bool = True, use_attachments: bool = None,
        auto_actions: bool = None) -> RunResult:
    """Fetch matching emails from Gmail (if enabled) and Yahoo (if configured/enabled)
    and triage them one at a time through the same pipeline.

    Pass max_results=None for batch mode: this pages through ALL matching
    messages per source instead of a single capped page. Each email is
    processed independently -- one failing (a bad enrichment call, a
    malformed message, etc.) is logged and skipped rather than aborting the
    rest of the run, since a failed email is simply left unread and picked
    up again on the next run.

    Pass a SlackNotifier as `notifier` to post each verdict to Slack; leave it
    None to skip Slack entirely.

    use_yahoo controls whether Yahoo is processed at all: None (default) means
    "enabled iff YAHOO_EMAIL/YAHOO_APP_PASSWORD are set" (config.yahoo_configured);
    True/False force it on/off regardless.

    use_gmail controls whether Gmail is processed at all (default True).

    use_attachments controls attachment analysis (download into memory, hash,
    static checks): None (default) follows ATTACHMENT_ANALYSIS in .env (on unless
    set to 0); True/False force it on/off for this run.

    auto_actions controls acting on high-confidence verdicts (spam folder, or
    Trash + block sender): None (default) follows AUTO_MAIL_ACTIONS in .env (on
    unless set to 0). Mail from already-blocked senders is trashed either way.
    """
    vt = VirusTotalClient(config.virustotal_api_key)
    abuseipdb = AbuseIPDBClient(config.abuseipdb_api_key)
    analyzer = ClaudeAnalyzer(config.anthropic_api_key, config.claude_model)
    urlscan = UrlscanClient(config.urlscan_api_key) if config.urlscan_configured else None
    db_conn = database.connect(config.findings_db_path)
    database.purge_expired(db_conn)  # opportunistic cleanup of anything trashed 7+ days ago
    mail_actor = MailActor(
        db_conn,
        never_block=config.never_block + ((config.yahoo_email.lower(),) if config.yahoo_email else ()),
        auto_enabled=config.auto_mail_actions if auto_actions is None else auto_actions,
    )
    logger.info("Automatic mail actions %s (high-confidence verdicts only).",
                "on" if mail_actor.auto_enabled else "off")

    if use_attachments is None:
        attachment_bytes = config.max_attachment_bytes
    else:
        attachment_bytes = config.attachment_max_mb * 1024 * 1024 if use_attachments else 0
    if attachment_bytes:
        logger.info("Attachment analysis on (per-file limit %d MB; hash + static checks, nothing executed or uploaded).",
                    attachment_bytes // (1024 * 1024))

    result = RunResult()
    try:
        if use_gmail:
            try:
                _run_gmail(config, vt, abuseipdb, analyzer, db_conn, notifier, urlscan, max_results, mark_read,
                           result, attachment_bytes, mail_actor=mail_actor)
            except Exception as exc:  # sign-in / connection problems: report it and still try Yahoo
                logger.exception("Gmail could not be checked: %s", exc)
                result.failures.append({"source": "gmail", "message_id": "(mailbox)", "error": str(exc)})
        else:
            logger.info("Gmail disabled for this run; skipping.")

        if use_yahoo is None:
            yahoo_enabled = config.yahoo_configured
        elif use_yahoo:
            if not config.yahoo_configured:
                raise RuntimeError(
                    "Yahoo was requested via --yahoo but YAHOO_EMAIL/YAHOO_APP_PASSWORD "
                    "are not fully set"
                )
            yahoo_enabled = True
        else:
            yahoo_enabled = False

        if yahoo_enabled:
            try:
                _run_yahoo(config, vt, abuseipdb, analyzer, db_conn, notifier, urlscan, max_results, mark_read,
                           result, attachment_bytes, mail_actor=mail_actor)
            except Exception as exc:  # login / connection problems: report it instead of crashing the run
                logger.exception("Yahoo could not be checked: %s", exc)
                result.failures.append({"source": "yahoo", "message_id": "(mailbox)", "error": str(exc)})
        else:
            logger.info("Yahoo not configured or disabled; skipping.")

        return result
    finally:
        db_conn.close()
