"""Yahoo Mail access via IMAP with an app-specific password.

Yahoo has no self-serve OAuth path to Mail data for third-party apps (their
current developer platform only lists Fantasy Sports and Sign In With Yahoo
-- confirmed live, see docs/README.md), so this authenticates the plain IMAP
way instead: an app-specific password generated under Yahoo Account
Security, used as the IMAP login password. Store it via
`python scripts/setup_secrets.py` (YAHOO_APP_PASSWORD) rather than in
plaintext .env.
"""
import imaplib
import logging
from email import message_from_bytes, policy

from src.attachments.models import MAX_FILES_PER_EMAIL, MAX_TOTAL_BYTES_PER_EMAIL, RawAttachment
from src.auth_headers import parse_authentication_results
from src.email_message import EmailMessage
from src.html_text import html_to_text

logger = logging.getLogger(__name__)

IMAP_HOST = "imap.mail.yahoo.com"


class YahooListener:
    """Fetches unread Yahoo Mail messages via IMAP + an app-specific password.

    Mirrors gmail_client's interface (list_message_ids / get_message /
    mark_processed) but as a class, since an IMAP connection is per-instance
    state rather than a service object passed around.
    """

    def __init__(self, email_address: str, app_password: str,
                 folder: str = "INBOX", search_criteria: str = "UNSEEN"):
        self._email_address = email_address
        self._app_password = app_password
        self._folder = folder
        self._search_criteria = search_criteria
        self._conn = None

    def connect(self) -> None:
        conn = imaplib.IMAP4_SSL(IMAP_HOST)
        conn.login(self._email_address, self._app_password)
        self._conn = conn

    def close(self) -> None:
        if self._conn is None:
            return
        try:
            self._conn.close()
        except imaplib.IMAP4.error:
            pass
        self._conn.logout()
        self._conn = None

    def list_message_ids(self, max_results: int = 25) -> list:
        if self._conn is None:
            self.connect()

        typ, _ = self._conn.select(self._folder)
        if typ != "OK":
            raise RuntimeError(f"Could not select Yahoo folder {self._folder!r}. Does it exist?")

        typ, data = self._conn.search(None, self._search_criteria)
        if typ != "OK":
            raise RuntimeError(f"Yahoo IMAP search failed for criteria {self._search_criteria!r}")

        ids = data[0].split()
        if max_results is not None:
            ids = ids[-max_results:]
        return [i.decode() for i in ids]

    def get_message(self, message_id: str, max_attachment_bytes: int = 0) -> EmailMessage:
        # BODY.PEEK avoids implicitly marking the message \Seen just by reading it;
        # mark_processed() flips \Seen explicitly once enrichment succeeds.
        typ, data = self._conn.fetch(message_id, "(BODY.PEEK[])")
        if typ != "OK" or not data or data[0] is None:
            raise RuntimeError(f"Could not fetch Yahoo message {message_id}")

        raw = data[0][1]
        msg = message_from_bytes(raw, policy=policy.default)

        return EmailMessage(
            id=message_id,
            thread_id="",
            subject=str(msg.get("subject", "")),
            sender=str(msg.get("from", "")),
            date=str(msg.get("date", "")),
            body_text=self._body_text(msg),
            attachment_names=self._attachment_names(msg),
            source="yahoo",
            mailbox=self._email_address,
            auth_results=parse_authentication_results(str(msg.get("Authentication-Results", ""))),
            attachments=self._raw_attachments(msg, max_attachment_bytes),
        )

    def mark_processed(self, message_id: str) -> None:
        self._conn.store(message_id, "+FLAGS", "\\Seen")

    # $Junk / $NotJunk keywords are set in place (verified in the folder's
    # PERMANENTFLAGS); the message is not moved to Bulk.
    def mark_as_spam(self, message_id: str) -> None:
        self._conn.store(message_id, "+FLAGS", "$Junk")
        self._conn.store(message_id, "-FLAGS", "$NotJunk")

    def mark_as_not_spam(self, message_id: str) -> None:
        self._conn.store(message_id, "+FLAGS", "$NotJunk")
        self._conn.store(message_id, "-FLAGS", "$Junk")

    @staticmethod
    def _body_text(msg) -> str:
        plain_part = msg.get_body(preferencelist=("plain",))
        if plain_part is not None:
            return plain_part.get_content()

        html_part = msg.get_body(preferencelist=("html",))
        if html_part is not None:
            return html_to_text(html_part.get_content())

        return ""

    @staticmethod
    def _raw_attachments(msg, max_bytes: int) -> list:
        """Attachment bytes held in memory for static analysis (never written to
        disk or opened). Oversized/extra/unreadable ones come back with
        `skipped_reason` set. max_bytes=0 skips downloading entirely."""
        if max_bytes <= 0:
            return []
        limit_mb = max_bytes // (1024 * 1024)
        attachments, total = [], 0
        for index, part in enumerate(msg.iter_attachments()):
            ctype = part.get_content_type()
            name = part.get_filename() or ("attached_message.eml" if ctype == "message/rfc822" else "unnamed_attachment")
            if index >= MAX_FILES_PER_EMAIL:
                attachments.append(RawAttachment(name, ctype, b"", 0, f"more than {MAX_FILES_PER_EMAIL} attachments"))
                continue
            try:
                if ctype == "message/rfc822":
                    data = part.get_payload()[0].as_bytes()
                else:
                    raw_payload = part.get_payload()
                    estimate = len(raw_payload) * 3 // 4 if isinstance(raw_payload, str) else 0
                    if estimate > max_bytes:
                        attachments.append(RawAttachment(name, ctype, b"", estimate, f"larger than the {limit_mb} MB limit"))
                        continue
                    data = part.get_payload(decode=True) or b""
            except Exception as exc:  # noqa: BLE001 - one bad part must not sink the email
                attachments.append(RawAttachment(name, ctype, b"", 0, f"could not be read ({type(exc).__name__})"))
                continue
            if len(data) > max_bytes:
                attachments.append(RawAttachment(name, ctype, b"", len(data), f"larger than the {limit_mb} MB limit"))
            elif total + len(data) > MAX_TOTAL_BYTES_PER_EMAIL:
                attachments.append(RawAttachment(name, ctype, b"", len(data), "total attachment size limit reached"))
            else:
                total += len(data)
                attachments.append(RawAttachment(name, ctype, data, len(data)))
        return attachments

    @staticmethod
    def _attachment_names(msg) -> list:
        return [part.get_filename() for part in msg.iter_attachments() if part.get_filename()]
