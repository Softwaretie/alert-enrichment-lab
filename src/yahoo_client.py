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
import re
from email import message_from_bytes, policy

from src.attachments.models import MAX_FILES_PER_EMAIL, MAX_TOTAL_BYTES_PER_EMAIL, RawAttachment
from src.auth_headers import parse_authentication_results
from src.email_message import EmailMessage
from src.html_text import html_to_text

logger = logging.getLogger(__name__)

IMAP_HOST = "imap.mail.yahoo.com"

# Yahoo's IMAP names for its spam and trash folders. The folders' special-use flags
# (\Junk, \Trash) are checked first, so these only matter if Yahoo ever stops sending them.
DEFAULT_SPAM_FOLDER = "Bulk"
DEFAULT_TRASH_FOLDER = "Trash"

_LIST_RE = re.compile(rb'\((?P<flags>[^)]*)\) (?:"[^"]*"|NIL) (?P<name>.+)$')


def quote_mailbox(name: str) -> str:
    """IMAP-quote a folder name ("Phish Reports" has a space). Python's imaplib leaves an
    already-quoted argument alone, so this is safe on every Python version."""
    if len(name) >= 2 and name[0] == name[-1] == '"':
        return name
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _imap_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class YahooListener:
    """Fetches unread Yahoo Mail messages via IMAP + an app-specific password.

    Mirrors gmail_client's interface (list_message_ids / get_message /
    mark_processed) but as a class, since an IMAP connection is per-instance
    state rather than a service object passed around.

    Message ids are IMAP UIDs, not sequence numbers: a sequence number shifts as
    soon as any message in the folder is moved or deleted, so acting on one later
    (e.g. from the dashboard) could hit the wrong email. UIDs don't shift.
    """

    def __init__(self, email_address: str, app_password: str,
                 folder: str = "INBOX", search_criteria: str = "UNSEEN"):
        self._email_address = email_address
        self._app_password = app_password
        self._folder = folder
        self._search_criteria = search_criteria
        self._conn = None
        self._selected = None
        self._uidvalidity = ""
        self._special = None

    @property
    def folder(self) -> str:
        return self._folder

    @property
    def email_address(self) -> str:
        return self._email_address

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
        self._selected = None

    def _select(self, folder: str) -> None:
        if self._conn is None:
            self.connect()
        if self._selected == folder:
            return
        typ, _ = self._conn.select(quote_mailbox(folder))
        if typ != "OK":
            raise RuntimeError(f"Could not select Yahoo folder {folder!r}. Does it exist?")
        self._selected = folder
        _, data = self._conn.response("UIDVALIDITY")
        self._uidvalidity = data[0].decode() if data and data[0] else ""

    def list_message_ids(self, max_results: int = 25) -> list:
        self._select(self._folder)

        typ, data = self._conn.uid("SEARCH", None, self._search_criteria)
        if typ != "OK":
            raise RuntimeError(f"Yahoo IMAP search failed for criteria {self._search_criteria!r}")

        ids = data[0].split()
        if max_results is not None:
            ids = ids[-max_results:]
        return [i.decode() for i in ids]

    def get_message(self, message_id: str, max_attachment_bytes: int = 0) -> EmailMessage:
        # BODY.PEEK avoids implicitly marking the message \Seen just by reading it;
        # mark_processed() flips \Seen explicitly once enrichment succeeds.
        self._select(self._folder)
        typ, data = self._conn.uid("FETCH", message_id, "(BODY.PEEK[])")
        if typ != "OK" or not data or not isinstance(data[0], tuple):
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
            message_id=str(msg.get("message-id", "")).strip(),
            folder=self._folder,
            uidvalidity=self._uidvalidity,
        )

    def mark_processed(self, message_id: str) -> None:
        self._select(self._folder)
        self._conn.uid("STORE", message_id, "+FLAGS", "(\\Seen)")

    # $Junk / $NotJunk keywords are set in place (verified in the folder's
    # PERMANENTFLAGS); the message is not moved to Bulk.
    def mark_as_spam(self, message_id: str) -> None:
        self._select(self._folder)
        self._conn.uid("STORE", message_id, "+FLAGS", "($Junk)")
        self._conn.uid("STORE", message_id, "-FLAGS", "($NotJunk)")

    def mark_as_not_spam(self, message_id: str) -> None:
        self._select(self._folder)
        self._conn.uid("STORE", message_id, "+FLAGS", "($NotJunk)")
        self._conn.uid("STORE", message_id, "-FLAGS", "($Junk)")

    # --- Mail actions (spam folder / trash) ------------------------------------
    # These take a folder + uid + Message-ID so they also work later from the
    # dashboard, after the pipeline's connection is gone.

    def special_folders(self) -> dict:
        """{"spam": name, "trash": name} from the server's special-use flags."""
        if self._special is None:
            if self._conn is None:
                self.connect()
            found = {}
            typ, data = self._conn.list()
            for line in (data if typ == "OK" else []) or []:
                if not isinstance(line, bytes):
                    continue
                m = _LIST_RE.match(line)
                if not m:
                    continue
                flags = m.group("flags").lower()
                name = m.group("name").decode("utf-8", "replace").strip()
                if name.startswith('"') and name.endswith('"'):
                    name = name[1:-1].replace('\\"', '"').replace("\\\\", "\\")
                if b"\\junk" in flags or b"\\spam" in flags:
                    found.setdefault("spam", name)
                if b"\\trash" in flags:
                    found.setdefault("trash", name)
            self._special = {"spam": found.get("spam", DEFAULT_SPAM_FOLDER),
                             "trash": found.get("trash", DEFAULT_TRASH_FOLDER)}
        return self._special

    def locate(self, folder: str, uid: str = "", message_id: str = "", uidvalidity: str = ""):
        """UID of the message in `folder`, or None if it isn't there.

        Looks it up by Message-ID header when known (survives moves and UIDVALIDITY
        resets); otherwise trusts the stored UID only if the folder's UIDVALIDITY
        still matches, so a stale UID can never point at a different email."""
        self._select(folder)
        if message_id:
            typ, data = self._conn.uid("SEARCH", None, "HEADER", "Message-ID", _imap_string(message_id))
            hits = data[0].split() if typ == "OK" and data and data[0] else []
            if len(hits) == 1:
                return hits[0].decode()
            if len(hits) > 1:
                raise RuntimeError(f"{len(hits)} messages in {folder!r} share Message-ID {message_id}; not guessing")
        if uid and uidvalidity and uidvalidity == self._uidvalidity:
            # Fallback when the header search finds nothing: the stored UID, but only
            # if the message there really is the same email.
            typ, data = self._conn.uid("FETCH", uid, "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])")
            if typ == "OK" and data and isinstance(data[0], tuple):
                header = message_from_bytes(data[0][1], policy=policy.default)
                if not message_id or str(header.get("message-id", "")).strip() == message_id:
                    return uid
        return None

    def _move(self, uid: str, destination: str) -> None:
        """Move one message (folder already selected). Uses IMAP MOVE when the server
        has it; otherwise copy + flag deleted + expunge only that UID."""
        dest = quote_mailbox(destination)
        caps = getattr(self._conn, "capabilities", ()) or ()
        if "MOVE" in caps:
            typ, data = self._conn.uid("MOVE", uid, dest)
            if typ != "OK":
                raise RuntimeError(f"IMAP MOVE to {destination!r} failed: {data}")
            return
        typ, data = self._conn.uid("COPY", uid, dest)
        if typ != "OK":
            raise RuntimeError(f"IMAP COPY to {destination!r} failed: {data}")
        self._conn.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        if "UIDPLUS" in caps:
            self._conn.uid("EXPUNGE", uid)

    def _still_here(self, uid: str) -> bool:
        typ, data = self._conn.uid("FETCH", uid, "(FLAGS)")
        return typ == "OK" and any(isinstance(d, (bytes, tuple)) and d for d in (data or []))

    def _move_and_verify(self, uid: str, destination: str) -> None:
        """Move, then confirm the email really left this folder. A server can answer
        OK yet leave the original behind (a copy marked deleted but never expunged),
        which looks in Yahoo Mail like nothing happened -- so never report success blindly."""
        self._move(uid, destination)
        if not self._still_here(uid):
            return
        # Leftover copy marked \Deleted: expunge it, but only if it's the only message in
        # this folder marked deleted (plain EXPUNGE would also purge any others).
        typ, data = self._conn.uid("SEARCH", None, "DELETED")
        deleted = data[0].split() if typ == "OK" and data and data[0] else []
        if [d.decode() for d in deleted] == [str(uid)]:
            self._conn.expunge()
            if not self._still_here(uid):
                return
        raise RuntimeError(f"Yahoo said the email was moved to {destination!r}, but it is still in this folder")

    def move_message(self, folder: str, destination: str, uid: str = "", message_id: str = "",
                     uidvalidity: str = "", flags_add: str = "", flags_remove: str = "") -> None:
        found = self.locate(folder, uid, message_id, uidvalidity)
        if found is None:
            raise LookupError(f"Message not found in Yahoo folder {folder!r} (already moved or deleted?)")
        # Mark it read first so nothing re-processes it as new mail where it lands.
        self._conn.uid("STORE", found, "+FLAGS", "(\\Seen" + (" " + flags_add if flags_add else "") + ")")
        if flags_remove:
            self._conn.uid("STORE", found, "-FLAGS", "(" + flags_remove + ")")
        self._move_and_verify(found, destination)

    def move_to_spam(self, folder: str, uid: str = "", message_id: str = "", uidvalidity: str = "") -> str:
        dest = self.special_folders()["spam"]
        self.move_message(folder, dest, uid, message_id, uidvalidity, flags_add="$Junk", flags_remove="$NotJunk")
        return dest

    def move_to_trash(self, folder: str, uid: str = "", message_id: str = "", uidvalidity: str = "") -> str:
        dest = self.special_folders()["trash"]
        self.move_message(folder, dest, uid, message_id, uidvalidity)
        return dest

    def restore_to(self, from_folder: str, to_folder: str, message_id: str) -> None:
        """Undo a spam/trash move. Needs the Message-ID: the message has a new UID
        in the folder it was moved to."""
        if not message_id:
            raise LookupError("No Message-ID recorded for this email, so it can't be found to restore")
        self.move_message(from_folder, to_folder, message_id=message_id, flags_remove="$Junk")

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
