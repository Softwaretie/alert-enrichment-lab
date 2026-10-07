"""Act on Claude's verdicts in the real mailbox: spam folder, Trash, block sender.

What happens to a bad email:
  - category "spam"                         -> moved to the provider's spam folder
  - verdict "malicious", or category
    phishing/malware/scam (malicious or
    suspicious verdict)                     -> moved to Trash + sender blocked

Automatically only when Claude's confidence is "high" (and AUTO_MAIL_ACTIONS is
on); anything less shows up in the dashboard as a suggested action you click.

Safety rails:
  - "Delete" is always Trash, never a permanent delete, and every move can be undone.
  - A sender is NOT auto-blocked when the From address looks forged (DMARC fail, or
    SPF and DKIM both fail): phishing often fakes a real company's address, and
    blocking it would block that company's genuine mail. The email is still trashed.
  - Your own mailbox addresses and anything in NEVER_BLOCK are never blocked.
  - Every action (and every failure) is written to the mail_actions table.
"""
import json
import logging
import os
from email.utils import parseaddr

from src import database, gmail_client

logger = logging.getLogger(__name__)

SPAM = "spam"
BLOCK_AND_TRASH = "block_and_trash"

BLOCK_CATEGORIES = {"phishing", "malware", "scam"}
SPAM_CATEGORIES = {"spam"}


def decide_action(verdict: str, category: str):
    """Which action a verdict calls for: BLOCK_AND_TRASH, SPAM or None."""
    verdict = (verdict or "").lower()
    category = (category or "").lower()
    if verdict == "malicious":
        return BLOCK_AND_TRASH
    if category in BLOCK_CATEGORIES and verdict == "suspicious":
        return BLOCK_AND_TRASH
    if category in SPAM_CATEGORIES:
        return SPAM
    return None


def sender_address(sender: str) -> str:
    return parseaddr(sender or "")[1].strip().lower()


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1] if "@" in address else ""


def looks_forged(auth: dict) -> bool:
    auth = auth or {}
    if auth.get("dmarc") == "fail":
        return True
    return auth.get("spf") == "fail" and auth.get("dkim") == "fail"


def check_block(address: str, auth: dict, own_addresses=(), never_block=()) -> tuple:
    """(allowed, overridable, reason). overridable=True means a person may still
    choose to block from the dashboard after seeing the warning; automation never does."""
    if not address or "@" not in address:
        return False, False, "no usable sender address"
    own = {a.lower() for a in own_addresses if a}
    if address in own:
        return False, False, "that's your own address (the sender is spoofing you); blocking it would block your own mail"
    protected = {n.lower().lstrip("@") for n in never_block if n}
    if address in protected or _domain(address) in protected:
        return False, False, f"{address} is on your NEVER_BLOCK list"
    if looks_forged(auth):
        return False, True, ("the From address looks forged (sender authentication failed), so blocking it "
                             "could block the real owner of that address")
    return True, False, ""


def _as_dict(value):
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}


class MailActor:
    """Performs mail actions for findings and records them.

    The pipeline passes in the Gmail service / Yahoo connection it already has open;
    the dashboard passes nothing and connections are opened on first use."""

    def __init__(self, db_conn, gmail_service=None, yahoo=None, never_block=(),
                 gmail_factory=None, yahoo_factory=None, auto_enabled: bool = True):
        self._db = db_conn
        self._gmail = gmail_service
        self._yahoo = yahoo
        self._gmail_factory = gmail_factory
        self._yahoo_factory = yahoo_factory
        self._opened_yahoo = False
        self.never_block = tuple(never_block)
        self.auto_enabled = auto_enabled

    # --- connections -------------------------------------------------------------
    def gmail(self):
        if self._gmail is None:
            if self._gmail_factory is None:
                raise RuntimeError("Gmail isn't available for this action")
            self._gmail = self._gmail_factory()
        return self._gmail

    def yahoo(self):
        if self._yahoo is None:
            if self._yahoo_factory is None:
                raise RuntimeError("Yahoo isn't available for this action")
            self._yahoo = self._yahoo_factory()
            self._opened_yahoo = True
        return self._yahoo

    def set_gmail(self, service) -> None:
        self._gmail = service

    def set_yahoo(self, listener) -> None:
        self._yahoo = listener

    def close(self) -> None:
        if self._opened_yahoo and self._yahoo is not None:
            try:
                self._yahoo.close()
            except Exception:  # noqa: BLE001 - closing is best effort
                pass
            self._yahoo = None
            self._opened_yahoo = False

    # --- helpers -----------------------------------------------------------------
    def _own_addresses(self, finding: dict) -> list:
        own = [finding.get("mailbox") or ""]
        if self._yahoo is not None and getattr(self._yahoo, "email_address", None):
            own.append(self._yahoo.email_address)
        return own

    def _done(self, finding, action, trigger, ok, message):
        database.log_mail_action(self._db, finding.get("id") if finding else None, action, trigger, ok, message)
        (logger.info if ok else logger.warning)("[mail-action] %s (%s) finding %s: %s", action, trigger,
                                                finding.get("id") if finding else "-", message)
        return {"ok": ok, "action": action, "message": message}

    def _yahoo_location(self, finding: dict):
        """(folder the message is in now, uid or "" if it moved)."""
        detail = _as_dict(finding.get("mail_state_detail"))
        if finding.get("mail_state") and detail.get("folder"):
            return detail["folder"], ""
        return finding.get("mail_folder") or "", finding.get("email_id") or ""

    # --- actions -----------------------------------------------------------------
    def move_to_spam(self, finding: dict, trigger: str = "manual") -> dict:
        state = finding.get("mail_state")
        if state == "spam":
            return {"ok": True, "action": "spam", "message": "Already in the spam folder"}
        if state == "trash":
            return {"ok": False, "action": "spam", "message": "It's in Trash; restore it first"}
        try:
            if finding["source"] == "gmail":
                had_inbox = "INBOX" in gmail_client.get_label_ids(self.gmail(), finding["email_id"])
                gmail_client.move_to_spam(self.gmail(), finding["email_id"])
                detail = {"had_inbox": had_inbox}
                where = "Gmail Spam"
            elif finding["source"] == "yahoo":
                folder, uid = self._yahoo_location(finding)
                dest = self.yahoo().move_to_spam(folder, uid, finding.get("message_id") or "",
                                                 finding.get("uidvalidity") or "")
                detail = {"folder": dest, "from_folder": folder}
                where = f"Yahoo {dest}"
            else:
                return self._done(finding, "spam", trigger, False, f"Unknown source {finding['source']!r}")
        except Exception as exc:  # noqa: BLE001 - report, never crash the run/request
            return self._done(finding, "spam", trigger, False, f"Couldn't move to spam: {exc}")
        database.set_mail_state(self._db, finding["id"], "spam", detail)
        finding["mail_state"], finding["mail_state_detail"] = "spam", json.dumps(detail)
        return self._done(finding, "spam", trigger, True, f"Moved to {where}")

    def move_to_trash(self, finding: dict, trigger: str = "manual") -> dict:
        state = finding.get("mail_state")
        if state == "trash":
            return {"ok": True, "action": "trash", "message": "Already in Trash"}
        try:
            prior = _as_dict(finding.get("mail_state_detail")) if state else {}
            if finding["source"] == "gmail":
                had_inbox = prior.get("had_inbox")
                if had_inbox is None:
                    had_inbox = "INBOX" in gmail_client.get_label_ids(self.gmail(), finding["email_id"])
                gmail_client.trash_message(self.gmail(), finding["email_id"])
                detail = {"had_inbox": had_inbox, "was_spam": state == "spam"}
                where = "Gmail Trash"
            elif finding["source"] == "yahoo":
                folder, uid = self._yahoo_location(finding)
                dest = self.yahoo().move_to_trash(folder, uid, finding.get("message_id") or "",
                                                  finding.get("uidvalidity") or "")
                detail = {"folder": dest, "from_folder": prior.get("from_folder") or folder}
                where = f"Yahoo {dest}"
            else:
                return self._done(finding, "trash", trigger, False, f"Unknown source {finding['source']!r}")
        except Exception as exc:  # noqa: BLE001
            return self._done(finding, "trash", trigger, False, f"Couldn't move to Trash: {exc}")
        database.set_mail_state(self._db, finding["id"], "trash", detail)
        finding["mail_state"], finding["mail_state_detail"] = "trash", json.dumps(detail)
        return self._done(finding, "trash", trigger, True, f"Moved to {where} (recoverable)")

    def restore(self, finding: dict, trigger: str = "manual") -> dict:
        """Undo spam/trash: put the email back where it was."""
        state = finding.get("mail_state")
        if not state:
            return {"ok": True, "action": "restore", "message": "Nothing to undo"}
        detail = _as_dict(finding.get("mail_state_detail"))
        try:
            if finding["source"] == "gmail":
                service = self.gmail()
                if state == "trash":
                    gmail_client.untrash_message(service, finding["email_id"])
                    if detail.get("was_spam"):
                        gmail_client.restore_from_spam(service, finding["email_id"], bool(detail.get("had_inbox")))
                else:
                    gmail_client.restore_from_spam(service, finding["email_id"], bool(detail.get("had_inbox")))
            elif finding["source"] == "yahoo":
                original = detail.get("from_folder") or finding.get("mail_folder")
                self.yahoo().restore_to(detail.get("folder", ""), original, finding.get("message_id") or "")
            else:
                return self._done(finding, "restore", trigger, False, f"Unknown source {finding['source']!r}")
        except Exception as exc:  # noqa: BLE001
            return self._done(finding, "restore", trigger, False, f"Couldn't restore: {exc}")
        database.set_mail_state(self._db, finding["id"], None, {})
        finding["mail_state"], finding["mail_state_detail"] = None, "{}"
        return self._done(finding, "restore", trigger, True, "Moved back to where it was")

    def block_sender(self, finding: dict, trigger: str = "manual", force: bool = False) -> dict:
        address = sender_address(finding.get("sender"))
        auth = _as_dict(finding.get("enrichment")).get("sender_authentication") or {}
        allowed, overridable, reason = check_block(address, auth, self._own_addresses(finding), self.never_block)
        if not allowed and not (force and overridable and trigger == "manual"):
            result = self._done(finding, "block", trigger, False, f"Didn't block {address or 'sender'}: {reason}")
            result["needs_confirm"] = overridable and trigger == "manual"
            return result
        if database.get_blocked_sender(self._db, address) and finding["source"] != "gmail":
            return {"ok": True, "action": "block", "message": f"{address} is already blocked"}

        filter_id = None
        try:
            if finding["source"] == "gmail":
                filter_id = gmail_client.create_block_filter(self.gmail(), address)
        except Exception as exc:  # noqa: BLE001
            hint = ""
            if "insufficient" in str(exc).lower() or "403" in str(exc):
                hint = " (Gmail needs the new filter permission: run the analyzer once and sign in when the browser opens)"
            return self._done(finding, "block", trigger, False, f"Couldn't create the Gmail filter for {address}: {exc}{hint}")

        database.add_blocked_sender(self._db, address, finding.get("source", ""), finding.get("mailbox", ""),
                                    filter_id, finding.get("id"), reason="forced" if force and not allowed else trigger)
        how = "Gmail filter sends their mail to Trash" if filter_id else "their new mail is trashed on every run"
        return self._done(finding, "block", trigger, True, f"Blocked {address}: {how}")

    def unblock(self, address: str) -> dict:
        address = (address or "").lower()
        row = database.get_blocked_sender(self._db, address)
        if not row:
            return {"ok": True, "action": "unblock", "message": f"{address} wasn't blocked"}
        stub = {"id": row.get("finding_id")}
        if row.get("gmail_filter_id"):
            try:
                gmail_client.delete_filter(self.gmail(), row["gmail_filter_id"])
            except Exception as exc:  # noqa: BLE001
                if "404" not in str(exc) and "not found" not in str(exc).lower():
                    return self._done(stub, "unblock", "manual", False,
                                      f"Couldn't remove the Gmail filter for {address}: {exc}")
        database.remove_blocked_sender(self._db, address)
        return self._done(stub, "unblock", "manual", True, f"Unblocked {address}")

    # --- automation --------------------------------------------------------------
    def auto_act(self, finding: dict) -> list:
        """Run the verdict's action if Claude was highly confident. Returns results."""
        if not self.auto_enabled:
            return []
        action = decide_action(finding.get("verdict"), finding.get("category"))
        if action is None or (finding.get("confidence") or "").lower() != "high":
            return []
        if action == SPAM:
            return [self.move_to_spam(finding, trigger="auto")]
        results = [self.move_to_trash(finding, trigger="auto")]
        results.append(self.block_sender(finding, trigger="auto"))
        return results

    def is_blocked(self, sender: str) -> bool:
        return database.get_blocked_sender(self._db, sender_address(sender)) is not None


def dashboard_actor(db_conn, project_root: str) -> MailActor:
    """A MailActor that opens Gmail/Yahoo on demand, for dashboard button clicks.
    Needs only the mail settings, not the threat-intel/Claude keys."""
    from src.config import _get_secret, never_block_list
    from src.yahoo_client import YahooListener

    def _path(value: str) -> str:
        return value if os.path.isabs(value) else os.path.join(project_root, value)

    def gmail_factory():
        return gmail_client.authenticate(
            _path(os.environ.get("GMAIL_CREDENTIALS_PATH", "credentials.json")),
            _path(os.environ.get("GMAIL_TOKEN_PATH", "token.json")),
        )

    def yahoo_factory():
        address = os.environ.get("YAHOO_EMAIL", "")
        password = _get_secret("YAHOO_APP_PASSWORD")
        if not (address and password):
            raise RuntimeError("Yahoo isn't set up (YAHOO_EMAIL / YAHOO_APP_PASSWORD)")
        listener = YahooListener(address, password, folder=os.environ.get("YAHOO_FOLDER", "INBOX"))
        listener.connect()
        return listener

    yahoo_address = os.environ.get("YAHOO_EMAIL", "")
    actor = MailActor(db_conn, never_block=never_block_list() + ((yahoo_address.lower(),) if yahoo_address else ()),
                      gmail_factory=gmail_factory, yahoo_factory=yahoo_factory)
    return actor
