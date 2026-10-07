"""Tests for mail actions: spam folder / Trash / block sender, automatic and from the dashboard.

Everything runs against in-memory fakes of the Gmail API and a Yahoo IMAP server,
so no real mailbox is touched.
"""
import json
import os
import sqlite3
import tempfile
import unittest
from email.message import EmailMessage as MimeMessage
from unittest import mock

try:
    from src import database, gmail_client, mail_actions, pipeline
    from src.yahoo_client import YahooListener, quote_mailbox
except ImportError as exc:  # project dependencies (requirements.txt) not installed
    raise unittest.SkipTest(f"mail action tests need the project's requirements installed: {exc}")
from src.email_message import EmailMessage


# --- Fakes -----------------------------------------------------------------------

class _Call:
    def __init__(self, fn):
        self._fn = fn

    def execute(self):
        return self._fn()


class FakeGmail:
    """Just enough of the Gmail API for labels, trash and filters."""

    def __init__(self):
        self.labels = {}      # message id -> set of label ids
        self.filter_store = {}  # filter id -> filter body
        self.calls = []

    # service.users().messages()... / .settings().filters()...
    def users(self):
        return self

    def messages(self):
        return _Messages(self)

    def settings(self):
        return self

    def filters(self):
        return _Filters(self)


class _Messages:
    def __init__(self, g):
        self.g = g

    def get(self, userId, id, format="full"):
        return _Call(lambda: {"id": id, "labelIds": sorted(self.g.labels[id])})

    def modify(self, userId, id, body):
        def run():
            self.g.calls.append(("modify", id, body))
            self.g.labels[id] |= set(body.get("addLabelIds", []))
            self.g.labels[id] -= set(body.get("removeLabelIds", []))
            return {}
        return _Call(run)

    def trash(self, userId, id):
        def run():
            self.g.calls.append(("trash", id))
            self.g.labels[id].add("TRASH")
            return {}
        return _Call(run)

    def untrash(self, userId, id):
        def run():
            self.g.calls.append(("untrash", id))
            self.g.labels[id].discard("TRASH")
            return {}
        return _Call(run)


class _Filters:
    def __init__(self, g):
        self.g = g

    def list(self, userId):
        return _Call(lambda: {"filter": [dict(body, id=fid) for fid, body in self.g.filter_store.items()]})

    def create(self, userId, body):
        def run():
            fid = f"f{len(self.g.filter_store) + 1}"
            self.g.filter_store[fid] = body
            return dict(body, id=fid)
        return _Call(run)

    def delete(self, userId, id):
        def run():
            del self.g.filter_store[id]
            return {}
        return _Call(run)


def _raw(message_id, sender="Bad Guy <bad@evil.example>", subject="Hi"):
    msg = MimeMessage()
    msg["From"] = sender
    msg["To"] = "me@yahoo.com"
    msg["Subject"] = subject
    msg["Message-ID"] = message_id
    msg.set_content("click http://evil.example/login")
    return msg.as_bytes()


def _unquote(name):
    return name[1:-1].replace('\\"', '"').replace("\\\\", "\\") if name.startswith('"') else name


class FakeImap:
    """A tiny in-memory IMAP server: folders of {uid: [raw, flags]} plus the commands
    YahooListener uses. Mailbox arguments must arrive IMAP-quoted when they contain
    spaces, exactly as a real server requires."""

    def __init__(self, folders, capabilities=("IMAP4REV1", "MOVE", "UIDPLUS")):
        self.capabilities = tuple(capabilities)
        self.folders = {name: {} for name in folders}
        self.uidvalidity = {name: str(1000 + i) for i, name in enumerate(folders)}
        self.next_uid = {name: 1 for name in folders}
        self.selected = None
        self.log = []

    def add(self, folder, raw, flags=()):
        uid = self.next_uid[folder]
        self.next_uid[folder] += 1
        self.folders[folder][uid] = [raw, set(flags)]
        return str(uid)

    def _folder_arg(self, name):
        if " " in name and not name.startswith('"'):
            raise AssertionError(f"unquoted mailbox with a space sent to server: {name!r}")
        return _unquote(name)

    # imaplib surface
    def login(self, *_):
        return "OK", [b""]

    def select(self, name):
        name = self._folder_arg(name)
        if name not in self.folders:
            return "NO", [b"no such folder"]
        self.selected = name
        return "OK", [str(len(self.folders[name])).encode()]

    def response(self, code):
        return code, [self.uidvalidity[self.selected].encode()]

    def list(self):
        return "OK", [b'(\\HasNoChildren) "/" "Inbox"',
                      b'(\\HasNoChildren \\Junk) "/" "Bulk"',
                      b'(\\HasNoChildren \\Trash) "/" "Trash"',
                      b'(\\HasNoChildren) "/" "Phish Reports"']

    def close(self):
        return "OK", []

    def expunge(self):
        box = self.folders[self.selected]
        for uid in [u for u, (_, fl) in box.items() if "\\Deleted" in fl]:
            del box[uid]
        return "OK", []

    def logout(self):
        return "BYE", []

    def uid(self, command, *args):
        command = command.upper()
        self.log.append((command, args))
        box = self.folders[self.selected]
        if command == "SEARCH":
            criteria = [a for a in args if a is not None]
            if criteria[:2] == ["HEADER", "Message-ID"]:
                wanted = _unquote(criteria[2])
                hits = [u for u, (raw, _) in box.items() if f"Message-ID: {wanted}".encode() in raw]
            elif criteria == ["DELETED"]:
                hits = [u for u, (_, fl) in box.items() if "\\Deleted" in fl]
            elif criteria == ["UNSEEN"]:
                hits = [u for u, (_, fl) in box.items() if "\\Seen" not in fl]
            else:
                hits = list(box)
            return "OK", [" ".join(str(u) for u in hits).encode()]
        uid = int(args[0])
        if command == "FETCH":
            if uid not in box:
                return "OK", [None]
            return "OK", [(f"1 (UID {uid} BODY[] {{1}}".encode(), box[uid][0]), b")"]
        if command == "STORE":
            if uid in box:
                flags = args[2].strip("()").split()
                if args[1].startswith("+"):
                    box[uid][1].update(flags)
                else:
                    box[uid][1].difference_update(flags)
            return "OK", [b""]
        if command in ("MOVE", "COPY"):
            if command == "MOVE" and "MOVE" not in self.capabilities:
                raise AssertionError("MOVE used without the capability")
            dest = self._folder_arg(args[1])
            if dest not in self.folders or uid not in box:
                return "NO", [b"failed"]
            raw, flags = box[uid]
            self.add(dest, raw, flags)
            if command == "MOVE" and not getattr(self, "lie_about_move", False):
                del box[uid]
            return "OK", [b""]
        if command == "EXPUNGE":
            if "\\Deleted" in box.get(uid, [None, set()])[1]:
                del box[uid]
            return "OK", [b""]
        raise AssertionError(f"unexpected UID {command}")


def _yahoo_listener(fake, folder="Phish Reports"):
    listener = YahooListener("me@yahoo.com", "pw", folder=folder)
    listener._conn = fake
    return listener


# --- Helpers -----------------------------------------------------------------------

def _db(test=None):
    conn = database.connect(":memory:")
    if test is not None:
        test.addCleanup(conn.close)
    return conn


def _insert(conn, source="gmail", email_id="m1", verdict="malicious", category="phishing",
            confidence="high", sender="Bad Guy <bad@evil.example>", auth=None, mailbox="me@gmail.com",
            message_id="", folder="", uidvalidity=""):
    fid = database.insert_finding(conn, {
        "source": source, "mailbox": mailbox, "email_id": email_id, "subject": "s", "sender": sender,
        "date": "d", "extracted_iocs": {}, "enrichment": {"sender_authentication": auth or {}},
        "claude_analysis": {"verdict": verdict, "category": category, "confidence": confidence},
        "processed_at": "2026-10-06T00:00:00+00:00", "message_id": message_id, "mail_folder": folder,
        "uidvalidity": uidvalidity,
    })
    return database.get_finding(conn, fid)


# --- Tests -------------------------------------------------------------------------

class DecisionTests(unittest.TestCase):
    def test_action_for_each_verdict(self):
        d = mail_actions.decide_action
        self.assertEqual(d("malicious", "phishing"), mail_actions.BLOCK_AND_TRASH)
        self.assertEqual(d("malicious", "spam"), mail_actions.BLOCK_AND_TRASH)
        self.assertEqual(d("malicious", None), mail_actions.BLOCK_AND_TRASH)  # older findings had no category
        self.assertEqual(d("suspicious", "phishing"), mail_actions.BLOCK_AND_TRASH)
        self.assertEqual(d("suspicious", "scam"), mail_actions.BLOCK_AND_TRASH)
        self.assertEqual(d("likely_benign", "spam"), mail_actions.SPAM)
        self.assertEqual(d("suspicious", "spam"), mail_actions.SPAM)
        self.assertIsNone(d("likely_benign", "legitimate"))
        self.assertIsNone(d("suspicious", "unclear"))
        self.assertIsNone(d("likely_benign", "phishing"))  # contradictory: leave it to a human

    def test_block_safety(self):
        check = mail_actions.check_block
        self.assertEqual(check("bad@evil.example", {"dmarc": "pass"})[0], True)
        allowed, overridable, reason = check("service@paypal.com", {"dmarc": "fail"})
        self.assertFalse(allowed)
        self.assertTrue(overridable)
        self.assertIn("forged", reason)
        self.assertFalse(check("x@y.com", {"spf": "fail", "dkim": "fail"})[0])
        self.assertTrue(check("x@y.com", {"spf": "fail", "dkim": "pass"})[0])
        self.assertEqual(check("me@gmail.com", {}, own_addresses=["Me@Gmail.com"])[:2], (False, False))
        self.assertEqual(check("ceo@mybank.com", {}, never_block=["mybank.com"])[:2], (False, False))
        self.assertEqual(check("", {})[:2], (False, False))


class GmailActionTests(unittest.TestCase):
    def setUp(self):
        self.conn = _db(self)
        self.g = FakeGmail()
        self.g.labels["m1"] = {"INBOX", "UNREAD", "Label_phish"}
        self.actor = mail_actions.MailActor(self.conn, gmail_service=self.g)

    def test_high_confidence_phishing_is_trashed_and_sender_blocked(self):
        finding = _insert(self.conn)
        results = self.actor.auto_act(finding)
        self.assertTrue(all(r["ok"] for r in results), results)
        self.assertIn("TRASH", self.g.labels["m1"])
        (fid, body), = self.g.filter_store.items()
        self.assertEqual(body["criteria"], {"from": "bad@evil.example"})
        self.assertIn("TRASH", body["action"]["addLabelIds"])
        row = database.get_blocked_sender(self.conn, "bad@evil.example")
        self.assertEqual(row["gmail_filter_id"], fid)
        self.assertEqual(database.get_finding(self.conn, finding["id"])["mail_state"], "trash")

    def test_high_confidence_spam_goes_to_spam_and_undo_restores_inbox(self):
        finding = _insert(self.conn, verdict="likely_benign", category="spam")
        self.actor.auto_act(finding)
        self.assertIn("SPAM", self.g.labels["m1"])
        self.assertNotIn("INBOX", self.g.labels["m1"])
        self.assertEqual(self.g.filter_store, {})  # spam never blocks
        result = self.actor.restore(database.get_finding(self.conn, finding["id"]))
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.g.labels["m1"], {"INBOX", "UNREAD", "Label_phish"})

    def test_medium_confidence_is_only_suggested(self):
        finding = _insert(self.conn, confidence="medium")
        self.assertEqual(self.actor.auto_act(finding), [])
        self.assertEqual(self.g.calls, [])

    def test_auto_actions_can_be_switched_off(self):
        self.actor.auto_enabled = False
        self.assertEqual(self.actor.auto_act(_insert(self.conn)), [])
        self.assertEqual(self.g.calls, [])

    def test_forged_sender_is_trashed_but_not_auto_blocked(self):
        finding = _insert(self.conn, sender="PayPal <service@paypal.com>", auth={"dmarc": "fail"})
        trash, block = self.actor.auto_act(finding)
        self.assertTrue(trash["ok"])
        self.assertFalse(block["ok"])
        self.assertIn("forged", block["message"])
        self.assertEqual(self.g.filter_store, {})
        # A person can still choose to block it after the warning.
        manual = self.actor.block_sender(finding, trigger="manual")
        self.assertTrue(manual.get("needs_confirm"))
        forced = self.actor.block_sender(finding, trigger="manual", force=True)
        self.assertTrue(forced["ok"], forced)

    def test_own_address_is_never_blocked_even_when_forced(self):
        finding = _insert(self.conn, sender="Me <me@gmail.com>")
        result = self.actor.block_sender(finding, force=True)
        self.assertFalse(result["ok"])
        self.assertFalse(result.get("needs_confirm"))

    def test_trash_then_undo_after_spam(self):
        finding = _insert(self.conn, verdict="likely_benign", category="spam")
        self.actor.move_to_spam(finding)
        self.actor.move_to_trash(finding)
        self.assertIn("TRASH", self.g.labels["m1"])
        self.actor.restore(finding)
        self.assertEqual(self.g.labels["m1"], {"INBOX", "UNREAD", "Label_phish"})

    def test_unblock_removes_gmail_filter(self):
        finding = _insert(self.conn)
        self.actor.block_sender(finding)
        self.assertEqual(len(self.g.filter_store), 1)
        self.assertTrue(self.actor.unblock("BAD@evil.example")["ok"])
        self.assertEqual(self.g.filter_store, {})
        self.assertIsNone(database.get_blocked_sender(self.conn, "bad@evil.example"))

    def test_blocking_twice_reuses_the_filter(self):
        finding = _insert(self.conn)
        self.actor.block_sender(finding)
        self.actor.block_sender(finding)
        self.assertEqual(len(self.g.filter_store), 1)

    def test_failures_are_reported_not_raised(self):
        finding = _insert(self.conn, email_id="missing")
        result = self.actor.move_to_trash(finding)
        self.assertFalse(result["ok"])
        history = database.list_mail_actions(self.conn, [finding["id"]])[finding["id"]]
        self.assertEqual(history[-1]["success"], 0)


class YahooActionTests(unittest.TestCase):
    def setUp(self):
        self.conn = _db(self)
        self.imap = FakeImap(["Inbox", "Bulk", "Trash", "Phish Reports"])
        self.imap.add("Phish Reports", _raw("<keep@x>", sender="Friend <f@ok.example>"))
        self.uid = self.imap.add("Phish Reports", _raw("<bad1@evil.example>"))
        self.listener = _yahoo_listener(self.imap)
        self.actor = mail_actions.MailActor(self.conn, yahoo=self.listener)

    def _finding(self, **kw):
        email = self.listener.get_message(self.uid)
        defaults = dict(source="yahoo", email_id=email.id, mailbox="me@yahoo.com",
                        message_id=email.message_id, folder=email.folder, uidvalidity=email.uidvalidity)
        defaults.update(kw)
        return _insert(self.conn, **defaults)

    def test_get_message_records_location(self):
        email = self.listener.get_message(self.uid)
        self.assertEqual(email.message_id, "<bad1@evil.example>")
        self.assertEqual(email.folder, "Phish Reports")
        self.assertEqual(email.uidvalidity, self.imap.uidvalidity["Phish Reports"])
        self.assertEqual(self.listener.list_message_ids(None), ["1", "2"])  # UIDs, not sequence numbers

    def test_spam_moves_to_bulk_and_undo_moves_back(self):
        finding = self._finding(verdict="likely_benign", category="spam")
        self.actor.auto_act(finding)
        self.assertEqual(len(self.imap.folders["Phish Reports"]), 1)
        (raw, flags), = self.imap.folders["Bulk"].values()
        self.assertIn(b"<bad1@evil.example>", raw)
        self.assertIn("$Junk", flags)
        self.assertIn("\\Seen", flags)
        result = self.actor.restore(database.get_finding(self.conn, finding["id"]))
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(self.imap.folders["Bulk"]), 0)
        self.assertEqual(len(self.imap.folders["Phish Reports"]), 2)
        # "Phish Reports" has a space: it must have been sent quoted.
        moves = [args for cmd, args in self.imap.log if cmd == "MOVE"]
        self.assertEqual(moves[-1][1], '"Phish Reports"')

    def test_phishing_is_trashed_and_sender_on_app_blocklist(self):
        finding = self._finding()
        results = self.actor.auto_act(finding)
        self.assertTrue(all(r["ok"] for r in results), results)
        self.assertEqual(len(self.imap.folders["Trash"]), 1)
        self.assertEqual(len(self.imap.folders["Phish Reports"]), 1)  # the friend's mail is untouched
        row = database.get_blocked_sender(self.conn, "bad@evil.example")
        self.assertIsNone(row["gmail_filter_id"])

    def test_finds_message_after_other_mail_moved(self):
        finding = self._finding()
        del self.imap.folders["Phish Reports"][1]  # an earlier message disappears; UIDs don't shift
        self.assertTrue(self.actor.move_to_trash(finding)["ok"])
        (raw, _), = self.imap.folders["Trash"].values()
        self.assertIn(b"<bad1@evil.example>", raw)

    def test_missing_message_is_reported(self):
        finding = self._finding()
        del self.imap.folders["Phish Reports"][int(self.uid)]
        result = self.actor.move_to_trash(finding)
        self.assertFalse(result["ok"])
        self.assertIn("not found", result["message"])

    def test_server_without_move_uses_copy_and_expunges_only_that_uid(self):
        self.imap.capabilities = ("IMAP4REV1", "UIDPLUS")
        finding = self._finding()
        self.assertTrue(self.actor.move_to_trash(finding)["ok"], )
        self.assertEqual(list(self.imap.folders["Phish Reports"]), [1])
        self.assertEqual(len(self.imap.folders["Trash"]), 1)

    def test_copy_without_uidplus_expunges_leftover(self):
        self.imap.capabilities = ("IMAP4REV1",)
        finding = self._finding(verdict="likely_benign", category="spam")
        self.assertTrue(self.actor.move_to_spam(finding)["ok"])
        self.assertEqual(list(self.imap.folders["Phish Reports"]), [1])  # only the friend's mail is left
        self.assertEqual(len(self.imap.folders["Bulk"]), 1)

    def test_leftover_not_expunged_when_other_mail_is_marked_deleted(self):
        self.imap.capabilities = ("IMAP4REV1",)
        self.imap.folders["Phish Reports"][1][1].add("\\Deleted")  # someone else's pending delete
        finding = self._finding(verdict="likely_benign", category="spam")
        result = self.actor.move_to_spam(finding)
        self.assertFalse(result["ok"])
        self.assertIn("still in this folder", result["message"])
        self.assertIn(1, self.imap.folders["Phish Reports"])  # the other message was not purged

    def test_move_reported_ok_but_email_still_there_is_an_error(self):
        self.imap.lie_about_move = True
        finding = self._finding(verdict="likely_benign", category="spam")
        result = self.actor.move_to_spam(finding)
        self.assertFalse(result["ok"])
        self.assertIsNone(database.get_finding(self.conn, finding["id"])["mail_state"])

    def test_quote_mailbox(self):
        self.assertEqual(quote_mailbox("Phish Reports"), '"Phish Reports"')
        self.assertEqual(quote_mailbox('"Phish Reports"'), '"Phish Reports"')
        self.assertEqual(quote_mailbox('a"b'), '"a\\"b"')


class _Analyzer:
    def __init__(self, analysis):
        self.analysis = analysis
        self.calls = 0

    def analyze(self, *_):
        self.calls += 1
        return dict(self.analysis)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)  # logs/*.json go here
        self.conn = _db(self)
        self.g = FakeGmail()

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def _email(self, mid="m1", sender="Bad Guy <bad@evil.example>"):
        self.g.labels[mid] = {"INBOX", "UNREAD"}
        return EmailMessage(id=mid, thread_id="t", subject="Reset your password", sender=sender, date="d",
                            body_text="no links here", source="gmail", mailbox="me@gmail.com",
                            message_id=f"<{mid}@evil.example>")

    def test_process_email_acts_on_high_confidence_phishing(self):
        actor = mail_actions.MailActor(self.conn, gmail_service=self.g)
        analyzer = _Analyzer({"verdict": "malicious", "category": "phishing", "confidence": "high"})
        pipeline._process_email(self._email(), None, None, analyzer, self.conn, None, None, mail_actor=actor)
        self.assertIn("TRASH", self.g.labels["m1"])
        self.assertIsNotNone(database.get_blocked_sender(self.conn, "bad@evil.example"))

    def test_blocked_sender_is_trashed_without_analysis(self):
        database.add_blocked_sender(self.conn, "bad@evil.example", "gmail")
        actor = mail_actions.MailActor(self.conn, gmail_service=self.g)
        email = self._email("m2")
        self.assertTrue(actor.is_blocked(email.sender))
        pipeline._handle_blocked_sender(email, self.conn, actor)
        self.assertIn("TRASH", self.g.labels["m2"])
        finding = database.list_findings(self.conn)[0]
        self.assertEqual(finding["category"], "blocked_sender")
        self.assertEqual(finding["mail_state"], "trash")


class MigrationTests(unittest.TestCase):
    def test_existing_database_gains_new_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "old.db")
            old = sqlite3.connect(path)
            old.executescript("""CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL,
                email_id TEXT NOT NULL, subject TEXT, sender TEXT, email_date TEXT, verdict TEXT NOT NULL,
                confidence TEXT, summary TEXT, key_indicators TEXT, recommended_action TEXT, extracted_iocs TEXT,
                enrichment TEXT, processed_at TEXT NOT NULL);
                INSERT INTO findings (source, email_id, verdict, processed_at) VALUES ('yahoo', '1', 'malicious', 'x');""")
            old.commit()
            old.close()
            conn = database.connect(path)
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
            self.assertTrue({"category", "message_id", "mail_folder", "uidvalidity", "mail_state"} <= cols)
            self.assertEqual(database.list_blocked_senders(conn), [])
            self.assertEqual(len(database.list_findings(conn)), 1)
            conn.close()


class DashboardTests(unittest.TestCase):
    def setUp(self):
        from dashboard import app as dashboard_app
        self.app_mod = dashboard_app
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "f.db")
        self.g = FakeGmail()
        self.g.labels["m1"] = {"INBOX"}
        conn = database.connect(self.db_path)
        self.fid = _insert(conn, confidence="medium")["id"]
        self.old_yahoo = _insert(conn, source="yahoo", email_id="3", confidence="medium")["id"]
        conn.close()
        self.patches = [
            mock.patch.object(dashboard_app, "DB_PATH", self.db_path),
            mock.patch.object(dashboard_app.mail_actions, "dashboard_actor",
                              side_effect=lambda conn, root: mail_actions.MailActor(conn, gmail_service=self.g)),
        ]
        for p in self.patches:
            p.start()
        self.client = dashboard_app.app.test_client()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self._tmp.cleanup()

    def test_index_shows_action_buttons_and_suggestion(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn("mailAction(%d, 'trash'" % self.fid, html)
        self.assertIn("Suggested: delete + block", html)
        self.assertIn("Not available for this older email", html)  # pre-feature Yahoo row

    def test_buttons_change_the_mailbox_and_undo(self):
        r = self.client.post(f"/api/findings/{self.fid}/mail-action", json={"action": "trash"})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertIn("TRASH", self.g.labels["m1"])
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn("In Trash", html)
        r = self.client.post(f"/api/findings/{self.fid}/mail-action", json={"action": "restore"})
        self.assertTrue(r.get_json()["ok"])
        self.assertNotIn("TRASH", self.g.labels["m1"])

    def test_block_and_unblock_from_dashboard(self):
        r = self.client.post(f"/api/findings/{self.fid}/mail-action", json={"action": "block"})
        self.assertTrue(r.get_json()["ok"], r.get_json())
        page = self.client.get("/blocked").get_data(as_text=True)
        self.assertIn("bad@evil.example", page)
        r = self.client.post("/api/blocked/unblock", json={"address": "bad@evil.example"})
        self.assertTrue(r.get_json()["ok"])
        self.assertEqual(self.g.filter_store, {})

    def test_bulk_delete_and_block(self):
        conn = database.connect(self.db_path)
        self.g.labels["m2"] = {"INBOX"}
        self.g.labels["m3"] = {"INBOX"}
        second = _insert(conn, email_id="m2")["id"]  # same sender as the first
        forged = _insert(conn, email_id="m3", sender="PayPal <service@paypal.com>", auth={"dmarc": "fail"})["id"]
        conn.close()
        r = self.client.post("/api/findings/bulk-mail-action",
                             json={"ids": [self.fid, second, forged, self.old_yahoo], "action": "block_and_trash"})
        body = r.get_json()
        self.assertEqual(body["ok"], 2, body)
        self.assertEqual(body["failed"], 2)  # forged sender not blocked + old Yahoo row
        for mid in ("m1", "m2", "m3"):
            self.assertIn("TRASH", self.g.labels[mid])  # the forged one is still trashed
        self.assertEqual(len(self.g.filter_store), 1)  # one filter for the repeated sender
        by_id = {x["id"]: x for x in body["results"]}
        self.assertIn("forged", by_id[forged]["message"])

        r = self.client.post("/api/findings/bulk-mail-action", json={"ids": [self.fid, second], "action": "restore"})
        self.assertEqual(r.get_json()["ok"], 2)
        self.assertNotIn("TRASH", self.g.labels["m1"])

    def test_bulk_spam_and_bad_action(self):
        r = self.client.post("/api/findings/bulk-mail-action", json={"ids": [self.fid], "action": "spam"})
        self.assertEqual(r.get_json()["ok"], 1)
        self.assertIn("SPAM", self.g.labels["m1"])
        self.assertEqual(self.client.post("/api/findings/bulk-mail-action",
                                          json={"ids": [self.fid], "action": "nuke"}).status_code, 400)

    def test_index_has_bulk_bar(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn('id="bulk-action"', html)
        self.assertIn("Select all (2)", html)

    def test_old_yahoo_finding_is_refused(self):
        r = self.client.post(f"/api/findings/{self.old_yahoo}/mail-action", json={"action": "trash"})
        self.assertEqual(r.status_code, 409)

    def test_bad_requests(self):
        self.assertEqual(self.client.post(f"/api/findings/{self.fid}/mail-action", json={"action": "nuke"}).status_code, 400)
        self.assertEqual(self.client.post("/api/findings/9999/mail-action", json={"action": "trash"}).status_code, 404)


if __name__ == "__main__":
    unittest.main()
