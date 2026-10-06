"""Tests for attachment download (Gmail/Yahoo), pipeline wiring, the prompt, and the dashboard."""
import base64
import os
import tempfile
import unittest
from email import message_from_bytes, policy
from email.message import EmailMessage as MimeMessage
from unittest import mock

try:
    from src import database, gmail_client, pipeline
except ImportError as exc:  # project dependencies (requirements.txt) not installed
    raise unittest.SkipTest(f"integration tests need the project's requirements installed: {exc}")
from src.attachments.models import RawAttachment
from src.claude_analyzer import _prompt_enrichment
from src.email_message import EmailMessage
from src.yahoo_client import YahooListener
from tests.support import make_docx, make_pe, make_zip


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def b64_nopad(data: bytes) -> str:
    return b64(data).rstrip("=")  # the attachment decoder must cope with missing padding too


class FakeGmailService:
    """Just enough of the Gmail API surface for message + attachment fetching."""

    def __init__(self, message: dict, attachments: dict):
        self._message, self._attachments, self.attachment_calls = message, attachments, []

    def users(self):
        return self

    def messages(self):
        return self

    def attachments(self):
        return _Attachments(self)

    def get(self, userId, id, format=None):
        return mock.Mock(execute=lambda: self._message)


class _Attachments:
    def __init__(self, service):
        self._service = service

    def get(self, userId, messageId, id):
        self._service.attachment_calls.append(id)
        if id == "BOOM":
            return mock.Mock(execute=mock.Mock(side_effect=RuntimeError("network")))
        return mock.Mock(execute=lambda: {"data": b64_nopad(self._service._attachments[id])})


def gmail_payload(parts):
    return {"mimeType": "multipart/mixed", "headers": [{"name": "Subject", "value": "Invoice"},
                                                        {"name": "From", "value": "x@example.org"}],
            "parts": [{"mimeType": "text/plain", "filename": "", "body": {"data": b64(b"see attached")}}] + parts}


class GmailAttachmentTests(unittest.TestCase):
    def test_downloads_in_memory_and_reports_skips(self):
        exe, doc = make_pe(), make_docx()
        parts = [
            {"filename": "a.exe", "mimeType": "application/octet-stream", "body": {"attachmentId": "A", "size": len(exe)}},
            {"filename": "tiny.txt", "mimeType": "text/plain", "body": {"data": b64(b"hello"), "size": 5}},
            {"filename": "huge.iso", "mimeType": "application/x-iso", "body": {"attachmentId": "H", "size": 90_000_000}},
            {"filename": "broken.bin", "mimeType": "application/octet-stream", "body": {"attachmentId": "BOOM", "size": 10}},
            {"mimeType": "multipart/related", "filename": "", "body": {}, "parts": [
                {"filename": "nested.docx", "mimeType": "application/zip", "body": {"attachmentId": "D", "size": len(doc)}}]},
        ]
        service = FakeGmailService({"id": "m1", "threadId": "t1", "payload": gmail_payload(parts)},
                                   {"A": exe, "D": doc})
        msg = gmail_client.get_message(service, "m1", mailbox="me@example.org", max_attachment_bytes=25 * 1024 * 1024)

        by_name = {a.filename: a for a in msg.attachments}
        self.assertEqual(by_name["a.exe"].data, exe)
        self.assertEqual(by_name["tiny.txt"].data, b"hello")          # inline data, no API call
        self.assertEqual(by_name["nested.docx"].data, doc)            # found inside a nested multipart
        self.assertIn("larger than", by_name["huge.iso"].skipped_reason)
        self.assertIn("download failed", by_name["broken.bin"].skipped_reason)
        self.assertNotIn("H", service.attachment_calls)                # oversized file was never downloaded
        self.assertEqual(msg.attachment_names, ["a.exe", "tiny.txt", "huge.iso", "broken.bin", "nested.docx"])

    def test_disabled_downloads_nothing(self):
        parts = [{"filename": "a.exe", "mimeType": "x", "body": {"attachmentId": "A", "size": 5}}]
        service = FakeGmailService({"id": "m1", "threadId": "t1", "payload": gmail_payload(parts)}, {"A": b"12345"})
        msg = gmail_client.get_message(service, "m1", max_attachment_bytes=0)
        self.assertEqual(msg.attachments, [])
        self.assertEqual(service.attachment_calls, [])
        self.assertEqual(msg.attachment_names, ["a.exe"])

    def test_attachment_count_limit(self):
        parts = [{"filename": f"f{i}.txt", "mimeType": "text/plain", "body": {"data": b64(b"x"), "size": 1}}
                 for i in range(14)]
        service = FakeGmailService({"id": "m1", "threadId": "t1", "payload": gmail_payload(parts)}, {})
        msg = gmail_client.get_message(service, "m1", max_attachment_bytes=1024)
        self.assertEqual(sum(1 for a in msg.attachments if a.data), 10)
        self.assertEqual(sum(1 for a in msg.attachments if a.skipped_reason), 4)


class YahooAttachmentTests(unittest.TestCase):
    def _mime(self):
        m = MimeMessage()
        m["From"], m["To"], m["Subject"] = "a@example.org", "me@yahoo.com", "Fwd: invoice"
        m.set_content("body")
        m.add_attachment(make_pe(), maintype="application", subtype="octet-stream", filename="setup.exe")
        m.add_attachment(b"x" * 50_000, maintype="application", subtype="octet-stream", filename="big.bin")
        inner = MimeMessage()
        inner["Subject"] = "inner"
        inner.set_content("hi http://evil.example/x")
        m.add_attachment(inner)
        return message_from_bytes(m.as_bytes(), policy=policy.default)

    def test_collects_bytes_and_attached_mail(self):
        atts = YahooListener._raw_attachments(self._mime(), 25 * 1024 * 1024)
        by_name = {a.filename: a for a in atts}
        self.assertEqual(by_name["setup.exe"].data, make_pe())
        self.assertIn(b"Subject: inner", by_name["attached_message.eml"].data)

    def test_size_limit_and_disabled(self):
        atts = YahooListener._raw_attachments(self._mime(), 10_000)
        big = next(a for a in atts if a.filename == "big.bin")
        self.assertEqual(big.data, b"")
        self.assertIn("larger than", big.skipped_reason)
        self.assertEqual(YahooListener._raw_attachments(self._mime(), 0), [])


class FakeVT:
    def __init__(self):
        self.urls, self.hashes = [], []

    def check_url(self, url):
        self.urls.append(url)
        return {"found": False}

    def check_domain(self, d):
        return {"found": False}

    def check_ip(self, ip):
        return {"found": False}

    def check_hash(self, sha):
        self.hashes.append(sha)
        return {"found": True, "malicious": 41, "suspicious": 0, "harmless": 0, "undetected": 20,
                "threat_label": "trojan.example"}


class FakeAbuse:
    def check_ip(self, ip):
        return {"found": False}


class FakeAnalyzer:
    def __init__(self):
        self.seen = None

    def analyze(self, email, iocs, enrichment):
        self.seen = {"iocs": iocs, "enrichment": enrichment}
        return {"verdict": "malicious", "confidence": "high", "summary": "s", "key_indicators": [],
                "recommended_action": "block"}


class PipelineTests(unittest.TestCase):
    def test_attachments_flow_through_enrichment_and_storage(self):
        docm = make_docx(macro_source='Sub AutoOpen()\r\n Shell "cmd /c x"\r\nEnd Sub',
                         external_rels=[("hyperlink", "https://phish.example/login")])
        email = EmailMessage(id="e1", thread_id="t", subject="Invoice", sender="x@evil.example", date="today",
                             body_text="The password is 1234. Open the file.", source="gmail", mailbox="me@x",
                             attachments=[RawAttachment("invoice.docm", "application/vnd.ms-word", docm, len(docm))])
        vt, analyzer = FakeVT(), FakeAnalyzer()
        conn = database.connect(":memory:")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(pipeline, "LOGS_DIR", tmp):
            pipeline._process_email(email, vt, FakeAbuse(), analyzer, conn, None, None)
            self.assertEqual(len(os.listdir(tmp)), 1)

        self.assertEqual(email.attachments, [])                              # bytes released
        enrichment = analyzer.seen["enrichment"]
        report = enrichment["attachments"]
        self.assertEqual(report["static_risk"], "high")
        self.assertEqual(report["files"][0]["virustotal"]["malicious"], 41)  # hash looked up
        self.assertIn("https://phish.example/login", vt.urls)                # URL inside file enriched like a body link
        self.assertIn("https://phish.example/login", analyzer.seen["iocs"].urls)

        row = database.list_findings(conn)[0]
        self.assertEqual(row["enrichment"]["attachments"]["files"][0]["filename"], "invoice.docm")
        self.assertIn("https://phish.example/login", database.get_finding(conn, row["id"])["extracted_iocs"]["urls"])
        conn.close()

    def test_email_without_attachments_is_unchanged(self):
        email = EmailMessage(id="e2", thread_id="t", subject="s", sender="a@b.c", date="d",
                             body_text="no links here", source="yahoo")
        analyzer = FakeAnalyzer()
        conn = database.connect(":memory:")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(pipeline, "LOGS_DIR", tmp):
            pipeline._process_email(email, FakeVT(), FakeAbuse(), analyzer, conn, None, None)
        self.assertNotIn("attachments", analyzer.seen["enrichment"])
        conn.close()

    def test_attachment_only_email_still_gets_enriched(self):
        docx = make_docx(external_rels=[("hyperlink", "https://only-in-file.example/x")])
        email = EmailMessage(id="e3", thread_id="t", subject="s", sender="a@b.c", date="d", body_text="see file",
                             source="gmail", attachments=[RawAttachment("a.docx", "", docx, len(docx))])
        vt = FakeVT()
        conn = database.connect(":memory:")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(pipeline, "LOGS_DIR", tmp):
            pipeline._process_email(email, vt, FakeAbuse(), FakeAnalyzer(), conn, None, None)
        conn.close()
        self.assertEqual(vt.urls, ["https://only-in-file.example/x"])


class GmailSignInTests(unittest.TestCase):
    """An expired saved sign-in (Google's 7-day limit for apps in Testing mode) must
    lead to a fresh browser sign-in, not a crash."""

    def _run(self, token_contents, creds_obj):
        with tempfile.TemporaryDirectory() as tmp:
            token = os.path.join(tmp, "token.json")
            secret = os.path.join(tmp, "credentials.json")
            open(secret, "w").write("{}")
            if token_contents is not None:
                open(token, "w").write(token_contents)
            fresh = mock.Mock(valid=True)
            fresh.to_json.return_value = '{"fresh": true}'
            flow = mock.Mock()
            flow.run_local_server.return_value = fresh
            with mock.patch.object(gmail_client.Credentials, "from_authorized_user_file", create=True,
                                   return_value=creds_obj), \
                 mock.patch.object(gmail_client.InstalledAppFlow, "from_client_secrets_file", create=True,
                                   return_value=flow), \
                 mock.patch.object(gmail_client, "build", return_value="service"):
                service = gmail_client.authenticate(secret, token)
            with open(token) as f:
                saved = f.read()
        return service, flow, saved

    def test_expired_refresh_token_falls_back_to_browser_sign_in(self):
        old = mock.Mock(valid=False, expired=True, refresh_token="r")
        old.refresh.side_effect = gmail_client.RefreshError("invalid_grant: Bad Request")
        service, flow, saved = self._run("{}", old)
        self.assertEqual(service, "service")
        flow.run_local_server.assert_called_once()
        self.assertEqual(saved, '{"fresh": true}')

    def test_working_refresh_does_not_open_browser(self):
        old = mock.Mock(valid=False, expired=True, refresh_token="r")
        old.to_json.return_value = '{"refreshed": true}'
        def refresh(_request):
            old.valid = True
        old.refresh.side_effect = refresh
        _, flow, saved = self._run("{}", old)
        flow.run_local_server.assert_not_called()
        self.assertEqual(saved, '{"refreshed": true}')

    def test_damaged_token_file_is_replaced(self):
        with mock.patch.object(gmail_client.Credentials, "from_authorized_user_file", create=True,
                               side_effect=ValueError("bad")):
            with tempfile.TemporaryDirectory() as tmp:
                secret = os.path.join(tmp, "credentials.json")
                token = os.path.join(tmp, "token.json")
                open(secret, "w").write("{}")
                open(token, "w").write("garbage")
                fresh = mock.Mock(valid=True)
                fresh.to_json.return_value = "{}"
                flow = mock.Mock()
                flow.run_local_server.return_value = fresh
                with mock.patch.object(gmail_client.InstalledAppFlow, "from_client_secrets_file", create=True,
                                       return_value=flow), mock.patch.object(gmail_client, "build", return_value="s"):
                    self.assertEqual(gmail_client.authenticate(secret, token), "s")


class MailboxIsolationTests(unittest.TestCase):
    def test_gmail_sign_in_failure_still_checks_yahoo(self):
        config = mock.Mock(virustotal_api_key="v", abuseipdb_api_key="a", anthropic_api_key="k",
                           claude_model="m", urlscan_configured=False, findings_db_path=":memory:",
                           max_attachment_bytes=0, yahoo_configured=True)
        with mock.patch.object(pipeline, "VirusTotalClient"), mock.patch.object(pipeline, "AbuseIPDBClient"), \
             mock.patch.object(pipeline, "ClaudeAnalyzer"), \
             mock.patch.object(pipeline, "_run_gmail", side_effect=RuntimeError("invalid_grant")), \
             mock.patch.object(pipeline, "_run_yahoo") as run_yahoo:
            result = pipeline.run(config, max_results=5)
        run_yahoo.assert_called_once()
        self.assertEqual(result.failures, [{"source": "gmail", "message_id": "(mailbox)", "error": "invalid_grant"}])


class DashboardPortTests(unittest.TestCase):
    def test_detects_a_port_that_is_already_taken(self):
        import socket
        from dashboard import app as dashboard_app
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            self.assertTrue(dashboard_app.port_in_use(port))
        self.assertFalse(dashboard_app.port_in_use(port))


class PromptTests(unittest.TestCase):
    def test_prompt_payload_is_trimmed(self):
        members = [{"filename": f"m{i}.txt", "md5": "x", "sha1": "y", "sha256": "z", "urls": [f"http://a/{j}" for j in range(30)]}
                   for i in range(40)]
        enrichment = {"attachments": {"count": 1, "files": [{"filename": "a.zip", "md5": "x", "members": members}]}}
        slim = _prompt_enrichment(enrichment)["attachments"]["files"][0]
        self.assertEqual(len(slim["members"]), 15)
        self.assertEqual(slim["members_omitted"], 25)
        self.assertNotIn("md5", slim["members"][0])
        self.assertEqual(len(slim["members"][0]["urls"]), 10)
        self.assertEqual(len(enrichment["attachments"]["files"][0]["members"]), 40)  # original untouched


class DashboardTests(unittest.TestCase):
    def test_attachment_panel_renders_and_escapes(self):
        from dashboard import app as dashboard_app

        zipped = make_zip({"<img src=x onerror=alert(1)>.exe": make_pe()})
        from src.attachments import RawAttachment as Raw, analyze_attachments
        report = analyze_attachments([Raw("<b>evil</b>.zip", "", zipped, len(zipped))], "the password is 1")
        finding = {"source": "gmail", "mailbox": "me@x", "email_id": "1", "subject": "s", "sender": "a@b.c",
                   "date": "d", "claude_analysis": {"verdict": "malicious", "confidence": "high", "summary": "sum",
                                                    "key_indicators": [], "recommended_action": "x"},
                   "extracted_iocs": {}, "enrichment": {"attachments": report}, "processed_at": "2026-10-05T00:00:00+00:00"}
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "f.db")
            conn = database.connect(db_path)
            database.insert_finding(conn, finding)
            conn.close()
            with mock.patch.object(dashboard_app, "DB_PATH", db_path):
                html = dashboard_app.app.test_client().get("/").get_data(as_text=True)
        self.assertIn("Attachments", html)
        self.assertIn("&lt;b&gt;evil&lt;/b&gt;.zip", html)          # filename is escaped
        self.assertNotIn("<b>evil</b>", html)
        self.assertNotIn("<img src=x onerror", html)                # member name is escaped too
        self.assertIn("high static risk", html)
        self.assertIn("Windows executable", html)                   # nested member rendered


if __name__ == "__main__":
    unittest.main()
