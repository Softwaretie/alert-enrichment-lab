"""Regression tests: crafted inputs must not make analysis slow.

Several of the patterns used to scan attachments (HTML tags, XML elements, PDF
streams, command lines) would take quadratic time on input like '<form <form
<form ...' with no closing '>'. A hostile attachment could then stall the whole
pipeline. Each case below used to (or easily could) take minutes; the budget is
generous so the tests only fail on a real regression, not a slow machine.
"""
import time
import unittest

from src.attachments.analyzer import analyze_file
from src.attachments.sniff import runnable_names, strip_tags
from tests.support import make_docx, make_zip

BUDGET_SECONDS = 6.0


class HostileInputTests(unittest.TestCase):
    def assert_fast(self, name, data, content_type=""):
        start = time.monotonic()
        result = analyze_file(name, data, content_type)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, BUDGET_SECONDS, f"{name}: {len(data)} bytes took {elapsed:.1f}s")
        self.assertTrue(result["analyzed"])
        return result

    def test_unclosed_html_tags(self):
        self.assert_fast("a.html", b"<html><body>" + b"<form " * 200_000)
        self.assert_fast("b.html", b"<html>" + b"<meta http-equiv=x " * 100_000)
        self.assert_fast("c.html", b"<html>" + b"<" * 2_000_000)

    def test_attached_email_with_tag_soup(self):
        eml = (b"From: a@example.org\r\nTo: b@example.org\r\nSubject: x\r\nContent-Type: text/html\r\n\r\n"
               + b"<" * 2_000_000)
        self.assert_fast("soup.eml", eml)

    def test_unclosed_xml_in_office_packages(self):
        rels = b"<Relationships>" + b"<Relationship " * 150_000
        self.assert_fast("a.docx", make_docx(extra={"word/_rels/document.xml.rels": rels}))
        doc = b"<w:document>" + b"<w:instrText " * 150_000
        self.assert_fast("b.docx", make_docx(document_xml=doc.decode()))
        sheet = b"<worksheet>" + b"<f " * 150_000
        self.assert_fast("c.xlsx", make_zip({"[Content_Types].xml": "<Types/>", "xl/workbook.xml": "<w/>",
                                              "xl/worksheets/sheet1.xml": sheet}))

    def test_pdf_stream_markers_without_end(self):
        self.assert_fast("a.pdf", b"%PDF-1.4\n" + b"stream\n" * 800_000)
        self.assert_fast("b.pdf", b"%PDF-1.4\n" + b"/URI (" * 300_000)
        self.assert_fast("c.pdf", b"%PDF-1.4\n/" + b"A" * 8_000_000)

    def test_scripts_and_binaries_with_repetitive_strings(self):
        self.assert_fast("a.ps1", b"certutil " * 800_000)
        self.assert_fast("b.bin", b"MZ" + b"a" * 8_000_000)
        self.assert_fast("c.bin", b"\x00" + b"a.b " * 2_000_000)
        self.assert_fast("d.rtf", b"{\\rtf1" + b"{\\*\\template " * 200_000)

    def test_enormous_filename(self):
        result = self.assert_fast("a" * 1_000_000 + ".pdf" + " " * 100_000 + ".exe", b"MZ")
        self.assertLess(len(result["filename"]), 600)

    def test_helpers_are_linear(self):
        start = time.monotonic()
        runnable_names("a" * 5_000_000 + ".exe")
        strip_tags("<" * 3_000_000)
        self.assertLess(time.monotonic() - start, BUDGET_SECONDS)

    def test_email_body_html_conversion_is_linear(self):
        from src.html_text import html_to_text
        start = time.monotonic()
        html_to_text("<" * 2_000_000)
        html_to_text("<a " * 500_000)
        self.assertLess(time.monotonic() - start, BUDGET_SECONDS)
        self.assertIn("http://x.example/y", html_to_text("<a href='http://x.example/y'>link</a>"))

    def test_runnable_names_still_works(self):
        names = runnable_names("copy C:\\temp\\setup.exe now, then run payload.js")
        self.assertTrue(any(n.endswith("setup.exe") for n in names))
        self.assertTrue(any(n.endswith("payload.js") for n in names))


if __name__ == "__main__":
    unittest.main()
