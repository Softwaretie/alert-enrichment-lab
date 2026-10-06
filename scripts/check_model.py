"""Live test of the Claude step: sends ONE made-up phishing email to the model.

    python scripts/check_model.py          (or double-click check_model.bat)

Confirms that your Anthropic API key works, that the model named in
CLAUDE_MODEL exists, and that its answer can be read by the pipeline. It does
not touch your mailbox or any other service, and it uses a fake email with a
harmless fake attachment, so it costs one small API request.
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from src import ioc_extractor  # noqa: E402
from src.attachments import analyze_attachments, merge_into_iocs  # noqa: E402
from src.attachments.models import RawAttachment  # noqa: E402
from src.claude_analyzer import ClaudeAnalyzer  # noqa: E402
from src.config import _get_secret  # noqa: E402
from src.email_message import EmailMessage  # noqa: E402
from tests.support import make_pe  # noqa: E402

BODY = ("Your invoice is attached. Open invoice.pdf.exe and sign in at "
        "http://account-verify.example.invalid/login within 24 hours or your account will be closed.")


def main() -> int:
    api_key = _get_secret("ANTHROPIC_API_KEY")
    if not api_key:
        print("No Anthropic API key saved. Run setup.bat (or scripts/setup_secrets.py) first.")
        return 1
    model = os.environ.get("CLAUDE_MODEL", "claude-sonnet-5-5")
    print(f"Model: {model}")
    print("Sending one fake phishing email to Claude ...\n")

    exe = make_pe(b"powershell -enc AAAA http://payload.example.invalid/x.bin\x00")
    email = EmailMessage(id="test", thread_id="test", subject="Urgent: unpaid invoice",
                         sender="billing@acc0unts-support.example.invalid", date="today", body_text=BODY, source="test")
    report = analyze_attachments([RawAttachment("invoice.pdf.exe", "", exe, len(exe))], BODY)
    iocs = ioc_extractor.extract(email.body_text, email.sender)
    merge_into_iocs(iocs, report)
    email.attachment_names = ["invoice.pdf.exe"]

    try:
        result = ClaudeAnalyzer(api_key, model).analyze(email, iocs, {"attachments": report})
    except Exception as exc:  # noqa: BLE001 - show the real reason plainly
        print(f"FAILED: {type(exc).__name__}: {exc}\n")
        print("Common causes: wrong model name in CLAUDE_MODEL, an invalid or unfunded API key,")
        print("or no internet connection. Model names: https://docs.claude.com/en/docs/about-claude/models")
        return 1

    print(f"Verdict:    {result.get('verdict')}  (confidence: {result.get('confidence')})")
    print(f"Summary:    {result.get('summary')}")
    print(f"Action:     {result.get('recommended_action')}")
    if result.get("raw_response"):
        print("\nWARNING: the model answered, but the reply could not be read as the expected JSON.")
        return 1
    ok = result.get("verdict") in ("malicious", "suspicious")
    print("\nPASS: the model answered and flagged the fake phish." if ok else
          "\nThe model answered, but did not flag an obvious fake phish - worth a look.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
