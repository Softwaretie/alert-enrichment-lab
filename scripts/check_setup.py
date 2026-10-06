"""Health check: tells you, in plain English, whether everything is set up.

    python scripts/check_setup.py          (or double-click check_setup.bat)

This only LOOKS at your setup -- it never prints a secret, never contacts any
service, and never changes anything. Each problem comes with the exact step
that fixes it. Exit code is 0 when everything required is ready, 1 otherwise.
"""
import importlib
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)  # relative paths in .env (credentials.json, findings.db) are relative to the project

MIN_PYTHON = (3, 10)

# (import name, pip name)
_PACKAGES = [
    ("googleapiclient", "google-api-python-client"),
    ("google_auth_oauthlib", "google-auth-oauthlib"),
    ("google_auth_httplib2", "google-auth-httplib2"),
    ("anthropic", "anthropic"),
    ("requests", "requests"),
    ("dotenv", "python-dotenv"),
    ("flask", "Flask"),
    ("apscheduler", "APScheduler"),
    ("slack_sdk", "slack_sdk"),
    ("keyring", "keyring"),
]

_REQUIRED_KEYS = [
    ("ANTHROPIC_API_KEY", "Anthropic (Claude) API key"),
    ("VIRUSTOTAL_API_KEY", "VirusTotal API key"),
    ("ABUSEIPDB_API_KEY", "AbuseIPDB API key"),
]
_OPTIONAL_KEYS = [
    ("URLSCAN_API_KEY", "urlscan.io API key (link sandboxing)"),
    ("SLACK_BOT_TOKEN", "Slack bot token (notifications)"),
    ("YAHOO_APP_PASSWORD", "Yahoo app password"),
]

_problems = []  # required things that are not ready


def ok(msg):
    print(f"  [ OK ] {msg}")


def bad(msg, fix):
    print(f"  [FAIL] {msg}")
    print(f"         Fix: {fix}")
    _problems.append(msg)


def note(msg, hint=""):
    print(f"  [ -- ] {msg}")
    if hint:
        print(f"         {hint}")


def check_python():
    print("Python")
    v = sys.version_info
    if (v.major, v.minor) >= MIN_PYTHON:
        ok(f"Python {v.major}.{v.minor}.{v.micro}")
    else:
        bad(f"Python {v.major}.{v.minor} is too old (need {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer)",
            "install a newer Python (see docs/SETUP_GUIDE.md, step 1), then run setup.bat again")
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    if in_venv:
        ok("running inside the project's private environment (.venv)")
    else:
        note("not running inside the project's private environment (.venv)",
             "Fine if you installed packages globally. Otherwise use the .bat files, which use .venv automatically.")


def check_packages():
    print("\nPython packages")
    missing = []
    for module, pip_name in _PACKAGES:
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(pip_name)
    if not missing:
        ok("all required packages are installed")
        return True
    bad("missing packages: " + ", ".join(missing),
        "double-click setup.bat (it installs everything), or run: python -m pip install -r requirements.txt")
    return False


def _has_secret(name):
    from src.config import _get_secret
    return bool(_get_secret(name))


def check_keys():
    print("\nAPI keys (only whether each one is saved -- the values are never shown)")
    for name, label in _REQUIRED_KEYS:
        if _has_secret(name):
            ok(f"{label} is saved")
        else:
            bad(f"{label} is missing", "run: python scripts/setup_secrets.py   (or double-click setup.bat)")
    for name, label in _OPTIONAL_KEYS:
        if _has_secret(name):
            ok(f"{label} is saved")
        else:
            note(f"{label}: not set (optional)")


def check_gmail():
    print("\nGmail")
    cred = os.environ.get("GMAIL_CREDENTIALS_PATH", "credentials.json")
    token = os.environ.get("GMAIL_TOKEN_PATH", "token.json")
    yahoo = bool(os.environ.get("YAHOO_EMAIL")) and _has_secret("YAHOO_APP_PASSWORD")
    if os.path.exists(cred):
        ok(f"{cred} found")
        if os.path.exists(token):
            ok(f"{token} found (you have signed in to Google before)")
            note("Google sign-ins expire after about 7 days while your Google app is in 'Testing' mode.",
                 "That's handled: if it has expired, the next run opens your browser to sign in again.")
        else:
            note(f"{token} not created yet",
                 "Normal before the first run: the first run opens your browser so you can sign in to Google once.")
    elif yahoo:
        note(f"{cred} not found, but Yahoo is configured",
             "Gmail will fail until you add it; run with: run_alerts.bat --no-gmail")
    else:
        bad(f"{cred} not found",
            "follow 'Step 4: Gmail' in docs/SETUP_GUIDE.md to download it, and put it in this folder")


def check_env_file():
    print("\nSettings file")
    if os.path.exists(".env"):
        ok(".env found")
    else:
        note(".env not created yet", "setup_secrets.py creates it for you; defaults work without it.")


def check_analyzer():
    print("\nAttachment analyzer (works offline)")
    try:
        from src.attachments import analyze_attachments
        from src.attachments.models import RawAttachment
        data = b"MZ" + b"\x00" * 100
        report = analyze_attachments([RawAttachment("invoice.pdf.exe", "", data, len(data))])
        if report["static_risk"] == "high":
            ok("self-test passed (a fake 'invoice.pdf.exe' was correctly flagged high risk)")
        else:
            bad("self-test gave an unexpected result", "re-download the project; a file may be damaged")
    except Exception as exc:  # noqa: BLE001 - this is a diagnostic, report anything
        bad(f"self-test crashed: {type(exc).__name__}: {exc}", "re-download the project; a file may be damaged")


def main():
    print("Alert Enrichment - setup check\n" + "=" * 34)
    check_python()
    packages_ok = check_packages()
    if packages_ok:
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except Exception:  # noqa: BLE001
            pass
        check_env_file()
        check_keys()
        check_gmail()
    check_analyzer()

    print("\n" + "=" * 34)
    if _problems:
        print(f"{len(_problems)} thing(s) need attention (see [FAIL] lines above).")
        print("Not sure what to do? Open docs/SETUP_GUIDE.md -> 'Something went wrong'.")
        return 1
    print("Everything required is ready. Try:  run_alerts.bat   then   run_dashboard.bat")
    return 0


if __name__ == "__main__":
    sys.exit(main())
