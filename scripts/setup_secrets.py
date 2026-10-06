"""Guided setup for the alert enrichment system.

Run this once to configure everything -- the three required API keys, and
any optional integrations you want (Slack notifications, Yahoo Mail, URL
sandboxing). For each one, this prints what it's for and exactly where to
get it before asking you to paste it in, so you don't need to cross-
reference the README to get started.

    python scripts/setup_secrets.py

Secrets are stored in your OS credential store (Windows Credential Manager /
macOS Keychain / Linux Secret Service) via `keyring`, not as plaintext in a
file. Non-secret companion settings (like a Slack channel ID) are written
straight to .env, which this creates from .env.example if it doesn't exist
yet. Safe to re-run any time -- existing values show as defaults you can
keep by just pressing Enter, and anything you skip stays unconfigured
without breaking the rest of the app.
"""
import getpass
import os
import shutil
import sys

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _PROJECT_ROOT)

import keyring
from dotenv import load_dotenv

from src.config import SERVICE_NAME

_ENV_PATH = os.path.join(_PROJECT_ROOT, ".env")
_ENV_EXAMPLE_PATH = os.path.join(_PROJECT_ROOT, ".env.example")


def _ensure_env_file() -> None:
    if not os.path.exists(_ENV_PATH) and os.path.exists(_ENV_EXAMPLE_PATH):
        shutil.copy(_ENV_EXAMPLE_PATH, _ENV_PATH)
        print("Created .env from .env.example.\n")
    load_dotenv(_ENV_PATH)


def _prompt_secret(prompt: str) -> str:
    """Hidden input via getpass, falling back to plain (visible) input if
    the terminal doesn't support hidden entry -- a crash here is a much
    worse first-run experience than an unmasked keystroke or two."""
    try:
        return getpass.getpass(f"{prompt}: ").strip()
    except Exception:
        print("  (hidden input isn't available in this terminal -- your typing will be visible)")
        return input(f"{prompt}: ").strip()


def _prompt_plain(prompt: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    value = input(f"{prompt}{hint}: ").strip()
    return value or default


def _existing_secret(env_name: str) -> str:
    return keyring.get_password(SERVICE_NAME, env_name) or os.environ.get(env_name, "")


def _store_secret(env_name: str, value: str) -> None:
    keyring.set_password(SERVICE_NAME, env_name, value)


def _set_env_var(key: str, value: str) -> None:
    """Update key=value in .env in place, preserving everything else;
    appends a new line if the key isn't there yet."""
    lines = []
    if os.path.exists(_ENV_PATH):
        with open(_ENV_PATH, encoding="utf-8") as f:
            lines = f.readlines()

    for i, line in enumerate(lines):
        if line.strip().startswith(f"{key}="):
            lines[i] = f"{key}={value}\n"
            break
    else:
        lines.append(f"{key}={value}\n")

    with open(_ENV_PATH, "w", encoding="utf-8") as f:
        f.writelines(lines)


def _ask_yes_no(prompt: str) -> bool:
    return input(f"{prompt} [y/N]: ").strip().lower() == "y"


def _setup_key(env_name: str, label: str, why: str, url: str, required: bool) -> None:
    existing = _existing_secret(env_name)
    print(f"\n{label}{' (required)' if required else ''}")
    print(f"  {why}")
    print(f"  Get one at: {url}")
    hint = " [Enter to keep existing]" if existing else " (Enter to skip)"
    value = _prompt_secret(f"  Paste key{hint}")
    if not value:
        value = existing
    if not value:
        note = "you'll need this before running main.py" if required else "skipping this integration"
        print(f"  Skipped -- {note}.")
        return
    _store_secret(env_name, value)
    print("  Stored.")


def setup_gmail() -> None:
    print("=" * 64)
    print("Gmail (required) -- this is a downloaded file, not a pasted key")
    print("=" * 64)
    print("1. Go to https://console.cloud.google.com/, create/reuse a project,")
    print("   and enable the Gmail API.")
    print("2. Under APIs & Services > Credentials, create an OAuth client ID")
    print("   (type: Desktop app), then download it as credentials.json into")
    print(f"   this project's folder: {_PROJECT_ROOT}")
    print("3. Create a Gmail label (e.g. 'phishing-reports') to file forwarded")
    print("   reports into -- that's what main.py polls by default.")
    print("   (Exact clicks for all three steps: docs/SETUP_GUIDE.md, 'Step 4: Gmail'.)")
    input("\nPress Enter once credentials.json is in place (or to skip for now)...")


def setup_required() -> None:
    print("\n" + "=" * 64)
    print("Required API keys -- the pipeline can't run without these three")
    print("=" * 64)
    _setup_key(
        "ANTHROPIC_API_KEY", "Anthropic (Claude) API key",
        "Claude reads each alert and decides the verdict.",
        "https://console.anthropic.com/settings/keys", required=True,
    )
    _setup_key(
        "VIRUSTOTAL_API_KEY", "VirusTotal API key",
        "Checks URLs/domains/IPs/file hashes against known threat intel.",
        "https://www.virustotal.com/gui/my-apikey", required=True,
    )
    _setup_key(
        "ABUSEIPDB_API_KEY", "AbuseIPDB API key",
        "Checks IP addresses for abuse reports.",
        "https://www.abuseipdb.com/account/api", required=True,
    )


def setup_slack() -> None:
    print("\n--- Slack notifications (optional) ---")
    print("Posts each triage verdict to a Slack channel.")
    if not _ask_yes_no("Set up Slack now?"):
        return
    print("1. Create an app at https://api.slack.com/apps, add the chat:write")
    print("   OAuth scope, install it to your workspace.")
    print("2. Invite the bot to your target channel: /invite @YourBotName")
    print("   (posting fails with not_in_channel until it's a member).")
    _setup_key(
        "SLACK_BOT_TOKEN", "Bot User OAuth Token",
        "Lets the bot post messages.", "https://api.slack.com/apps", required=False,
    )
    channel_id = _prompt_plain(
        "  Channel ID (right-click the channel -> View channel details, starts with C)"
    )
    if channel_id:
        _set_env_var("SLACK_CHANNEL_ID", channel_id)
        print("  Saved to .env.")


def setup_yahoo() -> None:
    print("\n--- Yahoo Mail (optional) ---")
    print("Pulls phishing reports from a Yahoo Mail folder alongside Gmail.")
    if not _ask_yes_no("Set up Yahoo now?"):
        return
    print("1. Enable 2-step verification on the Yahoo account (required first).")
    print("2. Go to Account Info > Account Security > Generate app password.")
    email = _prompt_plain("  Yahoo email address", os.environ.get("YAHOO_EMAIL", ""))
    if email:
        _set_env_var("YAHOO_EMAIL", email)
    _setup_key(
        "YAHOO_APP_PASSWORD", "App password",
        "Used to log into IMAP -- Yahoo has no OAuth Mail API for third-party apps.",
        "https://login.yahoo.com/myaccount/security", required=False,
    )
    folder = _prompt_plain(
        "  Folder to scan (a dedicated folder is far faster than a big INBOX)",
        os.environ.get("YAHOO_FOLDER", "INBOX"),
    )
    _set_env_var("YAHOO_FOLDER", folder)
    print("  Saved to .env.")


def setup_urlscan() -> None:
    print("\n--- URL sandboxing (optional) ---")
    print("Visits links in an isolated browser to see what they actually do,")
    print("catching freshly-registered pages VirusTotal has no history for.")
    if not _ask_yes_no("Set up urlscan.io now?"):
        return
    _setup_key(
        "URLSCAN_API_KEY", "urlscan.io API key",
        "Authenticates scan submissions and result lookups.",
        "https://urlscan.io/user/signup", required=False,
    )


def main():
    _ensure_env_file()
    setup_gmail()
    setup_required()
    setup_slack()
    setup_yahoo()
    setup_urlscan()

    print("\n" + "=" * 64)
    print("Done. Next (double-click these in the project folder):")
    print("  check_setup.bat          -- confirm everything is ready")
    print("  run_alerts.bat           -- process new reported emails")
    print("  run_dashboard.bat        -- view the results")
    print("Re-run setup.bat any time to add or change something.")
    print("=" * 64)


if __name__ == "__main__":
    main()
