"""Read-only Gmail check for the mail-actions feature.

    .venv\\Scripts\\python.exe scripts\\check_gmail.py

Signs in (your browser opens once to grant the new "manage filters" permission if
needed), then reports: which account, whether both permissions are granted, how many
emails match GMAIL_QUERY (what "Run Gmail" will analyse), and any block filters this
app created. Nothing in the mailbox is changed. Output is also saved to logs/gmail_check.log.
"""
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
os.chdir(PROJECT_ROOT)

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from src import gmail_client  # noqa: E402

lines = []


def out(text=""):
    print(text)
    lines.append(str(text))


def main():
    creds_path = os.environ.get("GMAIL_CREDENTIALS_PATH", "credentials.json")
    token_path = os.environ.get("GMAIL_TOKEN_PATH", "token.json")
    query = os.environ.get("GMAIL_QUERY", "label:phishing-reports is:unread")
    try:
        service = gmail_client.authenticate(creds_path, token_path)
    except Exception as exc:  # noqa: BLE001
        out(f"FAILED to sign in to Gmail: {exc}")
        return save()

    out(f"Signed in as: {gmail_client.get_profile_email(service)}")
    try:
        with open(token_path, encoding="utf-8") as fh:
            granted = set(json.load(fh).get("scopes") or [])
    except (OSError, ValueError):
        granted = set()
    for scope in gmail_client.SCOPES:
        out(f"  permission {scope.rsplit('/', 1)[-1]}: {'OK' if scope in granted else 'MISSING'}")

    labels = service.users().labels().list(userId="me").execute().get("labels", [])
    names = {l["name"] for l in labels}
    if "label:phishing-reports" in query and "phishing-reports" not in names:
        out("  WARNING: there is no Gmail label called 'phishing-reports', so Run Gmail will find nothing.")
    ids = gmail_client.list_message_ids(service, query, max_results=50)
    out(f"Emails matching GMAIL_QUERY ({query}): {len(ids)}{' (showing first 50)' if len(ids) == 50 else ''}")
    for mid in ids[:10]:
        msg = service.users().messages().get(userId="me", id=mid, format="metadata",
                                             metadataHeaders=["From", "Subject"]).execute()
        hdr = {h["name"]: h["value"] for h in msg["payload"].get("headers", [])}
        out(f"  - {hdr.get('From', '')[:50]}  |  {hdr.get('Subject', '')[:60]}")

    if not ids:
        # Work out why nothing matched: Gmail search skips Spam and Trash unless asked,
        # and the query also requires the emails to be unread.
        out("Why nothing matched -- the same label searched other ways:")
        for label_query, meaning in [
            ("label:phishing-reports", "labelled, read or unread (Inbox/archive only)"),
            ("label:phishing-reports in:anywhere", "labelled, anywhere incl. Spam and Trash"),
            ("label:phishing-reports in:spam", "labelled and sitting in Spam"),
            ("label:phishing-reports in:trash", "labelled and sitting in Trash"),
            ("in:anywhere label:phishing-reports is:unread", "labelled + unread, anywhere"),
            ("in:spam", "everything in your Spam folder"),
        ]:
            found = gmail_client.list_message_ids(service, label_query, max_results=50)
            out(f"  {len(found):>3}  {label_query:<45} ({meaning})")
        label = next((l for l in labels if l["name"] == "phishing-reports"), None)
        if label:
            info = service.users().labels().get(userId="me", id=label["id"]).execute()
            out(f"  Label 'phishing-reports' says it holds {info.get('messagesTotal', '?')} email(s), "
                f"{info.get('messagesUnread', '?')} unread.")
        similar = sorted(n for n in names if "phish" in n.lower() or "report" in n.lower())
        out(f"  Labels with 'phish' or 'report' in the name: {similar or 'none'}")

    try:
        filters = service.users().settings().filters().list(userId="me").execute().get("filter", [])
        blocks = [f for f in filters if "TRASH" in f.get("action", {}).get("addLabelIds", [])]
        out(f"Filters that send mail to Trash (blocked senders): {len(blocks)}")
        for f in blocks:
            out(f"  - from: {f.get('criteria', {}).get('from', '?')}")
    except Exception as exc:  # noqa: BLE001
        out(f"Could not read filters (block sender will fail): {exc}")
    save()


def save():
    os.makedirs("logs", exist_ok=True)
    with open(os.path.join("logs", "gmail_check.log"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\nSaved to logs\\gmail_check.log")


if __name__ == "__main__":
    main()
