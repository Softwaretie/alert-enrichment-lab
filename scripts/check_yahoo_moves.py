"""Read-only check: where are the emails the dashboard moved in Yahoo, right now?

    .venv\\Scripts\\python.exe scripts\\check_yahoo_moves.py

For every Yahoo finding the dashboard moved (spam/trash), looks up its Message-ID in
the scan folder, spam (Bulk) and Trash, and prints where it actually is. Folders are
opened read-only, so nothing in the mailbox changes. Output is also saved to
logs/yahoo_check.log.
"""
import os
import sqlite3
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
os.chdir(PROJECT_ROOT)

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from src.config import _get_secret  # noqa: E402
from src.yahoo_client import YahooListener, _imap_string, quote_mailbox  # noqa: E402

lines = []


def out(text=""):
    print(text)
    lines.append(str(text))


def main():
    address = os.environ.get("YAHOO_EMAIL", "")
    scan = os.environ.get("YAHOO_FOLDER", "INBOX")
    listener = YahooListener(address, _get_secret("YAHOO_APP_PASSWORD"), folder=scan)
    listener.connect()
    conn = listener._conn
    out(f"Server capabilities: {' '.join(conn.capabilities)}")
    special = listener.special_folders()
    out(f"Spam folder: {special['spam']!r}   Trash folder: {special['trash']!r}   Scan folder: {scan!r}")

    db = sqlite3.connect(os.environ.get("FINDINGS_DB_PATH", "findings.db"))
    db.row_factory = sqlite3.Row
    rows = db.execute("SELECT id, subject, message_id, mail_state FROM findings WHERE source='yahoo' "
                      "AND message_id IS NOT NULL AND message_id != '' ORDER BY id DESC LIMIT 30").fetchall()
    folders = [scan, special["spam"], special["trash"]]
    for row in rows:
        out(f"\n#{row['id']} dashboard says: {row['mail_state'] or 'not moved'} -- {(row['subject'] or '')[:60]}")
        for folder in folders:
            conn.select(quote_mailbox(folder), readonly=True)
            typ, data = conn.uid("SEARCH", None, "HEADER", "Message-ID", _imap_string(row["message_id"]))
            uids = data[0].split() if typ == "OK" and data and data[0] else []
            for uid in uids:
                _, fl = conn.uid("FETCH", uid, "(FLAGS)")
                flags = fl[0].decode(errors="replace") if fl and isinstance(fl[0], bytes) else fl
                out(f"   found in {folder!r} uid {uid.decode()}  {flags}")
            if not uids:
                out(f"   not in {folder!r}")
    listener.close()
    os.makedirs("logs", exist_ok=True)
    with open(os.path.join("logs", "yahoo_check.log"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\nSaved to logs\\yahoo_check.log")


if __name__ == "__main__":
    main()
