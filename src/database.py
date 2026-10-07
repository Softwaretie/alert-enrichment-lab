"""SQLite storage for triaged findings, shared by the pipeline and the dashboard."""
import glob
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

DB_PATH = "findings.db"
LOGS_DIR = "logs"
DEFAULT_RETENTION_DAYS = 7

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    mailbox TEXT,
    email_id TEXT NOT NULL,
    subject TEXT,
    sender TEXT,
    email_date TEXT,
    verdict TEXT NOT NULL,
    confidence TEXT,
    summary TEXT,
    key_indicators TEXT,
    recommended_action TEXT,
    extracted_iocs TEXT,
    enrichment TEXT,
    processed_at TEXT NOT NULL,
    deleted_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_verdict ON findings(verdict);
CREATE INDEX IF NOT EXISTS idx_findings_processed_at ON findings(processed_at);

-- Every spam/trash/block/restore the app performed, automatically or from the dashboard.
CREATE TABLE IF NOT EXISTS mail_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER,
    action TEXT NOT NULL,          -- spam | trash | block | unblock | restore
    trigger TEXT NOT NULL,         -- auto | manual | blocklist
    success INTEGER NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mail_actions_finding ON mail_actions(finding_id);

-- Senders whose future mail is trashed. Gmail also gets a real filter (gmail_filter_id);
-- Yahoo has no API for its block list, so the pipeline enforces this table on every run.
CREATE TABLE IF NOT EXISTS blocked_senders (
    address TEXT PRIMARY KEY,
    source TEXT,
    mailbox TEXT,
    gmail_filter_id TEXT,
    finding_id INTEGER,
    reason TEXT,
    created_at TEXT NOT NULL
);
"""

VERDICTS = ("malicious", "suspicious", "likely_benign", "unknown")

# Sortable columns, mapped to a SQL expression giving them a meaningful order
# rather than alphabetical (e.g. confidence "high" should sort before "low").
_SORT_COLUMNS = {
    "verdict": (
        "CASE verdict "
        "WHEN 'likely_benign' THEN 0 "
        "WHEN 'unknown' THEN 1 "
        "WHEN 'suspicious' THEN 2 "
        "WHEN 'malicious' THEN 3 "
        "ELSE 4 END"
    ),
    "confidence": (
        "CASE confidence "
        "WHEN 'high' THEN 0 "
        "WHEN 'medium' THEN 1 "
        "WHEN 'low' THEN 2 "
        "ELSE 3 END"
    ),
    "processed_at": "processed_at",
}


def connect(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns/indexes introduced after a findings.db may already exist on disk."""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(findings)")}
    if "deleted_at" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN deleted_at TEXT")
        conn.commit()
    if "mailbox" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN mailbox TEXT")
        conn.commit()
    # Mail actions: category from Claude, where the message lives, and what was done to it.
    for col in ("category", "message_id", "mail_folder", "uidvalidity", "mail_state", "mail_state_detail"):
        if col not in cols:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT")
            conn.commit()
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_deleted_at ON findings(deleted_at)")


def insert_finding(conn: sqlite3.Connection, result: dict) -> int:
    analysis = result.get("claude_analysis", {})
    cur = conn.execute(
        """INSERT INTO findings (
            source, mailbox, email_id, subject, sender, email_date, verdict, confidence,
            summary, key_indicators, recommended_action, extracted_iocs, enrichment, processed_at,
            category, message_id, mail_folder, uidvalidity
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            result.get("source", "gmail"),
            result.get("mailbox", ""),
            result.get("email_id", ""),
            result.get("subject", ""),
            result.get("sender", ""),
            result.get("date", ""),
            analysis.get("verdict", "unknown"),
            analysis.get("confidence", ""),
            analysis.get("summary", ""),
            json.dumps(analysis.get("key_indicators", [])),
            analysis.get("recommended_action", ""),
            json.dumps(result.get("extracted_iocs", {})),
            json.dumps(result.get("enrichment", {})),
            result.get("processed_at", ""),
            analysis.get("category", ""),
            result.get("message_id", ""),
            result.get("mail_folder", ""),
            result.get("uidvalidity", ""),
        ),
    )
    conn.commit()
    return cur.lastrowid


def get_stats(conn: sqlite3.Connection) -> dict:
    rows = conn.execute(
        "SELECT verdict, COUNT(*) AS n FROM findings WHERE deleted_at IS NULL GROUP BY verdict"
    ).fetchall()
    counts = {row["verdict"]: row["n"] for row in rows}
    return {
        "total": sum(counts.values()),
        "malicious": counts.get("malicious", 0),
        "suspicious": counts.get("suspicious", 0),
        "likely_benign": counts.get("likely_benign", 0),
        "unknown": counts.get("unknown", 0),
    }


def count_deleted(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) AS n FROM findings WHERE deleted_at IS NOT NULL").fetchone()
    return row["n"]


def list_sources(conn: sqlite3.Connection) -> list:
    """Distinct, non-deleted mail sources currently in findings.db, for the
    dashboard's source filter dropdown."""
    rows = conn.execute(
        "SELECT DISTINCT source FROM findings WHERE deleted_at IS NULL ORDER BY source"
    ).fetchall()
    return [row["source"] for row in rows]


def list_findings(conn: sqlite3.Connection, verdict: str = None, search: str = None,
                   source: str = None, sort: str = "processed_at", sort_dir: str = "desc",
                   limit: int = 200) -> list:
    query = "SELECT * FROM findings WHERE deleted_at IS NULL"
    params = []
    if verdict and verdict != "all":
        query += " AND verdict = ?"
        params.append(verdict)
    if source and source != "all":
        query += " AND source = ?"
        params.append(source)
    if search:
        query += " AND (subject LIKE ? OR sender LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like])

    sort_expr = _SORT_COLUMNS.get(sort, _SORT_COLUMNS["processed_at"])
    direction = "ASC" if sort_dir == "asc" else "DESC"
    # Tie-break on processed_at desc so equal verdicts/confidences still show newest first.
    query += f" ORDER BY {sort_expr} {direction}, processed_at DESC LIMIT ?"
    params.append(limit)

    findings = [dict(row) for row in conn.execute(query, params).fetchall()]
    for finding in findings:
        finding["key_indicators"] = json.loads(finding["key_indicators"] or "[]")
        finding["enrichment"] = json.loads(finding["enrichment"] or "{}")
    return findings


def get_finding(conn: sqlite3.Connection, finding_id: int) -> dict:
    row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    if not row:
        return None
    finding = dict(row)
    finding["key_indicators"] = json.loads(finding["key_indicators"] or "[]")
    finding["extracted_iocs"] = json.loads(finding["extracted_iocs"] or "{}")
    finding["enrichment"] = json.loads(finding["enrichment"] or "{}")
    return finding


def list_deleted_findings(conn: sqlite3.Connection, limit: int = 200) -> list:
    rows = conn.execute(
        "SELECT * FROM findings WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    findings = [dict(row) for row in rows]
    for finding in findings:
        finding["key_indicators"] = json.loads(finding["key_indicators"] or "[]")
    return findings


def soft_delete(conn: sqlite3.Connection, ids: list) -> int:
    """Move findings to the trash (excluded from the dashboard, listed on /deleted)."""
    if not ids:
        return 0
    now = datetime.now(timezone.utc).isoformat()
    placeholders = ",".join("?" for _ in ids)
    cur = conn.execute(
        f"UPDATE findings SET deleted_at = ? WHERE id IN ({placeholders}) AND deleted_at IS NULL",
        [now, *ids],
    )
    conn.commit()
    return cur.rowcount


def restore(conn: sqlite3.Connection, ids: list) -> int:
    """Move findings back out of the trash."""
    if not ids:
        return 0
    placeholders = ",".join("?" for _ in ids)
    cur = conn.execute(
        f"UPDATE findings SET deleted_at = NULL WHERE id IN ({placeholders})", ids
    )
    conn.commit()
    return cur.rowcount


def purge_expired(conn: sqlite3.Connection, days: int = DEFAULT_RETENTION_DAYS,
                   logs_dir: str = LOGS_DIR) -> int:
    """Permanently remove findings that have been in the trash longer than `days`,
    including their on-disk JSON log file, so deleted data doesn't sit around
    indefinitely. Safe to call often -- it's a no-op when nothing has expired."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = conn.execute(
        "SELECT id, email_id FROM findings WHERE deleted_at IS NOT NULL AND deleted_at <= ?",
        (cutoff,),
    ).fetchall()
    if not rows:
        return 0

    for row in rows:
        for path in glob.glob(os.path.join(logs_dir, f"*_{row['email_id']}.json")):
            try:
                os.remove(path)
            except OSError:
                pass

    ids = [row["id"] for row in rows]
    placeholders = ",".join("?" for _ in ids)
    conn.execute(f"DELETE FROM findings WHERE id IN ({placeholders})", ids)
    conn.execute(f"DELETE FROM mail_actions WHERE finding_id IN ({placeholders})", ids)
    conn.commit()
    return len(ids)


# --- Mail actions ----------------------------------------------------------------

def set_mail_state(conn: sqlite3.Connection, finding_id: int, state, detail: dict = None) -> None:
    """state: None (where it arrived) | "spam" | "trash". detail records what's needed
    to undo it (e.g. the folder it was moved to, whether it was in the inbox)."""
    conn.execute(
        "UPDATE findings SET mail_state = ?, mail_state_detail = ? WHERE id = ?",
        (state, json.dumps(detail or {}), finding_id),
    )
    conn.commit()


def log_mail_action(conn: sqlite3.Connection, finding_id, action: str, trigger: str,
                    success: bool, detail: str = "") -> None:
    conn.execute(
        "INSERT INTO mail_actions (finding_id, action, trigger, success, detail, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (finding_id, action, trigger, 1 if success else 0, detail,
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def list_mail_actions(conn: sqlite3.Connection, finding_ids: list) -> dict:
    """{finding_id: [action rows, oldest first]} for the given findings."""
    if not finding_ids:
        return {}
    placeholders = ",".join("?" for _ in finding_ids)
    rows = conn.execute(
        f"SELECT * FROM mail_actions WHERE finding_id IN ({placeholders}) ORDER BY id",
        list(finding_ids),
    ).fetchall()
    out = {}
    for row in rows:
        out.setdefault(row["finding_id"], []).append(dict(row))
    return out


def add_blocked_sender(conn: sqlite3.Connection, address: str, source: str = "", mailbox: str = "",
                       gmail_filter_id: str = None, finding_id: int = None, reason: str = "") -> None:
    conn.execute(
        """INSERT INTO blocked_senders (address, source, mailbox, gmail_filter_id, finding_id, reason, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(address) DO UPDATE SET
             gmail_filter_id = COALESCE(excluded.gmail_filter_id, blocked_senders.gmail_filter_id)""",
        (address.lower(), source, mailbox, gmail_filter_id, finding_id, reason,
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def get_blocked_sender(conn: sqlite3.Connection, address: str):
    row = conn.execute("SELECT * FROM blocked_senders WHERE address = ?", ((address or "").lower(),)).fetchone()
    return dict(row) if row else None


def remove_blocked_sender(conn: sqlite3.Connection, address: str) -> int:
    cur = conn.execute("DELETE FROM blocked_senders WHERE address = ?", ((address or "").lower(),))
    conn.commit()
    return cur.rowcount


def list_blocked_senders(conn: sqlite3.Connection) -> list:
    return [dict(r) for r in conn.execute("SELECT * FROM blocked_senders ORDER BY created_at DESC")]
