"""Flask dashboard for browsing triaged findings in findings.db."""
import os
import re
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from dotenv import load_dotenv
from flask import Flask, abort, jsonify, render_template, request

from src import database

load_dotenv()

DB_PATH = os.environ.get("FINDINGS_DB_PATH", database.DB_PATH)
RETENTION_DAYS = int(os.environ.get("DELETED_RETENTION_DAYS", str(database.DEFAULT_RETENTION_DAYS)))

app = Flask(__name__)

# --- "Run Now" support -----------------------------------------------------
# Runs main.py in a subprocess and tails its log output to report progress.
# No task queue/worker pool -- one run at a time, a single reader thread.

_run_lock = threading.Lock()
_run_state = {
    "status": "idle",  # idle | running | done | error
    "source": None,
    "processed": 0,
    "total": 0,
    "errors": [],
    "started_at": None,
    "finished_at": None,
}

_FOUND_RE = re.compile(r"(?:Gmail|Yahoo): found (\d+) message")
_PROCESSING_RE = re.compile(r"\[(?:gmail|yahoo) (\d+)/(\d+)\] Processing")
_FAILED_RE = re.compile(r"\[(?:gmail|yahoo) \d+/\d+\] Failed to process message (\S+): (.+)")

_SOURCE_ARGS = {
    "gmail": ["--no-yahoo"],
    "yahoo": ["--no-gmail"],
    "both": [],
}


def _run_pipeline(source: str) -> None:
    cmd = [sys.executable, "main.py", "--batch", *_SOURCE_ARGS[source]]
    with _run_lock:
        _run_state.update(
            status="running", source=source, processed=0, total=0, errors=[],
            started_at=datetime.now(timezone.utc).isoformat(), finished_at=None,
        )

    try:
        proc = subprocess.Popen(
            cmd, cwd=PROJECT_ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        for line in proc.stdout:
            found = _FOUND_RE.search(line)
            processing = _PROCESSING_RE.search(line)
            failed = _FAILED_RE.search(line)
            with _run_lock:
                if found:
                    _run_state["total"] += int(found.group(1))
                if processing:
                    _run_state["processed"] = max(_run_state["processed"], int(processing.group(1)))
                if failed:
                    _run_state["errors"].append(f"{failed.group(1)}: {failed.group(2)}")
        proc.wait()
        with _run_lock:
            _run_state["status"] = "done" if proc.returncode == 0 else "error"
            if proc.returncode != 0 and not _run_state["errors"]:
                _run_state["errors"].append(f"main.py exited with code {proc.returncode}")
            _run_state["finished_at"] = datetime.now(timezone.utc).isoformat()
    except Exception as exc:
        with _run_lock:
            _run_state["status"] = "error"
            _run_state["errors"].append(str(exc))
            _run_state["finished_at"] = datetime.now(timezone.utc).isoformat()


def get_db():
    conn = database.connect(DB_PATH)
    database.purge_expired(conn, days=RETENTION_DAYS)  # opportunistic cleanup on every request
    return conn


def _parse_ids(payload: dict) -> list:
    try:
        return [int(i) for i in payload.get("ids", [])]
    except (TypeError, ValueError):
        abort(400)


@app.route("/")
def index():
    verdict = request.args.get("verdict", "all")
    source = request.args.get("source", "all")
    search = request.args.get("q", "").strip()
    sort = request.args.get("sort", "processed_at")
    sort_dir = request.args.get("dir", "desc")
    if sort_dir not in ("asc", "desc"):
        sort_dir = "desc"

    conn = get_db()
    try:
        stats = database.get_stats(conn)
        sources = database.list_sources(conn)
        findings = database.list_findings(
            conn, verdict=verdict, search=search or None, source=source,
            sort=sort, sort_dir=sort_dir,
        )
        deleted_count = database.count_deleted(conn)
    finally:
        conn.close()

    return render_template(
        "index.html",
        stats=stats,
        findings=findings,
        verdict=verdict,
        source=source,
        sources=sources,
        search=search,
        sort=sort,
        sort_dir=sort_dir,
        deleted_count=deleted_count,
        retention_days=RETENTION_DAYS,
    )


@app.route("/deleted")
def deleted_page():
    conn = get_db()
    try:
        findings = database.list_deleted_findings(conn)
    finally:
        conn.close()

    now = datetime.now(timezone.utc)
    for finding in findings:
        deleted_at = datetime.fromisoformat(finding["deleted_at"])
        purge_at = deleted_at + timedelta(days=RETENTION_DAYS)
        finding["days_until_purge"] = max(0, (purge_at - now).days)

    return render_template("deleted.html", findings=findings, retention_days=RETENTION_DAYS)


@app.route("/api/stats")
def api_stats():
    conn = get_db()
    try:
        stats = database.get_stats(conn)
    finally:
        conn.close()
    return jsonify(stats)


@app.route("/api/findings/<int:finding_id>")
def api_finding(finding_id):
    conn = get_db()
    try:
        finding = database.get_finding(conn, finding_id)
    finally:
        conn.close()

    if not finding:
        abort(404)
    return jsonify(finding)


@app.route("/api/findings/delete", methods=["POST"])
def api_delete_findings():
    ids = _parse_ids(request.get_json(silent=True) or {})
    conn = get_db()
    try:
        count = database.soft_delete(conn, ids)
    finally:
        conn.close()
    return jsonify({"deleted": count})


@app.route("/api/findings/restore", methods=["POST"])
def api_restore_findings():
    ids = _parse_ids(request.get_json(silent=True) or {})
    conn = get_db()
    try:
        count = database.restore(conn, ids)
    finally:
        conn.close()
    return jsonify({"restored": count})


@app.route("/api/run/start", methods=["POST"])
def api_run_start():
    source = (request.get_json(silent=True) or {}).get("source", "both")
    if source not in _SOURCE_ARGS:
        abort(400)

    with _run_lock:
        if _run_state["status"] == "running":
            return jsonify({"error": "A run is already in progress"}), 409

    threading.Thread(target=_run_pipeline, args=(source,), daemon=True).start()
    return jsonify({"started": True, "source": source})


@app.route("/api/run/status")
def api_run_status():
    with _run_lock:
        return jsonify(dict(_run_state))


def port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """True if something is already answering on host:port. Windows lets two servers
    bind the same port, and the browser then silently reaches the older one, so we
    check up front instead of trusting the bind to fail."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


if __name__ == "__main__":
    PORT = 5000
    if port_in_use(PORT):
        print(f"Another program is already using port {PORT} -- most likely a dashboard window that is still open")
        print("(possibly from a different copy of this project, which shows ITS findings, not this one's).")
        print("Close that other 'Alert Enrichment Dashboard' window, then run run_dashboard.bat again.")
        try:
            input("\nPress Enter to close this window...")
        except EOFError:
            pass
        sys.exit(1)

    # Debug mode exposes Flask's interactive debugger, so it's off unless you
    # ask for it (set DASHBOARD_DEBUG=1 in .env while developing). The server
    # only listens on this computer (127.0.0.1) -- it has no login, so it must
    # never be reachable from the network.
    _debug = os.environ.get("DASHBOARD_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")
    app.run(host="127.0.0.1", port=PORT, debug=_debug, threaded=True)
