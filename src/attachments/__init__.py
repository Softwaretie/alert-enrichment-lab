"""Attachment analysis: read what's actually inside a reported email's attachments.

Flow (see docs/README.md, "Attachment analysis"):

  mail client downloads attachment bytes into memory        (gmail_client / yahoo_client)
    -> analyze_attachments(): hash, detect real file type, static red-flag checks,
       unpack archives / attached emails in memory, pull URLs out of the files
    -> merge_into_iocs(): URLs found inside files join the email's own URLs, so the
       existing VirusTotal / urlscan.io checks cover them too
    -> lookup_hashes(): ask VirusTotal about each file's SHA-256 (no upload)
    -> the compact report is added to the enrichment sent to Claude

Level: hash + static only. Files are never saved, opened by another program,
or executed, and nothing is uploaded anywhere. A hash VirusTotal has never seen
means "unknown", not "safe".
"""
import logging
import re

from src.attachments.analyzer import Budget, analyze_file
from src.attachments.models import (
    MAX_FILES_PER_EMAIL, MAX_TOTAL_BYTES_PER_EMAIL, RawAttachment,
)
from src.attachments.report import SEVERITY_ORDER
from src.attachments.sniff import safe_filename

logger = logging.getLogger(__name__)

__all__ = ["RawAttachment", "analyze_attachments", "merge_into_iocs", "lookup_hashes"]

_PASSWORD_HINT_RE = re.compile(r"\b(pass(?:word|code|phrase)?|pwd)\b", re.IGNORECASE)
_MAX_VT_LOOKUPS_PER_EMAIL = 5
_SKIP_LOOKUP_KINDS = {"png", "jpeg", "gif", "webp", "tiff", "text", "empty"}


def analyze_attachments(raw_attachments: list, email_body: str = "") -> dict:
    """Analyse every downloaded attachment. Returns a JSON-serialisable report
    (no file bytes) shaped like:

        {"count": 2, "static_risk": "high", "email_signals": [...],
         "files": [{filename, sha256, detected_type, static_risk, signals, urls, ...}]}
    """
    budget = Budget()
    files = []
    total = 0
    for index, att in enumerate(raw_attachments):
        if index >= MAX_FILES_PER_EMAIL:
            files.append({"filename": safe_filename(att.filename), "size": att.size, "analyzed": False,
                          "static_risk": "none", "reason": f"more than {MAX_FILES_PER_EMAIL} attachments; not analysed"})
            continue
        if att.skipped_reason or not att.data:
            files.append({"filename": safe_filename(att.filename), "size": att.size, "analyzed": False,
                          "static_risk": "none", "reason": att.skipped_reason or "empty or not downloaded"})
            continue
        total += len(att.data)
        if total > MAX_TOTAL_BYTES_PER_EMAIL:
            files.append({"filename": safe_filename(att.filename), "size": att.size, "analyzed": False,
                          "static_risk": "none", "reason": "total attachment size limit reached"})
            continue
        files.append(analyze_file(att.filename, att.data, att.content_type, 0, budget))

    email_signals = _email_level_signals(files, email_body)
    risk = "none"
    for level in [f.get("static_risk", "none") for f in files] + [s["severity"] for s in email_signals]:
        if SEVERITY_ORDER[level] > SEVERITY_ORDER[risk]:
            risk = level
    return {"count": len(files), "static_risk": risk, "email_signals": email_signals, "files": files}


def _walk(files: list):
    """Yield every analysed entry, including archive members and attached-email contents."""
    for entry in files:
        yield entry
        yield from _walk(entry.get("members", []))


def _email_level_signals(files: list, body: str) -> list:
    signals = []
    entries = list(_walk(files))
    encrypted = any(
        s["signal"] in ("encrypted_archive", "password_protected_office")
        for e in entries for s in e.get("signals", [])
    )
    if encrypted and _PASSWORD_HINT_RE.search(body or ""):
        signals.append({"severity": "high", "signal": "encrypted_attachment_with_password_in_body",
                        "detail": "An attachment is password-protected and the email body mentions a password -- "
                                  "a common way to hide malware from antivirus scanning."})
    unanalysed = [e for e in files if not e.get("analyzed", True)]
    if unanalysed:
        signals.append({"severity": "low", "signal": "attachments_not_analysed",
                        "detail": f"{len(unanalysed)} attachment(s) were not analysed "
                                  f"({unanalysed[0].get('reason', 'unknown reason')})."})
    return signals


def merge_into_iocs(iocs, report: dict) -> int:
    """Add URLs found inside attachments (and their domains) to the email's IOCs,
    at the front, so the per-category enrichment cap doesn't push them out.
    Returns how many new URLs were added."""
    existing = set(iocs.urls)
    new_urls = []
    for entry in _walk(report.get("files", [])):
        for url in entry.get("urls", []):
            if url not in existing and url not in new_urls:
                new_urls.append(url)
    if not new_urls:
        return 0
    iocs.urls = new_urls + list(iocs.urls)
    known_domains = set(iocs.domains)
    for url in new_urls:
        host = url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
        if host and host not in known_domains:
            iocs.domains = [host] + list(iocs.domains)
            known_domains.add(host)
    return len(new_urls)


def lookup_hashes(report: dict, vt, max_lookups: int = _MAX_VT_LOOKUPS_PER_EMAIL) -> int:
    """Ask VirusTotal about attachments' SHA-256 hashes (a lookup, never an upload).

    Riskiest files first; plain images and text are skipped to save the free
    tier's 4-requests/minute budget. Results land on each entry as
    entry["virustotal"]. Returns the number of lookups made."""
    candidates = [
        e for e in _walk(report.get("files", []))
        if e.get("sha256") and e.get("analyzed", True) and e.get("size", 0) > 0
        and not (e.get("detected_type") in _SKIP_LOOKUP_KINDS and e.get("static_risk") == "none")
    ]
    candidates.sort(key=lambda e: -SEVERITY_ORDER[e.get("static_risk", "none")])

    done = {}
    lookups = 0
    for entry in candidates:
        sha = entry["sha256"]
        if sha not in done:
            if lookups >= max_lookups:
                entry["virustotal"] = {"skipped": "lookup limit reached for this email"}
                continue
            try:
                done[sha] = vt.check_hash(sha)
            except Exception as exc:  # noqa: BLE001 - enrichment must never break triage
                logger.warning("VirusTotal hash lookup failed for %s: %s", sha[:12], exc)
                done[sha] = {"error": str(exc)}
            lookups += 1
        entry["virustotal"] = done[sha]
    return lookups
