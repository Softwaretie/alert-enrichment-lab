"""Read-only Gmail access for pulling forwarded phishing reports."""
import base64
import logging
import os

from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from src.attachments.models import MAX_FILES_PER_EMAIL, MAX_TOTAL_BYTES_PER_EMAIL, RawAttachment
from src.auth_headers import parse_authentication_results
from src.email_message import EmailMessage
from src.html_text import html_to_text

# Read-only: this tool never sends, deletes, or modifies mail content,
# it only removes the UNREAD label once an alert has been processed.
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

logger = logging.getLogger(__name__)


def authenticate(credentials_path: str, token_path: str):
    creds = None
    if os.path.exists(token_path):
        try:
            creds = Credentials.from_authorized_user_file(token_path, SCOPES)
        except (ValueError, OSError) as exc:  # damaged or hand-edited token file
            logger.warning("Ignoring unreadable Gmail token file %s (%s); signing in again.", token_path, exc)
            creds = None

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except RefreshError as exc:
                # Usually Google's 7-day limit for apps in "Testing" mode, or access was
                # revoked. The saved sign-in can't be renewed, so ask the user to sign in again.
                logger.warning("Saved Gmail sign-in has expired or was revoked (%s). "
                               "Opening your browser to sign in again...", exc)
                creds = None
        if not creds or not creds.valid:
            creds = _interactive_login(credentials_path)

        with open(token_path, "w") as token_file:
            token_file.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def _interactive_login(credentials_path: str):
    if not os.path.exists(credentials_path):
        raise RuntimeError(
            f"Gmail OAuth client secret not found at {credentials_path}. "
            "Download it from Google Cloud Console (see docs/SETUP_GUIDE.md, step 4c) "
            "and set GMAIL_CREDENTIALS_PATH."
        )
    flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
    return flow.run_local_server(port=0)


def get_profile_email(service) -> str:
    """The Gmail address this authenticated session belongs to, so findings
    can record which mailbox they were pulled from."""
    profile = service.users().getProfile(userId="me").execute()
    return profile.get("emailAddress", "")


def list_message_ids(service, query: str, max_results: int = 25) -> list:
    """List message ids matching `query`. Pass max_results=None to page through
    ALL matches (for batch runs) instead of a single capped page."""
    if max_results is not None:
        result = service.users().messages().list(
            userId="me", q=query, maxResults=max_results
        ).execute()
        return [m["id"] for m in result.get("messages", [])]

    # Batch mode: Gmail caps a single page at 500, so page through nextPageToken.
    # A hard cap keeps a runaway query from paging forever.
    hard_cap = 2000
    ids = []
    page_token = None
    while True:
        result = service.users().messages().list(
            userId="me", q=query, maxResults=500, pageToken=page_token
        ).execute()
        ids.extend(m["id"] for m in result.get("messages", []))
        page_token = result.get("nextPageToken")
        if not page_token or len(ids) >= hard_cap:
            break
    return ids[:hard_cap]


def _header(headers: list, name: str) -> str:
    for h in headers:
        if h["name"].lower() == name.lower():
            return h["value"]
    return ""


def _collect_parts(payload: dict, mime_type: str) -> list:
    parts = []
    if payload.get("mimeType") == mime_type and "data" in payload.get("body", {}):
        parts.append(base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="replace"))
    for part in payload.get("parts", []) or []:
        parts.extend(_collect_parts(part, mime_type))
    return parts


def _extract_body(payload: dict) -> str:
    """Prefer text/plain; fall back to text/html for HTML-only messages
    (converted via html_to_text so links in href attributes aren't lost)."""
    plain_parts = _collect_parts(payload, "text/plain")
    if plain_parts:
        return "\n".join(plain_parts)

    html_parts = _collect_parts(payload, "text/html")
    return "\n".join(html_to_text(p) for p in html_parts)


def _extract_attachment_names(payload: dict) -> list:
    names = []
    if payload.get("filename"):
        names.append(payload["filename"])
    for part in payload.get("parts", []) or []:
        names.extend(_extract_attachment_names(part))
    return names


def _attachment_refs(payload: dict) -> list:
    """Every named part that carries file content, as lightweight references
    (nothing is downloaded yet)."""
    refs = []
    body = payload.get("body") or {}
    if payload.get("filename") and (body.get("attachmentId") or body.get("data")):
        refs.append({
            "filename": payload["filename"],
            "mime": payload.get("mimeType", ""),
            "size": body.get("size", 0),
            "attachment_id": body.get("attachmentId"),
            "inline_data": body.get("data"),
        })
    for part in payload.get("parts", []) or []:
        refs.extend(_attachment_refs(part))
    return refs


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def fetch_attachments(service, message_id: str, payload: dict, max_bytes: int) -> list:
    """Download attachment bytes into memory for static analysis.

    Nothing is written to disk or opened. Oversized files, files beyond the
    per-email count/size limits, and failed downloads come back as
    RawAttachment entries with `skipped_reason` set, so the report can still
    say they existed. Pass max_bytes=0 to skip downloading entirely."""
    if max_bytes <= 0:
        return []
    limit_mb = max_bytes // (1024 * 1024)
    attachments, total = [], 0
    for index, ref in enumerate(_attachment_refs(payload)):
        name, mime, size = ref["filename"], ref["mime"], ref["size"] or 0
        if index >= MAX_FILES_PER_EMAIL:
            attachments.append(RawAttachment(name, mime, b"", size, f"more than {MAX_FILES_PER_EMAIL} attachments"))
        elif size > max_bytes:
            attachments.append(RawAttachment(name, mime, b"", size, f"larger than the {limit_mb} MB limit"))
        elif total + size > MAX_TOTAL_BYTES_PER_EMAIL:
            attachments.append(RawAttachment(name, mime, b"", size, "total attachment size limit reached"))
        else:
            try:
                if ref["attachment_id"]:
                    blob = service.users().messages().attachments().get(
                        userId="me", messageId=message_id, id=ref["attachment_id"]
                    ).execute()
                    data = _b64url_decode(blob.get("data", ""))
                else:
                    data = _b64url_decode(ref["inline_data"] or "")
            except Exception as exc:  # noqa: BLE001 - one bad download must not sink the email
                attachments.append(RawAttachment(name, mime, b"", size, f"download failed ({type(exc).__name__})"))
                continue
            if len(data) > max_bytes:
                attachments.append(RawAttachment(name, mime, b"", len(data), f"larger than the {limit_mb} MB limit"))
                continue
            total += len(data)
            attachments.append(RawAttachment(name, mime, data, len(data)))
    return attachments


def get_message(service, message_id: str, mailbox: str = "", max_attachment_bytes: int = 0) -> EmailMessage:
    msg = service.users().messages().get(
        userId="me", id=message_id, format="full"
    ).execute()
    payload = msg["payload"]
    headers = payload.get("headers", [])

    return EmailMessage(
        id=msg["id"],
        thread_id=msg["threadId"],
        subject=_header(headers, "Subject"),
        sender=_header(headers, "From"),
        date=_header(headers, "Date"),
        body_text=_extract_body(payload),
        attachment_names=[n for n in _extract_attachment_names(payload) if n],
        source="gmail",
        mailbox=mailbox,
        auth_results=parse_authentication_results(_header(headers, "Authentication-Results")),
        attachments=fetch_attachments(service, message_id, payload, max_attachment_bytes),
    )


def mark_processed(service, message_id: str) -> None:
    service.users().messages().modify(
        userId="me", id=message_id, body={"removeLabelIds": ["UNREAD"]}
    ).execute()


def mark_as_spam(service, message_id: str) -> None:
    # Gmail's only spam-training signal is the SPAM label, which also takes the
    # message out of normal label views (it lives under the Spam folder).
    service.users().messages().modify(
        userId="me", id=message_id, body={"addLabelIds": ["SPAM"]}
    ).execute()


def mark_as_not_spam(service, message_id: str) -> None:
    service.users().messages().modify(
        userId="me", id=message_id, body={"removeLabelIds": ["SPAM"]}
    ).execute()
