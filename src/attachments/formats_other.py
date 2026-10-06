"""Static checks for PDFs, web pages, scripts, executables, shortcuts, OneNote,
archives and attached emails. Everything is analysed as bytes in memory --
nothing is rendered, opened in another program, or executed.
"""
import email
import re
import struct
import zipfile
import zlib
from email import policy

from src.attachments.models import (
    MAX_MEMBER_BYTES, MAX_MEMBERS_LISTED, MAX_RATIO, MAX_NESTING_DEPTH,
)
from src.attachments.report import Report
from src.attachments.sniff import (
    DISK_IMAGE_EXT, RUNNABLE_EXT, decode_text, entropy, extension, extract_strings,
    filename_signals, safe_filename, strip_tags, urls_from_text,
)

# --- PDF -----------------------------------------------------------------------

_PDF_KEYS = ["JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "RichMedia", "XFA",
             "AcroForm", "Encrypt", "URI", "SubmitForm", "GoToR", "GoToE", "ImportData", "ObjStm"]
_PDF_KEY_RES = {k: re.compile(r"/" + k + r"(?![A-Za-z0-9])") for k in _PDF_KEYS}
_PDF_NAME_ESCAPE_RE = re.compile(r"/[^\s/\[\]<>()%]*#[0-9A-Fa-f]{2}[^\s/\[\]<>()%]*")
_PDF_URI_RE = re.compile(r"/URI\s*\(((?:[^()\\]|\\.)*)\)")
_PDF_PAGE_RE = re.compile(r"/Type\s*/Page(?![A-Za-z])")
_STREAM_START_RE = re.compile(rb"(?<!end)stream\r?\n")


def _unescape_pdf_names(text: str) -> str:
    """Undo #xx escapes in PDF names (/Java#53cript == /JavaScript), a standard obfuscation."""
    def fix(match):
        return re.sub(r"#([0-9A-Fa-f]{2})", lambda h: chr(int(h.group(1), 16)), match.group(0))
    return _PDF_NAME_ESCAPE_RE.sub(fix, text)


def _inflate_streams(data: bytes, max_streams: int = 300, per_stream: int = 2 * 1024 * 1024,
                     total: int = 16 * 1024 * 1024) -> str:
    """Decompress FlateDecode streams (bounded) so keywords hidden in object
    streams are visible to the scan."""
    out, used, count = [], 0, 0
    for match in _STREAM_START_RE.finditer(data):
        count += 1
        if count > max_streams or used > total:
            break
        end = data.find(b"endstream", match.end())
        if end == -1:
            break  # no later stream can have an end marker either
        raw = data[match.end():end]
        for candidate in (raw, raw.rstrip(b"\r\n")):
            try:
                chunk = zlib.decompressobj().decompress(candidate, per_stream)
            except zlib.error:
                continue
            if chunk:
                used += len(chunk)
                out.append(chunk.decode("latin-1", errors="replace"))
                break
    return "\n".join(out)


def analyze_pdf(data: bytes, rep: Report) -> None:
    text = data.decode("latin-1", errors="replace")
    corpus = _unescape_pdf_names(text + "\n" + _inflate_streams(data))
    counts = {k: len(rx.findall(corpus)) for k, rx in _PDF_KEY_RES.items()}
    counts = {k: v for k, v in counts.items() if v}
    pages = len(_PDF_PAGE_RE.findall(corpus))
    uris = [m.group(1).replace("\\(", "(").replace("\\)", ")") for m in _PDF_URI_RE.finditer(corpus)]
    rep.details["pdf"] = {"features": counts, "pages": pages, "link_count": len(uris)}
    rep.add_urls(urls_from_text("\n".join(uris)))

    js = counts.get("JavaScript", 0) + counts.get("JS", 0)
    autorun = counts.get("OpenAction", 0) + counts.get("AA", 0) + counts.get("Launch", 0)
    if counts.get("Launch"):
        rep.add("high", "pdf_launch_action", "PDF can launch an external program or file.")
    if js and autorun:
        rep.add("high", "pdf_javascript_autorun", "PDF contains JavaScript that runs automatically when opened.")
    elif js:
        rep.add("medium", "pdf_javascript", "PDF contains JavaScript.")
    if counts.get("EmbeddedFile"):
        rep.add("medium", "pdf_embedded_file", "PDF carries an embedded file attachment.")
    if counts.get("RichMedia"):
        rep.add("medium", "pdf_rich_media", "PDF embeds rich media (Flash/video), a historic exploit vector.")
    if counts.get("SubmitForm") or counts.get("ImportData") or counts.get("GoToR"):
        rep.add("medium", "pdf_remote_actions", "PDF has actions that talk to a remote location (form submit/import/remote goto).")
    if counts.get("Encrypt"):
        rep.add("low", "pdf_encrypted", "PDF is encrypted, so the scan of its contents is limited.")
        rep.note("Encrypted PDF: embedded streams could not be read, so keyword and link counts may be incomplete.")


# --- HTML / SVG ------------------------------------------------------------------

_HTML_PATTERNS = {
    "password_field": re.compile(r"""type\s*=\s*["']?password|autocomplete\s*=\s*["']?(?:current|new)-password""", re.I),
    "form_tag": re.compile(r"<form\b", re.I),
    "obfuscation": re.compile(r"\batob\s*\(|fromCharCode|\bunescape\s*\(|\beval\s*\(|document\.write\s*\(", re.I),
    "blob_download": re.compile(r"new\s+Blob\b", re.I),
    "blob_save": re.compile(r"msSaveOrOpenBlob|createObjectURL|\.download\s*=", re.I),
    "big_encoded_blob": re.compile(r"[A-Za-z0-9+/=]{2000,}"),
    "meta_refresh": re.compile(r"<meta[^<>]{0,300}http-equiv\s*=\s*[\"']?refresh", re.I),
    "iframe": re.compile(r"<iframe\b", re.I),
    "script_tag": re.compile(r"<script\b", re.I),
    "svg_event": re.compile(r"\bon(?:load|error|click)\s*=", re.I),
}
_FORM_ACTION_RE = re.compile(r"""<form[^<>]{0,500}?action\s*=\s*["']?(https?://[^\s"'>]+)""", re.I)
_SRC_RE = re.compile(r"""\b(?:src|action|data-url)\s*=\s*["'](https?://[^"'\s>]+)""", re.I)


def analyze_html(data: bytes, rep: Report, is_svg: bool = False) -> None:
    text = decode_text(data)
    hits = {name: bool(rx.search(text)) for name, rx in _HTML_PATTERNS.items()}
    rep.details["html"] = {k: v for k, v in hits.items() if v}

    actions = _FORM_ACTION_RE.findall(text)
    if hits["password_field"]:
        where = f" that submits to {actions[0][:100]}" if actions else ""
        rep.add("high", "credential_harvest_form", f"Page contains a password entry form{where}.")
    elif actions:
        rep.add("medium", "form_posts_remote", f"Form posts data to {actions[0][:100]}.")
    if hits["blob_download"] and hits["blob_save"]:
        rep.add("high", "html_smuggling",
                "Script builds a file in the browser (Blob) and saves it -- the 'HTML smuggling' technique.")
    if hits["obfuscation"] and hits["script_tag"]:
        rep.add("medium", "obfuscated_script", "Page uses encoding/eval functions typical of obfuscated scripts.")
    if hits["big_encoded_blob"]:
        rep.add("medium", "large_encoded_blob", "Page embeds a large base64-style blob.")
    if hits["meta_refresh"]:
        rep.add("medium", "meta_refresh_redirect", "Page redirects automatically via a meta refresh.")
    if hits["iframe"]:
        rep.add("low", "iframe", "Page embeds an iframe.")
    if is_svg and (hits["script_tag"] or hits["svg_event"]):
        rep.add("high", "svg_script", "SVG image contains script or event handlers.")
    elif not is_svg:
        rep.add("low", "html_attachment",
                "HTML file attachment (opens locally in the browser; often used to host fake login pages).")

    # URL scan works on the raw markup (hrefs/srcs are quoted attributes the URL pattern handles),
    # so no tag-stripping pass is needed.
    urls = _FORM_ACTION_RE.findall(text) + _SRC_RE.findall(text) + urls_from_text(text)
    rep.add_urls(urls_from_text("\n".join(urls)))


# --- Scripts -----------------------------------------------------------------------

_SCRIPT_PATTERNS = {
    "encoded_powershell": re.compile(r"-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|FromBase64String", re.I),
    "download_cradle": re.compile(r"DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|\biwr\b|"
                                  r"XMLHTTP|URLDownloadToFile|bitsadmin|certutil[^\n]{0,200}-urlcache", re.I),
    "runs_commands": re.compile(r"powershell|cmd(?:\.exe)?\s*/c|WScript\.Shell|\bShell\b|Start-Process|"
                                r"Invoke-Expression|\bIEX\b|mshta|regsvr32|rundll32", re.I),
    "obfuscation": re.compile(r"\beval\s*\(|fromCharCode|\bChr\w?\s*\(|\bunescape\s*\(|String\.fromCharCode", re.I),
    "persistence_or_defense_evasion": re.compile(
        r"schtasks|CurrentVersion\\Run|Set-MpPreference|DisableRealtimeMonitoring|Add-MpPreference", re.I),
}


def analyze_script(data: bytes, rep: Report, filename: str) -> None:
    text = decode_text(data)
    hits = [name for name, rx in _SCRIPT_PATTERNS.items() if rx.search(text)]
    rep.details["script"] = {"indicators": hits, "lines": text.count("\n") + 1}
    urls = urls_from_text(text)
    rep.add_urls(urls)
    rep.add("high", "script_attachment",
            f"Script file (.{extension(filename)}) that runs code when opened"
            + (f"; indicators: {', '.join(hits)}" if hits else "") + ".")


# --- Binary strings (executables, shortcuts, OneNote, unknown binaries) -------------

_BIN_PATTERNS = {
    "powershell": re.compile(r"powershell", re.I),
    "command_shell": re.compile(r"cmd(?:\.exe)?\s*/c|%comspec%", re.I),
    "script_hosts": re.compile(r"mshta|wscript|cscript|regsvr32|rundll32", re.I),
    "download_tools": re.compile(r"certutil|bitsadmin|DownloadString|DownloadFile|URLDownloadToFile|WinHttp|InternetOpen", re.I),
    "encoded_command": re.compile(r"-e(?:nc|ncodedcommand)\b|FromBase64String", re.I),
    "persistence": re.compile(r"CurrentVersion\\Run|schtasks|\\Startup\\", re.I),
}


def scan_binary_strings(data: bytes, rep: Report, key: str) -> list:
    strings = extract_strings(data)
    blob = "\n".join(strings)
    hits = [name for name, rx in _BIN_PATTERNS.items() if rx.search(blob)]
    urls = urls_from_text(blob)
    rep.add_urls(urls)
    rep.details[key] = {"suspicious_strings": hits, "urls_found": len(urls)}
    return hits


def analyze_pe(data: bytes, rep: Report, filename: str) -> None:
    detail = {}
    try:
        pe = int.from_bytes(data[0x3C:0x40], "little")
        machine, n_sections, timestamp = struct.unpack_from("<HHI", data, pe + 4)
        opt_size, characteristics = struct.unpack_from("<HH", data, pe + 4 + 16)
        opt = pe + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        com_dir = opt + (96 if magic == 0x10B else 112) + 14 * 8
        dotnet = struct.unpack_from("<I", data, com_dir)[0] != 0 if magic in (0x10B, 0x20B) else False
        sections = []
        table = opt + opt_size
        for i in range(min(n_sections, 20)):
            off = table + i * 40
            name = data[off:off + 8].rstrip(b"\x00").decode("latin-1", errors="replace")
            raw_size, raw_ptr = struct.unpack_from("<II", data, off + 16)
            sections.append({"name": name, "entropy": entropy(data[raw_ptr:raw_ptr + raw_size], 2 * 1024 * 1024)})
        detail = {"is_dll": bool(characteristics & 0x2000), "gui": subsystem == 2, "console": subsystem == 3,
                  "dotnet": dotnet, "sections": sections[:10], "compile_timestamp": timestamp,
                  "machine": hex(machine)}
        if any(s["entropy"] > 7.2 for s in sections):
            rep.add("medium", "packed_or_encrypted_section",
                    "A section has very high entropy, which usually means packed or encrypted code.")
    except (struct.error, IndexError):
        rep.note("PE header could not be fully parsed (truncated or malformed).")
    rep.details["pe"] = detail
    kind = "DLL" if detail.get("is_dll") else "program"
    rep.add("high", "windows_executable", f"Windows executable ({kind}) attached to an email.")
    scan_binary_strings(data, rep, "pe_strings")


# --- Archives ------------------------------------------------------------------------

def analyze_zip(zf: zipfile.ZipFile, rep: Report, recurse) -> None:
    infos = zf.infolist()
    rep.details["archive"] = {"entries": len(infos)}
    encrypted = [i for i in infos if i.flag_bits & 0x1]
    if encrypted:
        rep.add("medium", "encrypted_archive",
                f"{len(encrypted)} of {len(infos)} file(s) are password-protected, so antivirus cannot see inside.")
        rep.details["archive"]["encrypted"] = True

    bomb = [i for i in infos if i.file_size > 1024 * 1024 and i.file_size / max(i.compress_size, 1) > MAX_RATIO]
    if bomb:
        rep.add("high", "compression_bomb", "Archive expands by a ratio typical of a decompression bomb; not unpacked.")

    runnable = []
    nested_archives = 0
    for index, info in enumerate(infos):
        name = info.filename
        if name.endswith("/"):
            continue
        ext = extension(name)
        for severity, signal, detail in filename_signals(name):
            rep.add(severity, f"member_{signal}", f"{safe_filename(name)}: {detail}")
        if ext in RUNNABLE_EXT or ext in DISK_IMAGE_EXT:
            runnable.append(name)
        if ext in ("zip", "rar", "7z", "cab", "gz", "iso", "img"):
            nested_archives += 1
        if index >= MAX_MEMBERS_LISTED:
            continue
        if info.flag_bits & 0x1 or info in bomb or info.file_size > MAX_MEMBER_BYTES:
            rep.members.append({"filename": safe_filename(name), "size": info.file_size,
                                "analyzed": False, "static_risk": "none",
                                "reason": "encrypted" if info.flag_bits & 0x1 else "too large or suspicious ratio"})
            continue
        try:
            with zf.open(info) as fh:
                content = fh.read(MAX_MEMBER_BYTES + 1)
        except (RuntimeError, zipfile.BadZipFile, NotImplementedError, zlib.error, EOFError):
            rep.members.append({"filename": safe_filename(name), "size": info.file_size,
                                "analyzed": False, "static_risk": "none", "reason": "could not be read"})
            continue
        sub = recurse(name, content, "")
        if sub is not None:
            rep.members.append(sub)

    if len(infos) > MAX_MEMBERS_LISTED:
        rep.note(f"Archive has {len(infos)} entries; only the first {MAX_MEMBERS_LISTED} were inspected.")
    if runnable:
        rep.add("high", "archive_contains_runnable",
                f"Archive contains runnable/risky file(s): {', '.join(safe_filename(n) for n in runnable[:5])}.")
    if nested_archives:
        rep.add("low", "nested_archive", f"Contains {nested_archives} nested archive/disk-image file(s).")


# --- Attached emails (.eml) ----------------------------------------------------------

def analyze_eml(data: bytes, rep: Report, depth: int, recurse) -> None:
    try:
        msg = email.message_from_bytes(data, policy=policy.default)
    except Exception:  # noqa: BLE001 - malformed mail must never break the run
        rep.note("Attached email could not be parsed.")
        return

    body = ""
    try:
        part = msg.get_body(preferencelist=("html", "plain"))
        if part is not None:
            content = part.get_content()
            # Raw markup is fine for URL extraction; tags are only stripped for the short excerpt below.
            body = content
    except Exception:  # noqa: BLE001
        body = ""
    rep.add_urls(urls_from_text(body))
    rep.details["inner_email"] = {
        "subject": str(msg.get("subject", ""))[:200],
        "from": str(msg.get("from", ""))[:200],
        "date": str(msg.get("date", ""))[:80],
        "body_excerpt": " ".join(strip_tags(body[:20000]).split())[:300],
    }
    if depth >= MAX_NESTING_DEPTH:
        rep.note("Attached email nested too deeply; its attachments were not inspected.")
        return
    try:
        attachments = list(msg.iter_attachments())
    except Exception:  # noqa: BLE001
        attachments = []
    for part in attachments[:MAX_MEMBERS_LISTED]:
        name = part.get_filename() or "unnamed"
        try:
            if part.get_content_type() == "message/rfc822":
                inner = part.get_payload()[0]
                content = inner.as_bytes()
            else:
                content = part.get_payload(decode=True) or b""
        except Exception:  # noqa: BLE001
            continue
        sub = recurse(name, content, part.get_content_type())
        if sub is not None:
            rep.members.append(sub)
