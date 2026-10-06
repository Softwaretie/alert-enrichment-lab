"""Static checks for Microsoft Office files: OOXML (.docx/.xlsx/...), legacy
OLE (.doc/.xls/.ppt), their VBA macros, and RTF. Nothing is opened in Office
or executed; everything is read as bytes in memory.
"""
import re
import struct
import zipfile

from src.attachments.cfb import CFBError, CompoundFile, extract_vba_source
from src.attachments.models import MAX_RATIO
from src.attachments.report import Report
from src.attachments.sniff import (
    RUNNABLE_EXT, extension, extract_strings, runnable_names, urls_from_text,
)

_AUTOEXEC_RE = re.compile(
    r"\b(AutoOpen|AutoExec|AutoClose|AutoNew|Auto_Open|Auto_Close|Auto_Activate|Document_Open|DocumentOpen|"
    r"Document_New|Document_Close|Workbook_Open|Workbook_Activate|Workbook_BeforeClose|"
    r"Worksheet_Activate|Presentation_Open)\b", re.IGNORECASE)

_SUSPICIOUS_VBA = {
    "runs_programs": re.compile(r"\bShell\b|WScript\.Shell|\.Run\b|\.Exec\b|ShellExecute|Win32_Process|CreateProcess", re.I),
    "creates_objects": re.compile(r"\bCreateObject\b|\bGetObject\b", re.I),
    "downloads_files": re.compile(
        r"URLDownloadToFile|XMLHTTP|WinHttp|MSXML2|ADODB\.Stream|InternetOpen|DownloadFile|DownloadString|"
        r"Net\.WebClient|\bBITS\b", re.I),
    "command_line_tools": re.compile(
        r"powershell|cmd(?:\.exe)?\s*/c|mshta|wscript|cscript|regsvr32|rundll32|certutil|bitsadmin", re.I),
    "reads_environment": re.compile(r"\bEnviron\b", re.I),
    "native_api_or_shellcode": re.compile(
        r"VirtualAlloc|RtlMoveMemory|CreateThread|WriteProcessMemory|CallWindowProc|EnumSystemLocales", re.I),
}
_CHR_RE = re.compile(r"\bChrW?\s*\(", re.I)

_MAX_PART_BYTES = 8 * 1024 * 1024
_REL_RE = re.compile(r"<Relationship\b([^<>]{0,2000})>", re.I)
_ATTR_RE = re.compile(r'([A-Za-z:]+)\s*=\s*"([^"]*)"')
_DDE_RE = re.compile(r"\bDDE(?:AUTO)?\b", re.I)
_DDE_CELL_RE = re.compile(r"<f(?:\s[^<>]{0,200})?>[^<]{0,2000}?(?:cmd|powershell|mshta|regsvr32)[^<]{0,2000}?\|", re.I)


# --- VBA ----------------------------------------------------------------------

def analyze_vba_container(cfb: CompoundFile, rep: Report, where: str = "") -> None:
    """Report on the VBA project inside a compound file."""
    vba_streams = [p for p in cfb.streams if "VBA" in p.split("/")[:-1]]
    module_streams = [p for p in vba_streams
                      if p.split("/")[-1] not in ("dir", "_VBA_PROJECT") and not p.split("/")[-1].startswith("__SRP_")]
    modules = extract_vba_source(cfb)

    rep.add("medium", "vba_macros",
            f"Contains a VBA macro project{where} ({len(module_streams)} module stream(s)).")
    rep.details["vba"] = {"module_streams": [p.split("/")[-1] for p in module_streams][:20],
                          "source_decoded": bool(modules)}

    if not modules:
        rep.note("Macro source could not be decoded (corrupt, unusual layout, or deliberately obfuscated); "
                 "the presence of macros is still reported.")
        return

    source = "\n".join(modules.values())
    autoexec = sorted({m.group(1) for m in _AUTOEXEC_RE.finditer(source)})
    suspicious = [label for label, rx in _SUSPICIOUS_VBA.items() if rx.search(source)]
    chr_count = len(_CHR_RE.findall(source))
    urls = urls_from_text(source)

    rep.details["vba"].update({"auto_exec_entry_points": autoexec, "suspicious_keywords": suspicious,
                               "chr_calls": chr_count, "urls_in_macro": urls[:10]})
    rep.add_urls(urls)

    if autoexec and (suspicious or urls):
        rep.add("high", "vba_autoexec_suspicious",
                f"Macro runs automatically on open ({', '.join(autoexec)}) and uses: "
                f"{', '.join(suspicious) or 'embedded URLs'}.")
    elif autoexec:
        rep.add("medium", "vba_autoexec", f"Macro runs automatically on open ({', '.join(autoexec)}).")
    elif suspicious:
        rep.add("medium", "vba_suspicious_keywords", f"Macro uses: {', '.join(suspicious)}.")
    if chr_count > 30:
        rep.add("medium", "vba_obfuscated_strings", f"Macro builds text from {chr_count} Chr() calls (obfuscation).")


# --- OOXML ---------------------------------------------------------------------

def _read_part(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int = _MAX_PART_BYTES) -> bytes:
    if info.file_size > limit or info.flag_bits & 0x1:
        return b""
    ratio = info.file_size / max(info.compress_size, 1)
    if ratio > MAX_RATIO and info.file_size > 1024 * 1024:
        return b""
    with zf.open(info) as fh:
        return fh.read(limit)


def is_ooxml(names: set) -> bool:
    return "[Content_Types].xml" in names and any(
        n.startswith(("word/", "xl/", "ppt/", "visio/")) for n in names)


def analyze_ooxml(zf: zipfile.ZipFile, rep: Report, filename: str) -> None:
    infos = {i.filename: i for i in zf.infolist()}
    names = set(infos)
    ext = extension(filename)

    if any(n.startswith("word/") for n in names):
        flavor = "word"
    elif any(n.startswith("xl/") for n in names):
        flavor = "excel"
    elif any(n.startswith("ppt/") for n in names):
        flavor = "powerpoint"
    else:
        flavor = "other"
    rep.details["office_flavor"] = flavor

    # Macros: a vbaProject part is what makes a package macro-capable
    # (Microsoft documents converting .docm to .docx as removing that part).
    vba_parts = [n for n in names if n.lower().endswith("vbaproject.bin")]
    macro_ct = False
    if "[Content_Types].xml" in infos:
        ct = _read_part(zf, infos["[Content_Types].xml"], 1024 * 1024).decode("utf-8", errors="replace")
        macro_ct = "macroEnabled" in ct or "vbaProject" in ct
    for part in vba_parts:
        raw = _read_part(zf, infos[part])
        try:
            analyze_vba_container(CompoundFile(raw), rep)
        except CFBError:
            rep.add("medium", "vba_macros", "Contains a vbaProject part that could not be parsed.")
    if (vba_parts or macro_ct) and ext in ("docx", "xlsx", "pptx", "dotx", "xltx", "potx", "ppsx"):
        rep.add("high", "macros_hidden_behind_plain_extension",
                f"Has macro content but is named .{ext}, which normally cannot hold macros.")
    elif (vba_parts or macro_ct) and not any(s["signal"].startswith("vba") for s in rep.signals):
        rep.add("medium", "vba_macros", "Macro-enabled Office package.")

    # Excel 4.0 (XLM) macro sheets live outside the VBA project.
    macrosheets = [n for n in names if n.startswith("xl/macrosheets/")]
    if macrosheets:
        hidden = False
        if "xl/workbook.xml" in infos:
            wb = _read_part(zf, infos["xl/workbook.xml"], 2 * 1024 * 1024).decode("utf-8", errors="replace")
            hidden = "veryHidden" in wb
        if hidden:
            rep.add("high", "excel4_macro_sheet_hidden", "Contains Excel 4.0 (XLM) macro sheet(s) with hidden sheets.")
        else:
            rep.add("medium", "excel4_macro_sheet", "Contains Excel 4.0 (XLM) macro sheet(s).")

    # Embedded objects / ActiveX
    embeddings = [n for n in names if "/embeddings/" in n]
    if embeddings:
        bad = [n for n in embeddings if extension(n) in RUNNABLE_EXT]
        if bad:
            rep.add("high", "embedded_executable", f"Embeds a runnable file: {bad[0].rsplit('/', 1)[-1]}.")
        else:
            rep.add("medium", "embedded_objects", f"Embeds {len(embeddings)} object(s).")
        rep.details["embeddings"] = [n.rsplit("/", 1)[-1] for n in embeddings][:20]
    if any("/activeX/" in n for n in names):
        rep.add("medium", "activex_controls", "Contains ActiveX controls.")

    # Relationships pointing outside the file (remote templates, linked objects, links)
    external = []
    for name, info in infos.items():
        if not name.endswith(".rels"):
            continue
        xml = _read_part(zf, info, 2 * 1024 * 1024).decode("utf-8", errors="replace")
        for match in _REL_RE.finditer(xml):
            attrs = dict((k.lower(), v) for k, v in _ATTR_RE.findall(match.group(1)))
            if attrs.get("targetmode", "").lower() != "external":
                continue
            target = attrs.get("target", "")
            rel_type = attrs.get("type", "").rsplit("/", 1)[-1]
            external.append((rel_type, target))

    link_urls = []
    for rel_type, target in external:
        lowered = target.lower()
        unc_or_file = target.startswith("\\\\") or lowered.startswith(("file:", "//"))
        if unc_or_file:
            rep.add("high", "unc_or_file_link",
                    f"{rel_type} link to a network/file path ({target[:80]}); can leak Windows credentials.")
        elif rel_type in ("attachedTemplate", "oleObject", "subDocument", "mailMerge"):
            rep.add("high", "remote_content_link",
                    f"{rel_type} loaded from a remote location ({target[:100]}).")
        elif rel_type in ("externalLink", "frame", "externalLinkPath"):
            rep.add("medium", "external_data_link", f"{rel_type} points to {target[:100]}.")
        elif rel_type == "image":
            rep.add("low", "remote_image", "Loads a remote image when opened (can act as a tracking beacon).")
        if lowered.startswith(("http://", "https://", "hxxp")):
            link_urls.append(target)
    rep.add_urls(link_urls)
    rep.details["external_links"] = [f"{t}: {u[:120]}" for t, u in external][:15]

    # DDE: fields/cells that launch commands
    for name, info in infos.items():
        if name.startswith("word/") and name.endswith(".xml") and name.count("/") == 1:
            text = _read_part(zf, info).decode("utf-8", errors="replace")
            if re.search(r"<w:instrText[^<>]{0,200}>[^<]{0,2000}?" + _DDE_RE.pattern, text, re.I) or \
               re.search(r'w:instr="[^"]{0,2000}?' + _DDE_RE.pattern, text, re.I):
                rep.add("high", "dde_field", "Word field uses DDE/DDEAUTO to launch a command.")
                break
    if flavor == "excel":
        for name, info in infos.items():
            if name.startswith("xl/worksheets/") and name.endswith(".xml"):
                text = _read_part(zf, info).decode("utf-8", errors="replace")
                if _DDE_CELL_RE.search(text):
                    rep.add("high", "dde_cell_formula", "Spreadsheet formula uses DDE to launch a command.")
                    break


# --- Legacy OLE (.doc/.xls/.ppt/.msg) ------------------------------------------

def _xlm_sheets(workbook: bytes) -> list:
    """Sheet (type, visibility, name) tuples from an .xls workbook's BoundSheet
    records. Type 1 is an Excel 4.0 macro sheet; visibility 1/2 = hidden/very hidden."""
    sheets, pos = [], 0
    while pos + 4 <= len(workbook) and len(sheets) < 200:
        rtype, rlen = struct.unpack_from("<HH", workbook, pos)
        body = workbook[pos + 4:pos + 4 + rlen]
        if rtype == 0x0085 and len(body) >= 8:
            state, sheet_type = body[4] & 0x03, body[5]
            cch, flags = body[6], body[7]
            raw = body[8:8 + cch * (2 if flags & 1 else 1)]
            name = raw.decode("utf-16-le" if flags & 1 else "latin-1", errors="replace")
            sheets.append((sheet_type, state, name))
        elif rtype == 0x000A:  # EOF of the workbook-globals substream, where BoundSheets live
            break
        pos += 4 + rlen
    return sheets


def analyze_ole(data: bytes, rep: Report, filename: str) -> None:
    try:
        cfb = CompoundFile(data)
    except (CFBError, struct.error, IndexError):
        rep.add("low", "unparseable_ole", "Looks like an Office/OLE file but its structure could not be read.")
        return

    streams = set(cfb.streams)
    leaf = {p.split("/")[-1] for p in streams}
    if "WordDocument" in leaf:
        flavor = "word"
    elif "Workbook" in leaf or "Book" in leaf:
        flavor = "excel"
    elif "PowerPoint Document" in leaf:
        flavor = "powerpoint"
    elif any(n.startswith("__properties_version1.0") for n in leaf):
        flavor = "outlook_msg"
    elif "EncryptedPackage" in leaf:
        flavor = "encrypted_ooxml"
    else:
        flavor = "unknown"
    rep.details["ole_flavor"] = flavor

    if "EncryptedPackage" in leaf:
        rep.add("medium", "password_protected_office",
                "Password-protected Office document; its contents cannot be inspected.")
        return

    if any("VBA" in p.split("/")[:-1] for p in streams) or any(s.split("/")[-1] == "VBA" for s in cfb.storages):
        analyze_vba_container(cfb, rep)

    for book in ("Workbook", "Book"):
        for path in streams:
            if path.split("/")[-1] == book:
                try:
                    sheets = _xlm_sheets(cfb.read_stream(path))
                except (struct.error, KeyError):
                    sheets = []
                macro_sheets = [s for s in sheets if s[0] == 1]
                if macro_sheets:
                    if any(s[1] in (1, 2) for s in macro_sheets):
                        rep.add("high", "excel4_macro_sheet_hidden",
                                "Contains a hidden Excel 4.0 (XLM) macro sheet.")
                    else:
                        rep.add("medium", "excel4_macro_sheet", "Contains an Excel 4.0 (XLM) macro sheet.")
                    rep.details["xlm_sheets"] = [s[2] for s in macro_sheets][:10]

    ole_native = [p for p in streams if "Ole10Native" in p.split("/")[-1]]
    packages = [p for p in streams if p.split("/")[-1] in ("Package", "CONTENTS")]
    if ole_native or packages or "ObjectPool" in cfb.storages:
        embedded_names = []
        for path in ole_native[:5]:
            try:
                blob = cfb.read_stream(path, limit=64 * 1024)
            except (KeyError, struct.error):
                continue
            text = " ".join(extract_strings(blob[:4096]))
            embedded_names.extend(runnable_names(text))
        if embedded_names:
            rep.add("high", "embedded_executable", f"Embeds a runnable file ({embedded_names[0].strip()[:80]}).")
        else:
            rep.add("medium", "embedded_objects", "Contains embedded OLE object(s) / packaged files.")

    # URLs stored as UTF-16 text anywhere in the document (hyperlinks, fields)
    rep.add_urls(urls_from_text(" ".join(extract_strings(data, limit_bytes=4 * 1024 * 1024))))


# --- RTF -------------------------------------------------------------------------

def analyze_rtf(data: bytes, rep: Report) -> None:
    text = data[:8 * 1024 * 1024].decode("latin-1", errors="replace")
    low = text.lower()
    has_objdata = "\\objdata" in low
    if has_objdata:
        rep.add("medium", "rtf_embedded_object", "RTF embeds an OLE object.")
    if has_objdata and ("\\objupdate" in low or "\\objautlink" in low):
        rep.add("high", "rtf_auto_updating_object", "RTF object is set to update/launch automatically.")
    if re.search(r"\\objclass\s+equation", low) or "equation.3" in low:
        rep.add("high", "rtf_equation_editor", "RTF references the Equation Editor, a common exploit vector.")
    template = re.search(r"\\\*\\template\s+([^\}]+)", text, re.I)
    if template:
        target = template.group(1).strip()
        if re.match(r"(?i)(https?:|\\\\|file:)", target):
            rep.add("high", "remote_template", f"RTF loads a remote template ({target[:100]}).")
    if low.count("{") > 5000 and low.count("\\bin") > 0:
        rep.add("medium", "rtf_obfuscation", "Unusually dense RTF with raw binary data.")
    rep.add_urls(urls_from_text(text))
