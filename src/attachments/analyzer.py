"""Static analysis of a single attachment: hash it, work out what it really is,
and look for red flags -- all from bytes in memory.

Nothing here opens a file in another program, renders it, or runs it. Archives
and attached emails are unpacked in memory only (with size, ratio and nesting
limits) and each member is analysed the same way.
"""
import io
import logging
import zipfile
import zlib

from src.attachments import formats_office, formats_other
from src.attachments.models import (
    MAX_MEMBER_BYTES, MAX_NESTING_DEPTH, MAX_UNPACKED_BYTES_PER_EMAIL,
)
from src.attachments.report import SEVERITY_ORDER, Report
from src.attachments.sniff import (
    ARCHIVE_EXT, DISK_IMAGE_EXT, EXEC_EXT, HTML_EXT, INSTALLER_EXT, MACRO_OFFICE_EXT, OFFICE_EXT,
    RUNNABLE_EXT, SCRIPT_EXT, SHORTCUT_EXT, detect_kind, extension, filename_signals, hashes, runnable_names,
    safe_filename,
)

logger = logging.getLogger(__name__)

_DESCRIPTIONS = {
    "pe": "Windows executable (PE)", "dos_exe": "DOS/Windows executable", "elf": "Linux executable (ELF)",
    "macho": "macOS executable (Mach-O)", "pdf": "PDF document", "zip": "ZIP-based file", "ole": "Legacy Office/OLE file",
    "rtf": "RTF document", "lnk": "Windows shortcut (.lnk)", "rar": "RAR archive", "7z": "7-Zip archive",
    "gzip": "gzip archive", "bzip2": "bzip2 archive", "xz": "xz archive", "cab": "Cabinet archive",
    "iso": "ISO disk image", "vhd": "Virtual disk image", "onenote": "OneNote document", "png": "PNG image",
    "jpeg": "JPEG image", "gif": "GIF image", "webp": "WebP image", "tiff": "TIFF image",
    "eml": "Email message (.eml)", "html": "HTML page", "svg": "SVG image", "text": "Plain text", "unknown": "Unknown binary",
    "empty": "Empty file",
}

# What each declared extension should really contain, for mismatch detection.
_EXPECTED = {
    "pdf": {"pdf"}, "jpg": {"jpeg"}, "jpeg": {"jpeg"}, "png": {"png"}, "gif": {"gif"}, "webp": {"webp"},
    "zip": {"zip"}, "rar": {"rar"}, "7z": {"7z"}, "gz": {"gzip"}, "cab": {"cab"}, "rtf": {"rtf"},
    "exe": {"pe", "dos_exe"}, "dll": {"pe"}, "scr": {"pe", "dos_exe"}, "lnk": {"lnk"}, "iso": {"iso"},
    "eml": {"eml"}, "one": {"onenote"},
    "txt": {"text"}, "csv": {"text"}, "log": {"text"},
    "html": {"html", "text"}, "htm": {"html", "text"}, "svg": {"svg"},
}
for _ext in OFFICE_EXT:
    _EXPECTED[_ext] = {"zip"} if _ext.endswith(("x", "m")) or _ext in ("xlam", "ppam", "sldm", "xlsb") else {"ole"}
for _ext in ("doc", "dot", "xls", "xlt", "ppt", "pps", "pot"):
    _EXPECTED[_ext] = {"ole", "zip", "rtf", "html", "text"}  # Office tolerates renamed formats; flagged separately

_RUNNABLE_KINDS = {"pe", "dos_exe", "elf", "macho", "lnk", "iso", "vhd"}
_BENIGN_IMAGE_KINDS = {"png", "jpeg", "gif", "webp", "tiff"}


class Budget:
    """Tracks how much we've unpacked across one email so nested archives can't exhaust memory."""
    def __init__(self):
        self.unpacked = 0

    def take(self, n: int) -> bool:
        if self.unpacked + n > MAX_UNPACKED_BYTES_PER_EMAIL:
            return False
        self.unpacked += n
        return True


def analyze_file(filename: str, data: bytes, content_type: str = "", depth: int = 0,
                 budget: Budget = None) -> dict:
    budget = budget or Budget()
    rep = Report()
    ext = extension(filename)
    kind = detect_kind(data, filename, content_type)

    for severity, signal, detail in filename_signals(filename):
        rep.add(severity, signal, detail)

    def recurse(name, content, ctype):
        if depth + 1 > MAX_NESTING_DEPTH:
            rep.note("Nested content beyond the depth limit was not inspected.")
            return None
        if len(content) > MAX_MEMBER_BYTES or not budget.take(len(content)):
            return {"filename": safe_filename(name), "size": len(content), "analyzed": False,
                    "static_risk": "none", "reason": "size limit"}
        return analyze_file(name, content, ctype, depth + 1, budget)

    try:
        _dispatch(kind, data, filename, ext, rep, depth, recurse)
    except Exception as exc:  # noqa: BLE001 - a hostile file must never crash the pipeline
        logger.warning("Attachment analysis failed for %r (%s): %s", filename, kind, exc)
        rep.note(f"Static analysis was incomplete ({type(exc).__name__}).")

    _extension_signals(kind, ext, rep)

    result = {
        "filename": safe_filename(filename),
        "declared_content_type": content_type,
        "size": len(data),
        **hashes(data),
        "detected_type": kind,
        "description": _DESCRIPTIONS.get(kind, kind),
        "extension": ext,
        "static_risk": rep.risk(),
        "signals": sorted(rep.signals, key=lambda s: -SEVERITY_ORDER[s["severity"]]),
        "urls": rep.urls,
        "details": rep.details,
        "notes": rep.notes,
        "analyzed": True,
    }
    if rep.members:
        result["members"] = rep.members
    return result


def _dispatch(kind, data, filename, ext, rep, depth, recurse):
    if kind in ("pe", "dos_exe"):
        if kind == "pe":
            formats_other.analyze_pe(data, rep, filename)
        else:
            rep.add("high", "windows_executable", "DOS/Windows executable attached to an email.")
    elif kind == "elf" or kind == "macho":
        rep.add("high", "native_executable", f"{_DESCRIPTIONS[kind]} attached to an email.")
        formats_other.scan_binary_strings(data, rep, "strings")
    elif kind == "pdf":
        formats_other.analyze_pdf(data, rep)
    elif kind == "zip":
        _analyze_zip_family(data, filename, ext, rep, recurse)
    elif kind == "ole":
        formats_office.analyze_ole(data, rep, filename)
    elif kind == "rtf":
        formats_office.analyze_rtf(data, rep)
    elif kind == "lnk":
        rep.add("high", "shortcut_file", "Windows shortcut (.lnk) attached to an email; often used to run PowerShell or scripts.")
        hits = formats_other.scan_binary_strings(data, rep, "lnk")
        if hits:
            rep.add("high", "shortcut_runs_commands", f"Shortcut contains command-line indicators: {', '.join(hits)}.")
    elif kind == "onenote":
        rep.add("medium", "onenote_attachment", "OneNote file; can hide embedded scripts or launchers behind clickable images.")
        hits = formats_other.scan_binary_strings(data, rep, "onenote")
        names = runnable_names("\n".join(formats_other.extract_strings(data)))
        if names or hits:
            rep.add("high", "onenote_embedded_launcher",
                    "OneNote file references runnable files or command-line tools"
                    + (f" ({names[0].strip()[:60]})" if names else "") + ".")
    elif kind in ("iso", "vhd"):
        rep.add("high", "disk_image_attachment",
                "Disk image attachment; commonly used to smuggle files past Windows' download-origin warnings. Contents not inspected.")
    elif kind in ("rar", "7z", "gzip", "bzip2", "xz", "cab"):
        rep.add("low", "archive_not_inspected",
                f"{_DESCRIPTIONS[kind]}: contents were not unpacked (unsupported without extra tools).")
        rep.note("Archive contents were not inspected; treat unknown archives with care.")
    elif kind == "eml":
        formats_other.analyze_eml(data, rep, depth, recurse)
    elif kind == "html":
        formats_other.analyze_html(data, rep)
    elif kind == "svg":
        formats_other.analyze_html(data, rep, is_svg=True)
    elif kind in ("text", "unknown") and ext in SCRIPT_EXT | {"hta"}:
        formats_other.analyze_script(data, rep, filename)
    elif kind == "unknown" and data:
        formats_other.scan_binary_strings(data, rep, "strings")
        rep.note("File type not recognised.")


def _analyze_zip_family(data, filename, ext, rep, recurse):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, NotImplementedError, OSError):
        rep.add("low", "unparseable_zip", "Looks like a ZIP/Office file but its structure could not be read.")
        return
    try:
        with zf:
            names = {i.filename for i in zf.infolist()}
            if formats_office.is_ooxml(names):
                rep.details["package"] = "ooxml"
                formats_office.analyze_ooxml(zf, rep, filename)
            elif "META-INF/MANIFEST.MF" in names:
                rep.details["package"] = "jar"
                rep.add("high", "java_archive", "Java archive (.jar) runs code when executed.")
            elif "AndroidManifest.xml" in names:
                rep.details["package"] = "apk"
                rep.add("medium", "android_package", "Android application package.")
            else:
                rep.details["package"] = "zip"
                formats_other.analyze_zip(zf, rep, recurse)
    except (zipfile.BadZipFile, zlib.error, EOFError, ValueError, OSError, NotImplementedError, RuntimeError) as exc:
        # Truncated/corrupt/tampered archives are common in hostile mail; note it and move on.
        rep.add("low", "corrupt_archive", "Archive structure is damaged or unusual, so it was only partly inspected.")
        rep.note(f"ZIP parsing stopped early ({type(exc).__name__}).")


def _extension_signals(kind, ext, rep):
    """Signals from the declared extension, added only when the content-based
    checks haven't already flagged the same thing."""
    if kind not in _RUNNABLE_KINDS:
        if ext in EXEC_EXT | SHORTCUT_EXT | INSTALLER_EXT:
            rep.add("high", "dangerous_extension", f"Named .{ext}, a file type that runs code when opened.")
        elif ext in DISK_IMAGE_EXT:
            rep.add("high", "dangerous_extension", f"Named .{ext}, a disk-image type often used for malware delivery.")
        elif ext in SCRIPT_EXT and ext != "jar" and not any(s["signal"] == "script_attachment" for s in rep.signals):
            rep.add("high", "dangerous_extension", f"Named .{ext}, a script type that runs code when opened.")
        elif ext in MACRO_OFFICE_EXT and not any("macro" in s["signal"] or s["signal"].startswith("vba") for s in rep.signals):
            rep.add("medium", "macro_enabled_extension", f"Named .{ext}, a macro-capable Office format.")

    expected = _EXPECTED.get(ext)
    if expected and kind not in expected and kind not in ("empty",):
        if kind in _RUNNABLE_KINDS and ext not in RUNNABLE_EXT:
            rep.add("high", "disguised_executable", f"Named .{ext} but the content is actually {_DESCRIPTIONS.get(kind, kind)}.")
        elif kind in ("rtf", "html", "svg", "ole", "zip", "pdf", "eml", "pe", "unknown") and ext not in ARCHIVE_EXT | HTML_EXT:
            sev = "medium" if kind not in ("unknown",) else "low"
            rep.add(sev, "type_mismatch", f"Named .{ext} but the content looks like {_DESCRIPTIONS.get(kind, kind)}.")
        else:
            rep.add("low", "type_mismatch", f"Named .{ext} but the content looks like {_DESCRIPTIONS.get(kind, kind)}.")
