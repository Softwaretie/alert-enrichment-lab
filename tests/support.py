"""Builders for synthetic test files.

Everything here is made-up, harmless sample data assembled in memory: fake
headers and strings that trip the analyzer's checks without being real malware
(and deliberately without the EICAR string, which antivirus software would
flag in the repo itself).
"""
import io
import math
import struct
import zipfile

_END = 0xFFFFFFFE
_FREE = 0xFFFFFFFF
_FATSECT = 0xFFFFFFFD


def make_cfb(streams: dict) -> bytes:
    """Build a small valid OLE2 compound file. `streams` maps "Dir/Sub/Name" -> bytes."""
    tree = {}
    for path, data in streams.items():
        node = tree
        parts = path.split("/")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = data

    entries = [{"name": "Root Entry", "type": 5, "child": _FREE, "right": _FREE, "start": _END, "size": 0, "data": None}]

    def add_children(node: dict) -> int:
        indices = []
        for name, value in node.items():
            entry = {"name": name, "type": 1 if isinstance(value, dict) else 2, "child": _FREE,
                     "right": _FREE, "start": _END, "size": 0, "data": None if isinstance(value, dict) else value}
            entries.append(entry)
            indices.append(len(entries) - 1)
            if isinstance(value, dict):
                entry["child"] = add_children(value)
        for a, b in zip(indices, indices[1:]):
            entries[a]["right"] = b
        return indices[0] if indices else _FREE

    entries[0]["child"] = add_children(tree)

    ministream = bytearray()
    minifat = []
    large = []
    for entry in entries:
        data = entry["data"]
        if data is None:
            continue
        entry["size"] = len(data)
        if len(data) == 0:
            continue
        if len(data) < 4096:
            first = len(ministream) // 64
            padded = data + b"\x00" * (-len(data) % 64)
            ministream += padded
            count = len(padded) // 64
            entry["start"] = first
            for i in range(count):
                minifat.append(first + i + 1 if i < count - 1 else _END)
        else:
            large.append(entry)

    dir_sectors = math.ceil(len(entries) / 4)
    minifat_sectors = math.ceil(len(minifat) / 128) if minifat else 0
    ministream_sectors = math.ceil(len(ministream) / 512) if ministream else 0
    large_sectors = sum(math.ceil(e["size"] / 512) for e in large)
    data_sectors = dir_sectors + minifat_sectors + ministream_sectors + large_sectors
    n_fat = 1
    while n_fat * 128 < data_sectors + n_fat:
        n_fat += 1

    fat = [_FREE] * (n_fat * 128)
    for i in range(n_fat):
        fat[i] = _FATSECT
    cursor = n_fat

    def chain(count: int) -> int:
        nonlocal cursor
        start = cursor
        for i in range(count):
            fat[cursor + i] = cursor + i + 1 if i < count - 1 else _END
        cursor += count
        return start

    first_dir = chain(dir_sectors)
    first_minifat = chain(minifat_sectors) if minifat_sectors else _END
    first_ministream = chain(ministream_sectors) if ministream_sectors else _END
    entries[0]["start"] = first_ministream
    entries[0]["size"] = len(ministream)
    for entry in large:
        entry["start"] = chain(math.ceil(entry["size"] / 512))

    def pack_entry(entry):
        name = entry["name"].encode("utf-16-le")
        rec = bytearray(128)
        rec[0:len(name)] = name
        struct.pack_into("<H", rec, 64, len(name) + 2)
        rec[66] = entry["type"]
        rec[67] = 1
        struct.pack_into("<III", rec, 68, _FREE, entry["right"], entry["child"])
        struct.pack_into("<I", rec, 116, entry["start"])
        struct.pack_into("<Q", rec, 120, entry["size"])
        return bytes(rec)

    dir_bytes = b"".join(pack_entry(e) for e in entries).ljust(dir_sectors * 512, b"\x00")

    minifat_bytes = struct.pack("<%dI" % len(minifat), *minifat).ljust(minifat_sectors * 512, b"\xff")
    ministream_bytes = bytes(ministream).ljust(ministream_sectors * 512, b"\x00")
    large_bytes = b"".join(e["data"].ljust(math.ceil(e["size"] / 512) * 512, b"\x00") for e in large)
    fat_bytes = struct.pack("<%dI" % len(fat), *fat)

    header = bytearray(512)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHHH", header, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIIIIIII", header, 0x2C, n_fat, first_dir, 0, 4096, first_minifat, minifat_sectors, _END, 0)
    difat = list(range(n_fat)) + [_FREE] * (109 - n_fat)
    struct.pack_into("<109I", header, 0x4C, *difat)

    return bytes(header) + fat_bytes + dir_bytes + minifat_bytes + ministream_bytes + large_bytes


def ovba_compress_literal(data: bytes) -> bytes:
    """MS-OVBA 'compress' using literal tokens only (valid, just not small)."""
    out = bytearray([1])
    for i in range(0, len(data), 3584):
        chunk = data[i:i + 3584]
        body = bytearray()
        for j in range(0, len(chunk), 8):
            body.append(0)
            body += chunk[j:j + 8]
        header = ((len(body) + 2 - 3) & 0x0FFF) | 0x3000 | 0x8000
        out += header.to_bytes(2, "little") + body
    return bytes(out)


def vba_module_stream(source: str, perf_cache: bytes = b"\x00" * 16) -> bytes:
    """A VBA module stream: (ignored) performance cache, then the compressed source."""
    text = ("Attribute VB_Name = \"Module1\"\r\n" + source).encode("latin-1")
    return perf_cache + ovba_compress_literal(text)


def make_vba_project(source: str) -> bytes:
    """A vbaProject.bin-style compound file holding one module with `source`."""
    return make_cfb({"VBA/Module1": vba_module_stream(source), "VBA/dir": b"\x01\x00\x00", "VBA/_VBA_PROJECT": b"\xcc\x61"})


def make_zip(files: dict, flag_encrypted=()) -> bytes:
    """Build a ZIP. Names in `flag_encrypted` get the 'encrypted' general-purpose
    flag set (the content isn't really encrypted -- enough to exercise detection;
    Python's zipfile can't write encrypted entries, and resets the flag on write,
    so it's patched into the finished bytes)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
        start_dir = zf.start_dir
        offsets = {i.filename: i.header_offset for i in zf.infolist()}
    raw = bytearray(buf.getvalue())
    for name in flag_encrypted:
        raw[offsets[name] + 6] |= 0x1  # local file header flags
    pos = start_dir
    while raw[pos:pos + 4] == b"PK\x01\x02":
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", raw, pos + 28)
        entry_name = bytes(raw[pos + 46:pos + 46 + name_len]).decode("utf-8")
        if entry_name in flag_encrypted:
            raw[pos + 8] |= 0x1  # central directory flags
        pos += 46 + name_len + extra_len + comment_len
    return bytes(raw)


_CONTENT_TYPES = ('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                  '<Default Extension="xml" ContentType="application/xml"/></Types>')


def make_docx(macro_source: str = None, external_rels: list = (), extra: dict = None,
              document_xml: str = "<w:document/>", content_types: str = _CONTENT_TYPES) -> bytes:
    files = {"[Content_Types].xml": content_types, "word/document.xml": document_xml}
    if macro_source is not None:
        files["word/vbaProject.bin"] = make_vba_project(macro_source)
    if external_rels:
        rels = "".join(
            f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/{t}" '
            f'Target="{target}" TargetMode="External"/>' for i, (t, target) in enumerate(external_rels, start=1))
        files["word/_rels/document.xml.rels"] = (
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            + rels + "</Relationships>")
    files.update(extra or {})
    return make_zip(files)


def make_pe(extra_strings: bytes = b"", dll: bool = False) -> bytes:
    data = bytearray(2048)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x44, 0x14C, 1, 1_600_000_000, 0, 0, 224, 0x2102 if dll else 0x0102)
    opt = 0x58
    struct.pack_into("<H", data, opt, 0x10B)
    struct.pack_into("<H", data, opt + 68, 3)
    table = opt + 224
    data[table:table + 8] = b".text\x00\x00\x00"
    struct.pack_into("<II", data, table + 16, 512, 1024)
    data[1024:1024 + len(extra_strings)] = extra_strings
    return bytes(data)


def make_pdf(body: str = "", compress_extra: str = None) -> bytes:
    import zlib
    parts = [b"%PDF-1.4\n", body.encode("latin-1"), b"\n"]
    if compress_extra:
        parts += [b"7 0 obj\n<< /Filter /FlateDecode >>\nstream\n", zlib.compress(compress_extra.encode("latin-1")),
                  b"\nendstream\nendobj\n"]
    parts.append(b"%%EOF")
    return b"".join(parts)


def make_xls_workbook_stream(sheets: list) -> bytes:
    """BIFF8 workbook-globals stream with BoundSheet records: [(type, state, name)]."""
    out = struct.pack("<HH", 0x0809, 16) + b"\x00" * 16
    for sheet_type, state, name in sheets:
        raw = name.encode("latin-1")
        body = struct.pack("<I", 0) + bytes([state, sheet_type, len(raw), 0]) + raw
        out += struct.pack("<HH", 0x0085, len(body)) + body
    out += struct.pack("<HH", 0x000A, 0)
    return out
