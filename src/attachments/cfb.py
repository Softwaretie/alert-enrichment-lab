"""Minimal, dependency-free reader for OLE2 / Compound File Binary (CFB) files.

Legacy Office documents (.doc/.xls/.ppt), Outlook .msg files, encrypted
OOXML packages, and the `vbaProject.bin` part inside macro-enabled .docm/.xlsm
files are all CFB containers. This reads just enough of the format to list the
streams inside one and pull out VBA macro source, so the attachment analyzer
can spot macros, auto-run entry points and embedded payload URLs without
third-party packages (no olefile/oletools needed).

Everything here works on bytes in memory, never touches disk, never executes
anything, and bounds every loop and allocation so a malformed or hostile file
can only make parsing fail -- not hang or exhaust memory.
"""
import struct

CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

_ENDOFCHAIN = 0xFFFFFFFE
_FREESECT = 0xFFFFFFFF
_MAX_STREAM_BYTES = 20 * 1024 * 1024
_MAX_ENTRIES = 5000


class CFBError(Exception):
    """Raised when the data isn't a parseable compound file."""


class CompoundFile:
    def __init__(self, data: bytes):
        if len(data) < 512 or not data.startswith(CFB_MAGIC):
            raise CFBError("not a compound file")
        try:
            self._parse(data)
        except (struct.error, IndexError, OverflowError, MemoryError) as exc:
            raise CFBError(f"malformed compound file: {exc}") from exc

    def _parse(self, data: bytes) -> None:
        self._data = data

        sector_shift, mini_shift = struct.unpack_from("<HH", data, 0x1E)
        if sector_shift not in (9, 12) or mini_shift != 6:
            raise CFBError("unsupported sector size")
        self._sector_size = 1 << sector_shift
        self._mini_size = 1 << mini_shift

        (num_fat, first_dir, _tx, self._mini_cutoff, first_minifat, num_minifat,
         first_difat, num_difat) = struct.unpack_from("<IIIIIIII", data, 0x2C)

        self._max_sectors = max(0, len(data) // self._sector_size)
        self._fat = self._load_fat(num_fat, first_difat, num_difat)
        self._entries = self._load_directory(first_dir)
        self._minifat = self._load_minifat(first_minifat, num_minifat)

        root = self._entries[0] if self._entries else None
        self._ministream = b""
        if root is not None and root["type"] == 5 and root["start"] != _ENDOFCHAIN:
            self._ministream = self._read_chain(root["start"], root["size"])

        self.streams = {}  # path (str, "/"-joined) -> entry dict
        self.storages = set()
        self._build_paths()

    # --- low-level sector access ------------------------------------------

    def _sector(self, index: int) -> bytes:
        offset = (index + 1) * self._sector_size
        raw = self._data[offset:offset + self._sector_size] if index >= 0 else b""
        if not raw:
            raise CFBError("sector out of range")
        # Tolerate a truncated final sector (seen in real-world samples) by zero-padding it.
        return raw.ljust(self._sector_size, b"\x00")

    def _load_fat(self, num_fat: int, first_difat: int, num_difat: int) -> list:
        difat = list(struct.unpack_from("<109I", self._data, 0x4C))
        sector = first_difat
        seen = set()
        for _ in range(min(num_difat, 4096)):
            if sector in (_ENDOFCHAIN, _FREESECT) or sector in seen:
                break
            seen.add(sector)
            raw = self._sector(sector)
            entries = struct.unpack("<%dI" % (self._sector_size // 4), raw)
            difat.extend(entries[:-1])
            sector = entries[-1]

        fat = []
        for fat_sector in difat[:max(num_fat, 0)]:
            if fat_sector in (_ENDOFCHAIN, _FREESECT):
                continue
            raw = self._sector(fat_sector)
            fat.extend(struct.unpack("<%dI" % (self._sector_size // 4), raw))
        return fat

    def _chain(self, start: int, fat: list) -> list:
        chain = []
        sector = start
        seen = set()
        while sector < 0xFFFFFFFA and sector not in seen and len(chain) <= self._max_sectors + 1:
            if sector >= len(fat):
                break
            seen.add(sector)
            chain.append(sector)
            sector = fat[sector]
        return chain

    def _read_chain(self, start: int, size: int) -> bytes:
        size = min(size, _MAX_STREAM_BYTES)
        out = bytearray()
        for sector in self._chain(start, self._fat):
            out += self._sector(sector)
            if len(out) >= size:
                break
        return bytes(out[:size])

    def _load_minifat(self, first: int, count: int) -> list:
        if first == _ENDOFCHAIN or count == 0:
            return []
        raw = self._read_chain(first, count * self._sector_size)
        return list(struct.unpack("<%dI" % (len(raw) // 4), raw[:len(raw) // 4 * 4]))

    def _load_directory(self, first_dir: int) -> list:
        raw = self._read_chain(first_dir, _MAX_ENTRIES * 128)
        entries = []
        for i in range(min(len(raw) // 128, _MAX_ENTRIES)):
            rec = raw[i * 128:(i + 1) * 128]
            name_len = struct.unpack_from("<H", rec, 64)[0]
            name = rec[:max(0, min(name_len, 64) - 2)].decode("utf-16-le", errors="replace")
            etype = rec[66]
            left, right, child = struct.unpack_from("<III", rec, 68)
            start = struct.unpack_from("<I", rec, 116)[0]
            size = struct.unpack_from("<Q", rec, 120)[0]
            if self._sector_size == 512:
                size &= 0xFFFFFFFF  # v3 files: high dword is undefined
            entries.append({"name": name, "type": etype, "left": left, "right": right,
                            "child": child, "start": start, "size": size})
        return entries

    def _build_paths(self) -> None:
        """Walk the directory's sibling/child tree, recording full paths."""
        if not self._entries:
            return
        no_stream = 0xFFFFFFFF
        stack = [(self._entries[0]["child"], "")]
        visited = set()
        while stack:
            index, prefix = stack.pop()
            if index == no_stream or index >= len(self._entries) or index in visited:
                continue
            visited.add(index)
            entry = self._entries[index]
            path = f"{prefix}{entry['name']}"
            if entry["type"] == 2:
                self.streams[path] = entry
            elif entry["type"] == 1:
                self.storages.add(path)
                stack.append((entry["child"], path + "/"))
            stack.append((entry["left"], prefix))
            stack.append((entry["right"], prefix))

    # --- public API --------------------------------------------------------

    def read_stream(self, path: str, limit: int = _MAX_STREAM_BYTES) -> bytes:
        entry = self.streams[path]
        size = min(entry["size"], limit)
        if entry["size"] < self._mini_cutoff:
            out = bytearray()
            for sector in self._chain(entry["start"], self._minifat):
                offset = sector * self._mini_size
                out += self._ministream[offset:offset + self._mini_size]
                if len(out) >= size:
                    break
            return bytes(out[:size])
        return self._read_chain(entry["start"], size)


# --- VBA macro source extraction (MS-OVBA compression) ----------------------

def ovba_decompress(data: bytes, max_output: int = 1024 * 1024) -> bytes:
    """Decompress an MS-OVBA CompressedContainer (the format VBA module source
    is stored in). Raises ValueError on malformed input."""
    if not data or data[0] != 0x01:
        raise ValueError("bad container signature")
    out = bytearray()
    pos = 1
    while pos + 2 <= len(data):
        header = data[pos] | (data[pos + 1] << 8)
        chunk_size = (header & 0x0FFF) + 3
        if (header >> 12) & 0x7 != 0b011:
            raise ValueError("bad chunk signature")
        compressed = bool(header & 0x8000)
        chunk_end = min(pos + chunk_size, len(data))
        pos += 2
        chunk_start_out = len(out)

        if not compressed:
            out += data[pos:pos + 4096]
            pos = chunk_end
        else:
            while pos < chunk_end:
                flags = data[pos]
                pos += 1
                for bit in range(8):
                    if pos >= chunk_end:
                        break
                    if not (flags >> bit) & 1:
                        out.append(data[pos])
                        pos += 1
                    else:
                        if pos + 2 > chunk_end:
                            raise ValueError("truncated copy token")
                        token = data[pos] | (data[pos + 1] << 8)
                        pos += 2
                        difference = len(out) - chunk_start_out
                        bit_count = max((difference - 1).bit_length(), 4)
                        length_mask = 0xFFFF >> bit_count
                        length = (token & length_mask) + 3
                        offset = ((token & ~length_mask & 0xFFFF) >> (16 - bit_count)) + 1
                        if offset > difference:
                            raise ValueError("copy offset before chunk start")
                        for _ in range(length):
                            out.append(out[-offset])
        if len(out) > max_output:
            break
    return bytes(out[:max_output])


def extract_vba_source(cfb: CompoundFile, max_modules: int = 50) -> dict:
    """Best-effort pull of VBA module source out of a compound file.

    Returns {module_stream_path: source_text}. A module's compressed source
    always begins with the literal text "Attribute VB_...", and its first
    eight characters can't have been compressed (nothing precedes them to
    copy from), so the container is located by searching for them rather than
    parsing the project's `dir` stream. Modules that can't be decoded are
    skipped -- callers still know macros exist from the stream names alone."""
    modules = {}
    for path in cfb.streams:
        parts = path.split("/")
        if "VBA" not in parts[:-1]:
            continue
        name = parts[-1]
        if name in ("dir", "_VBA_PROJECT") or name.startswith("__SRP_") or name.startswith("PROJECT"):
            continue
        if len(modules) >= max_modules:
            break
        try:
            raw = cfb.read_stream(path)
            idx = raw.find(b"\x00Attribut")
            if idx < 3 or raw[idx - 3] != 0x01:
                continue
            source = ovba_decompress(raw[idx - 3:])
            modules[path] = source.decode("latin-1", errors="replace")
        except (ValueError, CFBError, struct.error, KeyError):
            continue
    return modules
