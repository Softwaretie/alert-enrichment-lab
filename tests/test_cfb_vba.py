"""Tests for the compound-file reader and VBA macro extraction."""
import unittest

from src.attachments.cfb import CFBError, CompoundFile, extract_vba_source, ovba_decompress
from tests.support import make_cfb, make_vba_project, ovba_compress_literal


class OvbaDecompressTests(unittest.TestCase):
    def test_copy_token(self):
        # Hand-computed per MS-OVBA: "abc" literals, then copy(offset=3, length=6).
        container = bytes([0x01, 0x05, 0xB0, 0x08, 0x61, 0x62, 0x63, 0x03, 0x20])
        self.assertEqual(ovba_decompress(container), b"abcabcabc")

    def test_literal_roundtrip_multi_chunk(self):
        text = (b"Sub AutoOpen()\r\n  MsgBox \"hi\"\r\nEnd Sub\r\n" * 300)  # > one 4096-byte chunk
        self.assertEqual(ovba_decompress(ovba_compress_literal(text)), text)

    def test_rejects_bad_signature(self):
        with self.assertRaises(ValueError):
            ovba_decompress(b"\x02\x00\x00")

    def test_rejects_copy_before_start(self):
        # copy token as the very first token has nothing to copy from
        with self.assertRaises(ValueError):
            ovba_decompress(bytes([0x01, 0x02, 0xB0, 0x01, 0x00, 0x00]))


class CompoundFileTests(unittest.TestCase):
    def test_lists_nested_streams_small_and_large(self):
        big = bytes(range(256)) * 40  # 10 KB -> regular sectors, not the mini stream
        cfb = CompoundFile(make_cfb({"Macros/VBA/ThisDocument": b"small", "WordDocument": big, "Top": b"x"}))
        self.assertEqual(set(cfb.streams), {"Macros/VBA/ThisDocument", "WordDocument", "Top"})
        self.assertIn("Macros/VBA", cfb.storages)
        self.assertEqual(cfb.read_stream("Macros/VBA/ThisDocument"), b"small")
        self.assertEqual(cfb.read_stream("WordDocument"), big)

    def test_not_a_compound_file(self):
        with self.assertRaises(CFBError):
            CompoundFile(b"hello" * 200)

    def test_truncated_file_does_not_hang_or_crash_unexpectedly(self):
        data = make_cfb({"A/B": b"x" * 100})
        for cut in (600, 1024, len(data) - 10):
            try:
                CompoundFile(data[:cut])
            except CFBError:
                pass


class VbaExtractionTests(unittest.TestCase):
    def test_extracts_module_source(self):
        cfb = CompoundFile(make_vba_project('Sub AutoOpen()\r\n  Shell "calc"\r\nEnd Sub'))
        modules = extract_vba_source(cfb)
        self.assertEqual(list(modules), ["VBA/Module1"])
        self.assertIn("Sub AutoOpen()", modules["VBA/Module1"])
        self.assertIn('Shell "calc"', modules["VBA/Module1"])

    def test_module_without_attribute_marker_is_skipped(self):
        cfb = CompoundFile(make_cfb({"VBA/Module1": b"\x00" * 64, "VBA/dir": b"\x01"}))
        self.assertEqual(extract_vba_source(cfb), {})


if __name__ == "__main__":
    unittest.main()
