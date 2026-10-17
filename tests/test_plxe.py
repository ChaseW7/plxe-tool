"""Tests use made-up keys and made-up data only."""
import base64
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import plxe  # noqa: E402

try:
    import brotli
except ImportError:
    brotli = None

try:
    import zstandard
except ImportError:
    zstandard = None


DUMMY_KEY1 = bytes(range(64))
DUMMY_MASTER3 = bytes(range(64, 128))
SAMPLE_XML = b'<root><item id="1"/></root>\n'
LONG_XML = b"<root>" + b"".join(b'<row n="%d" v="%d"/>' % (i, i * 7) for i in range(400)) + b"</root>\n"


def dummy_keys():
    return plxe.Keys(type1=DUMMY_KEY1, type3_master=DUMMY_MASTER3)


def container(subtype, extra, payload):
    return plxe.MAGIC + subtype.to_bytes(2, "little") + len(extra).to_bytes(2, "little") + extra + payload


class HeaderTests(unittest.TestCase):
    def test_parse(self):
        raw = container(3, b"\x04\x09\x44", b"payload")
        header = plxe.parse_header(raw)
        self.assertEqual(header.subtype, 3)
        self.assertEqual(header.extra, b"\x04\x09\x44")
        self.assertEqual(header.payload_offset, 11)

    def test_bad_magic(self):
        with self.assertRaises(plxe.PlxeError):
            plxe.parse_header(b"NOPE\x01\x00\x00\x00")

    def test_too_short(self):
        with self.assertRaises(plxe.PlxeError):
            plxe.parse_header(b"PLXE")

    def test_truncated_extra(self):
        with self.assertRaises(plxe.PlxeError):
            plxe.parse_header(b"PLXE\x03\x00\x03\x00\x04")

    def test_unknown_subtype(self):
        with self.assertRaises(plxe.PlxeError):
            plxe.decode(container(9, b"", b"x"), dummy_keys(), "a.xml")


class CipherTests(unittest.TestCase):
    def test_known_answer(self):
        expected = bytes.fromhex(
            "3c584952b50f00921770433e81c901aacdbf94da5d952a720085afff"
        )
        self.assertEqual(plxe.encrypt(DUMMY_KEY1, SAMPLE_XML), expected)
        self.assertEqual(plxe.decrypt(DUMMY_KEY1, expected), SAMPLE_XML)

    def test_roundtrip_all_byte_values(self):
        data = bytes(range(256)) * 20
        self.assertEqual(plxe.decrypt(DUMMY_KEY1, plxe.encrypt(DUMMY_KEY1, data)), data)

    def test_key_shorter_than_data(self):
        key = b"\x01\x02\x03"
        self.assertEqual(plxe.decrypt(key, plxe.encrypt(key, LONG_XML)), LONG_XML)

    def test_empty_input(self):
        self.assertEqual(plxe.encrypt(DUMMY_KEY1, b""), b"")
        self.assertEqual(plxe.decrypt(DUMMY_KEY1, b""), b"")

    def test_empty_key(self):
        with self.assertRaises(plxe.PlxeError):
            plxe.decrypt(b"", b"abc")

    def test_wrong_key_does_not_roundtrip(self):
        other = bytes(reversed(DUMMY_KEY1))
        self.assertNotEqual(plxe.decrypt(other, plxe.encrypt(DUMMY_KEY1, LONG_XML)), LONG_XML)


class KeyRotationTests(unittest.TestCase):
    def test_known_answer(self):
        rotated = plxe.rotate_master_key(DUMMY_MASTER3, "Example.xml")
        self.assertEqual(rotated[:8].hex(), "04414843228ac874")
        self.assertEqual(len(rotated), len(DUMMY_MASTER3))

    def test_depends_on_name(self):
        a = plxe.rotate_master_key(DUMMY_MASTER3, "One.xml")
        b = plxe.rotate_master_key(DUMMY_MASTER3, "Two.xml")
        self.assertNotEqual(a, b)

    def test_rotation_preserves_bit_counts(self):
        rotated = plxe.rotate_master_key(DUMMY_MASTER3, "Example.xml")
        for before, after in zip(DUMMY_MASTER3, rotated):
            self.assertEqual(bin(before).count("1"), bin(after).count("1"))


class ContainerTests(unittest.TestCase):
    def test_subtype1_roundtrip(self):
        raw = plxe.encode(LONG_XML, 1, dummy_keys())
        self.assertEqual(raw[:9], b"PLXE\x01\x00\x01\x00\x00")
        self.assertEqual(plxe.decode(raw, dummy_keys()), LONG_XML)

    def test_subtype3_roundtrip(self):
        raw = plxe.encode(LONG_XML, 3, dummy_keys(), name="Example.xml")
        self.assertEqual(raw[:11], b"PLXE\x03\x00\x03\x00\x04\x09\x44")
        self.assertEqual(plxe.decode(raw, dummy_keys(), "Example.xml"), LONG_XML)

    def test_subtype3_ignores_directory_part_of_name(self):
        raw = plxe.encode(LONG_XML, 3, dummy_keys(), name="Example.xml")
        self.assertEqual(plxe.decode(raw, dummy_keys(), "some/dir/Example.xml"), LONG_XML)

    def test_subtype3_wrong_name(self):
        raw = plxe.encode(LONG_XML, 3, dummy_keys(), name="Example.xml")
        with self.assertRaises(plxe.PlxeError):
            plxe.decode(raw, dummy_keys(), "Other.xml")

    def test_subtype3_requires_name(self):
        raw = plxe.encode(LONG_XML, 3, dummy_keys(), name="Example.xml")
        with self.assertRaises(plxe.PlxeError):
            plxe.decode(raw, dummy_keys(), None)

    def test_subtype3_honours_window_bits(self):
        raw = plxe.encode(LONG_XML, 3, dummy_keys(), name="Example.xml", window_bits=12)
        self.assertEqual(raw[9], 12)
        self.assertEqual(plxe.decode(raw, dummy_keys(), "Example.xml"), LONG_XML)

    def test_subtype3_rejects_odd_window_bits(self):
        raw = container(3, b"\x04\x02\x44", b"xx")
        with self.assertRaises(plxe.PlxeError):
            plxe.decode(raw, dummy_keys(), "Example.xml")

    def test_missing_keys(self):
        raw = plxe.encode(SAMPLE_XML, 1, dummy_keys())
        with self.assertRaises(plxe.PlxeError):
            plxe.decode(raw, plxe.Keys())

    def test_encode_unsupported_subtype(self):
        with self.assertRaises(plxe.PlxeError):
            plxe.encode(SAMPLE_XML, 4, dummy_keys())

    @unittest.skipIf(brotli is None, "brotli not installed")
    def test_subtype2(self):
        raw = container(2, b"", brotli.compress(LONG_XML))
        self.assertEqual(plxe.decode(raw), LONG_XML)

    @unittest.skipIf(zstandard is None, "zstandard not installed")
    def test_subtype4(self):
        packed = zstandard.ZstdCompressor().compress(LONG_XML)
        raw = container(4, b"", packed)
        self.assertEqual(plxe.decode(raw), LONG_XML)

    @unittest.skipUnless(brotli is None, "only meaningful without brotli")
    def test_subtype2_without_brotli(self):
        with self.assertRaises(plxe.PlxeError):
            plxe.decode(container(2, b"", b"xx"))


class KeysFileTests(unittest.TestCase):
    def write(self, tmp, data):
        path = Path(tmp) / "keys.json"
        path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
        return path

    def test_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(tmp, {
                "type1": DUMMY_KEY1.hex(),
                "type3": base64.b64encode(DUMMY_MASTER3).decode(),
            })
            keys = plxe.Keys.load(path)
        self.assertEqual(keys.type1, DUMMY_KEY1)
        self.assertEqual(keys.type3_master, DUMMY_MASTER3)

    def test_partial_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys = plxe.Keys.load(self.write(tmp, {"type1": DUMMY_KEY1.hex()}))
        self.assertIsNone(keys.type3_master)

    def test_bad_hex(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(plxe.PlxeError):
                plxe.Keys.load(self.write(tmp, {"type1": "zz"}))

    def test_bad_base64(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(plxe.PlxeError):
                plxe.Keys.load(self.write(tmp, {"type3": "***"}))

    def test_not_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(plxe.PlxeError):
                plxe.Keys.load(self.write(tmp, "{nope"))

    def test_missing_file(self):
        with self.assertRaises(plxe.PlxeError):
            plxe.Keys.load("/definitely/not/here.json")

    def test_example_file_has_no_usable_keys(self):
        example = Path(__file__).resolve().parents[1] / "keys.example.json"
        data = json.loads(example.read_text(encoding="utf-8"))
        self.assertEqual(set(data), {"type1", "type3"})
        with self.assertRaises(plxe.PlxeError):
            plxe.Keys.load(example)


class CliTests(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = plxe.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.keys = self.dir / "keys.json"
        self.keys.write_text(json.dumps({
            "type1": DUMMY_KEY1.hex(),
            "type3": base64.b64encode(DUMMY_MASTER3).decode(),
        }))

    def tearDown(self):
        self.tmp.cleanup()

    def test_info(self):
        path = self.dir / "a.plxe"
        path.write_bytes(plxe.encode(SAMPLE_XML, 3, dummy_keys(), name="a.xml"))
        code, out, _ = self.run_cli("info", str(path))
        self.assertEqual(code, 0)
        self.assertIn("subtype:  3", out)
        self.assertIn("04 09 44", out)

    def test_decode_subtype1(self):
        src = self.dir / "Vars.plxe"
        src.write_bytes(plxe.encode(LONG_XML, 1, dummy_keys()))
        code, _, _ = self.run_cli("decode", str(src), "-k", str(self.keys))
        self.assertEqual(code, 0)
        self.assertEqual((self.dir / "Vars.decoded.xml").read_bytes(), LONG_XML)

    def test_decode_subtype3_uses_input_name(self):
        src = self.dir / "Consts.xml"
        src.write_bytes(plxe.encode(LONG_XML, 3, dummy_keys(), name="Consts.xml"))
        out = self.dir / "out.xml"
        code, _, _ = self.run_cli("decode", str(src), "-k", str(self.keys), "-o", str(out))
        self.assertEqual(code, 0)
        self.assertEqual(out.read_bytes(), LONG_XML)

    def test_decode_renamed_subtype3_needs_name(self):
        src = self.dir / "Consts.xml"
        src.write_bytes(plxe.encode(LONG_XML, 3, dummy_keys(), name="Consts.xml"))
        renamed = self.dir / "copy.xml"
        renamed.write_bytes(src.read_bytes())
        code, _, err = self.run_cli("decode", str(renamed), "-k", str(self.keys))
        self.assertEqual(code, 1)
        self.assertIn("error", err)
        code, _, _ = self.run_cli(
            "decode", str(renamed), "-k", str(self.keys), "--name", "Consts.xml"
        )
        self.assertEqual(code, 0)

    def test_encode_then_decode(self):
        src = self.dir / "Vars.decoded.xml"
        src.write_bytes(LONG_XML)
        code, _, _ = self.run_cli("encode", str(src), "-s", "1", "-k", str(self.keys))
        self.assertEqual(code, 0)
        packed = self.dir / "Vars.plxe"
        self.assertEqual(plxe.decode(packed.read_bytes(), dummy_keys()), LONG_XML)

    def test_encode_subtype3_needs_a_name(self):
        src = self.dir / "in.xml"
        src.write_bytes(LONG_XML)
        code, _, err = self.run_cli("encode", str(src), "-s", "3", "-k", str(self.keys))
        self.assertEqual(code, 1)
        self.assertIn("--name", err)

    def test_encode_subtype3_name_from_output(self):
        src = self.dir / "in.xml"
        src.write_bytes(LONG_XML)
        out = self.dir / "Consts.xml"
        code, _, _ = self.run_cli(
            "encode", str(src), "-s", "3", "-k", str(self.keys), "-o", str(out)
        )
        self.assertEqual(code, 0)
        self.assertEqual(plxe.decode(out.read_bytes(), dummy_keys(), "Consts.xml"), LONG_XML)

    def test_missing_keys_is_reported(self):
        src = self.dir / "Vars.plxe"
        src.write_bytes(plxe.encode(LONG_XML, 1, dummy_keys()))
        cwd = os.getcwd()
        os.chdir(self.dir / ".")
        try:
            self.keys.rename(self.dir / "elsewhere.json")
            env = dict(os.environ)
            os.environ.pop("PLXE_KEYS", None)
            code, _, err = self.run_cli("decode", str(src))
        finally:
            os.chdir(cwd)
            os.environ.clear()
            os.environ.update(env)
        self.assertEqual(code, 1)
        self.assertIn("no type 1 key", err)

    def test_refuses_to_overwrite_input(self):
        src = self.dir / "Vars.plxe"
        src.write_bytes(plxe.encode(LONG_XML, 1, dummy_keys()))
        code, _, err = self.run_cli(
            "decode", str(src), "-k", str(self.keys), "-o", str(src)
        )
        self.assertEqual(code, 1)
        self.assertIn("overwrite", err)

    def test_not_a_plxe_file(self):
        src = self.dir / "plain.xml"
        src.write_bytes(b"<root/>")
        code, _, err = self.run_cli("info", str(src))
        self.assertEqual(code, 1)
        self.assertIn("PLXE", err)


if __name__ == "__main__":
    unittest.main()
