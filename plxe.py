#!/usr/bin/env python3
"""Decode and encode Playrix PLXE asset containers.

Layout notes live in docs/FORMAT.md, usage in README.md. No key material
is bundled with this project; point the tool at your own keys file (see
keys.example.json).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

__version__ = "0.1.0"

MAGIC = b"PLXE"
FIXED_HEADER_SIZE = 8

SUBTYPE_ROLLING = 1
SUBTYPE_BROTLI = 2
SUBTYPE_ROLLING_ZLIB = 3
SUBTYPE_ZSTD = 4

SUBTYPE_NAMES = {
    SUBTYPE_ROLLING: "rolling cipher",
    SUBTYPE_BROTLI: "brotli",
    SUBTYPE_ROLLING_ZLIB: "rolling cipher + zlib (filename-keyed)",
    SUBTYPE_ZSTD: "zstd",
}

# The rolling cipher advances a 32-bit counter by this much per byte.
_COUNTER_STEP = 0x17
_MASK32 = 0xFFFFFFFF

# Extra header bytes written by the encoder. These are the values seen in
# the sample files that were examined; what the game does with them (beyond
# the zlib window bits) has not been verified.
_TYPE1_EXTRA = b"\x00"
_TYPE3_CODEC_BYTE = 0x04
_TYPE3_TAG_BYTE = 0x44
_DEFAULT_WINDOW_BITS = 9


class PlxeError(Exception):
    """Raised for malformed containers, missing keys and failed decodes."""


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Header:
    subtype: int
    extra: bytes

    @property
    def payload_offset(self) -> int:
        return FIXED_HEADER_SIZE + len(self.extra)


def parse_header(raw: bytes) -> Header:
    if len(raw) < FIXED_HEADER_SIZE:
        raise PlxeError("file is too short to be a PLXE container")
    if raw[:4] != MAGIC:
        raise PlxeError("missing PLXE magic bytes")
    subtype, extra_len = struct.unpack_from("<HH", raw, 4)
    end = FIXED_HEADER_SIZE + extra_len
    if len(raw) < end:
        raise PlxeError(
            f"truncated header: expected {extra_len} extra bytes, "
            f"only {len(raw) - FIXED_HEADER_SIZE} present"
        )
    return Header(subtype, raw[FIXED_HEADER_SIZE:end])


# ---------------------------------------------------------------------------
# Rolling cipher (subtypes 1 and 3)
# ---------------------------------------------------------------------------

def _rol8(value: int, shift: int) -> int:
    shift &= 7
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def _fold32(counter: int) -> int:
    """XOR of the four bytes of a 32-bit counter."""
    return (counter ^ (counter >> 8) ^ (counter >> 16) ^ (counter >> 24)) & 0xFF


def decrypt(key: bytes, data: bytes) -> bytes:
    if not key:
        raise PlxeError("empty key")
    out = bytearray(len(data))
    acc = 0
    counter = 0
    for i, c in enumerate(data):
        p = c ^ key[i % len(key)] ^ acc ^ _fold32(counter)
        out[i] = p
        acc = p ^ _rol8(acc, 1)
        counter = (counter + _COUNTER_STEP) & _MASK32
    return bytes(out)


def encrypt(key: bytes, data: bytes) -> bytes:
    if not key:
        raise PlxeError("empty key")
    out = bytearray(len(data))
    acc = 0
    counter = 0
    for i, p in enumerate(data):
        out[i] = p ^ key[i % len(key)] ^ acc ^ _fold32(counter)
        acc = p ^ _rol8(acc, 1)
        counter = (counter + _COUNTER_STEP) & _MASK32
    return bytes(out)


def _cycled_bits(data: bytes) -> Iterator[int]:
    """Endless bit stream over data, least significant bit of each byte first."""
    while True:
        for byte in data:
            for shift in range(8):
                yield (byte >> shift) & 1


def rotate_master_key(master: bytes, name: str) -> bytes:
    """Derive the per-file key used by subtype 3.

    Each master key byte is rotated left by 0-7 bits. The amounts come from
    the MD5 digest of the file name, three bits per key byte.
    """
    bits = _cycled_bits(hashlib.md5(name.encode("utf-8")).digest())
    rotated = bytearray()
    for byte in master:
        amount = (next(bits) << 2) | (next(bits) << 1) | next(bits)
        rotated.append(_rol8(byte, amount))
    return bytes(rotated)


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

@dataclass
class Keys:
    type1: Optional[bytes] = None
    type3_master: Optional[bytes] = None

    @classmethod
    def load(cls, path: os.PathLike | str) -> "Keys":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except OSError as exc:
            raise PlxeError(f"cannot read keys file: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise PlxeError(f"{path}: not valid JSON ({exc})") from exc
        if not isinstance(data, dict):
            raise PlxeError(f"{path}: expected a JSON object")

        keys = cls()
        if data.get("type1"):
            try:
                keys.type1 = bytes.fromhex(data["type1"])
            except (ValueError, TypeError) as exc:
                raise PlxeError(f"{path}: 'type1' must be a hex string") from exc
        if data.get("type3"):
            try:
                keys.type3_master = base64.b64decode(data["type3"], validate=True)
            except (binascii.Error, TypeError) as exc:
                raise PlxeError(f"{path}: 'type3' must be base64") from exc
        return keys


def find_keys_file(explicit: Optional[str] = None) -> Optional[Path]:
    """Look for a keys file: --keys, then $PLXE_KEYS, then ./keys.json."""
    if explicit:
        return Path(explicit)
    env = os.environ.get("PLXE_KEYS")
    if env:
        return Path(env)
    local = Path("keys.json")
    return local if local.is_file() else None


def _require(key: Optional[bytes], label: str) -> bytes:
    if not key:
        raise PlxeError(
            f"no {label} key available; supply a keys file "
            "(see 'Keys' in the README)"
        )
    return key


# ---------------------------------------------------------------------------
# Decode / encode
# ---------------------------------------------------------------------------

def _window_bits(header: Header) -> int:
    if len(header.extra) < 2:
        raise PlxeError("subtype 3 header is missing the window-bits byte")
    bits = header.extra[1]
    if not 8 <= bits <= 15:
        raise PlxeError(f"unexpected zlib window bits in header: {bits}")
    return bits


def decode(raw: bytes, keys: Optional[Keys] = None, name: Optional[str] = None) -> bytes:
    """Return the plain payload of a PLXE container.

    `name` is the asset's file name. Only subtype 3 uses it, because its
    key is derived from it.
    """
    keys = keys or Keys()
    header = parse_header(raw)
    payload = raw[header.payload_offset:]

    if header.subtype == SUBTYPE_ROLLING:
        return decrypt(_require(keys.type1, "type 1"), payload)

    if header.subtype == SUBTYPE_ROLLING_ZLIB:
        if not name:
            raise PlxeError("subtype 3 needs the asset file name (--name)")
        bits = _window_bits(header)
        master = _require(keys.type3_master, "type 3")
        key = rotate_master_key(master, os.path.basename(name))
        try:
            return zlib.decompress(decrypt(key, payload), bits)
        except zlib.error as exc:
            raise PlxeError(
                f"inflate failed ({exc}); the file name used for key "
                "derivation or the type 3 key is probably wrong"
            ) from exc

    if header.subtype == SUBTYPE_BROTLI:
        try:
            import brotli
        except ImportError as exc:
            raise PlxeError("subtype 2 needs the 'brotli' package") from exc
        try:
            return brotli.decompress(payload)
        except brotli.error as exc:
            raise PlxeError(f"brotli decompression failed: {exc}") from exc

    if header.subtype == SUBTYPE_ZSTD:
        try:
            import zstandard
        except ImportError as exc:
            raise PlxeError("subtype 4 needs the 'zstandard' package") from exc
        try:
            return zstandard.ZstdDecompressor().decompress(payload)
        except zstandard.ZstdError as exc:
            raise PlxeError(f"zstd decompression failed: {exc}") from exc

    raise PlxeError(f"unsupported PLXE subtype {header.subtype}")


def encode(
    plain: bytes,
    subtype: int,
    keys: Keys,
    name: Optional[str] = None,
    window_bits: int = _DEFAULT_WINDOW_BITS,
) -> bytes:
    """Wrap plain data in a PLXE container. Only subtypes 1 and 3 are supported."""
    if subtype == SUBTYPE_ROLLING:
        key = _require(keys.type1, "type 1")
        header = MAGIC + struct.pack("<HH", subtype, len(_TYPE1_EXTRA)) + _TYPE1_EXTRA
        return header + encrypt(key, plain)

    if subtype == SUBTYPE_ROLLING_ZLIB:
        if not name:
            raise PlxeError("subtype 3 needs the target asset file name (--name)")
        if not 9 <= window_bits <= 15:
            raise PlxeError("window bits must be between 9 and 15")
        master = _require(keys.type3_master, "type 3")
        key = rotate_master_key(master, os.path.basename(name))
        packer = zlib.compressobj(9, zlib.DEFLATED, window_bits)
        packed = packer.compress(plain) + packer.flush()
        extra = bytes([_TYPE3_CODEC_BYTE, window_bits, _TYPE3_TAG_BYTE])
        header = MAGIC + struct.pack("<HH", subtype, len(extra)) + extra
        return header + encrypt(key, packed)

    raise PlxeError("encoding is only implemented for subtypes 1 and 3")


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def _looks_like_xml(data: bytes) -> bool:
    return data.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"<")


def _load_keys(explicit: Optional[str]) -> Keys:
    path = find_keys_file(explicit)
    return Keys.load(path) if path else Keys()


def _cmd_info(args: argparse.Namespace) -> int:
    raw = Path(args.input).read_bytes()
    header = parse_header(raw)
    kind = SUBTYPE_NAMES.get(header.subtype, "unknown")
    extra = " ".join(f"{b:02x}" for b in header.extra) or "-"
    print(f"file:     {args.input}")
    print(f"subtype:  {header.subtype} ({kind})")
    print(f"extra:    {extra}")
    print(f"payload:  {len(raw) - header.payload_offset} bytes at offset {header.payload_offset}")
    return 0


def _cmd_decode(args: argparse.Namespace) -> int:
    src = Path(args.input)
    out = Path(args.output) if args.output else src.with_name(src.stem + ".decoded.xml")
    if out.resolve() == src.resolve():
        raise PlxeError("refusing to overwrite the input file")
    plain = decode(src.read_bytes(), _load_keys(args.keys), args.name or src.name)
    if not _looks_like_xml(plain):
        print("warning: output does not start with '<'; wrong key?", file=sys.stderr)
    out.write_bytes(plain)
    print(f"{src} -> {out} ({len(plain)} bytes)")
    return 0


def _cmd_encode(args: argparse.Namespace) -> int:
    src = Path(args.input)
    stem = src.stem[:-len(".decoded")] if src.stem.endswith(".decoded") else src.stem
    out = Path(args.output) if args.output else src.with_name(stem + ".plxe")
    if out.resolve() == src.resolve():
        raise PlxeError("refusing to overwrite the input file")
    # Subtype 3 keys depend on the name the file will have in the game, so
    # fall back to the output name only when it was given explicitly.
    name = args.name or (out.name if args.output else None)
    packed = encode(
        src.read_bytes(),
        args.subtype,
        _load_keys(args.keys),
        name=name,
        window_bits=args.window_bits,
    )
    out.write_bytes(packed)
    print(f"{src} -> {out} ({len(packed)} bytes)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="plxe",
        description="Decode and encode PLXE asset containers.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    info = sub.add_parser("info", help="print the container header")
    info.add_argument("input")
    info.set_defaults(func=_cmd_info)

    dec = sub.add_parser("decode", help="decode a container to plain data")
    dec.add_argument("input")
    dec.add_argument("-o", "--output", help="output path (default: <name>.decoded.xml)")
    dec.add_argument("-k", "--keys", help="path to keys file")
    dec.add_argument("--name", help="asset file name for subtype 3 (default: input file name)")
    dec.set_defaults(func=_cmd_decode)

    enc = sub.add_parser("encode", help="wrap plain data in a container (subtypes 1 and 3)")
    enc.add_argument("input")
    enc.add_argument("-s", "--subtype", type=int, choices=(1, 3), required=True)
    enc.add_argument("-o", "--output", help="output path (default: <name>.plxe)")
    enc.add_argument("-k", "--keys", help="path to keys file")
    enc.add_argument("--name", help="asset file name for subtype 3 (default: output file name)")
    enc.add_argument(
        "--window-bits",
        type=int,
        default=_DEFAULT_WINDOW_BITS,
        help="zlib window bits for subtype 3 (default: %(default)s)",
    )
    enc.set_defaults(func=_cmd_encode)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except PlxeError as exc:
        print(f"plxe: error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"plxe: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
