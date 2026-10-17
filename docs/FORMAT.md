# PLXE container format

Notes on the `PLXE` asset container as seen in Playrix mobile games. This
describes the container and the algorithms only. It does not include key
material or any information about where keys live in the game.

## How much of this is verified

| Subtype | Verified against a real file | Notes |
|---|---|---|
| 1 | yes (one file, ~126 KiB) | decode, and re-encoding reproduces the file byte for byte |
| 3 | yes (one file, 833 bytes) | decode; the cipher layer re-encrypts to the original bytes |
| 2 | no | implemented from the format description, tested with synthetic data only |
| 4 | no | same as above |

Everything below about subtypes 2 and 4 should be treated as provisional.
If you have real files of those types, a report is very welcome.

## Header

All integers are little-endian.

```
offset  size  field
0       4     magic, ASCII "PLXE"
4       2     subtype
6       2     extra_len, number of extra header bytes
8       n     extra bytes (n = extra_len)
8+n     ...   payload, to end of file
```

The payload starts at `8 + extra_len`. Other than that, the extra bytes are
subtype specific.

### Extra bytes seen in the wild

- Subtype 1: one byte, `00`.
- Subtype 3: three bytes, `04 09 44`.
  - Byte 1 is the zlib window bits (`09` = 9). This is the only byte the
    decoder uses, and the value is confirmed by the file inflating correctly.
  - Bytes 0 and 2 are written back unchanged by the encoder. They have been
    reported to select a codec and a key slot respectively, but that has not
    been verified here.

## Subtype 1: rolling cipher

A byte-wise stream cipher with a repeating key, an 8-bit accumulator `acc`
and a 32-bit counter `ctr`. Both start at zero.

For input byte `i`:

```
fold   = byte0(ctr) ^ byte1(ctr) ^ byte2(ctr) ^ byte3(ctr)
plain  = cipher ^ key[i % len(key)] ^ acc ^ fold
acc    = plain ^ rol8(acc, 1)
ctr    = (ctr + 0x17) mod 2^32
```

Encryption is the same expression solved for `cipher`. `acc` is always fed
with the plaintext byte, in both directions.

`fold` is the same value as
`(ctr & 0xFF) ^ ((ctr >> 16) & 0xFF) ^ (((ctr ^ (ctr >> 16)) & 0xFFFF) >> 8)`,
which is how it tends to appear in disassembly.

There is no integrity check in subtype 1. A wrong key produces noise, so the
tool warns when the output does not start with `<`.

## Subtype 3: filename-keyed cipher + zlib

The payload is a zlib stream that has been encrypted with the same rolling
cipher as subtype 1, using a key that depends on the file name.

### Per-file key

The file's *base name* (no directory) is hashed with MD5. The 16 digest bytes
are turned into an endless bit stream, least significant bit of each byte
first, wrapping around. For each byte of the 64-byte master key, three bits
`b0 b1 b2` are taken from the stream and

```
amount = (b0 << 2) | (b1 << 1) | b2        # 0..7
key[i] = rol8(master[i], amount)
```

Because of this, a subtype 3 file cannot be decoded after it has been
renamed unless you tell the tool the original name.

### Decoding

1. Read the window bits from extra byte 1.
2. Derive the per-file key from the name.
3. Decrypt the payload with the rolling cipher.
4. Inflate with `zlib.decompress(data, window_bits)`.

zlib's header and Adler-32 checksum make a wrong name or wrong master key
easy to detect: inflation fails.

## Subtype 2: Brotli

The payload is a plain Brotli stream. No encryption.

## Subtype 4: Zstandard

The payload is a plain Zstandard frame. No encryption.

## Out of scope

Some decoded payloads are themselves wrapped in another legacy container
(first byte `0x79`). That layer is not handled by this project.
