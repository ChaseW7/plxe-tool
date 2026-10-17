# plxe-tool

[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?logo=discord&logoColor=white)](https://discord.com/users/1104792474091782175)

A small command-line tool and Python module for reading and writing `PLXE`
asset containers, the wrapper format used around XML config files in several
Playrix mobile games.

- Pure standard library for subtypes 1 and 3. Brotli and zstd are optional.
- `info`, `decode` and `encode` commands.
- Clear errors instead of tracebacks for the usual mistakes (wrong key,
  renamed file, missing dependency).
- Tests included. They use made-up keys and made-up data.

This project is not affiliated with or endorsed by Playrix. See
[Legal](#legal).

## Status

| Subtype | What it is | Decode | Encode | Checked against a real file |
|---|---|---|---|---|
| 1 | rolling cipher | yes | yes | yes |
| 2 | Brotli | yes | no | no |
| 3 | rolling cipher + zlib, key depends on file name | yes | yes | yes |
| 4 | Zstandard | yes | no | no |

"Checked against a real file" means one sample of that type decoded to valid
XML. Subtypes 2 and 4 follow the format description and are only tested with
synthetic data. If you have real files of those types and something does not
work, please open an issue.

## Install

You need Python 3.9 or newer. There is nothing to install for subtypes 1 and
3, just copy `plxe.py`.

```sh
git clone <this repository>
cd plxe-tool
pip install -r requirements.txt   # only for subtype 2 and 4 files
```

## Keys

The tool does not ship with any keys, and this repository does not document
how to obtain them. You need the keys for the game you are working with,
obtained from your own copy of it.

Put them in a JSON file:

```json
{
  "type1": "<128 hex characters: the 64-byte subtype 1 key>",
  "type3": "<base64 of the 64-byte subtype 3 master key>"
}
```

`keys.example.json` has the layout. You only need the entries for the
subtypes you use. The tool looks for the file in this order:

1. `--keys path/to/keys.json`
2. the `PLXE_KEYS` environment variable
3. `keys.json` in the current directory

`keys.json` is in `.gitignore`. Keep it that way.

## Usage

Look at a file's header (no keys needed):

```sh
python plxe.py info GlobalVars.plxe
```

```
file:     GlobalVars.plxe
subtype:  1 (rolling cipher)
extra:    00
payload:  128865 bytes at offset 9
```

Decode a file. The output defaults to `<name>.decoded.xml`:

```sh
python plxe.py decode GlobalVars.plxe
python plxe.py decode GlobalVars.plxe -o vars.xml -k my-keys.json
```

### Subtype 3 and file names

For subtype 3 the key is derived from the asset's file name, so the name
matters. By default the tool uses the name of the file you give it. If you
have renamed the file, pass the original name:

```sh
python plxe.py decode copy-of-file.xml --name StartupConsts.xml
```

If the name is wrong you get:

```
plxe: error: inflate failed (...); the file name used for key derivation or the type 3 key is probably wrong
```

### Encoding

Subtypes 1 and 3 can be written back:

```sh
python plxe.py encode vars.decoded.xml -s 1 -o GlobalVars.plxe
python plxe.py encode consts.xml -s 3 -o StartupConsts.xml
```

For subtype 3, the name of the output file (or `--name`) is the name the key
is derived from, so use the name the game expects. `--window-bits` sets the
zlib window size (default 9).

Subtype 1 output has been checked to reproduce an original file byte for
byte. Subtype 3 output decodes correctly with this tool, but the compressed
bytes will not be identical to what the game's own packer produces, and it
has not been tested inside the game.

## Using it as a library

```python
from pathlib import Path
import plxe

keys = plxe.Keys.load("keys.json")

raw = Path("StartupConsts.xml").read_bytes()
xml = plxe.decode(raw, keys, name="StartupConsts.xml")

packed = plxe.encode(xml, 3, keys, name="StartupConsts.xml")
```

Everything raises `plxe.PlxeError` for bad input.

## Format notes

[`docs/FORMAT.md`](docs/FORMAT.md) describes the header, the cipher and the
per-file key derivation, and says which parts have been verified.

## Not covered

- Subtypes 2 and 4 have not been checked against real files.
- Some decoded payloads are wrapped in another legacy container that starts
  with the byte `0x79`. That layer is not handled.
- Encoding for subtypes 2 and 4.
- Anything to do with save files or game servers. This tool reads and writes
  static asset containers and nothing else. It is not meant for, and does not
  support, cheating in online play.

## Development

```sh
python -m unittest discover -s tests
```

Tests for subtypes 2 and 4 are skipped when `brotli` or `zstandard` is not
installed.

If you contribute, please do not include game files, keys, or details of how
to extract keys from the game. Patches containing them will not be merged.

## Legal

This is an independent interoperability and research project. "Playrix" and
the names of its games are trademarks of their owner and are used here only
to say which format the tool reads.

The repository contains no game assets and no key material, and you are
responsible for making sure that what you do with the tool complies with the
laws that apply to you and with the terms of the software you use it on. It
is provided as is, without warranty. Nothing here is legal advice.

## License

MIT, see [`LICENSE`](LICENSE).
