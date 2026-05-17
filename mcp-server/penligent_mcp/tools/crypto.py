"""
CTF-focused crypto and binary analysis tools (15 tools).
Most are pure Python — no external binary required.
"""
import base64
import binascii
import codecs
import hashlib
import json
import string
import urllib.parse
from pathlib import Path

from mcp.types import Tool, TextContent

from .register_all import register
from ._helpers import _chk, _need, _run, _ok, _s, _artifact

# ---------------------------------------------------------------------------
# base64_decode
# ---------------------------------------------------------------------------

async def _base64_decode(args: dict) -> list[TextContent]:
    data = args.get("data", "")
    variant = args.get("variant", "standard")
    padding = data + "=" * (-len(data) % 4)
    try:
        if variant == "urlsafe":
            result = base64.urlsafe_b64decode(padding)
        else:
            result = base64.b64decode(padding)
        try:
            return _ok(result.decode("utf-8"))
        except UnicodeDecodeError:
            return _ok(f"[binary] hex: {result.hex()}")
    except Exception as e:
        return _ok(f"Error: {e}")

register(Tool(
    name="base64_decode",
    description="Decode a Base64 string. Handles missing padding and URL-safe variant.",
    inputSchema=_s(["data"],
        data=("string", "Base64 encoded string"),
        variant=("string", "standard (default) or urlsafe")),
), _base64_decode)

# ---------------------------------------------------------------------------
# base64_encode
# ---------------------------------------------------------------------------

async def _base64_encode(args: dict) -> list[TextContent]:
    text = args.get("text", "")
    variant = args.get("variant", "standard")
    raw = text.encode("utf-8")
    if variant == "urlsafe":
        return _ok(base64.urlsafe_b64encode(raw).decode())
    return _ok(base64.b64encode(raw).decode())

register(Tool(
    name="base64_encode",
    description="Encode text to Base64 (standard or URL-safe).",
    inputSchema=_s(["text"],
        text=("string", "Text to encode"),
        variant=("string", "standard or urlsafe")),
), _base64_encode)

# ---------------------------------------------------------------------------
# hex_decode
# ---------------------------------------------------------------------------

async def _hex_decode(args: dict) -> list[TextContent]:
    data = args.get("data", "").replace(" ", "").replace("0x", "").replace("\\x", "")
    try:
        raw = bytes.fromhex(data)
        try:
            return _ok(raw.decode("utf-8"))
        except UnicodeDecodeError:
            return _ok(f"[binary] {raw!r}")
    except Exception as e:
        return _ok(f"Error: {e}")

register(Tool(
    name="hex_decode",
    description="Decode a hex string to text or bytes. Strips 0x/\\x prefixes and spaces.",
    inputSchema=_s(["data"], data=("string", "Hex encoded string")),
), _hex_decode)

# ---------------------------------------------------------------------------
# hex_encode
# ---------------------------------------------------------------------------

async def _hex_encode(args: dict) -> list[TextContent]:
    text = args.get("text", "")
    fmt = args.get("format", "plain")
    raw = text.encode("utf-8")
    if fmt == "0x":
        return _ok("0x" + raw.hex())
    if fmt == "escaped":
        return _ok("".join(f"\\x{b:02x}" for b in raw))
    return _ok(raw.hex())

register(Tool(
    name="hex_encode",
    description="Encode text to hex. Format: plain / 0x / escaped (\\x).",
    inputSchema=_s(["text"],
        text=("string", "Text to encode"),
        format=("string", "plain (default), 0x, or escaped")),
), _hex_encode)

# ---------------------------------------------------------------------------
# rot13
# ---------------------------------------------------------------------------

async def _rot13(args: dict) -> list[TextContent]:
    text = args.get("text", "")
    return _ok(codecs.encode(text, "rot_13"))

register(Tool(
    name="rot13",
    description="Apply ROT13 substitution cipher to text.",
    inputSchema=_s(["text"], text=("string", "Input text")),
), _rot13)

# ---------------------------------------------------------------------------
# caesar_brute
# ---------------------------------------------------------------------------

async def _caesar_brute(args: dict) -> list[TextContent]:
    text = args.get("text", "")
    lines = []
    for shift in range(26):
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                result.append(chr((ord(ch) - base + shift) % 26 + base))
            else:
                result.append(ch)
        lines.append(f"ROT{shift:02d}: {''.join(result)}")
    return _ok("\n".join(lines))

register(Tool(
    name="caesar_brute",
    description="Try all 26 Caesar cipher shifts and return each result.",
    inputSchema=_s(["text"], text=("string", "Ciphertext to brute force")),
), _caesar_brute)

# ---------------------------------------------------------------------------
# xor_single_byte
# ---------------------------------------------------------------------------

async def _xor_single_byte(args: dict) -> list[TextContent]:
    data = args.get("data", "")
    # Accept hex input
    try:
        raw = bytes.fromhex(data.replace(" ", ""))
    except ValueError:
        raw = data.encode("latin-1")
    results = []
    for key in range(256):
        decrypted = bytes(b ^ key for b in raw)
        printable = sum(1 for b in decrypted if chr(b) in string.printable)
        if printable / max(len(decrypted), 1) > 0.85:
            try:
                text = decrypted.decode("utf-8")
            except Exception:
                text = decrypted.decode("latin-1")
            results.append(f"key=0x{key:02x} ({key:3d}): {text[:120]}")
    if not results:
        return _ok("No high-confidence single-byte XOR key found.")
    return _ok("\n".join(results[:20]))

register(Tool(
    name="xor_single_byte",
    description=(
        "Brute-force single-byte XOR on hex-encoded or raw ciphertext. "
        "Returns keys that produce >85% printable ASCII output."
    ),
    inputSchema=_s(["data"],
        data=("string", "Hex string or raw ciphertext")),
), _xor_single_byte)

# ---------------------------------------------------------------------------
# url_decode
# ---------------------------------------------------------------------------

async def _url_decode(args: dict) -> list[TextContent]:
    text = args.get("text", "")
    return _ok(urllib.parse.unquote_plus(text))

register(Tool(
    name="url_decode",
    description="URL-decode a percent-encoded string (handles + as space).",
    inputSchema=_s(["text"], text=("string", "URL-encoded string")),
), _url_decode)

# ---------------------------------------------------------------------------
# url_encode
# ---------------------------------------------------------------------------

async def _url_encode(args: dict) -> list[TextContent]:
    text = args.get("text", "")
    safe = args.get("safe", "")
    return _ok(urllib.parse.quote(text, safe=safe))

register(Tool(
    name="url_encode",
    description="URL-encode a string. Optionally specify safe characters to leave unencoded.",
    inputSchema=_s(["text"],
        text=("string", "Text to encode"),
        safe=("string", "Characters to leave unencoded (default: none)")),
), _url_encode)

# ---------------------------------------------------------------------------
# hash_text
# ---------------------------------------------------------------------------

async def _hash_text(args: dict) -> list[TextContent]:
    text = args.get("text", "")
    algo = args.get("algorithm", "all")
    raw = text.encode("utf-8")
    if algo == "all":
        lines = [
            f"md5:    {hashlib.md5(raw).hexdigest()}",
            f"sha1:   {hashlib.sha1(raw).hexdigest()}",
            f"sha256: {hashlib.sha256(raw).hexdigest()}",
            f"sha512: {hashlib.sha512(raw).hexdigest()}",
        ]
        return _ok("\n".join(lines))
    h = hashlib.new(algo, raw)
    return _ok(f"{algo}: {h.hexdigest()}")

register(Tool(
    name="hash_text",
    description="Hash text with md5/sha1/sha256/sha512 (or 'all' for all at once).",
    inputSchema=_s(["text"],
        text=("string", "Text to hash"),
        algorithm=("string", "md5, sha1, sha256, sha512, or all (default)")),
), _hash_text)

# ---------------------------------------------------------------------------
# hash_file
# ---------------------------------------------------------------------------

async def _hash_file(args: dict) -> list[TextContent]:
    path = args.get("path", "")
    algo = args.get("algorithm", "sha256")
    try:
        raw = Path(path).read_bytes()
    except Exception as e:
        return _ok(f"Error reading file: {e}")
    h = hashlib.new(algo, raw)
    return _ok(f"{algo}: {h.hexdigest()}  {path}")

register(Tool(
    name="hash_file",
    description="Compute a hash of a local file.",
    inputSchema=_s(["path"],
        path=("string", "Absolute path to the file"),
        algorithm=("string", "md5, sha1, sha256 (default), or sha512")),
), _hash_file)

# ---------------------------------------------------------------------------
# strings_extract
# ---------------------------------------------------------------------------

async def _strings_extract(args: dict) -> list[TextContent]:
    path = args.get("path", "")
    min_len = int(args.get("min_length", 4))
    if _chk("strings"):
        out, err, _ = await _run(["strings", f"-n{min_len}", path])
        return _ok(out or err)
    # Pure-Python fallback
    try:
        raw = Path(path).read_bytes()
    except Exception as e:
        return _ok(f"Error: {e}")
    found, cur = [], []
    for b in raw:
        if 0x20 <= b < 0x7f:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                found.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        found.append("".join(cur))
    return _ok("\n".join(found[:500]))

register(Tool(
    name="strings_extract",
    description="Extract printable strings from a binary file.",
    inputSchema=_s(["path"],
        path=("string", "Absolute path to the binary file"),
        min_length=("integer", "Minimum string length (default: 4)")),
), _strings_extract)

# ---------------------------------------------------------------------------
# file_identify
# ---------------------------------------------------------------------------

_MAGIC = [
    (b"\x89PNG",      "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8",         "GIF image"),
    (b"PK\x03\x04",   "ZIP archive"),
    (b"\x1f\x8b",     "Gzip compressed"),
    (b"BZh",          "Bzip2 compressed"),
    (b"\xfd7zXZ",     "XZ compressed"),
    (b"\x7fELF",      "ELF executable"),
    (b"MZ",           "Windows PE/DLL"),
    (b"JFIF",         "JPEG JFIF"),
    (b"%PDF",         "PDF document"),
    (b"OggS",         "OGG media"),
    (b"ID3",          "MP3 audio"),
    (b"\x00\x01\x00\x00", "TTF font"),
    (b"RIFF",         "RIFF (WAV/AVI)"),
    (b"\xcf\xfa\xed\xfe", "Mach-O binary (LE)"),
    (b"\xce\xfa\xed\xfe", "Mach-O binary (BE)"),
    (b"#!",           "Script (shebang)"),
    (b"<?php",        "PHP script"),
    (b"<html",        "HTML document"),
    (b"<?xml",        "XML document"),
    (b"SQLite",       "SQLite database"),
]

async def _file_identify(args: dict) -> list[TextContent]:
    path = args.get("path", "")
    if _chk("file"):
        out, err, _ = await _run(["file", path])
        return _ok(out.strip() or err)
    try:
        header = Path(path).read_bytes()[:16]
    except Exception as e:
        return _ok(f"Error: {e}")
    for magic, label in _MAGIC:
        if header.startswith(magic):
            return _ok(f"{path}: {label}")
    return _ok(f"{path}: unknown ({header.hex()})")

register(Tool(
    name="file_identify",
    description="Identify a file's type via magic bytes (uses 'file' command if available).",
    inputSchema=_s(["path"], path=("string", "Absolute path to the file")),
), _file_identify)

# ---------------------------------------------------------------------------
# binwalk_run
# ---------------------------------------------------------------------------

async def _binwalk_run(args: dict) -> list[TextContent]:
    path = args.get("path", "")
    extract = args.get("extract", False)
    if not _chk("binwalk"):
        return _need("binwalk", "sudo apt install binwalk")
    cmd = ["binwalk"]
    if extract:
        cmd.append("-e")
    cmd.append(path)
    out, err, _ = await _run(cmd, timeout=120)
    return _ok(out or err)

register(Tool(
    name="binwalk_run",
    description="Scan a file for embedded files/data with binwalk. Set extract=true to extract.",
    inputSchema=_s(["path"],
        path=("string", "Absolute path to the file"),
        extract=("boolean", "Extract embedded files (default: false)")),
), _binwalk_run)

# ---------------------------------------------------------------------------
# stego_detect
# ---------------------------------------------------------------------------

async def _stego_detect(args: dict) -> list[TextContent]:
    path = args.get("path", "")
    wordlist = args.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    results = []

    if _chk("stegseek"):
        out, err, code = await _run(["stegseek", "--crack", path, wordlist], timeout=60)
        results.append(f"[stegseek]\n{out or err}")
    elif _chk("steghide"):
        out, err, code = await _run(["steghide", "info", "-sf", path], timeout=30)
        results.append(f"[steghide info]\n{out or err}")
    else:
        results.append("[TOOL_MISSING] Install stegseek or steghide for steganography analysis.")

    if _chk("exiftool"):
        out, err, _ = await _run(["exiftool", path], timeout=15)
        results.append(f"[exiftool]\n{out[:500] or err}")

    return _ok("\n\n".join(results))

register(Tool(
    name="stego_detect",
    description=(
        "Attempt steganography detection/extraction. "
        "Uses stegseek (brute-force) or steghide, plus exiftool for metadata."
    ),
    inputSchema=_s(["path"],
        path=("string", "Absolute path to the image/file"),
        wordlist=("string", "Wordlist for stegseek brute force (default: rockyou.txt)")),
), _stego_detect)
