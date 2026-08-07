#!/usr/bin/env python3
"""Fail closed when the public Git surface contains private or stale material."""

from __future__ import annotations

import json
import re
import struct
import subprocess
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    "", ".md", ".py", ".ps1", ".json", ".yml", ".yaml", ".svg", ".toml", ".txt"
}
SKIP_PARTS = {".git", ".pytest_cache", ".ruff_cache", "__pycache__", ".venv", "dist", "local"}
PRIVATE_PATTERNS = {
    "RFC1918 address": re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3})\b"
    ),
    "absolute POSIX home": re.compile(r"/home/[A-Za-z0-9._-]+"),
    "absolute Windows user home": re.compile(
        r"[A-Z]:(?:\\|/)Users(?:\\|/)[^\\/\s]+", re.IGNORECASE
    ),
    "machine-generated Windows hostname": re.compile(r"\bDESKTOP-[A-Z0-9]{7,}\b"),
    "account-specific domain SID": re.compile(r"\bS-1-5-21-(?:\d+-){3}\d+\b"),
    "delegation session identifier": re.compile(r"\bdeleg_[a-z0-9]{6,}\b"),
}
LEGACY_CLIENT_PATH = "nuc" + "-client"
LEGACY_CLIENT_LABEL = "NUC" + " client"
STALE_PUBLIC_CLAIMS = (
    "returns bounded, " + "sanitized results",
    "writes use atomic " + "replacement and re-attest the published file",
)
GRAPHIC_STALE_LABELS = (
    "target state",
    "not yet deployed",
    "candidate",
    "identity before change",
    "freeze",
    "apply",
    "development method",
)
FORBIDDEN_GRAPHIC_PATH_PARTS = {
    "candidates", "prompts", "history", "qa", "manifests"
}
PNG_CORE_CHUNKS = {b"IHDR", b"IDAT", b"IEND"}


def candidate_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    tracked = [value for value in result.stdout.split(b"\0") if value]
    if tracked:
        return [ROOT / value.decode("utf-8") for value in tracked]
    return [
        path
        for path in ROOT.rglob("*")
        if path.is_file() and not any(part in SKIP_PARTS for part in path.parts)
    ]


def png_chunk_error(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return "PNG is unavailable"
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "invalid PNG signature"
    offset = 8
    kinds: list[bytes] = []
    while offset < len(data):
        if offset + 12 > len(data):
            return "truncated PNG chunk"
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        end = offset + 12 + length
        if end > len(data):
            return "truncated PNG payload"
        kind = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", data[offset + 8 + length : end])[0]
        actual_crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            return "PNG CRC mismatch"
        if kind not in PNG_CORE_CHUNKS:
            return f"PNG metadata chunk: {kind.decode('ascii', errors='replace')}"
        kinds.append(kind)
        offset = end
    if not kinds or kinds[0] != b"IHDR" or kinds[-1] != b"IEND":
        return "invalid PNG chunk order"
    return None


def main() -> int:
    findings: list[dict[str, str]] = []
    files = candidate_files()
    private_key_marker = "-" * 5 + "BEGIN "
    private_key_suffix = "PRIVATE KEY" + "-" * 5
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        if any(part.casefold() in FORBIDDEN_GRAPHIC_PATH_PARTS for part in path.parts):
            findings.append({"file": relative, "reason": "graphic process artifact path"})
        if path.suffix.casefold() == ".png":
            error = png_chunk_error(path)
            if error:
                findings.append({"file": relative, "reason": error})
            continue
        if path.suffix.casefold() not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for label, pattern in PRIVATE_PATTERNS.items():
            if pattern.search(text):
                findings.append({"file": relative, "reason": label})
        lowered = text.casefold()
        if LEGACY_CLIENT_PATH in lowered or LEGACY_CLIENT_LABEL.casefold() in lowered:
            findings.append({"file": relative, "reason": "environment-specific client name"})
        for claim in STALE_PUBLIC_CLAIMS:
            if claim in lowered:
                findings.append({"file": relative, "reason": f"stale public claim: {claim}"})
        if private_key_marker in text and private_key_suffix in text:
            findings.append({"file": relative, "reason": "private key material"})
        if relative.startswith("docs/assets/") and path.suffix.casefold() == ".svg":
            lowered = text.casefold()
            for label in GRAPHIC_STALE_LABELS:
                if label in lowered:
                    findings.append({"file": relative, "reason": f"stale graphic label: {label}"})
    result = {
        "ok": not findings,
        "files_checked": len(files),
        "findings": findings,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
