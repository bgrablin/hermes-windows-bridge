#!/usr/bin/env python3
"""Build and verify a deterministic public Hermes Windows Bridge release."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import ssl
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath

SCHEMA_VERSION = 2
TRANSPORT = "tls-pinned-self-signed"
EXPECTED_LAYOUT = [
    ("release-layout.json", "release-layout"),
    ("hermes_windows_bridge.py", "bridge-server"),
    ("bridge_child_bootstrap.py", "child-bootstrap"),
    ("bridge-private-state.ps1", "private-state-attestor"),
    ("certs/bridge-cert.pem", "public-certificate"),
    ("client/hermes-windows-bridge", "controller-client"),
]
EXPECTED_PATHS = [path for path, _role in EXPECTED_LAYOUT]
EXECUTION_CHAIN = [
    "hermes_windows_bridge.py",
    "bridge_child_bootstrap.py",
    "bridge-private-state.ps1",
]
MANIFEST_FIELDS = {
    "schema_version",
    "listen_address",
    "port",
    "transport",
    "layout_path",
    "payloads",
    "bridge_sha256",
    "certificate_sha256",
    "certificate_der_sha256",
    "execution_chain",
    "canonical_tree_sha256",
}
HASH_FIELDS = {
    "bridge_sha256",
    "certificate_sha256",
    "certificate_der_sha256",
    "canonical_tree_sha256",
}
HASH_CHARS = frozenset("0123456789abcdef")


class ReleaseError(ValueError):
    """A release artifact failed a deterministic fail-closed check."""


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    folded: set[str] = set()
    for key, value in pairs:
        if not isinstance(key, str) or key in result or key.casefold() in folded:
            raise ReleaseError(f"duplicate JSON key: {key}")
        result[key] = value
        folded.add(key.casefold())
    return result


def load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object
        )
    except ReleaseError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"invalid JSON document: {path.name}") from exc
    if not isinstance(value, dict):
        raise ReleaseError(f"JSON root must be an object: {path.name}")
    return value


def _safe_relative(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ReleaseError("payload path must be a non-empty string")
    if "\\" in value or ":" in value or "\x00" in value or value.startswith("/"):
        raise ReleaseError(f"unsafe payload path: {value!r}")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ReleaseError(f"noncanonical payload path: {value!r}")
    if PurePosixPath(value).as_posix() != value:
        raise ReleaseError(f"noncanonical payload path: {value!r}")
    return value


def _is_reparse(metadata: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(metadata, "st_file_attributes", 0) & flag)


def _ensure_root(root: Path) -> Path:
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise ReleaseError("release root is unavailable") from exc
    if root.is_symlink() or _is_reparse(metadata) or not root.is_dir():
        raise ReleaseError("release root is symbolic, reparse, or non-directory")
    return root.resolve(strict=True)


def resolve_regular_payload(root: Path | str, relative: str) -> Path:
    root_path = _ensure_root(Path(root))
    relative = _safe_relative(relative)
    current = root_path
    for component in PurePosixPath(relative).parts:
        current = current / component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ReleaseError(f"missing payload: {relative}") from exc
        if current.is_symlink() or _is_reparse(metadata):
            raise ReleaseError(f"symbolic or reparse payload is forbidden: {relative}")
    try:
        resolved = current.resolve(strict=True)
        common = os.path.commonpath(
            [os.path.normcase(str(root_path)), os.path.normcase(str(resolved))]
        )
    except (OSError, ValueError) as exc:
        raise ReleaseError(f"payload resolution failed: {relative}") from exc
    if common != os.path.normcase(str(root_path)):
        raise ReleaseError(f"payload escaped release root: {relative}")
    try:
        metadata = current.stat()
    except OSError as exc:
        raise ReleaseError(f"missing payload: {relative}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ReleaseError(f"payload is not a regular file: {relative}")
    return current


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ReleaseError(f"payload could not be read: {path.name}") from exc
    return digest.hexdigest()


def _certificate_der(path: Path) -> tuple[bytes, dict[str, object]]:
    try:
        pem = path.read_text(encoding="ascii")
        stripped = pem.strip()
        lines = stripped.splitlines()
        if (
            len(lines) < 3
            or lines[0] != "-----BEGIN CERTIFICATE-----"
            or lines[-1] != "-----END CERTIFICATE-----"
            or stripped.count("-----BEGIN CERTIFICATE-----") != 1
            or stripped.count("-----END CERTIFICATE-----") != 1
            or any("-----" in line for line in lines[1:-1])
        ):
            raise ValueError("certificate PEM closure is invalid")
        der = ssl.PEM_cert_to_DER_cert(pem)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=stripped + "\n")
        decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
        if decoder is None:
            raise ValueError("X.509 decoder is unavailable")
        decoded = decoder(str(path))
        if not isinstance(decoded, dict):
            raise ValueError("X.509 decoder returned invalid data")
    except (OSError, UnicodeError, ValueError, ssl.SSLError) as exc:
        raise ReleaseError("public certificate is invalid") from exc
    return der, decoded


def _looks_like_legacy_ipv4_literal(value: str) -> bool:
    parts = value.casefold().split(".")
    if not 1 <= len(parts) <= 4 or any(not part for part in parts):
        return False
    return all(
        part.isdigit()
        or (
            part.startswith("0x")
            and len(part) > 2
            and all(character in "0123456789abcdef" for character in part[2:])
        )
        for part in parts
    )


def _is_unspecified_address(address: object) -> bool:
    if bool(getattr(address, "is_unspecified", False)):
        return True
    mapped = getattr(address, "ipv4_mapped", None)
    return mapped is not None and bool(mapped.is_unspecified)


def _normalized_dns_name(value: object) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or value.endswith(".")
        or "*" in value
    ):
        return None
    normalized = value.casefold()
    labels = normalized.split(".")
    if _looks_like_legacy_ipv4_literal(normalized) or len(normalized) > 253 or any(
        not 1 <= len(label) <= 63
        or label.startswith("-")
        or label.endswith("-")
        or any(not (character.isalnum() or character == "-") for character in label)
        for label in labels
    ):
        return None
    return normalized


def _certificate_der_hash(path: Path, listen_address: str) -> str:
    der, decoded = _certificate_der(path)
    try:
        expected_ip = ipaddress.ip_address(listen_address)
    except ValueError:
        expected_ip = None
    expected_dns = (
        _normalized_dns_name(listen_address) if expected_ip is None else None
    )
    if expected_ip is None and expected_dns is None:
        raise ReleaseError("listen address is invalid")
    matched = False
    subject_alt_name = decoded.get("subjectAltName", ())
    if not isinstance(subject_alt_name, (list, tuple)):
        raise ReleaseError("public certificate identity is invalid")
    for entry in subject_alt_name:
        if (
            not isinstance(entry, (list, tuple))
            or len(entry) != 2
            or not all(isinstance(item, str) for item in entry)
        ):
            raise ReleaseError("public certificate identity is invalid")
        kind, value = entry
        if expected_ip is not None and kind == "IP Address":
            try:
                matched = ipaddress.ip_address(value) == expected_ip
            except ValueError:
                matched = False
        elif expected_dns is not None and kind == "DNS":
            certificate_dns = _normalized_dns_name(value)
            matched = certificate_dns is not None and certificate_dns == expected_dns
        if matched:
            break
    if not matched:
        raise ReleaseError("public certificate identity does not match listen address")
    return hashlib.sha256(der).hexdigest()


def _valid_hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value).issubset(HASH_CHARS)
    )


def canonical_tree_sha256(payloads: dict[str, dict[str, object]]) -> str:
    digest = hashlib.sha256()
    for relative in sorted(payloads):
        record = payloads[relative]
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(record["size"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(record["sha256"]).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def load_layout(root: Path | str) -> list[dict[str, str]]:
    root_path = _ensure_root(Path(root))
    layout_path = resolve_regular_payload(root_path, "release-layout.json")
    layout = load_json(layout_path)
    if set(layout) != {"schema_version", "payloads"}:
        raise ReleaseError("release layout field closure is invalid")
    if isinstance(layout["schema_version"], bool) or layout["schema_version"] != 1:
        raise ReleaseError("release layout schema_version must equal 1")
    expected = [
        {"path": path, "role": role} for path, role in EXPECTED_LAYOUT
    ]
    if layout["payloads"] != expected:
        raise ReleaseError("release layout does not match the public allowlist")
    return expected


def _validate_listener(
    listen_address: object, port: object, transport: object
) -> None:
    if (
        not isinstance(listen_address, str)
        or not listen_address.strip()
        or len(listen_address) > 255
        or any(character.isspace() for character in listen_address)
    ):
        raise ReleaseError("listen address is invalid")
    try:
        address = ipaddress.ip_address(listen_address)
    except ValueError:
        address = None
    if address is not None and _is_unspecified_address(address):
        raise ReleaseError("wildcard listeners are forbidden")
    if address is None and _normalized_dns_name(listen_address) is None:
        raise ReleaseError("listen address is invalid")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ReleaseError("port is invalid")
    if transport != TRANSPORT:
        raise ReleaseError("transport is invalid")


def build_manifest(
    root: Path | str,
    *,
    listen_address: str,
    port: int,
    transport: str = TRANSPORT,
) -> dict[str, object]:
    root_path = _ensure_root(Path(root))
    _validate_listener(listen_address, port, transport)
    layout = load_layout(root_path)
    payloads: dict[str, dict[str, object]] = {}
    for entry in layout:
        relative = entry["path"]
        payload = resolve_regular_payload(root_path, relative)
        payloads[relative] = {
            "role": entry["role"],
            "size": payload.stat().st_size,
            "sha256": _hash_file(payload),
        }
    payloads = dict(sorted(payloads.items()))
    certificate = resolve_regular_payload(root_path, "certs/bridge-cert.pem")
    return {
        "schema_version": SCHEMA_VERSION,
        "listen_address": listen_address,
        "port": port,
        "transport": transport,
        "layout_path": "release-layout.json",
        "payloads": payloads,
        "bridge_sha256": payloads["hermes_windows_bridge.py"]["sha256"],
        "certificate_sha256": payloads["certs/bridge-cert.pem"]["sha256"],
        "certificate_der_sha256": _certificate_der_hash(certificate, listen_address),
        "execution_chain": list(EXECUTION_CHAIN),
        "canonical_tree_sha256": canonical_tree_sha256(payloads),
    }


def _atomic_write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.new-", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _package_inventory(root: Path, manifest_path: Path) -> None:
    expected = set(EXPECTED_PATHS) | {
        manifest_path.relative_to(root).as_posix()
    }
    actual: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if path.is_symlink() or _is_reparse(metadata):
            raise ReleaseError(f"symbolic or reparse package object: {relative}")
        if path.is_dir():
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ReleaseError(f"special package object: {relative}")
        actual.add(relative)
    extra = sorted(actual - expected)
    missing = sorted(expected - actual)
    if extra:
        raise ReleaseError(f"extra package file: {extra[0]}")
    if missing:
        raise ReleaseError(f"missing package file: {missing[0]}")


def _resolve_regular_manifest(root: Path, manifest: Path) -> Path:
    candidate = manifest if manifest.is_absolute() else root / manifest
    candidate = Path(os.path.abspath(candidate))
    try:
        root_normalized = os.path.normcase(str(root))
        candidate_normalized = os.path.normcase(str(candidate))
        if os.path.commonpath([root_normalized, candidate_normalized]) != root_normalized:
            raise ReleaseError("release manifest escaped release root")
        relative = os.path.relpath(candidate, root)
    except (OSError, ValueError) as exc:
        if isinstance(exc, ReleaseError):
            raise
        raise ReleaseError("release manifest is unavailable") from exc
    components = Path(relative).parts
    if not components or any(component in {"", ".", ".."} for component in components):
        raise ReleaseError("release manifest path is invalid")
    current = root
    for component in components:
        current = current / component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ReleaseError("release manifest is unavailable") from exc
        if current.is_symlink() or _is_reparse(metadata):
            raise ReleaseError("release manifest is symbolic or reparse")
    if not stat.S_ISREG(metadata.st_mode):
        raise ReleaseError("release manifest is not a regular file")
    return current


def check_manifest(
    root: Path | str,
    manifest_path: Path | str,
    *,
    mode: str = "runtime",
) -> dict[str, object]:
    root_path = _ensure_root(Path(root))
    if mode not in {"runtime", "package"}:
        raise ReleaseError("check mode is invalid")
    manifest_file = _resolve_regular_manifest(root_path, Path(manifest_path))
    manifest = load_json(manifest_file)
    if set(manifest) != MANIFEST_FIELDS:
        raise ReleaseError("release manifest field closure is invalid")
    if isinstance(manifest["schema_version"], bool) or manifest["schema_version"] != SCHEMA_VERSION:
        raise ReleaseError("release manifest schema_version is invalid")
    _validate_listener(
        manifest["listen_address"], manifest["port"], manifest["transport"]
    )
    if manifest["layout_path"] != "release-layout.json":
        raise ReleaseError("release manifest layout path is invalid")
    if manifest["execution_chain"] != EXECUTION_CHAIN:
        raise ReleaseError("release manifest execution chain is invalid")
    for field in HASH_FIELDS:
        if not _valid_hash(manifest[field]):
            raise ReleaseError(f"release manifest hash is invalid: {field}")
    layout = load_layout(root_path)
    roles = {entry["path"]: entry["role"] for entry in layout}
    payloads = manifest["payloads"]
    if (
        not isinstance(payloads, dict)
        or list(payloads) != sorted(EXPECTED_PATHS)
        or set(payloads) != set(EXPECTED_PATHS)
    ):
        raise ReleaseError("release payload closure is invalid")
    for relative in EXPECTED_PATHS:
        record = payloads[relative]
        if (
            not isinstance(record, dict)
            or set(record) != {"role", "size", "sha256"}
            or record["role"] != roles[relative]
            or isinstance(record["size"], bool)
            or not isinstance(record["size"], int)
            or record["size"] < 0
            or not _valid_hash(record["sha256"])
        ):
            raise ReleaseError(f"payload record is invalid: {relative}")
        payload = resolve_regular_payload(root_path, relative)
        if payload.stat().st_size != record["size"]:
            raise ReleaseError(f"payload size mismatch: {relative}")
        if _hash_file(payload) != record["sha256"]:
            raise ReleaseError(f"payload hash mismatch: {relative}")
    tree_hash = canonical_tree_sha256(payloads)
    if manifest["canonical_tree_sha256"] != tree_hash:
        raise ReleaseError("canonical tree hash mismatch")
    if manifest["bridge_sha256"] != payloads["hermes_windows_bridge.py"]["sha256"]:
        raise ReleaseError("bridge hash mismatch")
    if manifest["certificate_sha256"] != payloads["certs/bridge-cert.pem"]["sha256"]:
        raise ReleaseError("certificate hash mismatch")
    certificate = resolve_regular_payload(root_path, "certs/bridge-cert.pem")
    manifest_listen_address = manifest["listen_address"]
    if not isinstance(manifest_listen_address, str):
        raise ReleaseError("listen address is invalid")
    if manifest["certificate_der_sha256"] != _certificate_der_hash(
        certificate, manifest_listen_address
    ):
        raise ReleaseError("certificate DER hash mismatch")
    if mode == "package":
        _package_inventory(root_path, manifest_file)
    return {
        "ok": True,
        "mode": mode,
        "payload_count": len(payloads),
        "canonical_tree_sha256": tree_hash,
        "manifest_sha256": _hash_file(manifest_file),
    }


def package_release(
    source: Path | str,
    output: Path | str,
    *,
    certificate: Path | str,
    listen_address: str,
    port: int,
    transport: str = TRANSPORT,
) -> dict[str, object]:
    source_root = _ensure_root(Path(source))
    output_path = Path(output).absolute()
    certificate_path = Path(certificate)
    if output_path.exists() or output_path.is_symlink():
        raise ReleaseError("output path already exists")
    _validate_listener(listen_address, port, transport)
    load_layout(source_root)
    cert_metadata = certificate_path.lstat()
    if certificate_path.is_symlink() or _is_reparse(cert_metadata) or not certificate_path.is_file():
        raise ReleaseError("certificate is symbolic, reparse, or non-regular")
    _certificate_der_hash(certificate_path, listen_address)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_path.name}.new-", dir=output_path.parent))
    try:
        for relative in EXPECTED_PATHS:
            target = staging.joinpath(*PurePosixPath(relative).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            source_path = (
                certificate_path
                if relative == "certs/bridge-cert.pem"
                else resolve_regular_payload(source_root, relative)
            )
            shutil.copyfile(source_path, target, follow_symlinks=False)
            if relative == "client/hermes-windows-bridge":
                target.chmod(0o755)
            else:
                target.chmod(0o644)
        manifest = build_manifest(
            staging,
            listen_address=listen_address,
            port=port,
            transport=transport,
        )
        manifest_path = staging / "bridge-release.json"
        _atomic_write_json(manifest_path, manifest)
        result = check_manifest(staging, manifest_path, mode="package")
        staging.rename(output_path)
        return result
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _command_package(args: argparse.Namespace) -> int:
    result = package_release(
        args.source,
        args.output,
        certificate=args.certificate,
        listen_address=args.listen_address,
        port=args.port,
        transport=args.transport,
    )
    sys.stdout.write(_json_text(result))
    return 0


def _command_check(args: argparse.Namespace) -> int:
    result = check_manifest(args.root, args.manifest, mode=args.mode)
    sys.stdout.write(_json_text(result))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    package = commands.add_parser("package", help="create a closed release package")
    package.add_argument("--source", type=Path, required=True)
    package.add_argument("--output", type=Path, required=True)
    package.add_argument("--certificate", type=Path, required=True)
    package.add_argument("--listen-address", required=True)
    package.add_argument("--port", type=int, required=True)
    package.add_argument("--transport", default=TRANSPORT)
    package.set_defaults(handler=_command_package)
    check = commands.add_parser("check", help="verify a release package")
    check.add_argument("--root", type=Path, required=True)
    check.add_argument("--manifest", type=Path, required=True)
    check.add_argument("--mode", choices=("runtime", "package"), default="runtime")
    check.set_defaults(handler=_command_check)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, ReleaseError) as exc:
        parser.exit(2, f"release validation failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
