from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools" / "build_release.py"
TEST_ADDRESS = "192.0.2.10"
TEST_PORT = 8765
EXPECTED_LAYOUT = [
    ("release-layout.json", "release-layout"),
    ("hermes_windows_bridge.py", "bridge-server"),
    ("bridge_child_bootstrap.py", "child-bootstrap"),
    ("bridge-private-state.ps1", "private-state-attestor"),
    ("certs/bridge-cert.pem", "public-certificate"),
    ("client/hermes-windows-bridge", "controller-client"),
]


def load_tool():
    spec = importlib.util.spec_from_file_location("public_release_tool", TOOL_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def create_certificate(
    tmp_path: Path, *, dns_name: str = "bridge.example"
) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    cert = tmp_path / "bridge-cert.pem"
    key = tmp_path / "bridge-key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            f"/CN={dns_name}",
            "-addext",
            f"subjectAltName=DNS:{dns_name},IP:{TEST_ADDRESS}",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return cert, key


def build_package(tmp_path: Path):
    tool = load_tool()
    cert, key = create_certificate(tmp_path)
    output = tmp_path / "release"
    result = tool.package_release(
        ROOT,
        output,
        certificate=cert,
        listen_address=TEST_ADDRESS,
        port=TEST_PORT,
    )
    return tool, output, key, result


def file_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def test_public_release_layout_is_exact_and_ordered():
    tool = load_tool()
    layout = json.loads((ROOT / "release-layout.json").read_text(encoding="utf-8"))
    assert tool.EXPECTED_LAYOUT == EXPECTED_LAYOUT
    assert layout == {
        "schema_version": 1,
        "payloads": [
            {"path": path, "role": role} for path, role in EXPECTED_LAYOUT
        ],
    }


def test_package_release_is_deterministic_and_excludes_private_key(tmp_path):
    tool = load_tool()
    cert, key = create_certificate(tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"
    one = tool.package_release(
        ROOT, first, certificate=cert, listen_address=TEST_ADDRESS, port=TEST_PORT
    )
    two = tool.package_release(
        ROOT, second, certificate=cert, listen_address=TEST_ADDRESS, port=TEST_PORT
    )

    assert file_hashes(first) == file_hashes(second)
    assert one == two
    assert key.is_file()
    assert not list(first.rglob("*key*"))
    assert tool.check_manifest(
        first, first / "bridge-release.json", mode="package"
    )["ok"] is True


def test_runtime_validator_and_builder_share_the_same_manifest_contract(tmp_path):
    tool, package, _key, result = build_package(tmp_path)
    spec = importlib.util.spec_from_file_location(
        "public_bridge_for_manifest", package / "hermes_windows_bridge.py"
    )
    assert spec and spec.loader
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)

    attestation = bridge.validate_release_manifest(
        package / "bridge-release.json",
        TEST_ADDRESS,
        TEST_PORT,
        tls_cert=package / "certs" / "bridge-cert.pem",
    )
    assert attestation["release_manifest_sha256"] == result["manifest_sha256"]
    assert attestation["release_tree_sha256"] == result["canonical_tree_sha256"]


def test_builder_and_runtime_accept_valid_dns_listener(tmp_path):
    tool = load_tool()
    certificate, _key = create_certificate(tmp_path)
    package = tmp_path / "dns-release"
    result = tool.package_release(
        ROOT,
        package,
        certificate=certificate,
        listen_address="bridge.example",
        port=TEST_PORT,
    )
    spec = importlib.util.spec_from_file_location(
        "public_bridge_for_dns_listener", package / "hermes_windows_bridge.py"
    )
    assert spec and spec.loader
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)

    attestation = bridge.validate_release_manifest(
        package / "bridge-release.json",
        "bridge.example",
        TEST_PORT,
        tls_cert=package / "certs" / "bridge-cert.pem",
    )
    assert attestation["release_manifest_sha256"] == result["manifest_sha256"]


@pytest.mark.parametrize(
    "listen_address",
    (
        "*.example",
        "bad_name",
        ".",
        "-bad.example",
        "bad-.example",
        "two..labels",
        "bridge.example.",
        "bridge.example..",
        "bridge.example\u3002",
        "bridge.example\u3002\u3002",
        "b\u00fccher.example",
        " bridge.example ",
        "bad:host",
        "0",
        "0x0",
        "00",
        "0.0.0",
        "000.000.000.000",
        "127.1",
        "0x7f000001",
        "::ffff:0.0.0.0",
    ),
)
def test_release_builder_rejects_invalid_dns_listener_syntax(listen_address):
    tool = load_tool()

    with pytest.raises(
        tool.ReleaseError,
        match="listen address is invalid|wildcard listeners are forbidden",
    ):
        tool._validate_listener(listen_address, TEST_PORT, tool.TRANSPORT)


def test_release_builder_accepts_numeric_dns_label_with_nonnumeric_suffix():
    tool = load_tool()

    tool._validate_listener("123.example", TEST_PORT, tool.TRANSPORT)
    tool._validate_listener("Bridge.Example", TEST_PORT, tool.TRANSPORT)
    tool._validate_listener("xn--bcher-kva.example", TEST_PORT, tool.TRANSPORT)
    assert tool._normalized_dns_name("Bridge.Example") == "bridge.example"


def test_release_builder_detects_mapped_wildcard_under_legacy_ipaddress_semantics():
    tool = load_tool()

    class LegacyMappedAddress:
        is_unspecified = False
        ipv4_mapped = tool.ipaddress.ip_address("0.0.0.0")

    assert tool._is_unspecified_address(LegacyMappedAddress()) is True


@pytest.mark.parametrize(
    "dns_name", ("*.example", "bridge.example.", "bridge.example..")
)
def test_builder_certificate_match_rejects_invalid_dns_identity(tmp_path, dns_name):
    tool = load_tool()
    certificate, _key = create_certificate(tmp_path, dns_name=dns_name)

    with pytest.raises(tool.ReleaseError, match="identity"):
        tool._certificate_der_hash(certificate, "bridge.example")


@pytest.mark.parametrize(
    "dns_name", ("*.example", "bridge.example.", "bridge.example..")
)
def test_runtime_certificate_match_rejects_invalid_dns_identity(tmp_path, dns_name):
    certificate, _key = create_certificate(tmp_path, dns_name=dns_name)
    spec = importlib.util.spec_from_file_location(
        "public_bridge_for_invalid_dns", ROOT / "hermes_windows_bridge.py"
    )
    assert spec and spec.loader
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)

    with pytest.raises(bridge.ReleaseValidationError, match="listener|identity"):
        bridge._release_certificate_der(certificate, "bridge.example")


def test_manifest_checks_reject_tamper_duplicate_keys_and_extra_files(tmp_path):
    tool, package, _key, _result = build_package(tmp_path)
    manifest = package / "bridge-release.json"

    with (package / "bridge_child_bootstrap.py").open("ab") as handle:
        handle.write(b"\n# synthetic tamper\n")
    with pytest.raises(tool.ReleaseError, match="payload (size|hash) mismatch"):
        tool.check_manifest(package, manifest, mode="runtime")

    shutil.rmtree(package)
    tool, package, _key, _result = build_package(tmp_path / "duplicate")
    text = manifest_text = (package / "bridge-release.json").read_text(encoding="utf-8")
    text = text.replace('"schema_version": 2,', '"schema_version": 2,\n  "SCHEMA_VERSION": 2,', 1)
    (package / "bridge-release.json").write_text(text, encoding="utf-8")
    with pytest.raises(tool.ReleaseError, match="duplicate"):
        tool.check_manifest(package, package / "bridge-release.json", mode="runtime")
    assert manifest_text != text

    shutil.rmtree(package)
    tool, package, _key, _result = build_package(tmp_path / "extra")
    (package / "unexpected.txt").write_text("not part of release\n", encoding="utf-8")
    assert tool.check_manifest(
        package, package / "bridge-release.json", mode="runtime"
    )["ok"] is True
    with pytest.raises(tool.ReleaseError, match="extra"):
        tool.check_manifest(package, package / "bridge-release.json", mode="package")


def test_packager_rejects_existing_output_and_symbolic_payload(tmp_path):
    tool = load_tool()
    cert, _key = create_certificate(tmp_path)
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(tool.ReleaseError, match="output"):
        tool.package_release(
            ROOT,
            existing,
            certificate=cert,
            listen_address=TEST_ADDRESS,
            port=TEST_PORT,
        )

    source = tmp_path / "source"
    source.mkdir()
    for relative, _role in EXPECTED_LAYOUT:
        if relative == "certs/bridge-cert.pem":
            continue
        src = ROOT / relative
        dst = source / relative
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    (source / "bridge_child_bootstrap.py").unlink()
    try:
        (source / "bridge_child_bootstrap.py").symlink_to(ROOT / "bridge_child_bootstrap.py")
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")
    with pytest.raises(tool.ReleaseError, match="symbolic|reparse"):
        tool.package_release(
            source,
            tmp_path / "symlink-release",
            certificate=cert,
            listen_address=TEST_ADDRESS,
            port=TEST_PORT,
        )


def test_manifest_checker_rejects_symbolic_manifest_in_runtime_mode(tmp_path):
    tool, package, _key, _result = build_package(tmp_path)
    manifest = package / "bridge-release.json"
    real_manifest = package / "real-manifest.json"
    manifest.replace(real_manifest)
    try:
        manifest.symlink_to(real_manifest.name)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")
    with pytest.raises(tool.ReleaseError, match="manifest.*symbolic|symbolic.*manifest"):
        tool.check_manifest(package, manifest, mode="runtime")


def test_packager_rejects_non_x509_and_listener_identity_mismatch(tmp_path):
    tool = load_tool()
    invalid = tmp_path / "not-x509.pem"
    invalid.write_text(
        "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n",
        encoding="ascii",
    )
    with pytest.raises(tool.ReleaseError, match="certificate.*invalid"):
        tool.package_release(
            ROOT,
            tmp_path / "invalid-release",
            certificate=invalid,
            listen_address=TEST_ADDRESS,
            port=TEST_PORT,
        )

    cert, key = create_certificate(tmp_path / "valid")
    combined = tmp_path / "certificate-with-private-key.pem"
    combined.write_text(
        cert.read_text(encoding="ascii") + key.read_text(encoding="ascii"),
        encoding="ascii",
    )
    with pytest.raises(tool.ReleaseError, match="certificate.*invalid"):
        tool.package_release(
            ROOT,
            tmp_path / "private-key-release",
            certificate=combined,
            listen_address=TEST_ADDRESS,
            port=TEST_PORT,
        )

    with pytest.raises(tool.ReleaseError, match="certificate.*identity"):
        tool.package_release(
            ROOT,
            tmp_path / "identity-mismatch-release",
            certificate=cert,
            listen_address="198.51.100.20",
            port=TEST_PORT,
        )


def test_runtime_certificate_validator_rejects_non_x509_and_identity_mismatch(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "public_bridge_certificate_validation", ROOT / "hermes_windows_bridge.py"
    )
    assert spec and spec.loader
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)

    invalid = tmp_path / "not-x509.pem"
    invalid.write_text(
        "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n",
        encoding="ascii",
    )
    with pytest.raises(bridge.ReleaseValidationError, match="certificate.*invalid"):
        bridge._release_certificate_der(invalid, TEST_ADDRESS)

    cert, _key = create_certificate(tmp_path / "valid")
    with pytest.raises(bridge.ReleaseValidationError, match="certificate.*identity"):
        bridge._release_certificate_der(cert, "198.51.100.20")


def test_cli_package_and_check_return_machine_readable_json(tmp_path):
    cert, _key = create_certificate(tmp_path)
    output = tmp_path / "cli-release"
    package = subprocess.run(
        [
            sys.executable,
            str(TOOL_PATH),
            "package",
            "--source",
            str(ROOT),
            "--output",
            str(output),
            "--certificate",
            str(cert),
            "--listen-address",
            TEST_ADDRESS,
            "--port",
            str(TEST_PORT),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert json.loads(package.stdout)["ok"] is True

    check = subprocess.run(
        [
            sys.executable,
            str(TOOL_PATH),
            "check",
            "--root",
            str(output),
            "--manifest",
            str(output / "bridge-release.json"),
            "--mode",
            "package",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert json.loads(check.stdout)["payload_count"] == len(EXPECTED_LAYOUT)
