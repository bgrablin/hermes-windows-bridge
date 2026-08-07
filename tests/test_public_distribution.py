from __future__ import annotations

import hashlib
import importlib.util
import re
import tomllib
from importlib.machinery import SourceFileLoader
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT
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
}
PUBLIC_RELEASE_LAYOUT = [
    ("release-layout.json", "release-layout"),
    ("hermes_windows_bridge.py", "bridge-server"),
    ("bridge_child_bootstrap.py", "child-bootstrap"),
    ("bridge-private-state.ps1", "private-state-attestor"),
    ("certs/bridge-cert.pem", "public-certificate"),
    ("client/hermes-windows-bridge", "controller-client"),
]
PUBLIC_EXECUTION_CHAIN = [
    "hermes_windows_bridge.py",
    "bridge_child_bootstrap.py",
    "bridge-private-state.ps1",
]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None:
        spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def public_text_files():
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(
            part in {".git", ".pytest_cache", ".ruff_cache", "__pycache__", ".venv"}
            for part in path.parts
        ):
            continue
        try:
            yield path, path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue


def test_public_tree_contains_no_private_environment_markers():
    findings = []
    for path, text in public_text_files():
        for label, pattern in PRIVATE_PATTERNS.items():
            if pattern.search(text):
                findings.append((path.relative_to(ROOT).as_posix(), label))
    assert findings == []


def test_readme_places_a_bounded_hermes_agent_install_brief_near_the_top():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    heading = "## Install with Hermes Agent"
    assert heading in readme
    assert readme.index(heading) < readme.index("## What it does")
    required = (
        "Use only this public repository",
        "Default to a loopback-only listener",
        "Ask before using a non-loopback listener",
        "Never print, transmit, or commit the token or private key",
        "do not invent either without separate approval",
        "Do not report success until the bridge has run",
    )
    assert [phrase for phrase in required if phrase not in readme] == []


def test_private_marker_patterns_detect_real_windows_user_homes():
    checker = load_module(
        "public_surface_checker", ROOT / "scripts" / "public_surface_check.py"
    )
    slash = chr(92)
    forward = chr(47)
    private_paths = (
        f"C:{slash}Users{slash}Example{slash}private.txt",
        f"D:{forward}Users{forward}Example{forward}private.txt",
    )
    safe_path = f"C:{slash}ProgramData{slash}Hermes{slash}state.json"
    for patterns in (PRIVATE_PATTERNS, checker.PRIVATE_PATTERNS):
        pattern = patterns["absolute Windows user home"]
        assert all(pattern.search(value) for value in private_paths)
        assert pattern.search(safe_path) is None


def test_server_binds_only_the_reusable_public_release_closure():
    bridge = load_module("public_bridge", SRC / "hermes_windows_bridge.py")
    assert bridge.RELEASE_LAYOUT == PUBLIC_RELEASE_LAYOUT
    assert bridge.RELEASE_EXECUTION_CHAIN == PUBLIC_EXECUTION_CHAIN


def test_product_version_metadata_is_consistent():
    bridge = load_module("public_bridge_version", SRC / "hermes_windows_bridge.py")
    version = (ROOT / "VERSION").read_text().strip()
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())
    changelog = (ROOT / "CHANGELOG.md").read_text()
    assert bridge.Handler.bridge_version == version
    assert metadata["project"]["version"] == version
    assert f"## {version} -" in changelog


def test_builder_binds_only_the_reusable_public_release_closure():
    builder = load_module("public_builder", ROOT / "tools" / "build_release.py")
    assert builder.EXPECTED_LAYOUT == PUBLIC_RELEASE_LAYOUT
    assert builder.EXECUTION_CHAIN == PUBLIC_EXECUTION_CHAIN
    assert not hasattr(builder, "SERVICE_SID")
    assert not hasattr(builder, "BASE_DIR")


def test_client_honors_neutral_local_configuration(monkeypatch, tmp_path):
    config_root = tmp_path / "client-config"
    monkeypatch.setenv("HERMES_WINDOWS_BRIDGE_CONFIG_DIR", str(config_root))
    client = load_module(
        "public_client", SRC / "client" / "hermes-windows-bridge"
    )
    assert client.DEFAULT_URL == "https://127.0.0.1:8765"
    assert client.CA_FILE == config_root / "bridge-cert.pem"
    assert client.TOKEN_FILE == config_root / "bridge-token"


def test_server_honors_neutral_local_configuration(monkeypatch, tmp_path):
    hermes_home = tmp_path / "hermes-home"
    state_root = tmp_path / "bridge-state"
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setenv("HERMES_REPO", str(hermes_home / "hermes-agent"))
    monkeypatch.setenv("HERMES_WINDOWS_BRIDGE_STATE_DIR", str(state_root))
    bridge = load_module("public_bridge_paths", SRC / "hermes_windows_bridge.py")
    rendered = "\n".join(
        str(value)
        for value in (
            bridge.HERMES_HOME,
            bridge.REPO,
            bridge.TOKEN_FILE,
            bridge.LOG_FILE,
        )
    )
    assert str(hermes_home) in rendered
    assert str(state_root) in rendered
    rendered_without_configured_root = rendered.replace(str(tmp_path), "<configured-root>")
    assert not any(
        pattern.search(rendered_without_configured_root)
        for pattern in PRIVATE_PATTERNS.values()
    )


def test_private_state_helper_contains_no_scheduler_or_release_operations():
    text = (SRC / "bridge-private-state.ps1").read_text(encoding="utf-8")
    forbidden = (
        "ScheduledTask",
        "Get-BridgeRelease",
        "ValidateRelease",
        "ExpectedAddress",
        "ExpectedPort",
        "run-bridge.ps1",
        "bridge-watchdog.ps1",
        "rollback",
        "repair",
    )
    assert [marker for marker in forbidden if marker.casefold() in text.casefold()] == []
    assert "Test-PrivatePathAcl" in text
    assert "Protect-PrivateDirectory" in text
    assert "Protect-PrivateFile" in text
    assert "Initialize-BridgePrivateState" in text
    assert "AttestPrivatePaths" in text


def test_private_state_acl_check_rejects_reparse_points():
    text = (SRC / "bridge-private-state.ps1").read_text(encoding="utf-8")
    acl_check = text[
        text.index("function Test-PrivatePathAcl") :
        text.index("function Assert-PrivatePathAcl")
    ]
    assert "ReparsePoint" in acl_check


def test_runtime_attestor_drops_inherited_powershell_module_path(
    monkeypatch, tmp_path
):
    bridge = load_module("public_bridge_attestor_env", SRC / "hermes_windows_bridge.py")
    helper = tmp_path / "bridge-private-state.ps1"
    helper.write_text("# synthetic helper\n", encoding="utf-8")
    target = tmp_path / "state.json"
    target.write_text("{}", encoding="utf-8")
    expected = hashlib.sha256(helper.read_bytes()).hexdigest()
    captured = {}

    class Completed:
        returncode = 0
        stdout = '{"ok":true,"failed":0,"checked":1}\n'

    def fake_run(*_args, **kwargs):
        captured.update(kwargs)
        return Completed()

    monkeypatch.setenv("PSModulePath", "C:\\PowerShell7\\Modules")
    monkeypatch.setattr(bridge.subprocess, "run", fake_run)
    attest = bridge.make_private_path_attestor(helper, expected)

    assert attest([target]) is True
    assert "PSModulePath" not in captured["env"]


def test_public_docs_describe_output_certificate_and_quiesce_contracts():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    security = (ROOT / "docs" / "security-model.md").read_text(encoding="utf-8")
    operations = (ROOT / "docs" / "operations.md").read_text(encoding="utf-8")

    combined = "\n".join((readme, security, operations))
    legacy_client_path = "nuc" + "-client"
    legacy_client_label = "NUC" + " client"
    assert legacy_client_path not in combined.casefold()
    assert legacy_client_label not in combined
    assert "caller-visible and are not redacted" in security
    assert "server-generated errors and logs" in readme
    assert "subjectAltName=DNS:bridge.example" in operations
    assert "subjectAltName=IP:192.0.2.10" in operations
    assert "Initialize-BridgePrivateState" in operations
    assert '{"action":"begin"}' in operations
    assert '{"action":"status","generation":' in operations
    assert '{"action":"resume","generation":' in operations
    assert "python tools/build_release.py" not in combined
    assert "python -m pytest" not in readme


def test_security_reporting_fallback_is_actionable_without_profile_contact():
    policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "/security/advisories/new" in policy
    assert "Security contact request" in policy
    assert "Include no vulnerability details" in policy
    assert "public contact method listed" not in policy
