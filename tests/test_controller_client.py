import http.server
import importlib.util
import io
import json
import pathlib
import ssl
import subprocess
import threading
import urllib.error
import urllib.request
from importlib.machinery import SourceFileLoader

import pytest

CLIENT_PATH = pathlib.Path(__file__).parents[1] / "client" / "hermes-windows-bridge"
LOADER = SourceFileLoader("bridge_controller_client", str(CLIENT_PATH))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
client = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(client)


class FakeResponse:
    def __init__(self, body, status=200):
        self.body = json.dumps(body).encode()
        self.status = status
        self.headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


def test_client_defaults_to_https_and_pinned_ca_path():
    assert client.DEFAULT_URL == "https://127.0.0.1:8765"
    assert client.CA_FILE.name == "bridge-cert.pem"
    assert client.TOKEN_FILE.name == "bridge-token"


def test_client_honors_retry_after_for_capacity_rejection_without_leaking_token(tmp_path):
    token_file = tmp_path / "bridge-token"
    token_file.write_text("synthetic-secret-token")
    token_file.chmod(0o600)
    attempts = []
    sleeps = []

    def opener(request, **kwargs):
        attempts.append((request, kwargs))
        if len(attempts) == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                429,
                "busy",
                {"Retry-After": "2"},
                io.BytesIO(
                    b'{"ok":false,"error_code":"capacity_exhausted",'
                    b'"execution_started":false}'
                ),
            )
        return FakeResponse({"ok": True, "stdout": "done", "stderr": ""})

    result = client.req(
        "POST",
        "/run/terminal",
        {"command": "synthetic"},
        timeout=5,
        token_file=token_file,
        tls_context=object(),
        opener=opener,
        sleeper=sleeps.append,
    )
    assert result["ok"] is True
    assert len(attempts) == 2
    assert sleeps == [2.0]
    assert attempts[0][1]["context"] is attempts[1][1]["context"]


def test_client_bounds_retry_after_and_returns_sanitized_terminal_error(tmp_path):
    token_file = tmp_path / "bridge-token"
    token_file.write_text("synthetic-secret-token")
    token_file.chmod(0o600)
    sleeps = []

    def opener(request, **_kwargs):
        raise urllib.error.HTTPError(
            request.full_url,
            503,
            "pressure",
            {"Retry-After": "999"},
            io.BytesIO(
                b'{"ok":false,"error_code":"resource_pressure",'
                b'"execution_started":false}'
            ),
        )

    with pytest.raises(client.BridgeRequestError) as raised:
        client.req(
            "POST",
            "/run/terminal",
            {"command": "synthetic"},
            timeout=5,
            token_file=token_file,
            tls_context=object(),
            opener=opener,
            sleeper=sleeps.append,
            max_attempts=2,
        )
    assert sleeps == [30.0]
    rendered = str(raised.value)
    assert "503" in rendered
    assert "resource_pressure" in rendered
    assert "synthetic-secret-token" not in rendered


def test_controller_client_rejects_group_readable_token_on_posix(monkeypatch):
    import stat
    from types import SimpleNamespace

    class FakePath:
        def stat(self):
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o640, st_uid=1000)

    monkeypatch.setattr(client.os, "name", "posix")
    monkeypatch.setattr(client.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(client.pathlib, "Path", lambda _value: FakePath())
    with pytest.raises(client.BridgeRequestError):
        client._require_posix_private_file("token", secret=True)


@pytest.mark.parametrize(
    ("method", "path", "status", "body"),
    [
        ("POST", "/run/terminal", 503, b'{"error_code":"resource_pressure"}'),
        (
            "POST",
            "/run/hermes",
            503,
            b'{"error_code":"quiesced","execution_started":true}',
        ),
        (
            "POST",
            "/jobs/terminal",
            503,
            b'{"error_code":"job_state_unavailable","execution_started":0}',
        ),
        (
            "POST",
            "/jobs/hermes",
            503,
            b'{"error_code":"unknown","execution_started":false}',
        ),
        (
            "POST",
            "/jobs/hermes",
            503,
            b'{"error_code":[],"execution_started":false}',
        ),
        (
            "POST",
            "/jobs/hermes",
            503,
            (
                b'{"error_code":"quiesced","execution_started":true,'
                b'"execution_started":false}'
            ),
        ),
        ("POST", "/run/terminal", 503, b"not-json"),
        (
            "POST",
            "/jobs/job-123/cancel",
            503,
            b'{"error_code":"quiesced","execution_started":false}',
        ),
        (
            "GET",
            "/jobs/job-123",
            503,
            b'{"error_code":"quiesced","execution_started":false}',
        ),
    ],
)
def test_client_does_not_retry_without_unambiguous_no_start_proof(
    tmp_path, method, path, status, body
):
    token_file = tmp_path / "bridge-token"
    token_file.write_text("synthetic-secret-token")
    token_file.chmod(0o600)
    attempts = []
    sleeps = []

    def opener(request, **_kwargs):
        attempts.append(request)
        raise urllib.error.HTTPError(
            request.full_url,
            status,
            "synthetic rejection",
            {"Retry-After": "0"},
            io.BytesIO(body),
        )

    with pytest.raises(client.BridgeRequestError):
        client.req(
            method,
            path,
            {"synthetic": True} if method == "POST" else None,
            token_file=token_file,
            tls_context=object(),
            opener=opener,
            sleeper=sleeps.append,
            max_attempts=3,
        )

    assert len(attempts) == 1
    assert sleeps == []


@pytest.mark.parametrize(
    ("path", "status", "error_code"),
    [
        ("/run/terminal", 429, "capacity_exhausted"),
        ("/run/hermes", 503, "resource_pressure"),
        ("/jobs/terminal", 503, "quiesced"),
        ("/jobs/hermes", 503, "job_state_unavailable"),
    ],
)
def test_client_retries_allowlisted_execution_rejections_with_exact_false(
    tmp_path, path, status, error_code
):
    token_file = tmp_path / "bridge-token"
    token_file.write_text("synthetic-secret-token")
    token_file.chmod(0o600)
    attempts = []

    def opener(request, **_kwargs):
        attempts.append(request)
        if len(attempts) == 1:
            payload = json.dumps(
                {"error_code": error_code, "execution_started": False}
            ).encode()
            raise urllib.error.HTTPError(
                request.full_url,
                status,
                "synthetic rejection",
                {"Retry-After": "0"},
                io.BytesIO(payload),
            )
        return FakeResponse({"ok": True, "stdout": "done", "stderr": ""})

    result = client.req(
        "POST",
        path,
        {"synthetic": True},
        token_file=token_file,
        tls_context=object(),
        opener=opener,
        sleeper=lambda _seconds: None,
    )

    assert result["ok"] is True
    assert len(attempts) == 2


def test_client_sanitizes_untrusted_error_code(tmp_path):
    token_file = tmp_path / "bridge-token"
    token_file.write_text("synthetic-secret-token")
    token_file.chmod(0o600)
    attempts = []

    def opener(request, **_kwargs):
        attempts.append(request)
        raise urllib.error.HTTPError(
            request.full_url,
            503,
            "synthetic rejection",
            {"Retry-After": "0"},
            io.BytesIO(
                b'{"error_code":"resource_pressure\\nterminal-injection",'
                b'"execution_started":false}'
            ),
        )

    with pytest.raises(client.BridgeRequestError) as raised:
        client.req(
            "POST",
            "/run/terminal",
            {"command": "synthetic"},
            token_file=token_file,
            tls_context=object(),
            opener=opener,
            max_attempts=3,
        )

    assert len(attempts) == 1
    assert str(raised.value) == "bridge request failed (503, http_error)"


def test_client_does_not_retry_network_reset_after_execution_post(tmp_path):
    token_file = tmp_path / "bridge-token"
    token_file.write_text("synthetic-secret-token")
    token_file.chmod(0o600)
    attempts = []

    def opener(request, **_kwargs):
        attempts.append(request)
        raise urllib.error.URLError("synthetic network reset")

    with pytest.raises(client.BridgeRequestError, match="bridge connection failed"):
        client.req(
            "POST",
            "/run/terminal",
            {"command": "synthetic"},
            token_file=token_file,
            tls_context=object(),
            opener=opener,
            max_attempts=4,
        )

    assert len(attempts) == 1


class FakePeerSocket:
    def __init__(self, peer_der):
        self.peer_der = peer_der
        self.closed = False

    def getpeercert(self, *, binary_form=False):
        assert binary_form is True
        return self.peer_der

    def close(self):
        self.closed = True


def test_pinned_tls_connection_accepts_only_exact_peer_der(monkeypatch):
    expected_der = b"synthetic-expected-peer-der"
    matching_socket = FakePeerSocket(expected_der)
    mismatching_socket = FakePeerSocket(b"different-peer-der")
    sockets = [matching_socket, mismatching_socket]
    verified_connect_calls = []

    def verified_connect(connection):
        verified_connect_calls.append(connection.host)
        connection.sock = sockets.pop(0)

    monkeypatch.setattr(
        client.http.client.HTTPSConnection, "connect", verified_connect
    )
    context = ssl.create_default_context()

    matching = client._PinnedHTTPSConnection(
        "bridge.synthetic", context=context, expected_peer_der=expected_der
    )
    matching.connect()
    assert matching_socket.closed is False

    mismatching = client._PinnedHTTPSConnection(
        "bridge.synthetic", context=context, expected_peer_der=expected_der
    )
    with pytest.raises(ssl.SSLCertVerificationError, match="pin mismatch"):
        mismatching.connect()
    assert mismatching_socket.closed is True
    assert verified_connect_calls == ["bridge.synthetic", "bridge.synthetic"]


def test_pinned_https_handler_wires_verified_context_and_pin(monkeypatch):
    context = ssl.create_default_context()
    handler = client._PinnedHTTPSHandler(context, b"synthetic-peer-der")
    captured = []

    # Python 3.14 removed HTTPSHandler._check_hostname. Removing it under older
    # interpreters makes this test enforce the public SSLContext contract.
    if hasattr(handler, "_check_hostname"):
        del handler._check_hostname

    def fake_do_open(connection_factory, request, **kwargs):
        captured.append(
            (connection_factory("bridge.synthetic", context=context), request, kwargs)
        )
        return "opened"

    monkeypatch.setattr(handler, "do_open", fake_do_open)
    request = client.urllib.request.Request("https://bridge.synthetic/health")

    assert handler.https_open(request) == "opened"
    connection, captured_request, kwargs = captured[0]
    assert isinstance(connection, client._PinnedHTTPSConnection)
    assert connection._expected_peer_der == b"synthetic-peer-der"
    assert captured_request is request
    assert kwargs == {"context": context}

    opener = client._build_pinned_opener(context, b"synthetic-peer-der")
    assert any(
        isinstance(candidate, client._PinnedHTTPSHandler)
        for candidate in opener.handlers
    )


def test_pinned_opener_disables_ambient_proxy_inheritance(monkeypatch):
    monkeypatch.setattr(
        urllib.request,
        "getproxies",
        lambda: {"https": "http://ambient-proxy-attacker.invalid:8080"},
    )
    opener = client._build_pinned_opener(
        ssl.create_default_context(), b"synthetic-peer-der"
    )
    proxy_handlers = [
        candidate
        for candidate in opener.handlers
        if isinstance(candidate, urllib.request.ProxyHandler)
    ]

    assert proxy_handlers == []


def test_pinned_opener_rejects_plaintext_http_before_authorization_dispatch():
    received_authorization = []

    class CaptureHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            received_authorization.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"captured")

        def log_message(self, _format, *_args):
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        opener = client._build_pinned_opener(
            ssl.create_default_context(), b"synthetic-peer-der"
        )
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/capture",
            headers={"Authorization": "Bearer synthetic-secret-token"},
        )

        with pytest.raises(
            client.BridgeRequestError, match="plaintext HTTP rejected"
        ), opener.open(request, timeout=2) as response:
            response.read()

        assert received_authorization == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_pinned_opener_rejects_http_redirect_before_forwarding_authorization():
    context = ssl.create_default_context()
    opener = client._build_pinned_opener(context, b"synthetic-peer-der")
    redirect_handler = next(
        candidate
        for candidate in opener.handlers
        if isinstance(candidate, urllib.request.HTTPRedirectHandler)
    )
    request = urllib.request.Request(
        "https://bridge.synthetic/run/terminal",
        data=b"{}",
        method="POST",
        headers={"Authorization": "Bearer synthetic-secret-token"},
    )

    with pytest.raises(client.BridgeRequestError, match="redirect rejected"):
        redirect_handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "http://redirect-attacker.invalid/capture",
        )


def test_release_certificate_builds_ca_hostname_context_and_exact_der_pin(tmp_path):
    cert_file = tmp_path / "bridge-cert.pem"
    key_file = tmp_path / "bridge-key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
            "-nodes", "-keyout", str(key_file), "-out", str(cert_file),
            "-days", "1", "-subj", "/CN=bridge.example",
            "-addext", "subjectAltName=DNS:bridge.example,IP:192.0.2.10",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )

    cert_file.chmod(0o644)
    key_file.chmod(0o600)

    context = client.build_tls_context(cert_file)
    expected_der = client._load_certificate_der(cert_file)

    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert expected_der == ssl.PEM_cert_to_DER_cert(cert_file.read_text(encoding="utf-8"))


def test_req_uses_explicit_https_url_and_exact_cert_pin(monkeypatch, tmp_path):
    cert_file = tmp_path / "synthetic-cert.pem"
    cert_file.write_text("synthetic certificate")
    tls_context = ssl.create_default_context()
    expected_der = b"synthetic-peer-der"
    opened = []
    built = []

    class FakePinnedOpener:
        def open(self, request, **kwargs):
            opened.append((request, kwargs))
            return FakeResponse({"ok": True})

    monkeypatch.setattr(client, "build_tls_context", lambda ca_file: tls_context)
    monkeypatch.setattr(client, "_load_certificate_der", lambda path: expected_der)

    def build_opener(context, peer_der):
        built.append((context, peer_der))
        return FakePinnedOpener()

    monkeypatch.setattr(client, "_build_pinned_opener", build_opener)

    result = client.req(
        "GET",
        "/health",
        timeout=9,
        base_url="https://127.0.0.1:18765",
        cert_file=cert_file,
    )

    assert result == {"ok": True}
    assert built == [(tls_context, expected_der)]
    assert opened[0][0].full_url == "https://127.0.0.1:18765/health"
    assert opened[0][1] == {"timeout": 9}


def test_req_rejects_unverified_context_before_building_pinned_transport(
    monkeypatch, tmp_path
):
    cert_file = tmp_path / "synthetic-cert.pem"
    cert_file.write_text(ssl.DER_cert_to_PEM_cert(b"synthetic-peer-der"))
    context = ssl._create_unverified_context()
    monkeypatch.setattr(
        client,
        "_load_certificate_der",
        lambda _path: pytest.fail("pin must not load for an unverified context"),
    )

    with pytest.raises(client.BridgeRequestError, match="CA and hostname"):
        client.req(
            "GET",
            "/health",
            base_url="https://127.0.0.1:18765",
            cert_file=cert_file,
            tls_context=context,
        )


@pytest.mark.parametrize(
    "base_url",
    [
        "https://127.0.0.1\\attacker.invalid:18765",
        "https://127.0.0.1:18765\n",
        "https://127.0.0.1:\t18765",
        "https://127.0.0.1:18765\r",
        " https://127.0.0.1:18765",
        "https://127.0.0.1:18765 ",
        "https://127.0.0.1:18765/",
        "https://127.0.0.1:18765?",
        "https://127.0.0.1:18765#",
        "https://127.0.0.1:",
        "HTTPS://127.0.0.1:18765",
        "https://BRIDGE.example:18765",
        "https://127.0.0.1:018765",
        "https://bridge%2eexample:18765",
        "https://0.0.0.0:18765",
        "https://[::]:18765",
        "https://[::ffff:0.0.0.0]:18765",
    ],
)
def test_normalize_base_url_rejects_raw_parser_ambiguities(base_url):
    with pytest.raises(client.BridgeRequestError, match="invalid bridge URL"):
        client._normalize_base_url(base_url)


def test_client_detects_mapped_wildcard_under_legacy_ipaddress_semantics():
    class LegacyMappedAddress:
        is_unspecified = False
        ipv4_mapped = client.ipaddress.ip_address("0.0.0.0")

    assert client._is_unspecified_address(LegacyMappedAddress()) is True


@pytest.mark.parametrize(
    "base_url",
    [
        "http://127.0.0.1:18765",
        "https://user@127.0.0.1:18765",
        "https://127.0.0.1:18765/base",
        "https://127.0.0.1:18765?query=yes",
    ],
)
def test_req_rejects_urls_that_cannot_use_the_pinned_tls_origin(base_url):
    with pytest.raises(client.BridgeRequestError, match="invalid bridge URL"):
        client.req(
            "GET",
            "/health",
            base_url=base_url,
            tls_context=object(),
            opener=lambda *_args, **_kwargs: pytest.fail("request must not open"),
        )


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["health"], ("GET", "/health", None, 10)),
        (
            ["ps", "--timeout", "7", "Get-Process", "python"],
            (
                "POST",
                "/run/terminal",
                {"command": "Get-Process python", "timeout": 7},
                12,
            ),
        ),
        (
            [
                "hermes",
                "--toolsets",
                "terminal,file",
                "--timeout",
                "8",
                "do",
                "work",
            ],
            (
                "POST",
                "/run/hermes",
                {"prompt": "do work", "toolsets": "terminal,file", "timeout": 8},
                13,
            ),
        ),
        (
            ["job", "--timeout", "9", "terminal", "Get-Date"],
            (
                "POST",
                "/jobs/terminal",
                {"command": "Get-Date", "timeout": 9},
                10,
            ),
        ),
        (["get", "job-123"], ("GET", "/jobs/job-123", None, 10)),
    ],
)
def test_cli_preserves_existing_routes_with_explicit_staging_material(
    monkeypatch, tmp_path, capsys, argv, expected
):
    token_file = tmp_path / "bridge-token"
    cert_file = tmp_path / "bridge-cert.pem"
    calls = []

    def fake_req(method, path, body=None, timeout=60, **kwargs):
        calls.append((method, path, body, timeout, kwargs))
        if path.startswith("/run/"):
            return {"ok": True, "stdout": "done", "stderr": ""}
        if path.startswith("/jobs/") and method == "GET":
            return {"ok": True, "status": "running", "id": "job-123"}
        return {"ok": True, "job_id": "job-123", "status": "accepted"}

    monkeypatch.setattr(client, "req", fake_req)
    options = [
        "--url",
        "https://127.0.0.1:18765",
        "--token-file",
        str(token_file),
        "--cert-file",
        str(cert_file),
    ]

    assert client.main(options + argv) == 0
    method, path, body, timeout = expected
    assert calls == [
        (
            method,
            path,
            body,
            timeout,
            {
                "base_url": "https://127.0.0.1:18765",
                "token_file": token_file,
                "cert_file": cert_file,
            },
        )
    ]
    assert capsys.readouterr().out


def test_cli_cancel_posts_to_job_cancel_route(monkeypatch, tmp_path, capsys):
    token_file = tmp_path / "bridge-token"
    cert_file = tmp_path / "bridge-cert.pem"
    calls = []

    def fake_req(method, path, body=None, timeout=60, **kwargs):
        calls.append((method, path, body, timeout, kwargs))
        return {"ok": True, "job_id": "job-123", "status": "cancelling"}

    monkeypatch.setattr(client, "req", fake_req)
    assert (
        client.main(
            [
                "--url",
                "https://127.0.0.1:18765",
                "--token-file",
                str(token_file),
                "--cert-file",
                str(cert_file),
                "cancel",
                "job-123",
            ]
        )
        == 0
    )

    assert calls == [
        (
            "POST",
            "/jobs/job-123/cancel",
            None,
            10,
            {
                "base_url": "https://127.0.0.1:18765",
                "token_file": token_file,
                "cert_file": cert_file,
            },
        )
    ]
    assert "cancelling" in capsys.readouterr().out


def test_emit_preserves_active_completed_output_and_timeout_exit(capsys):
    assert client.emit({"ok": True, "status": "running", "id": "job-123"}) == 0
    active = capsys.readouterr()
    assert '"status": "running"' in active.out
    assert active.err == ""

    assert (
        client.emit(
            {
                "status": "succeeded",
                "result": {
                    "ok": True,
                    "exit_code": 0,
                    "stdout": "done",
                    "stderr": "note",
                },
            }
        )
        == 0
    )
    completed = capsys.readouterr()
    assert completed.out.strip() == "done"
    assert completed.err.strip() == "note"

    assert (
        client.emit(
            {
                "ok": False,
                "exit_code": 124,
                "stdout": "partial",
                "stderr": "timed out",
            }
        )
        == 124
    )
    timed_out = capsys.readouterr()
    assert timed_out.out.strip() == "partial"
    assert timed_out.err.strip() == "timed out"
