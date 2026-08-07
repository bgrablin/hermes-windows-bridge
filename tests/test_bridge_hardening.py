import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import threading
import time

import pytest

SOURCE = pathlib.Path(__file__).parents[1] / "hermes_windows_bridge.py"
SPEC = importlib.util.spec_from_file_location("hermes_windows_bridge_under_test", SOURCE)
bridge = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(bridge)


def test_admission_limits_are_atomic_under_a_mixed_route_race():
    controller = bridge.AdmissionController(
        global_limit=2,
        class_limits={"hermes": 1, "terminal": 2},
    )
    start = threading.Barrier(101)
    release = threading.Event()
    observations = []
    observations_lock = threading.Lock()

    def contender(kind, route):
        start.wait()
        reservation, error = controller.try_reserve(kind, route)
        with observations_lock:
            observations.append((kind, route, reservation, error, controller.snapshot()))
        if reservation is not None:
            release.wait(timeout=5)
            reservation.release()

    threads = []
    for index in range(100):
        kind = "hermes" if index % 2 else "terminal"
        route = "/run/" + kind if index % 4 < 2 else "/jobs/" + kind
        thread = threading.Thread(target=contender, args=(kind, route))
        thread.start()
        threads.append(thread)

    start.wait()
    while len(observations) < 100:
        threading.Event().wait(0.01)
    release.set()
    for thread in threads:
        thread.join(timeout=5)

    admitted = [item for item in observations if item[2] is not None]
    rejected = [item for item in observations if item[2] is None]
    assert len(admitted) == 2
    assert sum(1 for item in admitted if item[0] == "hermes") <= 1
    assert max(item[4]["active_global"] for item in observations) <= 2
    assert max(item[4]["active_by_class"]["hermes"] for item in observations) <= 1
    assert max(item[4]["active_by_class"]["terminal"] for item in observations) <= 2
    assert rejected
    assert all(item[3]["error_code"] == "capacity_exhausted" for item in rejected)
    assert controller.snapshot()["active_global"] == 0


def test_bounded_output_retains_only_the_cap_and_signals_emitted_limit_once():
    limit_calls = []
    buffer = bridge.BoundedOutputBuffer(
        retain_limit=10,
        emit_limit=20,
        on_limit=lambda: limit_calls.append("limit"),
    )

    buffer.feed(b"12345678")
    buffer.feed(b"abcdefgh")
    buffer.feed(b"WXYZ1234")
    snapshot = buffer.snapshot()

    assert snapshot["retained"] == b"12345678ab"
    assert snapshot["retained_bytes"] == 10
    assert snapshot["emitted_bytes"] == 24
    assert snapshot["truncated"] is True
    assert snapshot["limit_exceeded"] is True
    assert limit_calls == ["limit"]


def test_resource_pressure_requires_five_continuous_minutes_before_blocking():
    now = [1000.0]
    guard = bridge.ResourcePressureGuard(
        min_available_bytes=2 * 1024**3,
        max_commit_fraction=0.80,
        hold_seconds=300,
        clock=lambda: now[0],
    )
    low = {"available_physical_bytes": 1 * 1024**3, "commit_fraction": 0.50}
    healthy = {"available_physical_bytes": 8 * 1024**3, "commit_fraction": 0.50}

    assert guard.observe(low) is None
    now[0] += 299
    assert guard.observe(low) is None
    now[0] += 1
    blocked = guard.observe(low)
    assert blocked["error_code"] == "resource_pressure"
    assert blocked["reason"] == "available_memory_below_floor"

    assert guard.observe(healthy) is None
    assert guard.snapshot()["active"] is False


def test_job_store_never_evicts_active_work_and_uses_deterministic_completion_fifo():
    now = [100.0]
    store = bridge.JobStore(
        ttl_seconds=10,
        max_completed=2,
        max_completed_bytes=1000,
        tombstone_ttl_seconds=100,
        max_tombstones=10,
        clock=lambda: now[0],
    )
    store.create("running", "terminal", "/jobs/terminal")
    store.create("a", "terminal", "/jobs/terminal")
    store.create("b", "terminal", "/jobs/terminal")
    store.create("c", "terminal", "/jobs/terminal")
    store.mark_running("running")
    store.complete("a", "succeeded", {"ok": True, "stdout": "a" * 30})
    now[0] += 1
    store.complete("b", "succeeded", {"ok": True, "stdout": "b" * 30})
    now[0] += 1
    store.complete("c", "succeeded", {"ok": True, "stdout": "c" * 30})

    store.cleanup()

    running = store.get("running")
    assert running["status"] == "running"
    assert running["ok"] is True
    assert store.get("a")["status"] == "expired"
    completed = store.get("b")
    assert completed["status"] == "succeeded"
    assert completed["finished_at"] == completed["completed_at"]
    assert store.get("c")["status"] == "succeeded"
    snapshot = store.snapshot()
    assert snapshot["completed_entries"] == 2
    assert snapshot["tombstones"] == 1



@pytest.mark.skipif(os.name != "nt", reason="requires Windows runtime APIs")
def test_bounded_subprocess_retains_cap_without_killing_below_emit_ceiling():
    import sys
    result = bridge.run_subprocess_bounded(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 10000)"],
        timeout=10,
        retain_limit=1024,
        emit_limit=20000,
    )
    assert result["terminal_reason"] == "succeeded"
    assert result["returncode"] == 0
    assert result["stdout_emitted_bytes"] == 10000
    assert result["stdout_retained_bytes"] == 1024
    assert result["stdout_truncated"] is True
    assert result["process_tree_terminated"] is False
    assert result["process_pid"] > 0
    assert result["process_parent_pid"] == bridge.os.getpid()
    assert result["completed_at_epoch"] >= result["started_at_epoch"]
    assert result["started_at_utc"].endswith("Z")
    assert result["completed_at_utc"].endswith("Z")


@pytest.mark.skipif(os.name != "nt", reason="requires Windows runtime APIs")
def test_bounded_subprocess_kills_job_tree_when_stream_exceeds_emit_ceiling():
    import sys
    result = bridge.run_subprocess_bounded(
        [sys.executable, "-c", "import sys,time; sys.stdout.write('x' * 200000); sys.stdout.flush(); time.sleep(30)"],
        timeout=10,
        retain_limit=1024,
        emit_limit=4096,
    )
    assert result["terminal_reason"] == "output_limit"
    assert result["stdout_emitted_bytes"] > 4096
    assert result["stdout_retained_bytes"] == 1024
    assert result["process_tree_terminated"] is True


@pytest.mark.skipif(os.name != "nt", reason="requires Windows runtime APIs")
def test_timeout_kills_a_spawned_descendant_and_reaps_the_wrapper():
    import sys
    child_code = "import time; time.sleep(30)"
    parent_code = (
        "import subprocess,sys,time; "
        f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
        "print(p.pid, flush=True); time.sleep(30)"
    )
    result = bridge.run_subprocess_bounded(
        [sys.executable, "-c", parent_code],
        timeout=0.75,
        retain_limit=4096,
        emit_limit=65536,
    )
    child_pid = int(result["stdout"].strip())
    assert result["terminal_reason"] == "timed_out"
    assert result["exit_code"] == 124
    assert result["process_tree_terminated"] is True
    assert bridge.process_exists(child_pid) is False


@pytest.mark.skipif(os.name != "nt", reason="requires Windows runtime APIs")
def test_explicit_cancellation_kills_the_job_tree_and_returns_cancelled():
    import sys
    import time
    cancel = threading.Event()
    result_box = {}

    def target():
        result_box["result"] = bridge.run_subprocess_bounded(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout=20,
            cancel_event=cancel,
            retain_limit=4096,
            emit_limit=65536,
        )

    thread = threading.Thread(target=target)
    thread.start()
    time.sleep(0.5)
    cancel.set()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert result_box["result"]["terminal_reason"] == "cancelled"
    assert result_box["result"]["process_tree_terminated"] is True



def test_async_capacity_rejection_does_not_create_a_job_record():
    started = threading.Event()
    release = threading.Event()

    def executor(*_args, **_kwargs):
        started.set()
        release.wait(timeout=5)
        return {"ok": True, "terminal_reason": "succeeded", "returncode": 0,
                "stdout": "", "stderr": "", "stdout_retained_bytes": 0,
                "stderr_retained_bytes": 0, "stdout_emitted_bytes": 0,
                "stderr_emitted_bytes": 0, "stdout_truncated": False,
                "stderr_truncated": False, "process_tree_terminated": False}

    runtime = bridge.BridgeRuntime(
        admission=bridge.AdmissionController(global_limit=2, class_limits={"hermes": 1, "terminal": 2}),
        jobs=bridge.JobStore(max_completed=50, max_completed_bytes=1024**2),
        executor=executor,
    )
    code1, body1, _ = runtime.start_async("hermes", {"prompt": "first"}, "/jobs/hermes")
    assert code1 == 202
    assert started.wait(timeout=2)

    code2, body2, headers2 = runtime.start_async("hermes", {"prompt": "second"}, "/jobs/hermes")
    assert code2 == 429
    assert body2["error_code"] == "capacity_exhausted"
    assert headers2["Retry-After"] == "5"
    assert runtime.jobs.snapshot()["active_entries"] == 1
    assert runtime.admission.snapshot()["active_by_class"]["hermes"] == 1

    release.set()
    for _ in range(100):
        if runtime.get_job(body1["job_id"])["status"] == "succeeded":
            break
        threading.Event().wait(0.02)
    assert runtime.get_job(body1["job_id"])["status"] == "succeeded"
    assert runtime.admission.snapshot()["active_global"] == 0


def test_sync_executor_exception_releases_its_reservation():
    def explode(*_args, **_kwargs):
        raise RuntimeError("synthetic failure")

    runtime = bridge.BridgeRuntime(executor=explode)
    code, body, _ = runtime.run_sync("terminal", {"command": "Write-Output ok"}, "/run/terminal")
    assert code == 500
    assert body["ok"] is False
    assert body["error_code"] == "execution_failed"
    assert runtime.admission.snapshot()["active_global"] == 0


@pytest.mark.parametrize(
    ("command", "expected_pattern"),
    [
        ("[System.Windows.Forms.SendKeys]::SendWait('')", "sendkeys"),
        ("New-Object -ComObject WScript.Shell | Out-Null", "wscript.shell"),
        ("$shell.AppActivate('missing-window')", "appactivate"),
        ("Set-Clipboard -Value 'synthetic'", "set-clipboard"),
        ("Get-Clipboard | Out-Null", "get-clipboard"),
    ],
)
def test_sync_terminal_rejects_blind_gui_automation_before_execution(
    command, expected_pattern
):
    executions = []

    def executor(*args, **kwargs):
        executions.append((args, kwargs))
        return {"ok": True, "terminal_reason": "succeeded", "returncode": 0}

    runtime = bridge.BridgeRuntime(executor=executor)
    code, body, headers = runtime.run_sync(
        "terminal", {"command": command}, "/run/terminal"
    )

    assert code == 400
    assert headers == {}
    assert body["ok"] is False
    assert body["error_code"] == "blind_gui_automation_blocked"
    assert body["execution_started"] is False
    assert expected_pattern in body["blocked_patterns"]
    assert executions == []
    assert runtime.admission.snapshot()["active_global"] == 0
    assert runtime.snapshot()["counters"]["started"] == 0


def test_async_terminal_rejects_blind_gui_automation_without_creating_a_job():
    executions = []

    def executor(*args, **kwargs):
        executions.append((args, kwargs))
        return {"ok": True, "terminal_reason": "succeeded", "returncode": 0}

    runtime = bridge.BridgeRuntime(executor=executor)
    code, body, headers = runtime.start_async(
        "terminal",
        {"command": "New-Object -ComObject WScript.Shell | Out-Null"},
        "/jobs/terminal",
    )

    assert code == 400
    assert headers == {}
    assert body["error_code"] == "blind_gui_automation_blocked"
    assert body["execution_started"] is False
    assert executions == []
    assert runtime.jobs.snapshot()["active_entries"] == 0
    assert runtime.jobs.snapshot()["completed_entries"] == 0
    assert runtime.snapshot()["counters"]["submitted"] == 0


def test_explicit_async_cancel_reaches_a_terminal_cancelled_state():
    entered = threading.Event()

    def cancellable(*_args, cancel_event=None, **_kwargs):
        entered.set()
        assert cancel_event.wait(timeout=5)
        return {"ok": False, "terminal_reason": "cancelled", "returncode": 1,
                "stdout": "", "stderr": "", "stdout_retained_bytes": 0,
                "stderr_retained_bytes": 0, "stdout_emitted_bytes": 0,
                "stderr_emitted_bytes": 0, "stdout_truncated": False,
                "stderr_truncated": False, "process_tree_terminated": True}

    runtime = bridge.BridgeRuntime(executor=cancellable)
    code, body, _ = runtime.start_async("terminal", {"command": "Start-Sleep 30"}, "/jobs/terminal")
    assert code == 202 and entered.wait(timeout=2)
    cancel_code, cancel_body = runtime.cancel_job(body["job_id"])
    assert cancel_code == 202 and cancel_body["cancel_requested"] is True
    for _ in range(100):
        job = runtime.get_job(body["job_id"])
        if job["status"] == "cancelled":
            break
        threading.Event().wait(0.02)
    assert runtime.get_job(body["job_id"])["status"] == "cancelled"
    assert runtime.admission.snapshot()["active_global"] == 0



@pytest.mark.skipif(os.name != "nt", reason="requires Windows runtime APIs")
def test_windows_metrics_expose_required_privacy_safe_resource_fields():
    metrics = bridge.collect_windows_metrics()
    required = {
        "available_physical_bytes", "commit_bytes", "commit_limit_bytes",
        "commit_fraction", "kernel_paged_pool_bytes", "kernel_nonpaged_pool_bytes",
        "bridge_pid", "bridge_parent_pid", "bridge_working_set_bytes",
        "bridge_private_bytes", "bridge_handle_count", "bridge_thread_count",
        "honcho_8017_close_wait",
    }
    assert required <= set(metrics)
    assert metrics["available_physical_bytes"] > 0
    assert 0 <= metrics["commit_fraction"] <= 2
    assert metrics["bridge_handle_count"] > 0


@pytest.mark.skipif(os.name != "nt", reason="requires Windows runtime APIs")
def test_http_health_is_minimal_and_status_requires_constant_time_bearer_auth():
    import http.client
    import json

    runtime = bridge.BridgeRuntime()
    server = bridge.make_server("127.0.0.1", 0, token="unit-test-token", runtime=runtime, quiet=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address

    def request(method, path, body=None, token=None):
        connection = http.client.HTTPConnection(host, port, timeout=5)
        headers = {}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        data = None if body is None else json.dumps(body).encode()
        if data is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(data))
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        payload = response.read().decode()
        result = response.status, dict(response.getheaders()), json.loads(payload)
        connection.close()
        return result

    try:
        status, _, health = request("GET", "/health")
        assert status == 200 and health == {"ok": True, "service": "hermes-windows-bridge"}
        assert "user" not in health and "hermes_home" not in health
        assert request("GET", "/status")[0] == 401
        assert request("GET", "/status", token="wrong")[0] == 401
        status, _, snapshot = request("GET", "/status", token="unit-test-token")
        assert status == 200
        encoded = json.dumps(snapshot)
        assert "unit-test-token" not in encoded
        assert snapshot["ok"] is True
        assert snapshot["runtime"]["admission"]["global_limit"] == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_http_rejects_duplicate_authorization_headers_in_either_order():
    import socket

    server = bridge.make_server(
        "127.0.0.1", 0, token="unit-test-token",
        runtime=bridge.BridgeRuntime(), quiet=True,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address

    def raw_status(values):
        headers = "".join(f"Authorization: {value}\r\n" for value in values)
        request = (
            f"GET /unsupported HTTP/1.1\r\nHost: {host}\r\n{headers}"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        with socket.create_connection((host, port), timeout=5) as connection:
            connection.sendall(request)
            response = bytearray()
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
        return int(bytes(response).split(b" ", 2)[1])

    valid = "Bearer unit-test-token"
    invalid = "Bearer wrong-token"
    try:
        assert raw_status([valid]) == 404
        assert raw_status([invalid, valid]) == 401
        assert raw_status([valid, invalid]) == 401
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_http_capacity_rejection_has_retry_after_and_no_phantom_job():
    import http.client
    import json
    started = threading.Event()
    release = threading.Event()

    def executor(*_args, **_kwargs):
        started.set()
        release.wait(timeout=5)
        return {"ok": True, "terminal_reason": "succeeded", "returncode": 0,
                "stdout": "", "stderr": "", "stdout_retained_bytes": 0,
                "stderr_retained_bytes": 0, "stdout_emitted_bytes": 0,
                "stderr_emitted_bytes": 0, "stdout_truncated": False,
                "stderr_truncated": False, "process_tree_terminated": False}

    runtime = bridge.BridgeRuntime(executor=executor)
    server = bridge.make_server("127.0.0.1", 0, token="token", runtime=runtime, quiet=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address

    def submit(prompt):
        connection = http.client.HTTPConnection(host, port, timeout=5)
        body = json.dumps({"prompt": prompt}).encode()
        connection.request("POST", "/jobs/hermes", body=body,
                           headers={"Authorization": "Bearer token",
                                    "Content-Type": "application/json",
                                    "Content-Length": str(len(body))})
        response = connection.getresponse()
        payload = json.loads(response.read().decode())
        result = response.status, dict(response.getheaders()), payload
        connection.close()
        return result

    try:
        first = submit("first")
        assert first[0] == 202 and started.wait(timeout=2)
        second = submit("second")
        assert second[0] == 429
        assert second[1]["Retry-After"] == "5"
        assert second[2]["error_code"] == "capacity_exhausted"
        assert runtime.jobs.snapshot()["active_entries"] == 1
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)



def test_job_store_enforces_byte_budget_ttl_and_bounded_tombstones():
    now = [0.0]
    store = bridge.JobStore(
        ttl_seconds=10,
        max_completed=10,
        max_completed_bytes=800,
        tombstone_ttl_seconds=5,
        max_tombstones=2,
        clock=lambda: now[0],
    )
    store.create("active", "terminal", "/jobs/terminal")
    for job_id in ("a", "b", "c"):
        store.create(job_id, "terminal", "/jobs/terminal")
        store.complete(job_id, "succeeded", {"stdout": "x" * 300})
    snap = store.snapshot()
    assert snap["active_entries"] == 1
    assert snap["completed_result_bytes"] <= 800
    assert store.get("active")["status"] == "reserved"
    assert store.get("a") == {"status": "expired", "job_id": "a"}

    now[0] = 11.0
    store.cleanup()
    assert store.get("b") in ({"status": "expired", "job_id": "b"}, None)
    assert store.snapshot()["tombstones"] <= 2

    now[0] = 20.0
    store.cleanup()
    assert store.snapshot()["tombstones"] == 0


@pytest.mark.skipif(os.name != "nt", reason="requires Windows runtime APIs")
def test_stderr_emitted_ceiling_is_independent_and_bounded():
    import sys

    result = bridge.run_subprocess_bounded(
        [sys.executable, "-c", "import sys; sys.stderr.write('e' * 20000); sys.stderr.flush()"],
        timeout=10,
        retain_limit=1024,
        emit_limit=4096,
    )
    assert result["terminal_reason"] == "output_limit"
    assert result["stderr_emitted_bytes"] > 4096
    assert result["stderr_retained_bytes"] == 1024
    assert result["stderr_truncated"] is True
    assert result["process_tree_terminated"] is True


def test_resource_guard_blocks_sustained_commit_pressure_too():
    now = [0.0]
    guard = bridge.ResourcePressureGuard(
        min_available_bytes=10,
        max_commit_fraction=0.8,
        hold_seconds=300,
        clock=lambda: now[0],
    )
    healthy_available = 100
    assert guard.observe({"available_physical_bytes": healthy_available, "commit_fraction": 0.81}) is None
    now[0] = 301.0
    block = guard.observe({"available_physical_bytes": healthy_available, "commit_fraction": 0.81})
    assert block["error_code"] == "resource_pressure"
    assert block["reason"] == "commit_above_ceiling"
    assert guard.snapshot()["active"] is True



def test_http_malformed_json_is_sanitized_and_invalid_hermes_auth_is_stable():
    import http.client
    import json

    runtime = bridge.BridgeRuntime()
    server = bridge.make_server("127.0.0.1", 0, token="unit-test-token", runtime=runtime, quiet=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address

    def raw_request(path, body, token):
        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request(
            "POST",
            path,
            body=body,
            headers={
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        response = connection.getresponse()
        payload = json.loads(response.read().decode())
        result = response.status, payload
        connection.close()
        return result

    try:
        status, payload = raw_request("/jobs/hermes", b'{"prompt":"must-not-run"}', "wrong")
        assert status == 401
        assert payload == {"ok": False, "error_code": "unauthorized", "error": "unauthorized"}

        status, payload = raw_request("/jobs/hermes", b'{', "unit-test-token")
        assert status == 400
        assert payload["error_code"] == "invalid_request"
        assert "JSONDecodeError" not in json.dumps(payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)



def test_http_send_swallows_disconnects_before_headers_complete():
    class DisconnectedHandler:
        def send_response(self, _code):
            raise BrokenPipeError("client disconnected before headers")

    bridge.Handler._send(DisconnectedHandler(), 200, {"ok": True})



def test_unsupported_methods_authenticate_before_sanitized_405():
    import http.client
    import json

    server = bridge.make_server("127.0.0.1", 0, token="unit-test-token", runtime=bridge.BridgeRuntime(), quiet=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address

    def request(method, path, token=None):
        connection = http.client.HTTPConnection(host, port, timeout=5)
        headers = {"Content-Length": "0"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        body = response.read().decode()
        result = response.status, dict(response.getheaders()), body
        connection.close()
        return result

    try:
        for method, path in (("HEAD", "/status"), ("PUT", "/run/terminal"),
                             ("OPTIONS", "/jobs/hermes"), ("TRACE", "/status")):
            status, headers, body = request(method, path)
            assert status == 401
            assert "Python" not in headers.get("Server", "")
            assert "Hermes" not in headers.get("Server", "")
            assert headers.get("Connection") == "close"
            if method != "HEAD":
                assert json.loads(body)["error_code"] == "unauthorized"
        status, _, body = request("PUT", "/run/terminal", "unit-test-token")
        assert status == 405
        assert json.loads(body)["error_code"] == "method_not_allowed"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_authenticated_sync_disconnect_sets_cancel_and_releases_capacity():
    import socket
    import time

    entered = threading.Event()
    cancelled = threading.Event()

    def executor(*_args, cancel_event=None, **_kwargs):
        entered.set()
        assert cancel_event.wait(timeout=5)
        cancelled.set()
        return {"ok": False, "terminal_reason": "cancelled", "returncode": 1,
                "exit_code": 130, "stdout": "", "stderr": "",
                "stdout_retained_bytes": 0, "stderr_retained_bytes": 0,
                "stdout_emitted_bytes": 0, "stderr_emitted_bytes": 0,
                "stdout_truncated": False, "stderr_truncated": False,
                "process_tree_terminated": True}

    runtime = bridge.BridgeRuntime(executor=executor)
    server = bridge.make_server("127.0.0.1", 0, token="unit-test-token", runtime=runtime, quiet=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    body = b'{"command":"Start-Sleep -Seconds 30","timeout":60}'
    request = (
        f"POST /run/terminal HTTP/1.1\r\nHost: {host}\r\n"
        "Authorization: Bearer unit-test-token\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body

    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.sendall(request)
        assert entered.wait(timeout=2)
        sock.close()
        assert cancelled.wait(timeout=2)
        for _ in range(100):
            if runtime.admission.snapshot()["active_global"] == 0:
                break
            time.sleep(0.02)
        assert runtime.admission.snapshot()["active_global"] == 0
        assert runtime.snapshot()["counters"]["cancelled"] == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_async_thread_start_failure_discards_reserved_job_and_capacity():
    class FailingThread:
        def __init__(self, **_kwargs):
            pass

        def start(self):
            raise RuntimeError("synthetic thread-start failure")

    runtime = bridge.BridgeRuntime(thread_factory=FailingThread)
    code, body, _ = runtime.start_async(
        "terminal", {"command": "Write-Output never"}, "/jobs/terminal")
    assert code == 500
    assert body["error_code"] == "execution_failed"
    assert runtime.jobs.snapshot()["active_entries"] == 0
    assert runtime.admission.snapshot()["active_global"] == 0


@pytest.mark.skipif(os.name != "nt", reason="requires Windows runtime APIs")
def test_failed_terminate_job_object_uses_tree_fallback_and_reaps_descendant():
    import sys
    import time

    original = bridge.WindowsJobObject

    class FailingTerminateJob:
        def __init__(self):
            self.terminated = False
            self.closed = False

        def assign(self, process):
            self.process = process

        def terminate(self, _exit_code=1):
            return False

        def close(self):
            self.closed = True

    child_code = "import time; time.sleep(30)"
    parent_code = (
        "import subprocess,sys,time; "
        f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
        "print(p.pid, flush=True); time.sleep(30)"
    )
    bridge.WindowsJobObject = FailingTerminateJob
    started = time.monotonic()
    try:
        result = bridge.run_subprocess_bounded(
            [sys.executable, "-c", parent_code], timeout=0.5,
            retain_limit=4096, emit_limit=65536)
    finally:
        bridge.WindowsJobObject = original
    child_pid = int(result["stdout"].strip())
    assert time.monotonic() - started < 10
    assert result["terminal_reason"] == "timed_out"
    assert result["process_tree_terminated"] is True
    assert bridge.process_exists(child_pid) is False



@pytest.mark.skipif(os.name != "nt", reason="requires Windows runtime APIs")
def test_post_launch_drainer_failure_terminates_and_reaps_descendant(tmp_path):
    import sys
    import time

    pid_file = tmp_path / "drainer-child.pid"
    child_code = "import time; time.sleep(30)"
    parent_code = (
        "import pathlib,subprocess,sys,time; "
        f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
        f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid)); "
        "sys.stdout.write('x' * 70000); sys.stdout.flush(); time.sleep(30)"
    )
    original_feed = bridge.BoundedOutputBuffer.feed

    def explode_after_launch(self, _chunk):
        raise RuntimeError("synthetic drainer failure")

    bridge.BoundedOutputBuffer.feed = explode_after_launch
    started = time.monotonic()
    try:
        result = bridge.run_subprocess_bounded(
            [sys.executable, "-c", parent_code], timeout=20,
            retain_limit=4096, emit_limit=65536)
    finally:
        bridge.BoundedOutputBuffer.feed = original_feed
    child_pid = int(pid_file.read_text())
    assert time.monotonic() - started < 10
    assert result["terminal_reason"] == "internal_error"
    assert result["process_tree_terminated"] is True
    assert bridge.process_exists(child_pid) is False



def test_pre_auth_http_threads_and_slow_headers_bodies_are_bounded():
    import socket
    import time

    server = bridge.make_server(
        "127.0.0.1", 0, token="unit-test-token", runtime=bridge.BridgeRuntime(), quiet=True,
        max_request_threads=4, header_timeout_seconds=0.25, body_timeout_seconds=0.25)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    slow = []
    try:
        for _ in range(4):
            sock = socket.create_connection((host, port), timeout=2)
            sock.sendall(b"GET /status HTTP/1.1\r\nHost: localhost")
            slow.append(sock)
        for _ in range(100):
            if server.request_snapshot()["active"] == 4:
                break
            time.sleep(0.01)
        assert server.request_snapshot()["active"] == 4

        excess = socket.create_connection((host, port), timeout=2)
        excess.settimeout(2)
        assert excess.recv(1) == b""
        excess.close()
        assert server.request_snapshot()["rejected"] >= 1
        assert server.request_snapshot()["peak"] <= 4

        for sock in slow:
            sock.settimeout(2)
            try:
                assert sock.recv(1) == b""
            except ConnectionResetError:
                pass
        for _ in range(100):
            if server.request_snapshot()["active"] == 0:
                break
            time.sleep(0.01)
        assert server.request_snapshot()["active"] == 0

        body_sock = socket.create_connection((host, port), timeout=2)
        body_sock.sendall(
            b"POST /run/terminal HTTP/1.1\r\nHost: localhost\r\n"
            b"Authorization: Bearer unit-test-token\r\n"
            b"Content-Type: application/json\r\nContent-Length: 1000\r\n\r\n{")
        body_sock.settimeout(2)
        response = body_sock.recv(4096)
        assert b"400" in response or response == b""
        body_sock.close()
        for _ in range(100):
            if server.request_snapshot()["active"] == 0:
                break
            time.sleep(0.01)
        assert server.request_snapshot()["active"] == 0
    finally:
        for sock in slow:
            sock.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)



@pytest.mark.skipif(os.name != "nt", reason="requires Windows runtime APIs")
def test_header_deadline_timers_do_not_leak_windows_handles():
    import gc
    import time
    import urllib.request

    server = bridge.make_server("127.0.0.1", 0, token="unit-test-token",
                                runtime=bridge.BridgeRuntime(), quiet=True,
                                header_timeout_seconds=1)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/health", timeout=2) as response:
            assert response.status == 200
            response.read()
        gc.collect()
        time.sleep(0.1)
        before = bridge.collect_windows_metrics()["bridge_handle_count"]
        for _ in range(50):
            with urllib.request.urlopen(f"http://{host}:{port}/health", timeout=2) as response:
                assert response.status == 200
                response.read()
        gc.collect()
        time.sleep(0.2)
        after = bridge.collect_windows_metrics()["bridge_handle_count"]
        assert after - before <= 12, (before, after)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)



def test_resource_pressure_guard_preserves_continuity_across_reason_changes():
    clock = [0.0]
    guard = bridge.ResourcePressureGuard(100, 0.8, hold_seconds=300,
                                         clock=lambda: clock[0])
    assert guard.observe({"available_physical_bytes": 50, "commit_fraction": 0.5}) is None
    clock[0] = 300.0
    block = guard.observe({"available_physical_bytes": 150, "commit_fraction": 0.9})
    assert block is not None
    assert block["error_code"] == "resource_pressure"
    assert guard.snapshot()["since"] == 0.0


def test_resource_pressure_hold_survives_a_fresh_python_process(tmp_path):
    state_path = tmp_path / "resource-pressure.json"
    state_path.touch()
    driver = """
import importlib.util
import inspect
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
state_path = pathlib.Path(sys.argv[2])
phase = sys.argv[3]
clock = 100000.0 if phase == "A" else 100301.0
spec = importlib.util.spec_from_file_location("pressure_process", source)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
kwargs = {"hold_seconds": 300, "clock": lambda: clock}
if "state_path" in inspect.signature(module.ResourcePressureGuard).parameters:
    kwargs["state_path"] = state_path
guard = module.ResourcePressureGuard(100, 0.8, **kwargs)
if phase == "A":
    guard.commit("available_memory_below_floor", observed_at=100000.0)
    guard.commit("commit_above_ceiling", observed_at=100299.0)
    guard.commit("commit_above_ceiling", observed_at=100300.0)
else:
    guard.commit("commit_above_ceiling", observed_at=100301.0)
print(json.dumps(guard.snapshot(), sort_keys=True))
"""

    def run_process(phase):
        completed = subprocess.run(
            [sys.executable, "-I", "-B", "-c", driver,
             str(SOURCE), str(state_path), phase],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                 "PYTHONNOUSERSITE": "1", "PYTHONPATH": ""},
        )
        assert completed.returncode == 0, completed.stderr
        return json.loads(completed.stdout.strip().splitlines()[-1])

    process_a = run_process("A")
    process_b = run_process("B")

    assert process_a["active"] is True
    assert process_a["since"] == 100000.0
    assert (process_b["active"], process_b["since"]) == (True, 100000.0)


def _pressure_state_bytes(active, reason, since, updated_at, **extra):
    payload = {
        "schema_version": 1,
        "active": active,
        "reason": reason,
        "since": since,
        "updated_at": updated_at,
        **extra,
    }
    return json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def test_resource_pressure_state_is_tiny_exact_and_deterministic(tmp_path):
    state_path = tmp_path / "resource-pressure.json"
    state_path.touch()
    guard = bridge.ResourcePressureGuard(
        100, 0.8, hold_seconds=300, clock=lambda: 100000.0,
        state_path=state_path,
    )

    guard.commit("available_memory_below_floor", observed_at=100000.0)

    expected = _pressure_state_bytes(
        False, "available_memory_below_floor", 100000.0, 100000.0,
    )
    assert state_path.read_bytes() == expected
    assert len(expected) <= guard.MAX_STATE_BYTES <= 4096
    assert set(json.loads(expected)) == {
        "schema_version", "active", "reason", "since", "updated_at",
    }
    snapshot = guard.snapshot()
    assert snapshot["state_configured"] is True
    assert snapshot["persistence_ok"] is True
    assert snapshot["updated_at"] == 100000.0
    assert str(state_path) not in str(snapshot)


def test_resource_pressure_state_rejects_corrupt_or_inexact_records(tmp_path):
    valid = {
        "schema_version": 1,
        "active": False,
        "reason": "available_memory_below_floor",
        "since": 100000.0,
        "updated_at": 100001.0,
    }
    invalid_records = [
        b"{",
        _pressure_state_bytes(
            False, "available_memory_below_floor", 100000.0, 100001.0,
            unknown=True,
        ),
        (b"{\"schema_version\":1,\"SCHEMA_VERSION\":1,"
         b"\"active\":false,\"reason\":null,\"since\":null,"
         b"\"updated_at\":100001.0}"),
        json.dumps({**valid, "active": 1}, separators=(",", ":")).encode(),
        (b"{\"active\":false,\"reason\":null,\"schema_version\":1,"
         b"\"since\":null,\"updated_at\":NaN}"),
        _pressure_state_bytes(
            False, "unknown_pressure_reason", 100000.0, 100001.0,
        ),
    ]

    for index, record in enumerate(invalid_records):
        state_path = tmp_path / f"invalid-{index}.json"
        state_path.write_bytes(record)
        with pytest.raises(
                bridge.ResourcePressureStateError,
                match="resource pressure state unavailable"):
            bridge.ResourcePressureGuard(
                100, 0.8, clock=lambda: 100002.0, state_path=state_path,
            )


def test_resource_pressure_state_rejects_oversize_and_unsafe_paths(
        tmp_path, monkeypatch):
    maximum = bridge.ResourcePressureGuard.MAX_STATE_BYTES
    assert 0 < maximum <= 4096
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (maximum + 1))
    with pytest.raises(
            bridge.ResourcePressureStateError,
            match="resource pressure state unavailable"):
        bridge.ResourcePressureGuard(
            100, 0.8, clock=lambda: 1.0, state_path=oversized,
        )

    nonregular = tmp_path / "directory-state"
    nonregular.mkdir()
    with pytest.raises(
            bridge.ResourcePressureStateError,
            match="resource pressure state unavailable"):
        bridge.ResourcePressureGuard(
            100, 0.8, clock=lambda: 1.0, state_path=nonregular,
        )

    rejected = tmp_path / "reparse-state.json"
    rejected.touch()
    monkeypatch.setattr(
        bridge, "_resource_pressure_path_is_safe", lambda _path: False,
    )
    with pytest.raises(
            bridge.ResourcePressureStateError,
            match="resource pressure state unavailable"):
        bridge.ResourcePressureGuard(
            100, 0.8, clock=lambda: 1.0, state_path=rejected,
        )


def test_resource_pressure_future_clock_fails_closed_until_clean_commit(tmp_path):
    state_path = tmp_path / "resource-pressure.json"
    state_path.write_bytes(_pressure_state_bytes(
        False, "available_memory_below_floor", 100000.0, 100200.0,
    ))

    guard = bridge.ResourcePressureGuard(
        100, 0.8, hold_seconds=300, clock=lambda: 10.0,
        state_path=state_path,
    )

    snapshot = guard.snapshot()
    assert snapshot["active"] is True
    assert snapshot["reason"] == "pressure_clock_discontinuity"
    assert snapshot["since"] == 100000.0
    assert guard.current_block()["reason"] == "pressure_clock_discontinuity"

    assert guard.commit(None, observed_at=11.0) is None
    assert state_path.read_bytes() == _pressure_state_bytes(
        False, None, None, 11.0,
    )
    reloaded = bridge.ResourcePressureGuard(
        100, 0.8, hold_seconds=300, clock=lambda: 12.0,
        state_path=state_path,
    )
    assert reloaded.current_block() is None
    assert reloaded.snapshot()["active"] is False


def test_resource_pressure_reason_change_and_clean_clear_persist(tmp_path):
    state_path = tmp_path / "resource-pressure.json"
    state_path.touch()
    clock = [100000.0]
    guard = bridge.ResourcePressureGuard(
        100, 0.8, hold_seconds=300, clock=lambda: clock[0],
        state_path=state_path,
    )
    guard.commit("available_memory_below_floor")
    clock[0] = 100250.0
    guard.commit("commit_above_ceiling")
    assert json.loads(state_path.read_text(encoding="utf-8"))["since"] == 100000.0

    clock[0] = 100301.0
    reloaded = bridge.ResourcePressureGuard(
        100, 0.8, hold_seconds=300, clock=lambda: clock[0],
        state_path=state_path,
    )
    blocked = reloaded.commit("commit_above_ceiling")
    assert blocked["reason"] == "commit_above_ceiling"
    assert reloaded.snapshot()["since"] == 100000.0

    clock[0] = 100302.0
    assert reloaded.commit(None) is None
    assert state_path.read_bytes() == _pressure_state_bytes(
        False, None, None, 100302.0,
    )
    clock[0] = 100303.0
    clean_reload = bridge.ResourcePressureGuard(
        100, 0.8, hold_seconds=300, clock=lambda: clock[0],
        state_path=state_path,
    )
    assert clean_reload.current_block() is None


def test_resource_pressure_persistence_failure_blocks_admission_and_cleans_temp(
        tmp_path, monkeypatch):
    state_path = tmp_path / "resource-pressure.json"
    state_path.touch()
    guard = bridge.ResourcePressureGuard(
        100, 0.8, hold_seconds=300, clock=lambda: 100.0,
        state_path=state_path,
    )
    controller = bridge.AdmissionController(resource_guard=guard)
    before = state_path.read_bytes()
    leak_marker = "must-not-cross-pressure-status-boundary"

    def fail_replace(_replacement, _target):
        raise OSError(leak_marker)

    monkeypatch.setattr(bridge, "replace_file_preserving_dacl", fail_replace)
    blocked = guard.commit(
        "available_memory_below_floor", observed_at=101.0,
    )

    assert blocked == {
        "error_code": "resource_pressure",
        "error": "Windows resource-pressure hard stop is active",
        "reason": "pressure_state_unavailable",
        "retry_after_seconds": 60,
    }
    snapshot = guard.snapshot()
    assert snapshot["active"] is True
    assert snapshot["persistence_ok"] is False
    assert leak_marker not in str(snapshot)
    reservation, error = controller.try_reserve("terminal", "/run/terminal")
    assert reservation is None
    assert error["reason"] == "pressure_state_unavailable"
    assert error["execution_started"] is False
    assert state_path.read_bytes() == before
    assert list(tmp_path.glob(state_path.name + ".tmp-*")) == []


def test_resource_pressure_atomic_write_attests_before_and_after_publish(
        tmp_path, monkeypatch):
    state_path = tmp_path / "resource-pressure.json"
    state_path.touch()
    events = []

    def attest(paths):
        assert list(paths) == [state_path]
        events.append("attest")
        return True

    guard = bridge.ResourcePressureGuard(
        100, 0.8, hold_seconds=300, clock=lambda: 100.0,
        state_path=state_path, private_path_attestor=attest,
    )
    events.clear()
    before = state_path.read_bytes()

    def publish(replacement, target):
        assert target == state_path
        assert state_path.read_bytes() == before
        staged = json.loads(replacement.read_text(encoding="utf-8"))
        assert staged["reason"] == "available_memory_below_floor"
        events.append("replace")
        os.replace(replacement, target)

    monkeypatch.setattr(bridge, "replace_file_preserving_dacl", publish)
    guard.commit("available_memory_below_floor", observed_at=101.0)

    assert events == ["attest", "replace", "attest"]
    assert list(tmp_path.glob(state_path.name + ".tmp-*")) == []


def test_telemetry_collection_failures_eventually_fail_closed(tmp_path, monkeypatch):
    clock = [0.0]
    guard = bridge.ResourcePressureGuard(100, 0.8, hold_seconds=300,
                                         clock=lambda: clock[0])
    runtime = bridge.BridgeRuntime()
    writer = bridge.TelemetryWriter(runtime, guard, tmp_path / "metrics.jsonl")

    def unavailable():
        raise OSError("metrics unavailable")

    monkeypatch.setattr(bridge, "collect_windows_metrics", unavailable)
    with pytest.raises(OSError):
        writer.sample()
    assert guard.current_block() is None
    clock[0] = 300.0
    with pytest.raises(OSError):
        writer.sample()
    assert guard.current_block()["reason"] == "telemetry_unavailable"


def test_cancel_does_not_acknowledge_after_job_is_terminal():
    import time

    class BlockingCompleteStore(bridge.JobStore):
        def __init__(self):
            super().__init__()
            self.updated = threading.Event()
            self.release_complete = threading.Event()

        def complete(self, job_id, status, result):
            super().complete(job_id, status, result)
            self.updated.set()
            assert self.release_complete.wait(5)

    store = BlockingCompleteStore()

    def executor(*args, **kwargs):
        return {"ok": True, "terminal_reason": "succeeded", "returncode": 0,
                "stdout": "", "stderr": ""}

    runtime = bridge.BridgeRuntime(jobs=store, executor=executor)
    code, response, _ = runtime.start_async("terminal", {"command": "Write-Output ok"},
                                            "/jobs/terminal")
    assert code == 202
    assert store.updated.wait(5)
    cancellation = {}
    cancellation_done = threading.Event()

    def cancel():
        cancellation["value"] = runtime.cancel_job(response["job_id"])
        cancellation_done.set()

    cancel_thread = threading.Thread(target=cancel)
    cancel_thread.start()
    time.sleep(0.1)
    assert not cancellation_done.is_set()
    store.release_complete.set()
    cancel_thread.join(timeout=5)
    assert cancellation_done.is_set()
    cancel_code, cancel_body = cancellation["value"]
    assert cancel_code == 409
    assert cancel_body["error_code"] == "already_terminal"
    deadline = time.time() + 5
    while runtime.snapshot()["admission"]["active_global"] and time.time() < deadline:
        time.sleep(0.01)
    assert runtime.snapshot()["admission"]["active_global"] == 0





def test_copy_truncate_rotation_preserves_current_file_and_bounds_backups(tmp_path):
    path = tmp_path / "bridge.log"
    path.write_text("current", encoding="utf-8")
    (tmp_path / "bridge.log.1").write_text("previous", encoding="utf-8")
    bridge._rotate_copy_truncate(path, max_bytes=1, backups=2)
    assert path.exists()
    assert path.read_text(encoding="utf-8") == ""
    assert (tmp_path / "bridge.log.1").read_text(encoding="utf-8") == "current"
    assert (tmp_path / "bridge.log.2").read_text(encoding="utf-8") == "previous"



def test_execution_failures_never_reflect_exception_details():
    marker = "must-not-cross-execution-boundary"

    def exploding_executor(*_args, **_kwargs):
        raise RuntimeError(marker)

    runtime = bridge.BridgeRuntime(executor=exploding_executor)
    code, body, _ = runtime.run_sync("terminal", {"command": "Write-Output ok"}, "/run/terminal")
    assert code == 500
    assert marker not in str(body)
    assert "RuntimeError" not in str(body)
    assert body["error"] == "execution failed"

    class FailingThread:
        def start(self):
            raise RuntimeError(marker)

    failed = bridge.BridgeRuntime(
        executor=lambda *_args, **_kwargs: {},
        thread_factory=lambda **_kwargs: FailingThread(),
    )
    code, body, _ = failed.start_async("terminal", {"command": "Write-Output ok"}, "/jobs/terminal")
    assert code == 500
    assert marker not in str(body)
    assert "RuntimeError" not in str(body)
    counters = failed.snapshot()["counters"]
    assert counters["submitted"] == counters["completed"] == 0


def test_late_cancel_forces_cancelled_terminal_result_when_executor_ignores_event():
    entered = threading.Event()
    release = threading.Event()

    def executor(*_args, cancel_event=None, **_kwargs):
        entered.set()
        assert cancel_event is not None
        assert cancel_event.wait(timeout=5)
        assert release.wait(timeout=5)
        return {"ok": True, "terminal_reason": "succeeded", "returncode": 0, "exit_code": 0,
                "stdout": "", "stderr": "", "stdout_retained_bytes": 0,
                "stderr_retained_bytes": 0, "stdout_emitted_bytes": 0,
                "stderr_emitted_bytes": 0, "stdout_truncated": False,
                "stderr_truncated": False, "process_tree_terminated": True}

    runtime = bridge.BridgeRuntime(executor=executor)
    code, body, _ = runtime.start_async("terminal", {"command": "Write-Output ok"}, "/jobs/terminal")
    assert code == 202
    assert entered.wait(timeout=5)
    cancel_code, _ = runtime.cancel_job(body["job_id"])
    assert cancel_code == 202
    release.set()
    for _ in range(100):
        job = runtime.get_job(body["job_id"])
        if job and job.get("status") in bridge.JobStore.TERMINAL_STATUSES:
            break
        threading.Event().wait(0.02)
    assert job["status"] == "cancelled"
    assert job["result"]["terminal_reason"] == "cancelled"
    assert job["result"]["ok"] is False


def test_telemetry_thread_survives_sample_and_failure_log_exceptions(monkeypatch, tmp_path):
    writer = bridge.TelemetryWriter(bridge.BridgeRuntime(), None, tmp_path / "metrics.jsonl", interval_seconds=0.01)
    attempts = [0]

    def fail_sample():
        attempts[0] += 1
        raise RuntimeError("sample failed")

    monkeypatch.setattr(writer, "sample", fail_sample)
    monkeypatch.setattr(bridge, "log", lambda _message: (_ for _ in ()).throw(OSError("log failed")))
    writer.start()
    try:
        for _ in range(100):
            if attempts[0] >= 3:
                break
            threading.Event().wait(0.01)
        assert attempts[0] >= 3
        assert writer.thread.is_alive()
    finally:
        writer.stop()


def test_oversized_headers_are_rejected_before_authentication():
    import socket

    server = bridge.make_server(
        "127.0.0.1", 0, token="unit-test-token", runtime=bridge.BridgeRuntime(), quiet=True,
        max_header_bytes=1024,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        sock = socket.create_connection((host, port), timeout=5)
        request = ("GET /status HTTP/1.1\r\nHost: local\r\nX-Large: " + ("a" * 2048) + "\r\n\r\n").encode()
        sock.sendall(request)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        assert b" 431 " in response.split(b"\r\n", 1)[0]
        assert b"unauthorized" not in response
        assert b"request headers too large" in response
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)



def test_async_job_store_create_failure_does_not_underflow_counters_or_capacity():
    class FailingCreateStore(bridge.JobStore):
        def create(self, *_args, **_kwargs):
            raise RuntimeError("create failed")

    runtime = bridge.BridgeRuntime()
    runtime.jobs = FailingCreateStore()
    code, body, _ = runtime.start_async("terminal", {"command": "Write-Output ok"}, "/jobs/terminal")
    assert code == 500
    assert body["error"] == "execution failed"
    snapshot = runtime.snapshot()
    assert snapshot["counters"]["submitted"] == 0
    assert snapshot["counters"]["completed"] == 0
    assert snapshot["admission"]["active_global"] == 0



def test_authenticated_status_metrics_failure_is_sanitized_and_marks_guard(monkeypatch):
    import http.client
    import json

    guard = bridge.ResourcePressureGuard(1, 0.9, hold_seconds=0)
    runtime = bridge.BridgeRuntime(admission=bridge.AdmissionController(
        global_limit=2, class_limits={"hermes": 1, "terminal": 2}, resource_guard=guard))
    marker = "metrics-secret-marker"
    monkeypatch.setattr(bridge, "collect_windows_metrics", lambda: (_ for _ in ()).throw(RuntimeError(marker)))
    server = bridge.make_server("127.0.0.1", 0, token="unit-test-token", runtime=runtime, quiet=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request("GET", "/status", headers={"Authorization": "Bearer unit-test-token"})
        response = connection.getresponse()
        payload = json.loads(response.read().decode())
        connection.close()
        assert response.status == 503
        assert payload == {
            "ok": False,
            "error_code": "status_unavailable",
            "error": "bridge status unavailable",
        }
        assert marker not in str(payload)
        assert guard.snapshot()["active"] is True
        assert guard.snapshot()["reason"] == "telemetry_unavailable"

        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request("GET", "/ready", headers={"Authorization": "Bearer unit-test-token"})
        response = connection.getresponse()
        ready = json.loads(response.read().decode())
        connection.close()
        assert response.status == 503
        assert ready["ok"] is False
        assert ready["error_code"] == "resource_pressure"
        assert ready["reason"] == "telemetry_unavailable"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)



def test_async_completion_and_cancel_acknowledgement_are_linearized():
    normalized = threading.Event()
    release = threading.Event()

    def immediate_success(*_args, **_kwargs):
        return {"ok": True, "terminal_reason": "succeeded", "exit_code": 0,
                "stdout": "", "stderr": ""}

    runtime = bridge.BridgeRuntime(executor=immediate_success)
    original = runtime._apply_accepted_cancellation

    def pause_after_normalization(result, cancel_event):
        value = original(result, cancel_event)
        normalized.set()
        assert release.wait(5)
        return value

    runtime._apply_accepted_cancellation = pause_after_normalization
    code, body, _ = runtime.start_async("terminal", {"command": "Write-Output ok"}, "/jobs/terminal")
    assert code == 202
    job_id = body["job_id"]
    assert normalized.wait(5)
    cancel_result = {}
    cancel_done = threading.Event()

    def cancel():
        cancel_result["response"] = runtime.cancel_job(job_id)
        cancel_done.set()

    cancel_thread = threading.Thread(target=cancel)
    cancel_thread.start()
    assert not cancel_done.wait(0.1)
    release.set()
    assert cancel_done.wait(5)
    cancel_thread.join(timeout=5)
    assert cancel_result["response"][0] == 409
    deadline = time.time() + 5
    while time.time() < deadline:
        job = runtime.get_job(job_id)
        if job and job["status"] in bridge.JobStore.TERMINAL_STATUSES:
            break
        time.sleep(0.01)
    assert job["status"] == "succeeded"



def test_windows_listener_uses_exclusive_address_ownership():
    import socket

    server = bridge.make_server("127.0.0.1", 0, "synthetic-token", quiet=True)
    try:
        assert server.allow_reuse_address is False
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            assert server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE) == 1
            contender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                contender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                with pytest.raises(OSError):
                    contender.bind(server.server_address)
            finally:
                contender.close()
    finally:
        server.server_close()


@pytest.mark.parametrize(
    ("host", "cert", "key", "allowed"),
    [
        ("127.0.0.1", None, None, True),
        ("localhost", None, None, True),
        ("0.0.0.0", "cert", "key", False),
        ("::", "cert", "key", False),
        ("0", "cert", "key", False),
        ("0x0", "cert", "key", False),
        ("00", "cert", "key", False),
        ("0.0.0", "cert", "key", False),
        ("000.000.000.000", "cert", "key", False),
        ("127.1", "cert", "key", False),
        ("0x7f000001", "cert", "key", False),
        ("::ffff:0.0.0.0", "cert", "key", False),
        ("bridge.example.", "cert", "key", False),
        ("bridge.example..", "cert", "key", False),
        ("bridge.example\u3002", "cert", "key", False),
        ("bridge.example\u3002\u3002", "cert", "key", False),
        ("b\u00fccher.example", "cert", "key", False),
        (" bridge.example ", "cert", "key", False),
        ("192.0.2.10", None, None, False),
        ("192.0.2.10", "cert", None, False),
        ("192.0.2.10", "cert", "key", True),
        ("123.example", "cert", "key", True),
        ("Bridge.Example", "cert", "key", True),
        ("xn--bcher-kva.example", "cert", "key", True),
    ],
)
def test_listener_transport_rejects_plaintext_or_wildcard_network_bind(host, cert, key, allowed):
    if allowed:
        bridge.validate_listener_transport(host, cert, key)
    else:
        with pytest.raises(ValueError):
            bridge.validate_listener_transport(host, cert, key)


def test_listener_detects_mapped_wildcard_under_legacy_ipaddress_semantics():
    class LegacyMappedAddress:
        is_unspecified = False
        ipv4_mapped = bridge.ipaddress.ip_address("0.0.0.0")

    assert bridge._is_unspecified_address(LegacyMappedAddress()) is True


def test_tls_certificate_load_completes_before_server_socket_construction(monkeypatch):
    import ssl

    events = []

    class SyntheticContext:
        minimum_version = None

        def load_cert_chain(self, *, certfile, keyfile):
            events.append(("load_cert_chain", certfile, keyfile))
            raise ssl.SSLError("synthetic invalid TLS material")

    def context_factory(protocol):
        assert protocol == ssl.PROTOCOL_TLS_SERVER
        events.append(("context",))
        return SyntheticContext()

    def forbidden_server(*_args, **_kwargs):
        events.append(("server",))
        raise AssertionError("server socket constructed before TLS validation")

    monkeypatch.setattr(bridge.ssl, "SSLContext", context_factory)
    monkeypatch.setattr(bridge, "BridgeHTTPServer", forbidden_server)

    with pytest.raises(ssl.SSLError, match="synthetic invalid TLS material"):
        bridge.make_server(
            "bridge.example",
            8765,
            token="synthetic-token",
            runtime=bridge.BridgeRuntime(),
            tls_cert="certificate.pem",
            tls_key="private-key.pem",
        )

    assert events == [
        ("context",),
        ("load_cert_chain", "certificate.pem", "private-key.pem"),
    ]


def test_access_log_omits_query_strings_and_job_identifiers(monkeypatch):
    import json
    import threading
    import urllib.request

    records = []
    monkeypatch.setattr(bridge, "log", records.append)
    server = bridge.make_server("127.0.0.1", 0, "synthetic-token", quiet=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        canary = "private-query-canary"
        with urllib.request.urlopen(
            f"http://127.0.0.1:{server.server_address[1]}/health?value={canary}", timeout=5
        ) as response:
            assert json.loads(response.read())["ok"] is True
        assert records
        rendered = "\n".join(records)
        assert canary not in rendered
        assert "route=/health" in rendered
        assert "status=200" in rendered
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_telemetry_double_fault_keeps_thread_alive_and_fails_guard_closed(monkeypatch, tmp_path):
    guard = bridge.ResourcePressureGuard(2 * 1024**3, 0.8, hold_seconds=0.02)
    runtime = bridge.BridgeRuntime(admission=bridge.AdmissionController(resource_guard=guard))
    writer = bridge.TelemetryWriter(runtime, guard, tmp_path / "metrics.jsonl", interval_seconds=0.005)

    def fail_sample():
        raise OSError("synthetic telemetry failure")

    def fail_log(_message):
        raise OSError("synthetic log failure")

    monkeypatch.setattr(writer, "sample", fail_sample)
    monkeypatch.setattr(bridge, "log", fail_log)
    writer.start()
    try:
        deadline = time.time() + 1
        while time.time() < deadline and guard.current_block() is None:
            time.sleep(0.01)
        assert writer.thread.is_alive()
        assert guard.current_block()["error_code"] == "resource_pressure"
        snapshot = writer.snapshot()
        assert snapshot["thread_alive"] is True
        assert snapshot["consecutive_failures"] > 0
        assert snapshot["last_failure_at"] is not None
    finally:
        writer.stop()










def test_tls_handshake_is_deferred_to_bounded_worker_not_accept_loop(tmp_path):
    import socket
    import ssl

    tls_cert = tmp_path / "synthetic-cert.pem"
    tls_key = tmp_path / "synthetic-key.pem"
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
            str(tls_key),
            "-out",
            str(tls_cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    server = bridge.make_server(
        "127.0.0.1",
        0,
        "synthetic-token",
        tls_cert=tls_cert,
        tls_key=tls_key,
    )
    try:
        assert isinstance(server.socket, socket.socket)
        assert not isinstance(server.socket, ssl.SSLSocket)
        assert isinstance(server.tls_context, ssl.SSLContext)
    finally:
        server.server_close()





def test_validation_errors_never_reflect_payload_values():
    runtime = bridge.BridgeRuntime()
    marker = "private-timeout-canary"
    code, payload, _headers = runtime.run_sync(
        "terminal", {"command": "Write-Output safe", "timeout": marker}, "/run/terminal"
    )
    assert code == 400
    assert payload["error_code"] == "invalid_request"
    assert marker not in str(payload)



def test_authenticated_ready_reports_startup_source_hash():
    import hashlib
    import http.client
    import json

    server = bridge.make_server("127.0.0.1", 0, token="unit-test-token", quiet=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        connection.request("GET", "/ready", headers={"Authorization": "Bearer unit-test-token"})
        response = connection.getresponse()
        payload = json.loads(response.read())
        assert response.status == 200
        assert payload["source_sha256"] == hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)



def test_job_store_persists_results_tombstones_and_recovers_interrupted_jobs(tmp_path):
    now = [1000.0]
    state = tmp_path / 'private' / 'jobs.json'
    first = bridge.JobStore(ttl_seconds=10, tombstone_ttl_seconds=100,
                            state_path=state, clock=lambda: now[0])
    first.create('done', 'terminal', '/jobs/terminal')
    first.mark_running('done')
    first.complete('done', 'succeeded', {'ok': True, 'terminal_reason': 'succeeded'})
    reloaded = bridge.JobStore(ttl_seconds=10, tombstone_ttl_seconds=100,
                               state_path=state, clock=lambda: now[0])
    assert reloaded.get('done')['status'] == 'succeeded'
    reloaded.create('interrupted', 'terminal', '/jobs/terminal')
    reloaded.mark_running('interrupted')
    recovered = bridge.JobStore(ttl_seconds=10, tombstone_ttl_seconds=100,
                                state_path=state, clock=lambda: now[0])
    interrupted = recovered.get('interrupted')
    assert interrupted['status'] == 'failed'
    assert interrupted['result']['terminal_reason'] == 'bridge_restart'
    assert interrupted['result']['process_tree_terminated'] is True
    now[0] += 11
    recovered.cleanup()
    final = bridge.JobStore(ttl_seconds=10, tombstone_ttl_seconds=100,
                            state_path=state, clock=lambda: now[0])
    assert final.get('done')['status'] == 'expired'
    assert final.get('interrupted')['status'] == 'expired'


def test_fast_process_lifecycle_is_written_without_outputs_or_payloads(tmp_path):
    secret = 'PRIVATE-LIFECYCLE-PAYLOAD'
    def executor(*_args, **_kwargs):
        return {'ok': True, 'terminal_reason': 'succeeded', 'returncode': 0,
                'exit_code': 0, 'process_pid': 123, 'process_parent_pid': 45,
                'started_at_epoch': 1.0, 'completed_at_epoch': 2.0,
                'started_at_utc': '1970-01-01T00:00:01Z',
                'completed_at_utc': '1970-01-01T00:00:02Z',
                'process_tree_terminated': True,
                'stdout': secret, 'stderr': '', 'stdout_emitted_bytes': len(secret),
                'stderr_emitted_bytes': 0, 'stdout_retained_bytes': len(secret),
                'stderr_retained_bytes': 0, 'stdout_truncated': False,
                'stderr_truncated': False, 'duration_seconds': 1.0}
    runtime = bridge.BridgeRuntime(executor=executor)
    path = tmp_path / 'metrics.jsonl'
    writer = bridge.TelemetryWriter(runtime, None, path)
    runtime.set_lifecycle_sink(writer.record_lifecycle)
    status, result, _ = runtime.run_sync('terminal', {'command': 'Write-Output safe'}, '/run/terminal')
    assert status == 200 and result['ok']
    raw = path.read_text(encoding='utf-8')
    assert secret not in raw
    record = json.loads(raw.strip())
    assert record['record_type'] == 'process_lifecycle'
    assert record['event']['process_pid'] == 123
    assert record['event']['process_parent_pid'] == 45
    assert record['event']['terminal_reason'] == 'succeeded'
    assert record['event']['process_tree_terminated'] is True


def test_execution_boundary_error_has_complete_privacy_safe_lifecycle_fields():
    def broken(*_args, **_kwargs):
        raise RuntimeError('PRIVATE-EXECUTION-DETAIL')
    runtime = bridge.BridgeRuntime(executor=broken)
    status, result, _ = runtime.run_sync('terminal', {'command': 'Write-Output safe'}, '/run/terminal')
    assert status == 500
    assert 'PRIVATE-EXECUTION-DETAIL' not in json.dumps(result)
    for field in ('process_pid', 'process_parent_pid', 'started_at_epoch',
                  'completed_at_epoch', 'started_at_utc', 'completed_at_utc',
                  'process_tree_terminated', 'terminal_reason'):
        assert field in result



@pytest.mark.skipif(os.name != "nt", reason="requires Windows runtime APIs")
def test_natural_nonzero_exit_enforces_descendant_tree_cleanup():
    script = ("import subprocess,sys,time; "
              "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
              "print(p.pid,flush=True); sys.exit(3)")
    result = bridge.run_subprocess_bounded([bridge.sys.executable, '-c', script], timeout=15)
    child_pid = int(result['stdout'].strip().splitlines()[0])
    deadline = time.time() + 5
    while time.time() < deadline and bridge.process_exists(child_pid):
        time.sleep(0.05)
    assert result['terminal_reason'] == 'failed'
    assert result['returncode'] == 3
    assert result['process_tree_terminated'] is True
    assert not bridge.process_exists(child_pid)



def test_async_admission_fails_closed_when_persistent_state_cannot_commit(tmp_path):
    blocker = tmp_path / 'not-a-directory'
    blocker.write_text('x', encoding='utf-8')
    with pytest.raises(bridge.JobStateUnavailable):
        bridge.JobStore(state_path=blocker / 'jobs.json')


def test_lifecycle_telemetry_write_failure_marks_resource_guard(tmp_path):
    blocker = tmp_path / 'not-a-directory'
    blocker.write_text('x', encoding='utf-8')
    guard = bridge.ResourcePressureGuard(1, 0.9, hold_seconds=0)
    runtime = bridge.BridgeRuntime()
    writer = bridge.TelemetryWriter(runtime, guard, blocker / 'metrics.jsonl')
    with pytest.raises(OSError):
        writer.record_lifecycle({'terminal_reason': 'failed'})
    assert guard.current_block()['error_code'] == 'resource_pressure'
    assert writer.snapshot()['consecutive_failures'] == 1




def test_resource_pressure_hold_continues_when_unhealthy_reason_changes():
    now = [0.0]
    guard = bridge.ResourcePressureGuard(100, 0.8, hold_seconds=300, clock=lambda: now[0])
    assert guard.observe({'available_physical_bytes': 50, 'commit_fraction': 0.5}) is None
    now[0] = 299
    assert guard.observe({'available_physical_bytes': 150, 'commit_fraction': 0.9}) is None
    now[0] = 300
    assert guard.observe_failure() is not None
    snapshot = guard.snapshot()
    assert snapshot['since'] == 0.0
    assert snapshot['reason'] == 'telemetry_unavailable'



def _worker_a_result(reason='succeeded', ok=True, **overrides):
    result = {
        'ok': ok,
        'terminal_reason': reason,
        'returncode': 0 if ok else 1,
        'exit_code': 0 if ok else 1,
        'stdout': '',
        'stderr': '',
        'stdout_retained_bytes': 0,
        'stderr_retained_bytes': 0,
        'stdout_emitted_bytes': 0,
        'stderr_emitted_bytes': 0,
        'stdout_truncated': False,
        'stderr_truncated': False,
        'process_tree_terminated': False,
        'process_tree_cleanup_enforced': True,
        'cleanup_certified': True,
    }
    result.update(overrides)
    return result


def test_worker_a_healthy_pressure_reset_requires_persisted_acl_attested_sample(
        tmp_path, monkeypatch):
    monotonic = [0.0]
    wall = [1000.0]
    guard = bridge.ResourcePressureGuard(
        100, 0.8, hold_seconds=0, clock=lambda: monotonic[0])
    assert guard.observe_failure()['reason'] == 'telemetry_unavailable'
    initial_since = guard.snapshot()['since']
    runtime = bridge.BridgeRuntime()
    attest = [False]
    writer = bridge.TelemetryWriter(
        runtime, guard, tmp_path / 'metrics.jsonl', interval_seconds=1,
        max_stale_seconds=5, clock=lambda: wall[0],
        private_path_attestor=lambda _paths: attest[0])
    monkeypatch.setattr(
        bridge, 'collect_windows_metrics',
        lambda: {'available_physical_bytes': 1000, 'commit_fraction': 0.1})

    with pytest.raises(bridge.TelemetryPersistenceError):
        writer.sample()
    assert guard.snapshot()['active'] is True
    assert guard.snapshot()['since'] == initial_since
    assert writer.snapshot()['last_resource_sample_at'] is None

    attest[0] = True
    writer.sample()
    assert guard.snapshot()['active'] is False
    sample_at = writer.snapshot()['last_resource_sample_at']
    wall[0] += 1
    writer.record_lifecycle({'terminal_reason': 'succeeded'})
    assert writer.snapshot()['last_resource_sample_at'] == sample_at


def test_worker_a_telemetry_never_stale_and_dead_states_fail_admission_closed(
        tmp_path, monkeypatch):
    wall = [100.0]
    executions = []
    guard = bridge.ResourcePressureGuard(1, 0.9, hold_seconds=0)
    admission = bridge.AdmissionController(resource_guard=guard)
    runtime = bridge.BridgeRuntime(
        admission=admission,
        executor=lambda *_args, **_kwargs: executions.append('ran') or _worker_a_result())
    writer = bridge.TelemetryWriter(
        runtime, guard, tmp_path / 'metrics.jsonl', interval_seconds=1,
        max_stale_seconds=5, clock=lambda: wall[0],
        private_path_attestor=lambda _paths: True)
    runtime.set_telemetry(writer)

    status, body, _ = runtime.run_sync(
        'terminal', {'command': 'Write-Output safe'}, '/run/terminal')
    assert status == 503
    assert body['error_code'] == 'resource_pressure'
    assert body['reason'] == 'telemetry_never_persisted'
    assert body['execution_started'] is False
    assert executions == []

    monkeypatch.setattr(
        bridge, 'collect_windows_metrics',
        lambda: {'available_physical_bytes': 1000, 'commit_fraction': 0.1})

    class ThreadState:
        alive = True

        def is_alive(self):
            return self.alive

    writer.thread = ThreadState()
    writer.sample()
    status, _, _ = runtime.run_sync(
        'terminal', {'command': 'Write-Output safe'}, '/run/terminal')
    assert status == 200
    assert executions == ['ran']

    wall[0] += 6
    status, body, _ = runtime.run_sync(
        'terminal', {'command': 'Write-Output safe'}, '/run/terminal')
    assert status == 503 and body['reason'] == 'telemetry_stale'
    writer.thread.alive = False
    ready_status, ready = runtime.readiness()
    assert ready_status == 503
    assert ready['reason'] == 'telemetry_thread_dead'


def test_worker_a_pressure_transition_and_reservation_have_a_valid_linearization():
    guard = bridge.ResourcePressureGuard(100, 0.8, hold_seconds=0)
    controller = bridge.AdmissionController(resource_guard=guard)
    in_decision = threading.Event()
    order = []
    original = guard.current_block

    def paused_decision():
        decision = original()
        in_decision.set()
        time.sleep(0.1)
        return decision

    guard.current_block = paused_decision
    result = {}

    def reserve():
        result['reservation'], result['error'] = controller.try_reserve(
            'terminal', '/run/terminal')
        order.append('reservation')

    reserve_thread = threading.Thread(target=reserve)
    reserve_thread.start()
    assert in_decision.wait(2)

    def activate_pressure():
        guard.observe({'available_physical_bytes': 1, 'commit_fraction': 0.1})
        order.append('pressure')

    pressure_thread = threading.Thread(target=activate_pressure)
    pressure_thread.start()
    reserve_thread.join(5)
    pressure_thread.join(5)
    assert not reserve_thread.is_alive() and not pressure_thread.is_alive()
    if result['reservation'] is not None:
        result['reservation'].release()
        assert order == ['reservation', 'pressure']
    else:
        assert result['error']['error_code'] == 'resource_pressure'


def test_worker_a_quiesce_generation_closes_admission_and_records_stable_zero():
    wall = [1000.0]
    controller = bridge.AdmissionController(wall_clock=lambda: wall[0])
    reservation, error = controller.try_reserve('terminal', '/run/terminal')
    assert reservation is not None and error is None

    code, begun = controller.quiesce('begin')
    assert code == 200
    assert begun['generation'] == 1
    assert begun['quiesced'] is True
    assert begun['active_global'] == 1
    assert begun['zero_active_since_epoch'] is None
    assert controller.quiesce('begin') == (code, begun)

    rejected, rejection = controller.try_reserve('terminal', '/run/terminal')
    assert rejected is None
    assert rejection['error_code'] == 'quiesced'
    assert rejection['execution_started'] is False

    wall[0] = 1002.5
    reservation.release()
    status_code, drained = controller.quiesce('status', generation=1)
    assert status_code == 200
    assert drained['active_global'] == 0
    assert drained['zero_active_since_epoch'] == 1002.5
    wall[0] = 1010.0
    assert controller.quiesce('status', generation=1)[1]['zero_active_since_epoch'] == 1002.5
    assert controller.quiesce('resume', generation=0)[0] == 409
    assert controller.quiesce('resume', generation=1)[1]['quiesced'] is False


def test_worker_a_authenticated_quiesce_http_contract_uses_matching_generation():
    import http.client

    runtime = bridge.BridgeRuntime()
    server = bridge.make_server('127.0.0.1', 0, 'unit-test-token', runtime=runtime, quiet=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def post(body):
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        encoded = json.dumps(body).encode()
        connection.request(
            'POST', '/admin/quiesce', body=encoded,
            headers={'Authorization': 'Bearer unit-test-token',
                     'Content-Type': 'application/json',
                     'Content-Length': str(len(encoded))})
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
        return response.status, payload

    try:
        status, begun = post({'action': 'begin'})
        assert status == 200 and begun['generation'] == 1
        assert post({'action': 'status', 'generation': 0})[0] == 409
        assert post({'action': 'resume', 'generation': begun['generation']}) == (
            200, {'ok': True, 'generation': 1, 'quiesced': False,
                  'active_global': 0, 'zero_active_since_epoch': None})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)



def test_worker_a_job_store_required_mutations_roll_back_on_persistence_failure(
        tmp_path, monkeypatch):
    def fail_persistence(store):
        monkeypatch.setattr(store, '_persist_locked', lambda: False)

    create_store = bridge.JobStore(state_path=tmp_path / 'create.json')
    fail_persistence(create_store)
    with pytest.raises(bridge.JobStateUnavailable):
        create_store.create('new', 'terminal', '/jobs/terminal')
    assert create_store.get('new') is None

    running_store = bridge.JobStore(state_path=tmp_path / 'running.json')
    running_store.create('job', 'terminal', '/jobs/terminal')
    fail_persistence(running_store)
    with pytest.raises(bridge.JobStateUnavailable):
        running_store.mark_running('job')
    assert running_store.get('job')['status'] == 'reserved'

    process_store = bridge.JobStore(state_path=tmp_path / 'process.json')
    process_store.create('job', 'terminal', '/jobs/terminal')
    process_store.mark_running('job')
    fail_persistence(process_store)
    with pytest.raises(bridge.JobStateUnavailable):
        process_store.record_process('job', 123, 45, 10.0)
    assert 'process_pid' not in process_store.get('job')

    cancel_store = bridge.JobStore(state_path=tmp_path / 'cancel.json')
    cancel_store.create('job', 'terminal', '/jobs/terminal')
    fail_persistence(cancel_store)
    with pytest.raises(bridge.JobStateUnavailable):
        cancel_store.request_cancel('job')
    assert 'cancel_requested_at' not in cancel_store.get('job')

    discard_store = bridge.JobStore(state_path=tmp_path / 'discard.json')
    discard_store.create('job', 'terminal', '/jobs/terminal')
    fail_persistence(discard_store)
    with pytest.raises(bridge.JobStateUnavailable):
        discard_store.discard_active('job')
    assert discard_store.get('job')['status'] == 'reserved'


def test_worker_a_cleanup_expiry_rolls_back_when_tombstone_cannot_persist(
        tmp_path, monkeypatch):
    clock = [0.0]
    store = bridge.JobStore(
        state_path=tmp_path / 'expiry.json', ttl_seconds=1,
        clock=lambda: clock[0])
    store.create('job', 'terminal', '/jobs/terminal')
    assert store.complete('job', 'succeeded', _worker_a_result()) is True
    clock[0] = 2.0
    monkeypatch.setattr(store, '_persist_locked', lambda: False)
    with pytest.raises(bridge.JobStateUnavailable):
        store.cleanup()
    with store.lock:
        assert store.jobs['job']['status'] == 'succeeded'
        assert 'job' not in store.tombstones


def test_worker_a_startup_recovery_fails_closed_when_recovered_state_cannot_commit(
        tmp_path):
    state = tmp_path / 'jobs.json'
    initial = bridge.JobStore(state_path=state)
    initial.create('interrupted', 'terminal', '/jobs/terminal')
    initial.mark_running('interrupted')

    class RecoveryCommitFailure(bridge.JobStore):
        def _persist_locked(self):
            return False

    with pytest.raises(bridge.JobStateUnavailable):
        RecoveryCommitFailure(state_path=state)


def test_worker_a_terminal_settlement_journal_replays_exact_result_after_state_failure(
        tmp_path, monkeypatch):
    state = tmp_path / 'jobs.json'
    store = bridge.JobStore(state_path=state)
    store.create('job', 'terminal', '/jobs/terminal')
    store.mark_running('job')
    result = _worker_a_result(
        'timed_out', False, exit_code=124, returncode=None,
        stdout='synthetic partial output', process_pid=123,
        process_parent_pid=45, process_tree_terminated=True)
    monkeypatch.setattr(store, '_persist_locked', lambda: False)

    assert store.complete('job', 'timed_out', result) is False
    pending = store.get('job')
    assert pending['status'] == 'timed_out'
    assert pending['result'] == result
    assert store.snapshot()['pending_settlements'] == 1

    recovered = bridge.JobStore(state_path=state)
    replayed = recovered.get('job')
    assert replayed['status'] == 'timed_out'
    assert replayed['result'] == result
    assert recovered.snapshot()['pending_settlements'] == 0


def test_worker_a_process_metadata_commits_before_command_spec_is_released(monkeypatch):
    import io

    created = []

    class InputPipe:
        def __init__(self):
            self.writes = []

        def write(self, value):
            self.writes.append(bytes(value))

        def close(self):
            pass

    class Process:
        def __init__(self):
            self.pid = 4242
            self._handle = 99
            self.stdin = InputPipe()
            self.stdout = io.BytesIO(b'')
            self.stderr = io.BytesIO(b'')
            self.returncode = None

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = 1

        def wait(self, timeout=None):
            if self.returncode is None:
                raise bridge.subprocess.TimeoutExpired('bootstrap', timeout)
            return self.returncode

    class Job:
        def __init__(self):
            self.terminated = False
            self.closed = False
            self.process = None

        def assign(self, process):
            self.process = process

        def terminate(self, _exit_code=1):
            self.terminated = True
            self.process.kill()
            return True

        def close(self):
            self.closed = True

    def popen(*_args, **_kwargs):
        process = Process()
        created.append(process)
        return process

    monkeypatch.setattr(bridge.subprocess, 'Popen', popen)
    monkeypatch.setattr(bridge, 'WindowsJobObject', Job)

    def reject_metadata(*_args):
        raise bridge.JobStateUnavailable('synthetic process metadata failure')

    with pytest.raises(bridge.ExecutionFailure) as raised:
        bridge.run_subprocess_bounded(
            ['never-start'], execution_observer=reject_metadata, timeout=1)
    assert created[0].stdin.writes == []
    evidence = raised.value.result
    assert evidence['process_pid'] == 4242
    assert evidence['process_tree_cleanup_enforced'] is True
    assert evidence['cleanup_certified'] is True


def test_worker_a_job_id_collision_exhaustion_preserves_preexisting_record(
        monkeypatch):
    fixed_prefix = '20300102-030405-'
    original_strftime = bridge.time.strftime

    def fixed_strftime(fmt, *args):
        if fmt == '%Y%m%d-%H%M%S-':
            return fixed_prefix
        return original_strftime(fmt, *args)

    class FixedUuid:
        hex = 'deadbeef' + ('0' * 24)

    monkeypatch.setattr(bridge.time, 'strftime', fixed_strftime)
    monkeypatch.setattr(bridge.uuid, 'uuid4', lambda: FixedUuid())
    jobs = bridge.JobStore()
    collision = fixed_prefix + 'deadbeef'
    jobs.create(collision, 'terminal', '/jobs/terminal')
    runtime = bridge.BridgeRuntime(jobs=jobs)

    status, body, _ = runtime.start_async(
        'terminal', {'command': 'Write-Output never'}, '/jobs/terminal')
    assert status == 503
    assert body['error_code'] == 'job_state_unavailable'
    assert body['execution_started'] is False
    assert jobs.get(collision)['status'] == 'reserved'
    assert runtime.snapshot()['admission']['active_global'] == 0
    assert runtime.snapshot()['counters']['submitted'] == 0


def test_worker_a_terminal_status_mapper_is_identical_for_sync_async_and_lifecycle():
    lifecycle = []

    def internal(*_args, **_kwargs):
        return _worker_a_result('internal_error', True)

    sync = bridge.BridgeRuntime(executor=internal)
    sync.set_lifecycle_sink(lifecycle.append)
    status, result, _ = sync.run_sync(
        'terminal', {'command': 'Write-Output safe'}, '/run/terminal')
    assert status == 500
    assert result['terminal_reason'] == 'failed'
    assert result['error_code'] == 'execution_failed'
    assert sync.snapshot()['counters']['failed'] == 1
    assert lifecycle[0]['terminal_reason'] == 'failed'

    async_runtime = bridge.BridgeRuntime(
        executor=lambda *_args, **_kwargs: _worker_a_result('unknown_reason', True))
    code, submitted, _ = async_runtime.start_async(
        'terminal', {'command': 'Write-Output safe'}, '/jobs/terminal')
    assert code == 202
    deadline = time.time() + 5
    while time.time() < deadline:
        job = async_runtime.get_job(submitted['job_id'])
        if job and job.get('status') in bridge.JobStore.TERMINAL_STATUSES:
            break
        time.sleep(0.01)
    assert job['status'] == 'failed'
    assert job['result']['terminal_reason'] == 'failed'
    assert async_runtime.snapshot()['counters']['failed'] == 1


def test_worker_a_uncertified_cleanup_blocks_readiness_and_future_admission():
    calls = []

    def unresolved(*_args, **_kwargs):
        calls.append('ran')
        return _worker_a_result(
            'failed', False, process_pid=999, process_parent_pid=1,
            process_tree_cleanup_enforced=False, cleanup_certified=False)

    runtime = bridge.BridgeRuntime(executor=unresolved)
    status, result, _ = runtime.run_sync(
        'terminal', {'command': 'Write-Output safe'}, '/run/terminal')
    assert status == 500
    assert result['error_code'] == 'cleanup_unresolved'
    ready_status, ready = runtime.readiness()
    assert ready_status == 503 and ready['reason'] == 'cleanup_unresolved'

    rejected, body, _ = runtime.run_sync(
        'terminal', {'command': 'Write-Output never'}, '/run/terminal')
    assert rejected == 503
    assert body['reason'] == 'cleanup_unresolved'
    assert body['execution_started'] is False
    assert calls == ['ran']


def test_worker_a_ready_includes_release_attestation_hashes():
    runtime = bridge.BridgeRuntime()
    runtime.set_release_attestation({
        'release_manifest_sha256': 'a' * 64,
        'release_tree_sha256': 'b' * 64,
    })
    status, body = runtime.readiness()
    assert status == 200
    assert body['source_sha256'] == bridge.SOURCE_SHA256
    assert body['release_manifest_sha256'] == 'a' * 64
    assert body['release_tree_sha256'] == 'b' * 64









def test_worker_a_all_process_cleanup_fallback_failures_return_bounded_evidence(
        monkeypatch):
    import io

    class Input:
        def write(self, _value):
            return None

        def close(self):
            return None

    class Unreapable:
        pid = 5151
        _handle = 88
        stdin = Input()
        stdout = io.BytesIO(b'')
        stderr = io.BytesIO(b'')
        returncode = None

        def poll(self):
            return None

        def wait(self, timeout=None):
            raise bridge.subprocess.TimeoutExpired('bootstrap', timeout)

        def kill(self):
            raise OSError('synthetic refusal')

    class RefusingJob:
        def assign(self, _process):
            return None

        def terminate(self, _exit_code=1):
            return False

        def close(self):
            return None

    monkeypatch.setattr(bridge.subprocess, 'Popen', lambda *_a, **_k: Unreapable())
    monkeypatch.setattr(bridge, 'WindowsJobObject', RefusingJob)
    monkeypatch.setattr(bridge, '_fallback_terminate_process_tree',
                        lambda *_args: False)
    started = time.monotonic()
    result = bridge.run_subprocess_bounded(['never'], timeout=0)
    elapsed = time.monotonic() - started
    assert elapsed < 2
    assert result['ok'] is False
    assert result['error_code'] == 'cleanup_unresolved'
    assert result['cleanup_certified'] is False
    assert result['root_process_reaped'] is False
    assert result['process_pid'] == 5151

def test_default_hermes_executor_uses_the_installed_repo_launcher(monkeypatch):
    captured = {}
    sentinel = {"ok": True}

    def fake_run(argv, **kwargs):
        captured["argv"] = list(argv)
        captured["kwargs"] = dict(kwargs)
        return sentinel

    monkeypatch.setattr(bridge, "run_subprocess_bounded", fake_run)
    result = bridge.BridgeRuntime._default_execute(
        "hermes", {"prompt": "synthetic prompt", "timeout": 9}
    )

    expected = bridge.pathlib.Path(
        bridge.os.environ.get(
            "HERMES_EXECUTABLE", bridge.shutil.which("hermes") or "hermes"
        )
    )
    assert bridge.HERMES_EXE == expected
    assert captured["argv"] == [
        str(expected), "chat", "-Q", "-q", "synthetic prompt",
        "--toolsets", bridge.DEFAULT_HERMES_TOOLSETS
    ]
    assert captured["kwargs"]["timeout"] == 9
    assert result is sentinel






def _protect_temp_job_state_paths(tmp_path, state, journal):
    lifecycle = SOURCE.parent / "bridge-private-state.ps1"
    setup = tmp_path / "protect-job-state.ps1"
    setup.write_text(
        "param([string]$Lifecycle,[string]$Directory,[string]$State,[string]$Journal)\n"
        ". $Lifecycle\n"
        "Protect-PrivateDirectory -Path $Directory\n"
        "Protect-PrivateFile -Path $State -RequireExisting\n"
        "Protect-PrivateFile -Path $Journal -RequireExisting\n",
        encoding="utf-8",
    )
    powershell = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    result = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
         "Bypass", "-File", str(setup), "-Lifecycle", str(lifecycle),
         "-Directory", str(state.parent), "-State", str(state),
         "-Journal", str(journal)],
        check=False, capture_output=True, text=True, timeout=30,
        env=bridge._windows_powershell_environment(),
    )
    if result.returncode != 0:
        pytest.fail(
            "private-path setup failed\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    expected = hashlib.sha256(lifecycle.read_bytes()).hexdigest()
    return bridge.make_private_path_attestor(lifecycle, expected)


@pytest.mark.skipif(os.name != "nt", reason="requires Windows DACL APIs")
def test_private_state_initializer_creates_exact_runtime_file_set(tmp_path):
    helper = SOURCE.parent / "bridge-private-state.ps1"
    setup = tmp_path / "initialize-private-state.ps1"
    setup.write_text(
        "param([string]$Helper,[string]$StateRoot)\n"
        ". $Helper\n"
        "$state = Initialize-BridgePrivateState -StateRoot $StateRoot\n"
        "$paths = @($state.JobState,$state.SettlementJournal,$state.PressureState,"
        "$state.BridgeLog,$state.MetricsLog)\n"
        "$acl = Test-PrivateAclSet -Paths $paths\n"
        "[pscustomobject]@{ok=[bool]$acl.Ok;paths=[string[]]$paths} | "
        "ConvertTo-Json -Compress\n",
        encoding="utf-8",
    )
    powershell = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    state_root = tmp_path / "state"
    result = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
         "Bypass", "-File", str(setup), "-Helper", str(helper),
         "-StateRoot", str(state_root)],
        check=False, capture_output=True, text=True, timeout=30,
        env=bridge._windows_powershell_environment(),
    )
    if result.returncode != 0:
        pytest.fail(
            "private-state initialization failed\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    payload = json.loads(lines[-1])
    paths = [pathlib.Path(path) for path in payload["paths"]]
    assert payload["ok"] is True
    assert len(paths) == 5
    assert all(path.is_file() and path.stat().st_size == 0 for path in paths)
    assert bridge.make_windows_private_path_attestor()(paths) is True


@pytest.mark.skipif(os.name != "nt", reason="requires Windows DACL APIs")
def test_job_store_preserves_real_private_dacl_across_atomic_replacements(tmp_path):
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    state = private_dir / "jobs.json"
    journal = private_dir / "jobs.json.settlements.json"
    state.touch()
    journal.touch()
    powershell_attest = _protect_temp_job_state_paths(tmp_path, state, journal)
    native_attest = bridge.make_windows_private_path_attestor()
    assert powershell_attest([state, journal]) is True
    assert native_attest([state, journal]) is True

    store = bridge.JobStore(state_path=state, private_path_attestor=native_attest)
    store.create("job", "terminal", "/jobs/terminal")
    store.mark_running("job")
    assert store.complete("job", "succeeded", _worker_a_result()) is True

    assert native_attest([state, journal]) is True
    assert powershell_attest([state, journal]) is True
    inherited = tmp_path / "ordinary-inherited.json"
    inherited.write_text("{}", encoding="utf-8")
    assert native_attest([inherited]) is False
    assert powershell_attest([inherited]) is False


@pytest.mark.skipif(os.name != "nt", reason="requires Windows DACL APIs")
def test_resource_pressure_replacement_preserves_exact_private_dacl(tmp_path):
    private_dir = tmp_path / "private" / "jobs"
    private_dir.mkdir(parents=True)
    pressure_state = private_dir / "resource-pressure.json"
    companion = private_dir / "companion.json"
    pressure_state.touch()
    companion.touch()
    powershell_attest = _protect_temp_job_state_paths(
        tmp_path, pressure_state, companion,
    )
    native_attest = bridge.make_windows_private_path_attestor()
    assert powershell_attest([pressure_state]) is True
    assert native_attest([pressure_state]) is True

    clock = [100.0]
    guard = bridge.ResourcePressureGuard(
        100, 0.8, hold_seconds=300, clock=lambda: clock[0],
        state_path=pressure_state, private_path_attestor=native_attest,
    )
    guard.commit("available_memory_below_floor")
    clock[0] = 400.0
    assert guard.commit("commit_above_ceiling") is not None

    assert powershell_attest([pressure_state]) is True
    assert native_attest([pressure_state]) is True
    assert list(private_dir.glob(pressure_state.name + ".tmp-*")) == []


def test_job_store_startup_fails_closed_when_private_dacl_attestation_fails(tmp_path):
    state = tmp_path / "jobs.json"
    state.touch()
    with pytest.raises(bridge.JobStateUnavailable):
        bridge.JobStore(
            state_path=state,
            private_path_attestor=lambda _paths: False,
        )




@pytest.mark.skipif(os.name != "nt", reason="requires Windows runtime APIs")
def test_replace_file_preserving_dacl_retries_precommit_error_1175(
        tmp_path, monkeypatch):
    target = tmp_path / "state.json"
    replacement = tmp_path / "state.json.tmp"
    target.write_text("prior", encoding="utf-8")
    replacement.write_text("current", encoding="utf-8")
    calls = []

    class RetryableReplaceError(OSError):
        winerror = 1175

    def replace_once(source, destination):
        calls.append(len(calls) + 1)
        if len(calls) < 3:
            raise RetryableReplaceError("synthetic pre-commit failure")
        os.replace(source, destination)

    monkeypatch.setattr(bridge, "_replace_file_windows_once", replace_once)
    bridge.replace_file_preserving_dacl(replacement, target)

    assert calls == [1, 2, 3]
    assert target.read_text(encoding="utf-8") == "current"
    assert not replacement.exists()


def test_hermes_toolsets_contract_is_shared_by_sync_async_and_argv_safe(monkeypatch):
    calls = []

    def fake_subprocess(argv, **kwargs):
        calls.append((list(argv), dict(kwargs)))
        return _worker_a_result(
            stdout="synthetic output",
            stdout_retained_bytes=16,
            stdout_emitted_bytes=16,
        )

    monkeypatch.setattr(bridge, "run_subprocess_bounded", fake_subprocess)
    runtime = bridge.BridgeRuntime(executor=bridge.BridgeRuntime._default_execute)
    prompt = "summarize literal \"--help\" and \"-m injected/model\" as prompt text"
    payload = {
        "prompt": prompt,
        "toolsets": "terminal,file",
        "timeout": 9,
    }

    status, result, _headers = runtime.run_sync("hermes", payload, "/run/hermes")
    assert status == 200
    assert result["ok"] is True

    status, accepted, _headers = runtime.start_async(
        "hermes", dict(payload), "/jobs/hermes"
    )
    assert status == 202
    deadline = time.time() + 5
    while time.time() < deadline:
        job = runtime.get_job(accepted["job_id"])
        if job["status"] in runtime.jobs.TERMINAL_STATUSES:
            break
        time.sleep(0.01)
    assert job["status"] == "succeeded"

    assert len(calls) == 2
    assert calls[0][0] == calls[1][0]
    for argv, kwargs in calls:
        assert isinstance(argv, list)
        assert argv == [
            str(bridge.HERMES_EXE),
            "chat",
            "-Q",
            "-q",
            prompt,
            "--toolsets",
            "terminal,file",
        ]
        assert argv.count("-Q") == 1
        assert argv.count("-q") == 1
        assert argv[argv.index("-q") + 1] == prompt
        assert "-m" not in argv
        assert "--model" not in argv
        assert "--provider" not in argv
        assert argv.count("--toolsets") == 1
        toolsets_index = argv.index("--toolsets")
        assert argv[toolsets_index + 1] == "terminal,file"
        assert kwargs["timeout"] == 9

    call_count = len(calls)
    rejected_payloads = (
        {"prompt": "x", "toolsets": "terminal,file;Write-Output injected"},
        {"prompt": "x", "toolsets": "terminal,file", "unknown": "field"},
    )
    for rejected in rejected_payloads:
        sync_status, sync_body, _headers = runtime.run_sync(
            "hermes", rejected, "/run/hermes"
        )
        async_status, async_body, _headers = runtime.start_async(
            "hermes", rejected, "/jobs/hermes"
        )
        assert sync_status == 400
        assert async_status == 400
        assert sync_body["error_code"] == "invalid_request"
        assert async_body["error_code"] == "invalid_request"
    assert len(calls) == call_count


def test_hermes_sync_and_async_inherit_configured_primary_route(monkeypatch):
    calls = []

    def fake_subprocess(argv, **_kwargs):
        calls.append(list(argv))
        return _worker_a_result()

    monkeypatch.setattr(bridge, "run_subprocess_bounded", fake_subprocess)
    runtime = bridge.BridgeRuntime(executor=bridge.BridgeRuntime._default_execute)
    prompt = "treat literal \"-m injected/model\" and \"--provider other\" as prompt text"
    payload = {"prompt": prompt, "toolsets": "terminal,file", "timeout": 9}

    sync_status, sync_result, _headers = runtime.run_sync(
        "hermes", dict(payload), "/run/hermes"
    )
    assert sync_status == 200
    assert sync_result["ok"] is True

    async_status, accepted, _headers = runtime.start_async(
        "hermes", dict(payload), "/jobs/hermes"
    )
    assert async_status == 202
    deadline = time.time() + 5
    while time.time() < deadline:
        job = runtime.get_job(accepted["job_id"])
        if job["status"] in runtime.jobs.TERMINAL_STATUSES:
            break
        time.sleep(0.01)
    assert job["status"] == "succeeded"

    expected = [
        str(bridge.HERMES_EXE),
        "chat",
        "-Q",
        "-q",
        prompt,
        "--toolsets",
        "terminal,file",
    ]
    assert len(calls) == 2
    prohibited = [
        argv for argv in calls
        if "-m" in argv or "--model" in argv or "--provider" in argv
    ]
    assert prohibited == [], json.dumps(
        {"sync_argv": calls[0], "async_argv": calls[1]},
        sort_keys=True,
    )
    assert calls == [expected, expected]
    assert all(isinstance(argv, list) for argv in calls)


@pytest.mark.skipif(
    not pathlib.Path(str(bridge.HERMES_EXE) + ".exe").is_file(),
    reason="requires an installed Windows Hermes CLI",
)
def test_hermes_sync_and_async_argv_pass_installed_parser_without_provider(
        monkeypatch, tmp_path):
    calls = []

    def fake_subprocess(argv, **_kwargs):
        assert isinstance(argv, list)
        calls.append(list(argv))
        return _worker_a_result()

    monkeypatch.setattr(bridge, "run_subprocess_bounded", fake_subprocess)
    runtime = bridge.BridgeRuntime(executor=bridge.BridgeRuntime._default_execute)
    prompt = "explain literal \"--help\" and \"-m injected/model\" as plain text"
    payload = {"prompt": prompt, "toolsets": "terminal,file", "timeout": 9}

    sync_status, sync_result, _headers = runtime.run_sync(
        "hermes", dict(payload), "/run/hermes"
    )
    assert sync_status == 200
    assert sync_result["ok"] is True

    async_status, accepted, _headers = runtime.start_async(
        "hermes", dict(payload), "/jobs/hermes"
    )
    assert async_status == 202
    deadline = time.time() + 5
    while time.time() < deadline:
        job = runtime.get_job(accepted["job_id"])
        if job["status"] in runtime.jobs.TERMINAL_STATUSES:
            break
        time.sleep(0.01)
    assert job["status"] == "succeeded"

    assert len(calls) == 2
    assert calls[0] == calls[1]
    installed = pathlib.Path(str(bridge.HERMES_EXE) + ".exe")
    assert installed.is_file()
    parser_env = os.environ.copy()
    parser_env["HERMES_HOME"] = str(tmp_path / "parser-only-hermes-home")
    for argv in calls:
        parser_argv = [str(installed), *argv[1:], "--help"]
        probe = subprocess.run(
            parser_argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env=parser_env,
        )
        if probe.returncode != 0:
            assert probe.returncode == 2
            assert (
                "hermes chat: error: argument -q/--query: expected one argument"
                in probe.stderr
            )
        assert probe.returncode == 0, json.dumps(
            {
                "command": subprocess.list2cmdline(parser_argv),
                "returncode": probe.returncode,
                "stdout": probe.stdout,
                "stderr": probe.stderr,
            },
            sort_keys=True,
        )


def test_authenticated_status_snapshot_and_jobstore_failures_are_stable_and_sanitized(
        tmp_path, monkeypatch):
    import http.client

    leak_markers = (
        r"C:\synthetic-private\jobs.json",
        "synthetic-token-value",
        "synthetic prompt input",
        "synthetic tool input",
        "synthetic raw state",
    )
    leak_text = " | ".join(leak_markers)

    runtime_failure = bridge.BridgeRuntime()

    def raise_snapshot_failure():
        raise RuntimeError(leak_text)

    runtime_failure.snapshot = raise_snapshot_failure

    class CleanupFailureStore(bridge.JobStore):
        def cleanup(self):
            raise bridge.JobStateUnavailable(leak_text)

    cleanup_failure = bridge.BridgeRuntime(jobs=CleanupFailureStore())

    now = [100.0]
    state_path = tmp_path / "jobs.json"
    state_path.touch()
    state_path.with_name(state_path.name + ".settlements.json").touch()
    persistence_store = bridge.JobStore(
        state_path=state_path,
        clock=lambda: now[0],
        ttl_seconds=1,
        private_path_attestor=lambda _paths: True,
    )
    with persistence_store.lock:
        persistence_store.jobs["expired"] = {
            "id": "expired",
            "kind": "terminal",
            "route": "/jobs/terminal",
            "status": "succeeded",
            "completed_at": 0.0,
            "result_bytes": 0,
        }

    def raise_persistence_failure():
        raise OSError(leak_text)

    persistence_store._persist_locked = raise_persistence_failure
    persistence_failure = bridge.BridgeRuntime(jobs=persistence_store)

    monkeypatch.setattr(
        bridge,
        "collect_windows_metrics",
        lambda: {
            "available_physical_bytes": 8 * 1024**3,
            "commit_fraction": 0.25,
        },
    )

    class SyntheticTelemetry:
        @staticmethod
        def snapshot():
            return {"samples": 1}

    expected = {
        "ok": False,
        "error_code": "status_unavailable",
        "error": "bridge status unavailable",
    }
    token = "synthetic-status-token"
    for runtime in (runtime_failure, cleanup_failure, persistence_failure):
        server = bridge.BridgeHTTPServer(
            ("127.0.0.1", 0), bridge.Handler, token, runtime, quiet=True
        )
        server.telemetry = SyntheticTelemetry()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection(*server.server_address, timeout=5)
            connection.request(
                "GET", "/status", headers={"Authorization": f"Bearer {token}"}
            )
            response = connection.getresponse()
            raw = response.read()
            connection.close()
            assert response.status == 503
            assert len(raw) <= 128
            assert json.loads(raw) == expected
            decoded = raw.decode("utf-8")
            assert all(marker not in decoded for marker in leak_markers)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
