import argparse
import base64
import contextlib
import copy
import hashlib
import inspect
import ipaddress
import json
import math
import os
import pathlib
import re
import shutil
import socket
import ssl
import stat
import subprocess  # nosec B404
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

# subprocess is the authenticated bridge feature; all launches use fixed argv and shell=False.
# Non-loopback listeners require pinned TLS; every operational route also requires a bearer token.
BRIDGE_VERSION = '1.0.0'
HOST = os.environ.get('HERMES_WINDOWS_BRIDGE_HOST', '127.0.0.1')
PORT = int(os.environ.get('HERMES_WINDOWS_BRIDGE_PORT', '8765'))
STATE_ROOT = pathlib.Path(os.environ.get(
    'HERMES_WINDOWS_BRIDGE_STATE_DIR',
    pathlib.Path.home() / '.local' / 'state' / 'hermes-windows-bridge'))
PRIVATE_STATE_ROOT = STATE_ROOT / 'private'
TOKEN_FILE = pathlib.Path(os.environ.get(
    'HERMES_WINDOWS_BRIDGE_TOKEN_FILE',
    PRIVATE_STATE_ROOT / 'bridge-token'))
LOG_FILE = pathlib.Path(os.environ.get(
    'HERMES_WINDOWS_BRIDGE_LOG',
    PRIVATE_STATE_ROOT / 'logs' / 'bridge.log'))
HERMES_HOME = pathlib.Path(os.environ.get(
    'HERMES_HOME', pathlib.Path.home() / '.hermes'))
REPO = pathlib.Path(os.environ.get(
    'HERMES_REPO', HERMES_HOME / 'hermes-agent'))
SITE = REPO / 'venv' / 'Lib' / 'site-packages'
PY = pathlib.Path(os.environ.get('HERMES_UV_PYTHON', sys.executable))
HERMES_EXE = pathlib.Path(os.environ.get(
    'HERMES_EXECUTABLE', shutil.which('hermes') or 'hermes'))
SOURCE_SHA256 = hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
DEFAULT_HERMES_TOOLSETS = 'computer_use,terminal,file,browser'
HERMES_TOOLSET_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')
FORBIDDEN_GUI_PATTERNS = (
    'sendkeys',
    'wscript.shell',
    'appactivate',
    'system.windows.forms.sendkeys',
    'set-clipboard',
    'get-clipboard',
)

JOBS = {}
JOBS_LOCK = threading.Lock()


class JobStateUnavailable(RuntimeError):
    """A required durable job-state transition could not be committed."""


class DuplicateJobId(JobStateUnavailable):
    """The requested job identifier is already durably owned."""


class ExecutionFailure(RuntimeError):
    """Sanitized execution failure carrying privacy-safe lifecycle evidence."""

    def __init__(self, result):
        super().__init__('execution failed')
        self.result = copy.deepcopy(result)


class TelemetryPersistenceError(RuntimeError):
    """A resource sample or its private-path attestation did not commit."""


class ReleaseValidationError(ValueError):
    """The reviewed release manifest or payload closure is invalid."""


def normalize_hermes_toolsets(value):
    """Return the bounded comma-list accepted by both Hermes request routes."""
    if value is None:
        return DEFAULT_HERMES_TOOLSETS
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError('toolsets must be a bounded comma-separated string')
    names = value.split(',')
    if (len(names) > 16 or len(set(names)) != len(names) or
            any(HERMES_TOOLSET_NAME_RE.fullmatch(name) is None for name in names)):
        raise ValueError('toolsets contains an invalid toolset name')
    return value


def blind_gui_automation_error(command):
    lowered = command.casefold()
    hits = [pattern for pattern in FORBIDDEN_GUI_PATTERNS if pattern in lowered]
    if not hits:
        return None
    return {
        'ok': False,
        'error_code': 'blind_gui_automation_blocked',
        'error': ('blocked blind GUI automation on Windows bridge; '
                  'use computer_use or element-aware GUI control instead'),
        'blocked_patterns': hits,
        'execution_started': False,
    }


class Reservation:
    def __init__(self, controller, kind, route):
        self.controller, self.kind, self.route = controller, kind, route
        self.released = False
        self.lock = threading.Lock()

    def release(self):
        with self.lock:
            if self.released:
                return False
            self.released = True
        self.controller._release(self.kind, self.route)
        return True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.release()


class AdmissionController:
    def __init__(self, global_limit=2, class_limits=None, resource_guard=None,
                 wall_clock=time.time, health_providers=None):
        self.global_limit = int(global_limit)
        self.class_limits = dict(class_limits or {'hermes': 1, 'terminal': 2})
        self.resource_guard = resource_guard
        self.wall_clock = wall_clock
        self.lock = threading.RLock()
        self.active_global = 0
        self.active_by_class = {kind: 0 for kind in self.class_limits}
        self.active_by_route = {}
        self.rejections = {
            'capacity_exhausted': 0,
            'resource_pressure': 0,
            'quiesced': 0,
            'job_state_unavailable': 0,
        }
        self._quiesced = False
        self._generation = 0
        self._zero_active_since_epoch = None
        self._health_providers = dict(health_providers or {})
        if self.resource_guard is not None:
            self.resource_guard.bind_decision_lock(self.lock)

    @staticmethod
    def _pre_execution_error(error_code, error, **fields):
        return {'ok': False, 'error_code': error_code, 'error': error,
                'execution_started': False, **fields}

    def set_health_provider(self, name, provider):
        with self.lock:
            if provider is None:
                self._health_providers.pop(str(name), None)
            else:
                self._health_providers[str(name)] = provider

    def _record_rejection_locked(self, error):
        code = error.get('error_code', 'resource_pressure')
        self.rejections[code] = self.rejections.get(code, 0) + 1
        error.setdefault('execution_started', False)
        error.setdefault('ok', False)
        return error

    def _health_error_locked(self):
        if self.resource_guard is not None:
            pressure = self.resource_guard.current_block()
            if pressure:
                return self._pre_execution_error(**pressure)
        for name in sorted(self._health_providers):
            try:
                unhealthy = self._health_providers[name]()
            except Exception:  # noqa: BLE001 - admission fails closed on provider faults
                unhealthy = {
                    'error_code': 'resource_pressure',
                    'error': 'Windows bridge health is unavailable',
                    'reason': 'health_provider_unavailable',
                    'retry_after_seconds': 60,
                }
            if unhealthy:
                value = dict(unhealthy)
                value.setdefault('error_code', 'resource_pressure')
                value.setdefault('error', 'Windows bridge is not ready for execution')
                value.setdefault('retry_after_seconds', 60)
                return self._pre_execution_error(**value)
        return None

    def health_error(self):
        with self.lock:
            return self._health_error_locked()

    def try_reserve(self, kind, route):
        if kind not in self.class_limits:
            return None, self._pre_execution_error(
                'invalid_class', 'invalid execution class')
        with self.lock:
            if self._quiesced:
                return None, self._record_rejection_locked(
                    self._pre_execution_error(
                        'quiesced', 'Windows bridge admission is quiesced',
                        generation=self._generation, retry_after_seconds=5))
            health_error = self._health_error_locked()
            if health_error:
                return None, self._record_rejection_locked(health_error)
            class_active = self.active_by_class[kind]
            if (self.active_global >= self.global_limit or
                    class_active >= self.class_limits[kind]):
                return None, self._record_rejection_locked(
                    self._pre_execution_error(
                        'capacity_exhausted',
                        'Windows bridge subprocess capacity is exhausted',
                        job_class=kind, global_limit=self.global_limit,
                        global_current=self.active_global,
                        class_limit=self.class_limits[kind],
                        class_current=class_active, retry_after_seconds=5))
            self.active_global += 1
            self.active_by_class[kind] += 1
            self.active_by_route[route] = self.active_by_route.get(route, 0) + 1
            self._zero_active_since_epoch = None
            return Reservation(self, kind, route), None

    def _release(self, kind, route):
        with self.lock:
            self.active_global = max(0, self.active_global - 1)
            self.active_by_class[kind] = max(0, self.active_by_class.get(kind, 0) - 1)
            left = max(0, self.active_by_route.get(route, 0) - 1)
            if left:
                self.active_by_route[route] = left
            else:
                self.active_by_route.pop(route, None)
            if (self._quiesced and self.active_global == 0 and
                    self._zero_active_since_epoch is None):
                self._zero_active_since_epoch = float(self.wall_clock())

    def _quiesce_snapshot_locked(self):
        return {
            'ok': True,
            'generation': self._generation,
            'quiesced': self._quiesced,
            'active_global': self.active_global,
            'zero_active_since_epoch': self._zero_active_since_epoch,
        }

    def quiesce(self, action, generation=None):
        with self.lock:
            if action == 'begin':
                if not self._quiesced:
                    self._generation += 1
                    self._quiesced = True
                    self._zero_active_since_epoch = (
                        float(self.wall_clock()) if self.active_global == 0 else None)
                return 200, self._quiesce_snapshot_locked()
            if action not in {'status', 'resume'}:
                return 400, {'ok': False, 'error_code': 'invalid_request',
                             'error': 'invalid quiesce action'}
            if generation != self._generation:
                body = self._quiesce_snapshot_locked()
                body.update({'ok': False, 'error_code': 'stale_generation',
                             'error': 'stale quiesce generation'})
                return 409, body
            if action == 'resume':
                self._quiesced = False
                self._zero_active_since_epoch = None
            return 200, self._quiesce_snapshot_locked()

    def snapshot(self):
        with self.lock:
            result = {
                'global_limit': self.global_limit,
                'class_limits': dict(self.class_limits),
                'active_global': self.active_global,
                'active_by_class': dict(self.active_by_class),
                'active_by_route': dict(self.active_by_route),
                'rejections': dict(self.rejections),
            }
            result.update({key: value for key, value in
                           self._quiesce_snapshot_locked().items() if key != 'ok'})
            return result


class BoundedOutputBuffer:
    def __init__(self, retain_limit, emit_limit, on_limit=None):
        self.retain_limit, self.emit_limit = max(0, int(retain_limit)), max(1, int(emit_limit))
        self.on_limit = on_limit
        self.retained, self.emitted, self.limit_exceeded = bytearray(), 0, False
        self.lock = threading.Lock()

    def feed(self, chunk):
        if not chunk:
            return
        callback = None
        with self.lock:
            self.emitted += len(chunk)
            room = max(0, self.retain_limit - len(self.retained))
            self.retained.extend(chunk[:room])
            if self.emitted > self.emit_limit and not self.limit_exceeded:
                self.limit_exceeded, callback = True, self.on_limit
        if callback:
            callback()

    def snapshot(self):
        with self.lock:
            data = bytes(self.retained)
            return {'retained': data, 'retained_bytes': len(data),
                    'emitted_bytes': self.emitted, 'truncated': self.emitted > len(data),
                    'limit_exceeded': self.limit_exceeded}


_RESOURCE_PRESSURE_REASONS = frozenset({
    'available_memory_below_floor',
    'commit_above_ceiling',
    'telemetry_acl_unverified',
    'telemetry_unavailable',
    'telemetry_unpersisted',
})
_RESOURCE_PRESSURE_STABLE_ERROR = 'resource pressure state unavailable'


class ResourcePressureStateError(RuntimeError):
    pass


def _resource_pressure_path_is_safe(path):
    path = pathlib.Path(path)
    reparse_flag = getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
    try:
        if not path.is_absolute() or not path.name:
            return False
        if os.name == 'nt' and ':' in path.name:
            return False
        parent_stat = path.parent.lstat()
        state_stat = path.lstat()
    except (OSError, ValueError):
        return False
    parent_attributes = getattr(parent_stat, 'st_file_attributes', 0)
    state_attributes = getattr(state_stat, 'st_file_attributes', 0)
    if stat.S_ISLNK(parent_stat.st_mode) or parent_attributes & reparse_flag:
        return False
    if not stat.S_ISDIR(parent_stat.st_mode):
        return False
    if stat.S_ISLNK(state_stat.st_mode) or state_attributes & reparse_flag:
        return False
    if not stat.S_ISREG(state_stat.st_mode):
        return False
    return getattr(state_stat, 'st_nlink', 1) == 1


def _resource_pressure_json_object(pairs):
    result = {}
    folded = set()
    for key, value in pairs:
        normalized = key.casefold()
        if normalized in folded:
            raise ResourcePressureStateError(_RESOURCE_PRESSURE_STABLE_ERROR)
        folded.add(normalized)
        result[key] = value
    return result


def _reject_resource_pressure_json_constant(_value):
    raise ResourcePressureStateError(_RESOURCE_PRESSURE_STABLE_ERROR)


class ResourcePressureGuard:
    SCHEMA_VERSION = 1
    MAX_STATE_BYTES = 1024
    MAX_CLOCK_SECONDS = 1_000_000_000_000.0
    _STATE_KEYS = frozenset({
        'schema_version', 'active', 'reason', 'since', 'updated_at',
    })

    def __init__(self, min_available_bytes, max_commit_fraction,
                 hold_seconds=300, clock=time.monotonic, state_path=None,
                 private_path_attestor=None):
        self.min_available_bytes = int(min_available_bytes)
        self.max_commit_fraction = float(max_commit_fraction)
        self.hold_seconds = float(hold_seconds)
        self.clock = clock
        self.state_path = pathlib.Path(state_path) if state_path is not None else None
        self.private_path_attestor = private_path_attestor
        self.lock = threading.RLock()
        self.reason = None
        self.since = None
        self.active = False
        self.updated_at = None
        self.persistence_ok = True
        self._failure_reason = None
        if self.state_path is not None:
            self._load_state()

    @classmethod
    def _clock_value(cls, value):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ResourcePressureStateError(_RESOURCE_PRESSURE_STABLE_ERROR)
        result = float(value)
        if not math.isfinite(result) or not 0.0 <= result <= cls.MAX_CLOCK_SECONDS:
            raise ResourcePressureStateError(_RESOURCE_PRESSURE_STABLE_ERROR)
        return result

    @classmethod
    def _validate_record(cls, record):
        if not isinstance(record, dict) or set(record) != cls._STATE_KEYS:
            raise ResourcePressureStateError(_RESOURCE_PRESSURE_STABLE_ERROR)
        if (type(record['schema_version']) is not int
                or record['schema_version'] != cls.SCHEMA_VERSION):
            raise ResourcePressureStateError(_RESOURCE_PRESSURE_STABLE_ERROR)
        if type(record['active']) is not bool:
            raise ResourcePressureStateError(_RESOURCE_PRESSURE_STABLE_ERROR)
        reason = record['reason']
        if reason is not None and reason not in _RESOURCE_PRESSURE_REASONS:
            raise ResourcePressureStateError(_RESOURCE_PRESSURE_STABLE_ERROR)
        updated_at = cls._clock_value(record['updated_at'])
        since = record['since']
        if reason is None:
            if since is not None or record['active']:
                raise ResourcePressureStateError(_RESOURCE_PRESSURE_STABLE_ERROR)
        else:
            since = cls._clock_value(since)
            if updated_at < since:
                raise ResourcePressureStateError(_RESOURCE_PRESSURE_STABLE_ERROR)
        return {
            'schema_version': cls.SCHEMA_VERSION,
            'active': record['active'],
            'reason': reason,
            'since': since,
            'updated_at': updated_at,
        }

    @classmethod
    def _decode_record(cls, raw):
        if not raw or len(raw) > cls.MAX_STATE_BYTES:
            raise ResourcePressureStateError(_RESOURCE_PRESSURE_STABLE_ERROR)
        try:
            decoded = raw.decode('utf-8', errors='strict')
            record = json.loads(
                decoded,
                object_pairs_hook=_resource_pressure_json_object,
                parse_constant=_reject_resource_pressure_json_constant,
            )
            return cls._validate_record(record)
        except ResourcePressureStateError:
            raise
        except (UnicodeError, ValueError, TypeError, OverflowError):
            raise ResourcePressureStateError(
                _RESOURCE_PRESSURE_STABLE_ERROR) from None

    @classmethod
    def _encode_record(cls, record):
        validated = cls._validate_record(record)
        try:
            encoded = json.dumps(
                validated,
                ensure_ascii=False,
                separators=(',', ':'),
                sort_keys=True,
                allow_nan=False,
            ).encode('utf-8')
        except (TypeError, ValueError, OverflowError):
            raise ResourcePressureStateError(
                _RESOURCE_PRESSURE_STABLE_ERROR) from None
        if not encoded or len(encoded) > cls.MAX_STATE_BYTES:
            raise ResourcePressureStateError(_RESOURCE_PRESSURE_STABLE_ERROR)
        return encoded

    def _attest_state_locked(self):
        if not _resource_pressure_path_is_safe(self.state_path):
            raise ResourcePressureStateError(_RESOURCE_PRESSURE_STABLE_ERROR)
        if self.private_path_attestor is None:
            return
        try:
            result = self.private_path_attestor([self.state_path])
            ok = bool(result.get('ok')) if isinstance(result, dict) else bool(result)
        except Exception:  # noqa: BLE001 - attestation detail stays private
            ok = False
        if not ok:
            raise ResourcePressureStateError(_RESOURCE_PRESSURE_STABLE_ERROR)

    def _persist_record_locked(self, record):
        encoded = self._encode_record(record)
        self._attest_state_locked()
        descriptor = None
        temporary = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=self.state_path.name + '.tmp-',
                dir=self.state_path.parent,
            )
            temporary = pathlib.Path(temporary_name)
            with os.fdopen(descriptor, 'wb') as handle:
                descriptor = None
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            replace_file_preserving_dacl(temporary, self.state_path)
            temporary = None
            self._attest_state_locked()
        except ResourcePressureStateError:
            raise
        except Exception:  # noqa: BLE001 - persistence detail stays private
            raise ResourcePressureStateError(
                _RESOURCE_PRESSURE_STABLE_ERROR) from None
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass

    def _load_state(self):
        with self.lock:
            try:
                now = self._clock_value(self.clock())
                self._attest_state_locked()
                with self.state_path.open('rb') as handle:
                    raw = handle.read(self.MAX_STATE_BYTES + 1)
                if len(raw) > self.MAX_STATE_BYTES:
                    raise ResourcePressureStateError(
                        _RESOURCE_PRESSURE_STABLE_ERROR)
                if not raw:
                    record = self._clean_record(now)
                    self._persist_record_locked(record)
                else:
                    record = self._decode_record(raw)
                self._apply_record_locked(record)
                if (record['updated_at'] > now
                        or (record['since'] is not None
                            and record['since'] > now)):
                    self.active = True
                    self._failure_reason = 'pressure_clock_discontinuity'
            except ResourcePressureStateError:
                raise
            except Exception:  # noqa: BLE001 - persistence detail stays private
                raise ResourcePressureStateError(
                    _RESOURCE_PRESSURE_STABLE_ERROR) from None

    def bind_decision_lock(self, lock):
        if not hasattr(lock, '__enter__') or not hasattr(lock, '__exit__'):
            raise TypeError('resource pressure lock must be a context manager')
        with self.lock:
            self.lock = lock

    def evaluate(self, metrics):
        available = metrics.get('available_physical_bytes')
        commit = metrics.get('commit_fraction')
        if available is not None and available < self.min_available_bytes:
            return 'available_memory_below_floor'
        if commit is not None and commit > self.max_commit_fraction:
            return 'commit_above_ceiling'
        return None

    @classmethod
    def _clean_record(cls, observed_at):
        return {
            'schema_version': cls.SCHEMA_VERSION,
            'active': False,
            'reason': None,
            'since': None,
            'updated_at': observed_at,
        }

    def _project_record_locked(self, reason, observed_at):
        if reason is None:
            return self._clean_record(observed_at)
        if reason not in _RESOURCE_PRESSURE_REASONS:
            raise ResourcePressureStateError(_RESOURCE_PRESSURE_STABLE_ERROR)
        since = self.since if self.reason is not None else observed_at
        if since is None:
            since = observed_at
        if (self._failure_reason == 'pressure_clock_discontinuity'
                and since > observed_at):
            since = observed_at
        elapsed = observed_at - since
        active = bool(
            self.active
            or self._failure_reason is not None
            or elapsed >= self.hold_seconds
        )
        return {
            'schema_version': self.SCHEMA_VERSION,
            'active': active,
            'reason': reason,
            'since': since,
            'updated_at': observed_at,
        }

    def _apply_record_locked(self, record):
        self.active = record['active']
        self.reason = record['reason']
        self.since = record['since']
        self.updated_at = record['updated_at']

    def _status_locked(self, record=None):
        if record is None:
            active = self.active
            reason = self.reason
            since = self.since
            updated_at = self.updated_at
        else:
            active = record['active']
            reason = record['reason']
            since = record['since']
            updated_at = record['updated_at']
        if self._failure_reason is not None:
            active = True
            reason = self._failure_reason
        return {
            'active': active,
            'reason': reason,
            'since': since,
            'updated_at': updated_at,
            'persistence_ok': self.persistence_ok,
            'state_configured': self.state_path is not None,
        }

    def preview(self, reason, observed_at=None):
        with self.lock:
            try:
                now = self._clock_value(
                    self.clock() if observed_at is None else observed_at)
                record = self._project_record_locked(reason, now)
                status = self._status_locked(record)
            except ResourcePressureStateError:
                status = self._status_locked()
                status['active'] = True
                status['reason'] = 'pressure_clock_discontinuity'
            return {
                'active': status['active'],
                'reason': status['reason'],
                'since': status['since'],
            }

    def _mark_persistence_failure_locked(self, reason, observed_at):
        if self.since is None:
            self.since = observed_at
        if self.reason is None and reason in _RESOURCE_PRESSURE_REASONS:
            self.reason = reason
        self.active = True
        self.updated_at = observed_at
        self.persistence_ok = False
        self._failure_reason = 'pressure_state_unavailable'

    def commit(self, reason, observed_at=None):
        with self.lock:
            try:
                now = self._clock_value(
                    self.clock() if observed_at is None else observed_at)
                record = self._project_record_locked(reason, now)
                if self.state_path is not None:
                    self._persist_record_locked(record)
            except ResourcePressureStateError:
                try:
                    failure_time = self._clock_value(
                        self.clock() if observed_at is None else observed_at)
                except ResourcePressureStateError:
                    failure_time = self.updated_at or 0.0
                self._mark_persistence_failure_locked(reason, failure_time)
                return self._block_locked()
            self._apply_record_locked(record)
            self.persistence_ok = True
            self._failure_reason = None
            return self._block_locked()

    def observe(self, metrics):
        return self.commit(self.evaluate(metrics))

    def observe_failure(self, reason='telemetry_unavailable'):
        return self.commit(reason)

    def _block_locked(self):
        if not self.active and self._failure_reason is None:
            return None
        return {
            'error_code': 'resource_pressure',
            'error': 'Windows resource-pressure hard stop is active',
            'reason': self._failure_reason or self.reason,
            'retry_after_seconds': 60,
        }

    def current_block(self):
        with self.lock:
            return self._block_locked()

    def snapshot(self):
        with self.lock:
            return self._status_locked()


def _replace_file_windows_once(replacement, target):
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.ReplaceFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
        wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID]
    kernel32.ReplaceFileW.restype = wintypes.BOOL
    if not kernel32.ReplaceFileW(
            str(target), str(replacement), None, 0, None, None):
        raise ctypes.WinError(ctypes.get_last_error())


def replace_file_preserving_dacl(replacement, target):
    """Atomically replace target while preserving its Windows DACL."""
    if os.name != 'nt' or not target.exists():
        os.replace(replacement, target)
        return
    for attempt in range(5):
        try:
            _replace_file_windows_once(replacement, target)
            return
        except OSError as exc:
            if getattr(exc, 'winerror', None) != 1175 or attempt == 4:
                raise
            time.sleep(0.01 * (attempt + 1))


class JobStore:
    ACTIVE_STATUSES = frozenset({'reserved', 'starting', 'running'})
    TERMINAL_STATUSES = frozenset(
        {'succeeded', 'failed', 'cancelled', 'timed_out', 'output_limit'})
    MAX_STATE_BYTES = 256 * 1024**2
    MAX_JOURNAL_ENTRIES = 100

    def __init__(self, ttl_seconds=86400, max_completed=50,
                 max_completed_bytes=128 * 1024**2,
                 tombstone_ttl_seconds=7 * 86400, max_tombstones=500,
                 clock=time.time, state_path=None, private_path_attestor=None):
        self.ttl_seconds = float(ttl_seconds)
        self.max_completed = int(max_completed)
        self.max_completed_bytes = int(max_completed_bytes)
        self.tombstone_ttl_seconds = float(tombstone_ttl_seconds)
        self.max_tombstones = int(max_tombstones)
        self.clock = clock
        self.jobs = {}
        self.tombstones = {}
        self.state_path = pathlib.Path(state_path) if state_path else None
        self.private_path_attestor = private_path_attestor
        self.journal_path = (self.state_path.with_name(
            self.state_path.name + '.settlements.json') if self.state_path else None)
        self.pending_settlements = {}
        self.persistence_ok = True
        self.last_persistence_failure_at = None
        self.recovered_events = []
        self.lock = threading.RLock()
        with self.lock:
            self._load_locked()
            self._load_journal_locked()
            replayed = self._replay_settlements_locked()
            recovered = self._recover_interrupted_locked()
            cleaned = self._cleanup_locked(self.clock())
            # Opening persistent state is itself a readiness probe. Startup must
            # not continue with recovered/cleaned truth only in memory.
            if self.state_path is not None:
                if not self._persist_locked():
                    raise JobStateUnavailable(
                        'persistent job state could not be committed at startup')
                if self.pending_settlements:
                    self.pending_settlements = {}
                    if not self._write_journal_locked():
                        raise JobStateUnavailable(
                            'terminal settlement journal could not be cleared')
            _ = replayed, recovered, cleaned

    def _state_payload_locked(self):
        return {'schema_version': 1, 'updated_at': self.clock(),
                'jobs': self.jobs, 'tombstones': self.tombstones}

    @staticmethod
    def _json_bytes(payload):
        return json.dumps(payload, ensure_ascii=False, separators=(',', ':'),
                          sort_keys=True).encode('utf-8')

    def _mark_persistence_failure_locked(self):
        self.persistence_ok = False
        self.last_persistence_failure_at = time.time()

    def _attest_private_path_locked(self, path):
        if self.private_path_attestor is None:
            return True
        try:
            return path.is_file() and bool(self.private_path_attestor([path]))
        except (OSError, TypeError, ValueError, subprocess.SubprocessError):
            return False

    def _atomic_write_locked(self, path, data):
        temporary = path.with_name(path.name + '.tmp')
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if not self._attest_private_path_locked(path):
                raise OSError('private path DACL precondition failed')
            with temporary.open('wb') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            replace_file_preserving_dacl(temporary, path)
            if not self._attest_private_path_locked(path):
                raise OSError('private path DACL postcondition failed')
            return True
        except (OSError, TypeError, ValueError):
            self._mark_persistence_failure_locked()
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            return False

    def _load_locked(self):
        if (self.state_path is None or not self.state_path.exists() or
                self.state_path.stat().st_size == 0):
            return
        if self.state_path.stat().st_size > self.MAX_STATE_BYTES:
            raise ValueError('bridge job state exceeds safety limit')
        try:
            payload = json.loads(self.state_path.read_text(encoding='utf-8'))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError('invalid bridge job state') from exc
        if (not isinstance(payload, dict) or payload.get('schema_version') != 1 or
                set(payload) != {'schema_version', 'updated_at', 'jobs', 'tombstones'} or
                not isinstance(payload.get('jobs'), dict) or
                not isinstance(payload.get('tombstones'), dict)):
            raise ValueError('invalid bridge job state schema')
        if len(payload['jobs']) > 1000 or len(payload['tombstones']) > 2000:
            raise ValueError('bridge job state entry limit exceeded')
        self.jobs = copy.deepcopy(payload['jobs'])
        self.tombstones = copy.deepcopy(payload['tombstones'])

    def _load_journal_locked(self):
        if (self.journal_path is None or not self.journal_path.exists() or
                self.journal_path.stat().st_size == 0):
            return
        if self.journal_path.stat().st_size > self.MAX_STATE_BYTES:
            raise ValueError('bridge settlement journal exceeds safety limit')
        try:
            payload = json.loads(self.journal_path.read_text(encoding='utf-8'))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError('invalid bridge settlement journal') from exc
        if (not isinstance(payload, dict) or
                set(payload) != {'schema_version', 'settlements'} or
                payload.get('schema_version') != 1 or
                not isinstance(payload.get('settlements'), dict) or
                len(payload['settlements']) > self.MAX_JOURNAL_ENTRIES):
            raise ValueError('invalid bridge settlement journal schema')
        for job_id, job in payload['settlements'].items():
            if (not isinstance(job_id, str) or not isinstance(job, dict) or
                    job.get('id') != job_id or
                    job.get('status') not in self.TERMINAL_STATUSES):
                raise ValueError('invalid bridge settlement entry')
        self.pending_settlements = copy.deepcopy(payload['settlements'])

    def _write_journal_locked(self):
        if self.journal_path is None:
            return True
        payload = {'schema_version': 1,
                   'settlements': self.pending_settlements}
        data = self._json_bytes(payload)
        if len(data) > self.MAX_STATE_BYTES:
            self._mark_persistence_failure_locked()
            return False
        return self._atomic_write_locked(self.journal_path, data)

    def _replay_settlements_locked(self):
        changed = False
        for job_id, terminal_job in self.pending_settlements.items():
            current = self.jobs.get(job_id)
            if current != terminal_job:
                self.jobs[job_id] = copy.deepcopy(terminal_job)
                self.tombstones.pop(job_id, None)
                changed = True
        return changed

    def _recover_interrupted_locked(self):
        now = self.clock()
        changed = False
        for job in self.jobs.values():
            if job.get('status') not in self.ACTIVE_STATUSES:
                continue
            changed = True
            started = float(job.get('started_at', job.get('created_at', now)))
            process_pid = job.get('process_pid')
            root_reaped = process_pid is None or not process_exists(process_pid)
            result = {
                'ok': False,
                'error_code': 'bridge_restart',
                'error': 'bridge restarted before execution completed',
                'terminal_reason': 'bridge_restart',
                'returncode': None,
                'exit_code': 1,
                'process_pid': process_pid,
                'process_parent_pid': job.get('process_parent_pid'),
                'started_at_epoch': started,
                'completed_at_epoch': now,
                'started_at_utc': time.strftime(
                    '%Y-%m-%dT%H:%M:%SZ', time.gmtime(started)),
                'completed_at_utc': time.strftime(
                    '%Y-%m-%dT%H:%M:%SZ', time.gmtime(now)),
                'process_tree_terminated': bool(root_reaped),
                'process_tree_cleanup_enforced': bool(root_reaped),
                'root_process_reaped': bool(root_reaped),
                'cleanup_certified': bool(root_reaped),
                'stdout': '',
                'stderr': '',
                'stdout_emitted_bytes': 0,
                'stderr_emitted_bytes': 0,
                'stdout_retained_bytes': 0,
                'stderr_retained_bytes': 0,
                'stdout_truncated': False,
                'stderr_truncated': False,
                'duration_seconds': max(0.0, now - started),
            }
            job.update(
                status='failed', completed_at=now, finished_at=now,
                result=result,
                result_bytes=len(self._json_bytes(result)))
            self.recovered_events.append({
                'kind': job.get('kind'), 'route': job.get('route'),
                'job_id': job.get('id'), 'result': copy.deepcopy(result)})
        return changed

    def _persist_locked(self):
        if self.state_path is None:
            return True
        try:
            data = self._json_bytes(self._state_payload_locked())
        except (TypeError, ValueError):
            self._mark_persistence_failure_locked()
            return False
        if len(data) > self.MAX_STATE_BYTES:
            self._mark_persistence_failure_locked()
            return False
        if not self._atomic_write_locked(self.state_path, data):
            return False
        self.persistence_ok = True
        return True

    def _transaction_locked(self, mutation):
        before_jobs = copy.deepcopy(self.jobs)
        before_tombstones = copy.deepcopy(self.tombstones)
        before_events = copy.deepcopy(self.recovered_events)
        try:
            changed, result = mutation()
            if changed and not self._persist_locked():
                raise JobStateUnavailable(
                    'persistent job state transition could not be committed')
            return result
        except BaseException:
            self.jobs = before_jobs
            self.tombstones = before_tombstones
            self.recovered_events = before_events
            raise

    def create(self, job_id, kind, route):
        with self.lock:
            def mutate():
                if job_id in self.jobs or job_id in self.tombstones:
                    raise DuplicateJobId('duplicate job id')
                self.jobs[job_id] = {
                    'id': job_id, 'kind': kind, 'route': route,
                    'status': 'reserved', 'created_at': self.clock()}
                return True, copy.deepcopy(self.jobs[job_id])
            return self._transaction_locked(mutate)

    def mark_running(self, job_id):
        with self.lock:
            def mutate():
                job = self.jobs[job_id]
                if job['status'] not in {'reserved', 'starting'}:
                    raise ValueError('job is not startable')
                job.update(status='running', started_at=self.clock())
                return True, True
            return self._transaction_locked(mutate)

    def record_process(self, job_id, pid, parent_pid, started_at):
        with self.lock:
            def mutate():
                job = self.jobs.get(job_id)
                if not job or job.get('status') not in self.ACTIVE_STATUSES:
                    raise ValueError('job cannot accept process metadata')
                job.update(process_pid=int(pid),
                           process_parent_pid=int(parent_pid),
                           process_started_at=float(started_at))
                return True, True
            return self._transaction_locked(mutate)

    def request_cancel(self, job_id):
        with self.lock:
            def mutate():
                job = self.jobs.get(job_id)
                if not job or job.get('status') not in self.ACTIVE_STATUSES:
                    raise ValueError('job is not cancellable')
                if 'cancel_requested_at' in job:
                    return False, copy.deepcopy(job)
                job['cancel_requested_at'] = self.clock()
                return True, copy.deepcopy(job)
            return self._transaction_locked(mutate)

    def complete(self, job_id, status, result):
        if status not in self.TERMINAL_STATUSES:
            raise ValueError('invalid terminal status')
        with self.lock:
            current = self.jobs.get(job_id)
            if current is None:
                raise KeyError(job_id)
            if current.get('status') in self.TERMINAL_STATUSES:
                if (current.get('status') == status and
                        current.get('result') == result):
                    return not bool(self.pending_settlements)
                raise ValueError('job is already terminal')
            completed_at = self.clock()
            terminal_job = copy.deepcopy(current)
            terminal_job.update(
                status=status, completed_at=completed_at,
                finished_at=completed_at, result=copy.deepcopy(result),
                result_bytes=len(self._json_bytes(result)))

            if self.state_path is None:
                self.jobs[job_id] = terminal_job
                self._cleanup_locked(completed_at)
                return True

            if (job_id not in self.pending_settlements and
                    len(self.pending_settlements) >= self.MAX_JOURNAL_ENTRIES):
                self._mark_persistence_failure_locked()
                raise JobStateUnavailable(
                    'terminal settlement journal entry limit reached')
            previous_pending = copy.deepcopy(self.pending_settlements)
            self.pending_settlements[job_id] = copy.deepcopy(terminal_job)
            if not self._write_journal_locked():
                self.pending_settlements = previous_pending
                raise JobStateUnavailable(
                    'terminal settlement journal could not be committed')

            self.jobs[job_id] = terminal_job
            self._cleanup_locked(completed_at)
            if not self._persist_locked():
                # Exact terminal truth remains both in memory and in the durable
                # bounded journal. Admission/readiness remain fail-closed.
                return False

            self.pending_settlements.pop(job_id, None)
            if not self._write_journal_locked():
                # The redundant journal is still durable; retain the in-memory
                # pending marker so health cannot falsely certify settlement.
                self.pending_settlements[job_id] = copy.deepcopy(terminal_job)
                self._mark_persistence_failure_locked()
                return False
            self.persistence_ok = True
            return True

    def _expire(self, job_id, job, now):
        self.jobs.pop(job_id, None)
        self.tombstones[job_id] = {
            'id': job_id, 'status': 'expired', 'expired_at': now,
            'completed_at': job.get('completed_at')}

    def _cleanup_locked(self, now):
        before_jobs = copy.deepcopy(self.jobs)
        before_tombstones = copy.deepcopy(self.tombstones)
        terminal = [(job_id, job) for job_id, job in self.jobs.items()
                    if job.get('status') in self.TERMINAL_STATUSES]
        for job_id, job in terminal:
            if now - job.get('completed_at', now) >= self.ttl_seconds:
                self._expire(job_id, job, now)
        terminal = sorted(
            ((job_id, job) for job_id, job in self.jobs.items()
             if job.get('status') in self.TERMINAL_STATUSES),
            key=lambda item: (item[1].get('completed_at', 0), item[0]))
        total = sum(job.get('result_bytes', 0) for _, job in terminal)
        while terminal and (len(terminal) > self.max_completed or
                            total > self.max_completed_bytes):
            job_id, job = terminal.pop(0)
            total -= job.get('result_bytes', 0)
            self._expire(job_id, job, now)
        for job_id, tombstone in list(self.tombstones.items()):
            if (now - tombstone.get('expired_at', now) >=
                    self.tombstone_ttl_seconds):
                self.tombstones.pop(job_id, None)
        ordered = sorted(
            self.tombstones.items(),
            key=lambda item: (item[1].get('expired_at', 0), item[0]))
        while len(ordered) > self.max_tombstones:
            job_id, _ = ordered.pop(0)
            self.tombstones.pop(job_id, None)
        return before_jobs != self.jobs or before_tombstones != self.tombstones

    def cleanup(self):
        with self.lock:
            def mutate():
                changed = self._cleanup_locked(self.clock())
                return changed, changed
            return self._transaction_locked(mutate)

    def discard_active(self, job_id):
        with self.lock:
            def mutate():
                job = self.jobs.get(job_id)
                if job is None or job.get('status') not in self.ACTIVE_STATUSES:
                    return False, False
                self.jobs.pop(job_id, None)
                return True, True
            return self._transaction_locked(mutate)

    def get(self, job_id):
        self.cleanup()
        with self.lock:
            item = self.jobs.get(job_id)
            if item:
                response = copy.deepcopy(item)
                if response.get('status') in self.ACTIVE_STATUSES:
                    response['ok'] = True
                return response
            if job_id in self.tombstones:
                return {'status': 'expired', 'job_id': job_id}
            return None

    def take_recovered_events(self):
        with self.lock:
            events = self.recovered_events
            self.recovered_events = []
            return copy.deepcopy(events)

    def health_error(self):
        with self.lock:
            if self.state_path is None:
                return None
            if not self.persistence_ok or self.pending_settlements:
                return {
                    'error_code': 'job_state_unavailable',
                    'error': 'persistent job state is unavailable',
                    'reason': ('terminal_settlement_pending'
                               if self.pending_settlements
                               else 'job_state_unavailable'),
                    'retry_after_seconds': 60,
                }
            return None

    def snapshot(self):
        self.cleanup()
        with self.lock:
            terminal = [job for job in self.jobs.values()
                        if job.get('status') in self.TERMINAL_STATUSES]
            active = [job for job in self.jobs.values()
                      if job.get('status') in self.ACTIVE_STATUSES]
            return {
                'active_entries': len(active),
                'completed_entries': len(terminal),
                'completed_result_bytes': sum(
                    job.get('result_bytes', 0) for job in terminal),
                'tombstones': len(self.tombstones),
                'persistence_enabled': self.state_path is not None,
                'persistence_ok': self.persistence_ok,
                'last_persistence_failure_at': self.last_persistence_failure_at,
                'pending_settlements': len(self.pending_settlements),
            }


LOG_LOCK = threading.Lock()


def _rotate_copy_truncate(path, max_bytes, backups):
    path = pathlib.Path(path)
    if backups < 1 or not path.exists() or path.stat().st_size < int(max_bytes):
        return False
    for index in range(int(backups), 1, -1):
        source = path.with_name(path.name + f'.{index - 1}')
        destination = path.with_name(path.name + f'.{index}')
        if source.exists():
            destination.touch(exist_ok=True)
            shutil.copyfile(source, destination)
        elif destination.exists():
            destination.write_bytes(b'')
    first = path.with_name(path.name + '.1')
    first.touch(exist_ok=True)
    shutil.copyfile(path, first)
    path.write_bytes(b'')
    return True


def log(msg):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_LOCK:
        LOG_FILE.touch(exist_ok=True)
        _rotate_copy_truncate(LOG_FILE, 5 * 1024**2, 5)
        with LOG_FILE.open('a', encoding='utf-8') as f:
            f.write(time.strftime('%Y-%m-%dT%H:%M:%S%z') + ' ' + msg + '\n')



class WindowsJobObject:
    KILL_ON_JOB_CLOSE = 0x00002000
    EXTENDED_LIMIT_INFORMATION = 9

    def __init__(self):
        import ctypes
        from ctypes import wintypes
        if os.name != 'nt':
            raise OSError('Windows Job Objects require Windows')

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [('ReadOperationCount', ctypes.c_ulonglong),
                        ('WriteOperationCount', ctypes.c_ulonglong),
                        ('OtherOperationCount', ctypes.c_ulonglong),
                        ('ReadTransferCount', ctypes.c_ulonglong),
                        ('WriteTransferCount', ctypes.c_ulonglong),
                        ('OtherTransferCount', ctypes.c_ulonglong)]

        class BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [('PerProcessUserTimeLimit', ctypes.c_longlong),
                        ('PerJobUserTimeLimit', ctypes.c_longlong),
                        ('LimitFlags', wintypes.DWORD),
                        ('MinimumWorkingSetSize', ctypes.c_size_t),
                        ('MaximumWorkingSetSize', ctypes.c_size_t),
                        ('ActiveProcessLimit', wintypes.DWORD),
                        ('Affinity', ctypes.c_size_t),
                        ('PriorityClass', wintypes.DWORD),
                        ('SchedulingClass', wintypes.DWORD)]

        class EXTENDED_LIMIT_INFORMATION_STRUCT(ctypes.Structure):
            _fields_ = [('BasicLimitInformation', BASIC_LIMIT_INFORMATION),
                        ('IoInfo', IO_COUNTERS),
                        ('ProcessMemoryLimit', ctypes.c_size_t),
                        ('JobMemoryLimit', ctypes.c_size_t),
                        ('PeakProcessMemoryUsed', ctypes.c_size_t),
                        ('PeakJobMemoryUsed', ctypes.c_size_t)]

        self.ctypes = ctypes
        self.wintypes = wintypes
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                           ctypes.c_void_p, wintypes.DWORD]
        self.kernel32.SetInformationJobObject.restype = wintypes.BOOL
        self.kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        self.kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.kernel32.TerminateJobObject.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.closed = False
        self.terminated = False
        self.handle = self.kernel32.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        info = EXTENDED_LIMIT_INFORMATION_STRUCT()
        info.BasicLimitInformation.LimitFlags = self.KILL_ON_JOB_CLOSE
        if not self.kernel32.SetInformationJobObject(
                self.handle, self.EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(info), ctypes.sizeof(info)):
            error = ctypes.WinError(ctypes.get_last_error())
            self.close()
            raise error

    def assign(self, process):
        handle = self.wintypes.HANDLE(int(process._handle))
        if not self.kernel32.AssignProcessToJobObject(self.handle, handle):
            raise self.ctypes.WinError(self.ctypes.get_last_error())

    def terminate(self, exit_code=1):
        if self.closed:
            return False
        if self.terminated:
            return True
        ok = bool(self.kernel32.TerminateJobObject(self.handle, int(exit_code)))
        if ok:
            self.terminated = True
        return ok

    def close(self):
        if not getattr(self, 'closed', True) and getattr(self, 'handle', None):
            self.kernel32.CloseHandle(self.handle)
            self.handle = None
            self.closed = True


def process_exists(pid):
    import ctypes
    from ctypes import wintypes
    if os.name != 'nt':
        try:
            os.kill(int(pid), 0)
            return True
        except OSError:
            return False
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.OpenProcess(0x1000, False, int(pid))
    if not handle:
        return False
    try:
        code = wintypes.DWORD()
        return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
    finally:
        kernel32.CloseHandle(handle)


def _fallback_terminate_process_tree(job, proc):
    # Closing a kill-on-close Job Object is the first fallback for a failed
    # TerminateJobObject call. taskkill /T is a second, independent tree kill.
    job.close()
    if proc.poll() is None and os.name == 'nt':
        try:
            # Fixed argv only; PID comes from the Popen handle, never the caller.
            taskkill = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                                    'System32', 'taskkill.exe')
            subprocess.run([taskkill, '/PID', str(proc.pid), '/T', '/F'],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10, check=False,
                           shell=False)  # nosec B603
        except (OSError, subprocess.TimeoutExpired):
            pass
    if proc.poll() is None:
        try:
            proc.kill()
        except OSError:
            pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        return False
    return proc.poll() is not None


def _executor_accepts_observer(executor):
    try:
        parameters = inspect.signature(executor).parameters.values()
    except (TypeError, ValueError):
        return False
    positional = [parameter for parameter in parameters
                  if parameter.kind in {
                      inspect.Parameter.POSITIONAL_ONLY,
                      inspect.Parameter.POSITIONAL_OR_KEYWORD}]
    return (any(parameter.name == 'execution_observer'
                for parameter in parameters) or
            any(parameter.kind == inspect.Parameter.VAR_POSITIONAL
                for parameter in parameters) or
            len(positional) >= 4)


def run_subprocess_bounded(argv, cwd=None, env_overrides=None, timeout=120,
                           cancel_event=None, retain_limit=4 * 1024**2,
                           emit_limit=64 * 1024**2,
                           execution_observer=None):
    started = time.monotonic()
    started_epoch = time.time()
    cancel_event = cancel_event or threading.Event()
    reason = [None]
    reason_lock = threading.Lock()
    cleanup_lock = threading.Lock()
    cleanup_attempted = [False]
    cleanup_enforced = [False]
    cleanup_unresolved = threading.Event()
    root_reaped = [True]
    job = None
    proc = None
    drainers = []

    def utc(epoch):
        return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(epoch))

    def terminate_tree(exit_code=1):
        nonlocal proc
        if proc is None:
            return True
        with cleanup_lock:
            cleanup_attempted[0] = True
            terminated = False
            try:
                terminated = bool(job and job.terminate(exit_code))
            except Exception:  # noqa: BLE001 - fixed fallback still runs
                terminated = False
            if not terminated:
                try:
                    terminated = bool(
                        _fallback_terminate_process_tree(job, proc))
                except Exception:  # noqa: BLE001 - unresolved cleanup is explicit
                    terminated = False
            if proc.poll() is None and terminated:
                try:
                    proc.wait(timeout=1)
                except (OSError, subprocess.TimeoutExpired):
                    terminated = False
            root_reaped[0] = proc.poll() is not None
            cleanup_enforced[0] = bool(terminated and root_reaped[0])
            if not cleanup_enforced[0]:
                cleanup_unresolved.set()
            return cleanup_enforced[0]

    def trigger(value):
        with reason_lock:
            if reason[0] is None:
                reason[0] = value
        terminate_tree(1)

    stdout_buffer = BoundedOutputBuffer(
        retain_limit, emit_limit, lambda: trigger('output_limit'))
    stderr_buffer = BoundedOutputBuffer(
        retain_limit, emit_limit, lambda: trigger('output_limit'))

    def snapshots():
        try:
            out = stdout_buffer.snapshot()
        except Exception:  # noqa: BLE001 - lifecycle evidence remains bounded
            out = {'retained': b'', 'retained_bytes': 0, 'emitted_bytes': 0,
                   'truncated': False, 'limit_exceeded': False}
        try:
            err = stderr_buffer.snapshot()
        except Exception:  # noqa: BLE001
            err = {'retained': b'', 'retained_bytes': 0, 'emitted_bytes': 0,
                   'truncated': False, 'limit_exceeded': False}
        return out, err

    def result_for(terminal_reason, returncode=None, error_code=None):
        out, err = snapshots()
        completed_epoch = time.time()
        exit_code = {
            'timed_out': 124,
            'cancelled': 130,
            'output_limit': 125,
            'internal_error': 1,
        }.get(terminal_reason, returncode)
        result = {
            'ok': terminal_reason == 'succeeded',
            'terminal_reason': terminal_reason,
            'returncode': returncode,
            'exit_code': exit_code,
            'process_pid': proc.pid if proc is not None else None,
            'process_parent_pid': os.getpid(),
            'started_at_epoch': started_epoch,
            'completed_at_epoch': completed_epoch,
            'started_at_utc': utc(started_epoch),
            'completed_at_utc': utc(completed_epoch),
            'stdout': out['retained'].decode('utf-8', errors='replace'),
            'stderr': err['retained'].decode('utf-8', errors='replace'),
            'stdout_emitted_bytes': out['emitted_bytes'],
            'stderr_emitted_bytes': err['emitted_bytes'],
            'stdout_retained_bytes': out['retained_bytes'],
            'stderr_retained_bytes': err['retained_bytes'],
            'stdout_truncated': out['truncated'],
            'stderr_truncated': err['truncated'],
            'cleanup_attempted': cleanup_attempted[0],
            'root_process_reaped': root_reaped[0],
            'process_tree_cleanup_enforced': cleanup_enforced[0],
            'cleanup_certified': (proc is None or cleanup_enforced[0]),
            'process_tree_terminated': bool(
                cleanup_enforced[0] and terminal_reason != 'succeeded'),
            'duration_seconds': round(time.monotonic() - started, 3),
        }
        if error_code:
            result.update({'ok': False, 'error_code': error_code,
                           'error': ('process cleanup could not be certified'
                                     if error_code == 'cleanup_unresolved'
                                     else 'execution failed')})
        return result

    if cancel_event.is_set():
        cleanup_enforced[0] = True
        return result_for('cancelled', returncode=None,
                          error_code='cancelled')

    helper = str(pathlib.Path(__file__).resolve().parent /
                 'bridge_child_bootstrap.py')
    flags = (getattr(subprocess, 'CREATE_NO_WINDOW', 0) |
             getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0))
    try:
        job = WindowsJobObject()
        proc = subprocess.Popen(
            [sys.executable, helper], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=str(pathlib.Path(__file__).resolve().parent), shell=False,
            creationflags=flags)  # nosec B603
        root_reaped[0] = False
        try:
            job.assign(proc)
        except BaseException:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
            raise

        def drain(stream, buffer):
            try:
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    buffer.feed(chunk)
            except Exception:  # noqa: BLE001 - any drainer fault kills the tree
                trigger('internal_error')
            finally:
                try:
                    stream.close()
                except OSError:
                    pass

        for stream, buffer, name in (
                (proc.stdout, stdout_buffer, 'stdout'),
                (proc.stderr, stderr_buffer, 'stderr')):
            thread = threading.Thread(
                target=drain, args=(stream, buffer),
                name=f'bridge-drain-{name}', daemon=True)
            thread.start()
            drainers.append(thread)

        # The bootstrap is blocked on stdin and already Job-assigned here.
        # Persistent async callers must durably record this PID before this
        # function releases any authenticated command bytes.
        if execution_observer:
            observer_result = execution_observer(
                proc.pid, stdout_buffer, stderr_buffer)
            if observer_result is False:
                raise JobStateUnavailable(
                    'process metadata could not be committed')

        if cancel_event.is_set():
            trigger('cancelled')
            try:
                proc.stdin.close()
            except OSError:
                pass
        else:
            spec = json.dumps(
                {'argv': [str(item) for item in argv],
                 'cwd': str(cwd) if cwd else None,
                 'env_overrides': env_overrides or {}},
                ensure_ascii=False).encode('utf-8')
            proc.stdin.write(spec)
            proc.stdin.close()

        while proc.poll() is None:
            elapsed = time.monotonic() - started
            if cancel_event.is_set():
                trigger('cancelled')
            elif timeout is not None and elapsed >= float(timeout):
                trigger('timed_out')
            if cleanup_unresolved.is_set():
                break
            time.sleep(0.025)

        returncode = proc.poll()
        if returncode is not None:
            returncode = proc.wait()
            if not cleanup_attempted[0]:
                terminate_tree(0 if returncode == 0 else 1)

        for thread in drainers:
            thread.join(timeout=2 if cleanup_unresolved.is_set() else 10)
        if any(thread.is_alive() for thread in drainers):
            trigger('internal_error')
            for thread in drainers:
                thread.join(timeout=0.5)

        if cleanup_unresolved.is_set() or not cleanup_enforced[0]:
            return result_for(
                'internal_error', returncode=returncode,
                error_code='cleanup_unresolved')
        terminal_reason = reason[0] or (
            'succeeded' if returncode == 0 else 'failed')
        return result_for(terminal_reason, returncode=returncode)
    except ExecutionFailure:
        raise
    except BaseException as exc:  # cleanup must run for all exits
        if (proc is not None and
                (proc.poll() is None or not cleanup_attempted[0])):
            terminate_tree(1)
        error_code = ('cleanup_unresolved'
                      if proc is not None and not cleanup_enforced[0]
                      else 'execution_failed')
        raise ExecutionFailure(
            result_for('failed', returncode=(proc.poll() if proc else None),
                       error_code=error_code)) from exc
    finally:
        for thread in drainers:
            if thread.is_alive():
                thread.join(timeout=0.2)
        if job is not None:
            # Closing a Job handle must not mask an already-certified result.
            with contextlib.suppress(Exception):
                job.close()


class BridgeRuntime:
    TERMINAL_COUNTERS: ClassVar[dict[str, str]] = {
        'succeeded': 'completed',
        'failed': 'failed',
        'timed_out': 'timed_out',
        'cancelled': 'cancelled',
        'output_limit': 'output_limit',
    }

    def __init__(self, admission=None, jobs=None, executor=None,
                 release_attestation=None, thread_factory=threading.Thread):
        self.admission = admission or AdmissionController()
        self.jobs = jobs or JobStore()
        self.executor = executor or self._default_execute
        self.thread_factory = thread_factory
        self.lock = threading.RLock()
        self.terminal_lock = threading.RLock()
        self.counters = {
            'submitted': 0, 'started': 0, 'completed': 0, 'failed': 0,
            'timed_out': 0, 'cancelled': 0, 'output_limit': 0,
        }
        self.cancel_events = {}
        self.active_executions = {}
        self.lifecycle_sink = None
        self.telemetry = None
        self.release_attestation = {
            'release_manifest_sha256': None,
            'release_tree_sha256': None,
        }
        if release_attestation:
            self.release_attestation.update(copy.deepcopy(release_attestation))
        self.cleanup_healthy = True
        self.cleanup_failure_at = None
        self._recovered_events = self.jobs.take_recovered_events()
        self.admission.set_health_provider(
            'job_state', self.jobs.health_error)
        self.admission.set_health_provider(
            'process_cleanup', self._cleanup_health_error)

    def set_release_attestation(self, attestation):
        required = {'release_manifest_sha256', 'release_tree_sha256'}
        if not isinstance(attestation, dict) or not required.issubset(attestation):
            raise ValueError('invalid release attestation')
        with self.lock:
            self.release_attestation.update({
                key: str(attestation[key]) for key in required})

    def set_telemetry(self, telemetry):
        self.telemetry = telemetry
        self.admission.set_health_provider(
            'telemetry', telemetry.health_error if telemetry else None)

    def _cleanup_health_error(self):
        with self.lock:
            if self.cleanup_healthy:
                return None
        return {
            'error_code': 'resource_pressure',
            'error': 'process cleanup is unresolved',
            'reason': 'cleanup_unresolved',
            'retry_after_seconds': 60,
        }

    def _mark_cleanup_result(self, result):
        if result.get('cleanup_certified') is not False:
            return
        with self.lock:
            self.cleanup_healthy = False
            if self.cleanup_failure_at is None:
                self.cleanup_failure_at = time.time()

    @staticmethod
    def _default_execute(kind, payload, cancel_event=None,
                         execution_observer=None):
        timeout = int(payload.get('timeout', payload.get('timeout_seconds', 120)))
        cwd = payload.get('cwd') or None
        if kind == 'hermes':
            command = payload['prompt']
            argv = [str(HERMES_EXE), 'chat', '-Q', '-q', command, '--toolsets',
                    normalize_hermes_toolsets(payload.get('toolsets'))]
        elif kind == 'terminal':
            argv = ['powershell.exe', '-NoProfile', '-NonInteractive',
                    '-Command', payload['command']]
        else:
            raise ValueError('invalid execution kind')
        return run_subprocess_bounded(
            argv, cwd=cwd, timeout=timeout, cancel_event=cancel_event,
            execution_observer=execution_observer)

    def _observe_execution(self, execution_id, kind, route, pid,
                           stdout_buffer, stderr_buffer,
                           persist_process_metadata):
        started_at = time.time()
        if persist_process_metadata:
            self.jobs.record_process(
                execution_id, pid, os.getpid(), started_at)
        with self.lock:
            self.active_executions[execution_id] = {
                'execution_id': execution_id,
                'kind': kind,
                'route': route,
                'pid': pid,
                'parent_pid': os.getpid(),
                'started_at': started_at,
                'stdout_buffer': stdout_buffer,
                'stderr_buffer': stderr_buffer,
            }
        return True

    @staticmethod
    def _payload_error(kind, payload):
        if not isinstance(payload, dict):
            return {'ok': False, 'error_code': 'invalid_request',
                    'error': 'invalid request', 'execution_started': False}
        required = 'prompt' if kind == 'hermes' else 'command'
        allowed = {required, 'cwd', 'timeout', 'timeout_seconds'}
        if kind == 'hermes':
            allowed.add('toolsets')
        command = payload.get(required)
        timeout_keys = {'timeout', 'timeout_seconds'} & set(payload)
        valid = (
            kind in {'hermes', 'terminal'} and
            set(payload).issubset(allowed) and
            isinstance(command, str) and 0 < len(command) <= 1024 * 1024 and
            len(timeout_keys) <= 1)
        cwd = payload.get('cwd')
        if cwd is not None and (not isinstance(cwd, str) or len(cwd) > 32768):
            valid = False
        if timeout_keys:
            timeout = payload[next(iter(timeout_keys))]
            if (isinstance(timeout, bool) or not isinstance(timeout, int) or
                    timeout < 1 or timeout > 3600):
                valid = False
        if kind == 'hermes':
            try:
                normalize_hermes_toolsets(payload.get('toolsets'))
            except ValueError:
                valid = False
        if not valid:
            return {'ok': False, 'error_code': 'invalid_request',
                    'error': 'invalid request', 'execution_started': False}
        if kind == 'terminal':
            blocked = blind_gui_automation_error(command)
            if blocked:
                return blocked
        return None

    @staticmethod
    def _apply_accepted_cancellation(result, cancel_event):
        value = copy.deepcopy(result)
        if (cancel_event is not None and cancel_event.is_set() and
                value.get('terminal_reason') not in {'timed_out', 'output_limit'} and
                value.get('cleanup_certified') is not False):
            value['ok'] = False
            value['terminal_reason'] = 'cancelled'
            value['exit_code'] = 130
            value.pop('source_terminal_reason', None)
            if value.get('error_code') == 'execution_failed':
                value.pop('error_code', None)
                value.pop('error', None)
        return value

    def _execute(self, kind, payload, cancel_event, execution_id, route,
                 persist_process_metadata=False):
        def observer(pid, out, err):
            return self._observe_execution(
                execution_id, kind, route, pid, out, err,
                persist_process_metadata)

        try:
            parameters = inspect.signature(self.executor).parameters
        except (TypeError, ValueError):
            parameters = {}
        accepts_keywords = any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values())
        accepts_observer = _executor_accepts_observer(self.executor)
        if accepts_keywords or 'execution_observer' in parameters:
            kwargs = {'cancel_event': cancel_event}
            if accepts_observer:
                kwargs['execution_observer'] = observer
            return self.executor(kind, payload, **kwargs)
        if accepts_observer:
            return self.executor(kind, payload, cancel_event, observer)
        if 'cancel_event' in parameters:
            return self.executor(kind, payload, cancel_event=cancel_event)
        return self.executor(kind, payload, cancel_event)

    @staticmethod
    def _normalize_terminal_result(result):
        value = copy.deepcopy(result) if isinstance(result, dict) else {}
        source_reason = value.get('terminal_reason')
        canonical = source_reason if source_reason in {
            'succeeded', 'failed', 'timed_out', 'cancelled', 'output_limit'
        } else 'failed'
        if canonical == 'succeeded' and value.get('ok') is False:
            canonical = 'failed'
        value['terminal_reason'] = canonical
        value['ok'] = canonical == 'succeeded'
        if source_reason != canonical:
            value['source_terminal_reason'] = (
                str(source_reason)[:64] if source_reason is not None else 'missing')
            value['error_code'] = 'execution_failed'
            value['error'] = 'execution failed'
        if value.get('cleanup_certified') is False:
            value['error_code'] = 'cleanup_unresolved'
            value['error'] = 'process cleanup could not be certified'
            value['ok'] = False
            canonical = 'failed'
            value['terminal_reason'] = canonical
        value.setdefault('returncode', None)
        value.setdefault('exit_code', 0 if canonical == 'succeeded' else 1)
        value.setdefault('stdout', '')
        value.setdefault('stderr', '')
        for key in ('stdout_emitted_bytes', 'stderr_emitted_bytes',
                    'stdout_retained_bytes', 'stderr_retained_bytes'):
            value.setdefault(key, 0)
        value.setdefault('stdout_truncated', False)
        value.setdefault('stderr_truncated', False)
        value.setdefault('process_tree_terminated', False)
        value.setdefault('process_tree_cleanup_enforced', False)
        http_status = (500 if value.get('error_code') in {
            'execution_failed', 'cleanup_unresolved'} else 200)
        return canonical, value, http_status

    @classmethod
    def _execution_error(cls, exc):
        if isinstance(exc, ExecutionFailure):
            return cls._normalize_terminal_result(exc.result)
        now = time.time()
        result = {
            'ok': False,
            'terminal_reason': 'internal_error',
            'returncode': None,
            'exit_code': 1,
            'process_pid': None,
            'process_parent_pid': os.getpid(),
            'started_at_epoch': now,
            'completed_at_epoch': now,
            'started_at_utc': time.strftime(
                '%Y-%m-%dT%H:%M:%SZ', time.gmtime(now)),
            'completed_at_utc': time.strftime(
                '%Y-%m-%dT%H:%M:%SZ', time.gmtime(now)),
            'process_tree_terminated': False,
            'process_tree_cleanup_enforced': True,
            'cleanup_certified': True,
            'root_process_reaped': True,
            'stdout': '', 'stderr': '',
            'stdout_emitted_bytes': 0, 'stderr_emitted_bytes': 0,
            'stdout_retained_bytes': 0, 'stderr_retained_bytes': 0,
            'stdout_truncated': False, 'stderr_truncated': False,
            'duration_seconds': 0.0,
        }
        return cls._normalize_terminal_result(result)

    def _record_terminal(self, status):
        counter = self.TERMINAL_COUNTERS.get(status, 'failed')
        with self.lock:
            self.counters[counter] += 1

    def _lifecycle_event(self, kind, route, execution_id, result):
        allowed = {
            'terminal_reason', 'source_terminal_reason', 'error_code',
            'returncode', 'exit_code', 'process_pid', 'process_parent_pid',
            'started_at_epoch', 'completed_at_epoch', 'started_at_utc',
            'completed_at_utc', 'stdout_emitted_bytes', 'stderr_emitted_bytes',
            'stdout_retained_bytes', 'stderr_retained_bytes',
            'stdout_truncated', 'stderr_truncated', 'cleanup_attempted',
            'root_process_reaped', 'process_tree_cleanup_enforced',
            'cleanup_certified', 'process_tree_terminated', 'duration_seconds',
        }
        event = {key: copy.deepcopy(value) for key, value in result.items()
                 if key in allowed}
        event.update({
            'kind': kind, 'route': route,
            'job_id': (execution_id if execution_id and
                       not execution_id.startswith('sync-') else None),
        })
        return event

    def _emit_lifecycle(self, kind, route, execution_id, result):
        sink = self.lifecycle_sink
        if sink is None:
            return
        try:
            sink(self._lifecycle_event(kind, route, execution_id, result))
        except Exception as exc:  # noqa: BLE001 - execution result stays final
            # Diagnostic logging must never change an authentic terminal result.
            with contextlib.suppress(Exception):
                log(f'lifecycle telemetry failed: {type(exc).__name__}')

    def set_lifecycle_sink(self, sink):
        self.lifecycle_sink = sink
        if sink and self._recovered_events:
            events = self._recovered_events
            self._recovered_events = []
            for event in events:
                status, normalized, _ = self._normalize_terminal_result(
                    event['result'])
                self._mark_cleanup_result(normalized)
                self._record_terminal(status)
                self._emit_lifecycle(
                    event.get('kind'), event.get('route'),
                    event.get('job_id'), normalized)

    def run_sync(self, kind, payload, route, cancel_event=None):
        validation = self._payload_error(kind, payload)
        if validation:
            return 400, validation, {}
        reservation, error = self.admission.try_reserve(kind, route)
        if not reservation:
            code = 429 if error.get('error_code') == 'capacity_exhausted' else 503
            return code, error, {'Retry-After': str(error.get('retry_after_seconds', 5))}
        execution_id = 'sync-' + uuid.uuid4().hex
        cancel_event = cancel_event or threading.Event()
        with self.lock:
            self.counters['started'] += 1
        try:
            raw = self._execute(
                kind, payload, cancel_event, execution_id, route,
                persist_process_metadata=False)
            status, result, http_status = self._normalize_terminal_result(raw)
        except BaseException as exc:  # noqa: BLE001 - normalize all execution exits
            status, result, http_status = self._execution_error(exc)
        finally:
            with self.lock:
                self.active_executions.pop(execution_id, None)
            reservation.release()
        result = self._apply_accepted_cancellation(result, cancel_event)
        status, result, http_status = self._normalize_terminal_result(result)
        self._mark_cleanup_result(result)
        self._record_terminal(status)
        self._emit_lifecycle(kind, route, execution_id, result)
        return http_status, result, {}

    @staticmethod
    def _new_job_id():
        return time.strftime('%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:8]

    def start_async(self, kind, payload, route):
        validation = self._payload_error(kind, payload)
        if validation:
            return 400, validation, {}
        reservation, error = self.admission.try_reserve(kind, route)
        if not reservation:
            code = 429 if error.get('error_code') == 'capacity_exhausted' else 503
            return code, error, {'Retry-After': str(error.get('retry_after_seconds', 5))}

        job_id = None
        try:
            for _ in range(16):
                candidate = self._new_job_id()
                try:
                    self.jobs.create(candidate, kind, route)
                    job_id = candidate
                    break
                except DuplicateJobId:
                    continue
            if job_id is None:
                raise JobStateUnavailable(
                    'collision-safe job identifier allocation exhausted')
        except JobStateUnavailable:
            reservation.release()
            return 503, {
                'ok': False, 'error_code': 'job_state_unavailable',
                'error': 'persistent job state is unavailable',
                'execution_started': False,
            }, {'Retry-After': '60'}
        except BaseException:  # noqa: BLE001 - reservation must close on every exit
            reservation.release()
            return 500, {
                'ok': False, 'error_code': 'execution_failed',
                'error': 'execution failed',
                'execution_started': False,
            }, {}

        cancel_event = threading.Event()
        with self.lock:
            self.cancel_events[job_id] = cancel_event

        def cancelled_without_launch():
            now = time.time()
            return {
                'ok': False, 'terminal_reason': 'cancelled',
                'returncode': None, 'exit_code': 130,
                'process_pid': None, 'process_parent_pid': os.getpid(),
                'started_at_epoch': now, 'completed_at_epoch': now,
                'process_tree_terminated': False,
                'process_tree_cleanup_enforced': True,
                'cleanup_certified': True, 'root_process_reaped': True,
                'stdout': '', 'stderr': '',
            }

        def worker():
            status = 'failed'
            result = None
            try:
                self.jobs.mark_running(job_id)
                with self.lock:
                    self.counters['started'] += 1
                if cancel_event.is_set():
                    status, result, _ = self._normalize_terminal_result(
                        cancelled_without_launch())
                else:
                    raw = self._execute(
                        kind, payload, cancel_event, job_id, route,
                        persist_process_metadata=True)
                    status, result, _ = self._normalize_terminal_result(raw)
            except BaseException as exc:  # noqa: BLE001 - normalize all worker exits
                status, result, _ = self._execution_error(exc)
            with self.terminal_lock:
                result = self._apply_accepted_cancellation(result, cancel_event)
                status, result, _ = self._normalize_terminal_result(result)
                try:
                    self.jobs.complete(job_id, status, result)
                except BaseException:  # noqa: BLE001,S110 - health gate records persistence failure
                    # The JobStore health gate reflects journal/persistence
                    # failure. Preserve the authentic terminal result.
                    pass
                with self.lock:
                    self.cancel_events.pop(job_id, None)
                    self.active_executions.pop(job_id, None)
            self._mark_cleanup_result(result)
            self._record_terminal(status)
            self._emit_lifecycle(kind, route, job_id, result)
            reservation.release()

        try:
            thread = self.thread_factory(
                target=worker, name=f'bridge-job-{job_id}', daemon=True)
            thread.start()
        except BaseException:  # noqa: BLE001 - thread-start failure must release reservation
            with self.lock:
                self.cancel_events.pop(job_id, None)
            failed = self._normalize_terminal_result({
                'ok': False, 'terminal_reason': 'internal_error',
                'error_code': 'execution_start_failed',
                'cleanup_certified': True,
            })[1]
            try:
                self.jobs.complete(job_id, 'failed', failed)
            except BaseException:  # noqa: BLE001,S110 - health gate records persistence failure
                pass
            reservation.release()
            return 500, {
                'ok': False, 'error_code': 'execution_failed',
                'error': 'execution failed',
                'execution_started': False,
            }, {}
        with self.lock:
            self.counters['submitted'] += 1
        return 202, {
            'ok': True, 'accepted': True, 'job_id': job_id,
            'status': 'reserved', 'poll_url': f'/jobs/{job_id}',
        }, {}

    def cancel_job(self, job_id):
        with self.terminal_lock:
            with self.lock:
                event = self.cancel_events.get(job_id)
            if event is None:
                job = self.jobs.get(job_id)
                if job is None:
                    return 404, {'ok': False, 'error_code': 'not_found',
                                 'error': 'job not found'}
                if job.get('status') in JobStore.TERMINAL_STATUSES:
                    return 409, {'ok': False, 'error_code': 'already_terminal',
                                 'error': 'job is already terminal'}
                return 409, {'ok': False, 'error_code': 'not_cancellable',
                             'error': 'job is not cancellable'}
            try:
                self.jobs.request_cancel(job_id)
            except JobStateUnavailable:
                return 503, {
                    'ok': False, 'error_code': 'job_state_unavailable',
                    'error': 'persistent job state is unavailable',
                    'execution_started': False,
                }
            except (KeyError, ValueError):
                return 409, {'ok': False, 'error_code': 'not_cancellable',
                             'error': 'job is not cancellable'}
            event.set()
            return 202, {
                'ok': True, 'job_id': job_id,
                'status': 'cancellation_requested',
                'cancel_requested': True,
            }

    def get_job(self, job_id):
        return self.jobs.get(job_id)

    def readiness(self):
        try:
            health_error = self.admission.health_error()
        except Exception:  # noqa: BLE001 - readiness fails closed on provider errors
            health_error = {
                'error_code': 'job_state_unavailable',
                'error': 'bridge readiness state is unavailable',
                'reason': 'health_provider_unavailable',
            }
        with self.lock:
            identity = {
                'source_sha256': SOURCE_SHA256,
                'release_manifest_sha256': self.release_attestation.get(
                    'release_manifest_sha256'),
                'release_tree_sha256': self.release_attestation.get(
                    'release_tree_sha256'),
            }
        if health_error:
            return 503, {
                'ok': False,
                'error_code': health_error.get('error_code', 'resource_pressure'),
                'error': health_error.get('error', 'bridge is not ready'),
                'reason': health_error.get('reason', 'not_ready'),
                **identity,
            }
        return 200, {'ok': True, 'status': 'ready', **identity}

    def snapshot(self):
        admission = self.admission.snapshot()
        jobs = self.jobs.snapshot()
        pressure = (self.admission.resource_guard.snapshot()
                    if self.admission.resource_guard else None)
        telemetry = self.telemetry.snapshot() if self.telemetry else None
        with self.lock:
            active = {}
            for execution_id, item in self.active_executions.items():
                out = item['stdout_buffer'].snapshot()
                err = item['stderr_buffer'].snapshot()
                active[execution_id] = {
                    key: value for key, value in item.items()
                    if key not in {'stdout_buffer', 'stderr_buffer'}
                }
                active[execution_id]['stdout_emitted_bytes'] = out['emitted_bytes']
                active[execution_id]['stderr_emitted_bytes'] = err['emitted_bytes']
                active[execution_id]['stdout_retained_bytes'] = out['retained_bytes']
                active[execution_id]['stderr_retained_bytes'] = err['retained_bytes']
            return {
                'admission': admission,
                'counters': dict(self.counters),
                'active_executions': active,
                'resource_pressure': pressure,
                'jobs': jobs,
                'telemetry': telemetry,
                'process_cleanup': {
                    'healthy': self.cleanup_healthy,
                    'last_failure_at': self.cleanup_failure_at,
                },
            }


def _get_windows_metrics_bindings():
    cached = getattr(_get_windows_metrics_bindings, '_cached', None)
    if cached is not None:
        return cached
    import ctypes
    from ctypes import wintypes

    ULONG_PTR = ctypes.c_size_t

    class PERFORMANCE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ('cb', wintypes.DWORD),
            ('CommitTotal', ULONG_PTR),
            ('CommitLimit', ULONG_PTR),
            ('CommitPeak', ULONG_PTR),
            ('PhysicalTotal', ULONG_PTR),
            ('PhysicalAvailable', ULONG_PTR),
            ('SystemCache', ULONG_PTR),
            ('KernelTotal', ULONG_PTR),
            ('KernelPaged', ULONG_PTR),
            ('KernelNonpaged', ULONG_PTR),
            ('PageSize', ULONG_PTR),
            ('HandleCount', wintypes.DWORD),
            ('ProcessCount', wintypes.DWORD),
            ('ThreadCount', wintypes.DWORD),
        ]

    class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
        _fields_ = [
            ('cb', wintypes.DWORD),
            ('PageFaultCount', wintypes.DWORD),
            ('PeakWorkingSetSize', ULONG_PTR),
            ('WorkingSetSize', ULONG_PTR),
            ('QuotaPeakPagedPoolUsage', ULONG_PTR),
            ('QuotaPagedPoolUsage', ULONG_PTR),
            ('QuotaPeakNonPagedPoolUsage', ULONG_PTR),
            ('QuotaNonPagedPoolUsage', ULONG_PTR),
            ('PagefileUsage', ULONG_PTR),
            ('PeakPagefileUsage', ULONG_PTR),
            ('PrivateUsage', ULONG_PTR),
        ]

    class MIB_TCPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ('dwState', wintypes.DWORD),
            ('dwLocalAddr', wintypes.DWORD),
            ('dwLocalPort', wintypes.DWORD),
            ('dwRemoteAddr', wintypes.DWORD),
            ('dwRemotePort', wintypes.DWORD),
            ('dwOwningPid', wintypes.DWORD),
        ]

    psapi = ctypes.WinDLL('psapi.dll', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)
    iphlpapi = ctypes.WinDLL('iphlpapi.dll', use_last_error=True)
    psapi.GetPerformanceInfo.argtypes = [
        ctypes.POINTER(PERFORMANCE_INFORMATION), wintypes.DWORD]
    psapi.GetPerformanceInfo.restype = wintypes.BOOL
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX),
        wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetProcessHandleCount.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetProcessHandleCount.restype = wintypes.BOOL
    iphlpapi.GetExtendedTcpTable.argtypes = [
        wintypes.LPVOID, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL,
        wintypes.ULONG, wintypes.ULONG, wintypes.ULONG]
    iphlpapi.GetExtendedTcpTable.restype = wintypes.DWORD
    cached = (ctypes, wintypes, PERFORMANCE_INFORMATION,
              PROCESS_MEMORY_COUNTERS_EX, MIB_TCPROW_OWNER_PID,
              psapi, kernel32, iphlpapi)
    _get_windows_metrics_bindings._cached = cached
    return cached


def collect_windows_metrics():
    (ctypes, wintypes, PERFORMANCE_INFORMATION, PROCESS_MEMORY_COUNTERS_EX,
     MIB_TCPROW_OWNER_PID, psapi, kernel32, iphlpapi) = _get_windows_metrics_bindings()
    perf = PERFORMANCE_INFORMATION()
    perf.cb = ctypes.sizeof(perf)
    if not psapi.GetPerformanceInfo(ctypes.byref(perf), perf.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    process = kernel32.GetCurrentProcess()
    memory = PROCESS_MEMORY_COUNTERS_EX()
    memory.cb = ctypes.sizeof(memory)
    if not psapi.GetProcessMemoryInfo(process, ctypes.byref(memory), memory.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    handles = wintypes.DWORD()
    if not kernel32.GetProcessHandleCount(process, ctypes.byref(handles)):
        raise ctypes.WinError(ctypes.get_last_error())

    close_wait = 0
    try:
        size = wintypes.ULONG(0)
        first_result = iphlpapi.GetExtendedTcpTable(
            None, ctypes.byref(size), False, socket.AF_INET, 5, 0)
        if first_result not in {0, 122}:  # ERROR_INSUFFICIENT_BUFFER is expected for the sizing call.
            raise OSError(int(first_result), 'GetExtendedTcpTable sizing failed')
        buffer = ctypes.create_string_buffer(size.value)
        second_result = iphlpapi.GetExtendedTcpTable(
            buffer, ctypes.byref(size), False, socket.AF_INET, 5, 0)
        if second_result != 0:
            raise OSError(int(second_result), 'GetExtendedTcpTable query failed')
        count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
        offset = ctypes.sizeof(wintypes.DWORD)
        row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
        for index in range(count):
            row = MIB_TCPROW_OWNER_PID.from_buffer_copy(buffer, offset + index * row_size)
            remote_port = socket.ntohs(row.dwRemotePort & 0xFFFF)
            if row.dwState == 8 and remote_port == 8017:
                close_wait += 1
    except (OSError, ValueError):
        close_wait = -1

    page = int(perf.PageSize)
    commit_bytes = int(perf.CommitTotal) * page
    commit_limit = int(perf.CommitLimit) * page
    return {
        'timestamp_epoch': time.time(),
        'bridge_pid': os.getpid(),
        'bridge_parent_pid': os.getppid(),
        'available_physical_bytes': int(perf.PhysicalAvailable) * page,
        'physical_total_bytes': int(perf.PhysicalTotal) * page,
        'commit_bytes': commit_bytes,
        'commit_limit_bytes': commit_limit,
        'commit_fraction': (commit_bytes / commit_limit) if commit_limit else 0.0,
        'kernel_paged_pool_bytes': int(perf.KernelPaged) * page,
        'kernel_nonpaged_pool_bytes': int(perf.KernelNonpaged) * page,
        'system_handle_count': int(perf.HandleCount),
        'system_process_count': int(perf.ProcessCount),
        'system_thread_count': int(perf.ThreadCount),
        'bridge_working_set_bytes': int(memory.WorkingSetSize),
        'bridge_private_bytes': int(memory.PrivateUsage),
        'bridge_page_fault_count': int(memory.PageFaultCount),
        'bridge_handle_count': int(handles.value),
        'bridge_thread_count': threading.active_count(),
        'honcho_8017_close_wait': close_wait,
    }


class TelemetryWriter:
    def __init__(self, runtime, resource_guard, path, interval_seconds=60,
                 rotate_bytes=10 * 1024**2, backups=7,
                 max_stale_seconds=180, clock=time.time,
                 private_path_attestor=None):
        self.runtime = runtime
        self.resource_guard = resource_guard
        self.path = pathlib.Path(path)
        self.interval_seconds = max(0.001, float(interval_seconds))
        self.rotate_bytes = int(rotate_bytes)
        self.backups = int(backups)
        self.max_stale_seconds = max(
            1.0, min(float(max_stale_seconds), 3600.0))
        self.clock = clock
        self.private_path_attestor = private_path_attestor
        self.stop_event = threading.Event()
        self.thread = None
        self._state_lock = threading.Lock()
        self._file_lock = threading.RLock()
        self.last_resource_sample_at = None
        self.last_lifecycle_write_at = None
        self.last_write_success_at = None
        self.last_failure_at = None
        self.last_failure_reason = None
        self.consecutive_failures = 0
        self.acl_attested = private_path_attestor is None

    def _mark_resource_success(self):
        now = float(self.clock())
        with self._state_lock:
            self.last_resource_sample_at = now
            self.last_write_success_at = now
            self.last_failure_reason = None
            self.consecutive_failures = 0

    def _mark_lifecycle_success(self):
        now = float(self.clock())
        with self._state_lock:
            self.last_lifecycle_write_at = now
            self.last_write_success_at = now

    def _mark_failure(self, reason='telemetry_unavailable'):
        if self.resource_guard:
            self.resource_guard.observe_failure(reason)
        with self._state_lock:
            self.last_failure_at = float(self.clock())
            self.last_failure_reason = reason
            self.consecutive_failures += 1
            if reason == 'telemetry_acl_unverified':
                self.acl_attested = False

    def snapshot(self):
        with self._state_lock:
            return {
                'thread_alive': bool(self.thread and self.thread.is_alive()),
                'last_success_at': self.last_resource_sample_at,
                'last_resource_sample_at': self.last_resource_sample_at,
                'last_lifecycle_write_at': self.last_lifecycle_write_at,
                'last_write_success_at': self.last_write_success_at,
                'last_failure_at': self.last_failure_at,
                'last_failure_reason': self.last_failure_reason,
                'consecutive_failures': self.consecutive_failures,
                'max_stale_seconds': self.max_stale_seconds,
                'acl_attested': self.acl_attested,
            }

    def health_error(self):
        with self._state_lock:
            thread_alive = bool(self.thread and self.thread.is_alive())
            last_sample = self.last_resource_sample_at
            acl_attested = self.acl_attested
        if last_sample is None:
            reason = 'telemetry_never_persisted'
        elif not thread_alive:
            reason = 'telemetry_thread_dead'
        elif float(self.clock()) - last_sample > self.max_stale_seconds:
            reason = 'telemetry_stale'
        elif not acl_attested:
            reason = 'telemetry_acl_unverified'
        else:
            return None
        return {
            'error_code': 'resource_pressure',
            'error': 'host telemetry is unavailable',
            'reason': reason,
            'retry_after_seconds': 60,
        }

    def _rotation_paths(self):
        paths = [self.path.parent, self.path]
        paths.extend(self.path.with_name(self.path.name + f'.{index}')
                     for index in range(1, self.backups + 1))
        return [path for path in paths if path.exists()]

    def _attest_private_paths(self):
        if self.private_path_attestor is None:
            with self._state_lock:
                self.acl_attested = True
            return True
        try:
            result = self.private_path_attestor(self._rotation_paths())
            ok = bool(result.get('ok')) if isinstance(result, dict) else bool(result)
        except Exception:  # noqa: BLE001 - ACL details never cross the boundary
            ok = False
        with self._state_lock:
            self.acl_attested = ok
        if not ok:
            raise TelemetryPersistenceError(
                'private metrics path attestation failed')
        return True

    def _rotate(self):
        _rotate_copy_truncate(self.path, self.rotate_bytes, self.backups)

    def _write_record(self, record):
        with self._file_lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._rotate()
            with self.path.open('a', encoding='utf-8') as handle:
                handle.write(json.dumps(
                    record, ensure_ascii=False, separators=(',', ':')) + '\n')
                handle.flush()
                os.fsync(handle.fileno())
            self._attest_private_paths()

    def record_lifecycle(self, event):
        record = {
            'schema_version': 1,
            'record_type': 'process_lifecycle',
            'recorded_at_epoch': float(self.clock()),
            'event': copy.deepcopy(event),
        }
        try:
            self._write_record(record)
            self._mark_lifecycle_success()
        except Exception as exc:
            reason = ('telemetry_acl_unverified'
                      if isinstance(exc, TelemetryPersistenceError)
                      else 'telemetry_unpersisted')
            self._mark_failure(reason)
            raise
        return record

    def sample(self):
        try:
            metrics = collect_windows_metrics()
        except Exception:
            self._mark_failure('telemetry_unavailable')
            raise
        reason = self.resource_guard.evaluate(metrics) if self.resource_guard else None
        observed_at = (self.resource_guard.clock()
                       if self.resource_guard else time.monotonic())
        projected = (self.resource_guard.preview(reason, observed_at)
                     if self.resource_guard else None)
        record = {
            'schema_version': 1,
            'record_type': 'resource_sample',
            'host': metrics,
            'runtime': self.runtime.snapshot(),
            'resource_pressure': projected,
        }
        try:
            self._write_record(record)
        except Exception as exc:
            failure_reason = ('telemetry_acl_unverified'
                              if isinstance(exc, TelemetryPersistenceError)
                              else 'telemetry_unpersisted')
            self._mark_failure(failure_reason)
            if isinstance(exc, TelemetryPersistenceError):
                raise
            raise TelemetryPersistenceError(
                'resource sample could not be persisted') from exc
        if self.resource_guard:
            self.resource_guard.commit(reason, observed_at)
        self._mark_resource_success()
        return record

    def _run(self):
        while not self.stop_event.is_set():
            with self._state_lock:
                failures_before = self.consecutive_failures
            try:
                self.sample()
            except Exception as exc:  # noqa: BLE001 - worker must remain alive
                with self._state_lock:
                    already_marked = self.consecutive_failures > failures_before
                if not already_marked:
                    self._mark_failure('telemetry_unavailable')
                try:
                    log(f'telemetry sample failed: {type(exc).__name__}')
                except Exception:  # noqa: BLE001 - logging cannot kill telemetry
                    if self.stop_event.wait(self.interval_seconds):
                        return
                    continue
            self.stop_event.wait(self.interval_seconds)

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        if self.stop_event.is_set():
            self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self._run, name='bridge-telemetry', daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)


class BridgeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def server_bind(self):
        if os.name == 'nt' and hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def __init__(self, address, handler, token, runtime, quiet=False,
                 max_request_threads=32, header_timeout_seconds=5.0,
                 body_timeout_seconds=10.0, max_header_bytes=65536):
        self.auth_token = token
        self.runtime = runtime
        self.quiet = quiet
        self.started_at = time.time()
        self.max_request_threads = max(1, int(max_request_threads))
        self.header_timeout_seconds = max(0.1, float(header_timeout_seconds))
        self.body_timeout_seconds = max(0.1, float(body_timeout_seconds))
        self.max_header_bytes = max(1024, int(max_header_bytes))
        self._request_slots = threading.BoundedSemaphore(self.max_request_threads)
        self._request_lock = threading.Lock()
        self._request_active = 0
        self._request_peak = 0
        self._request_rejected = 0
        self._request_errors = 0
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            with self._request_lock:
                self._request_rejected += 1
            self.shutdown_request(request)
            return
        with self._request_lock:
            self._request_active += 1
            self._request_peak = max(self._request_peak, self._request_active)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._request_lock:
                self._request_active -= 1
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        active_request = request
        try:
            context = getattr(self, 'tls_context', None)
            if context is not None:
                request.settimeout(self.header_timeout_seconds)
                try:
                    active_request = context.wrap_socket(request, server_side=True)
                except (ssl.SSLError, OSError):
                    with self._request_lock:
                        self._request_errors += 1
                    self.shutdown_request(request)
                    return
            super().process_request_thread(active_request, client_address)
        finally:
            with self._request_lock:
                self._request_active -= 1
            self._request_slots.release()

    def handle_error(self, request, client_address):
        with self._request_lock:
            self._request_errors += 1
        if not self.quiet:
            log('request connection terminated before completion')

    def request_snapshot(self):
        with self._request_lock:
            return {
                'limit': self.max_request_threads,
                'active': self._request_active,
                'peak': self._request_peak,
                'rejected': self._request_rejected,
                'errors': self._request_errors,
                'header_timeout_seconds': self.header_timeout_seconds,
                'body_timeout_seconds': self.body_timeout_seconds,
                'max_header_bytes': self.max_header_bytes,
            }


class HeaderLimitExceeded(Exception):
    pass


class LimitedHeaderReader:
    def __init__(self, raw, limit):
        self.raw = raw
        self.limit = int(limit)
        self.total = 0

    def readline(self, size=-1):
        remaining_with_probe = self.limit - self.total + 1
        if remaining_with_probe <= 0:
            raise HeaderLimitExceeded('request headers too large')
        request_size = remaining_with_probe if size is None or size < 0 else min(size, remaining_with_probe)
        data = self.raw.readline(request_size)
        self.total += len(data)
        if self.total > self.limit:
            raise HeaderLimitExceeded('request headers too large')
        return data

    def __getattr__(self, name):
        return getattr(self.raw, name)


class Handler(BaseHTTPRequestHandler):
    bridge_version = BRIDGE_VERSION
    server_version = 'service'
    sys_version = ''
    protocol_version = 'HTTP/1.1'

    def version_string(self):
        return 'service'

    def __getattr__(self, name):
        if name.startswith('do_'):
            return self._do_unsupported
        raise AttributeError(name)

    def setup(self):
        self._header_timer = None
        super().setup()
        timeout = self.server.header_timeout_seconds
        self.connection.settimeout(timeout)

        def expire_incomplete_headers():
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        self._header_timer = threading.Timer(timeout, expire_incomplete_headers)
        self._header_timer.daemon = True
        self._header_timer.start()

    def _stop_header_timer(self):
        timer = self._header_timer
        if timer is None:
            return
        self._header_timer = None
        timer.cancel()
        if timer is not threading.current_thread():
            timer.join(timeout=self.server.header_timeout_seconds + 0.2)

    def parse_request(self):
        original_reader = self.rfile
        self.rfile = LimitedHeaderReader(original_reader, self.server.max_header_bytes)
        try:
            try:
                return super().parse_request()
            except HeaderLimitExceeded:
                self.close_connection = True
                self._stop_header_timer()
                self._send(431, {'ok': False, 'error_code': 'headers_too_large',
                                 'error': 'request headers too large'})
                return False
        finally:
            self.rfile = original_reader
            self._stop_header_timer()

    def finish(self):
        self._stop_header_timer()
        try:
            super().finish()
        except OSError:
            pass

    def _do_unsupported(self):
        if self.route != '/health' and not self._auth():
            self._send(401, {'ok': False, 'error_code': 'unauthorized', 'error': 'unauthorized'})
            return
        self._send(405, {'ok': False, 'error_code': 'method_not_allowed',
                         'error': 'method not allowed'}, {'Allow': 'GET, POST'})

    def _send(self, code, obj, headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        try:
            self.close_connection = True
            self.send_response(code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if getattr(self, 'command', None) != 'HEAD':
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def _auth(self):
        import hmac
        expected = 'Bearer ' + self.server.auth_token
        supplied_headers = self.headers.get_all('Authorization', [])
        if len(supplied_headers) != 1:
            return False
        supplied = supplied_headers[0]
        return hmac.compare_digest(supplied.encode('utf-8'), expected.encode('utf-8'))

    def _read_json(self):
        try:
            length = int(self.headers.get('Content-Length') or '0')
        except ValueError as exc:
            raise ValueError('invalid Content-Length') from exc
        if length < 0 or length > 2_000_000:
            raise ValueError('request body exceeds 2,000,000-byte limit')
        raw = bytearray()
        if length:
            deadline = time.monotonic() + self.server.body_timeout_seconds
            reader = getattr(self.rfile, 'read1', self.rfile.read)
            try:
                while len(raw) < length:
                    remaining_seconds = deadline - time.monotonic()
                    if remaining_seconds <= 0:
                        raise ValueError('request body deadline exceeded')
                    self.connection.settimeout(min(1.0, max(0.05, remaining_seconds)))
                    chunk = reader(min(65536, length - len(raw)))
                    if not chunk:
                        raise ValueError('incomplete request body')
                    raw.extend(chunk)
            except TimeoutError as exc:
                raise ValueError('request body timeout') from exc
            finally:
                self.connection.settimeout(self.server.header_timeout_seconds)
        else:
            raw.extend(b'{}')
        try:
            value = json.loads(bytes(raw).decode('utf-8') or '{}')
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError('request body must be valid UTF-8 JSON') from exc
        if not isinstance(value, dict):
            raise TypeError('request JSON must be an object')
        return value

    @property
    def route(self):
        return self.path.split('?', 1)[0]

    def _start_disconnect_monitor(self):
        import select
        import socket

        cancel_event = threading.Event()
        done_event = threading.Event()

        def monitor():
            while not done_event.wait(0.05):
                try:
                    readable, _, _ = select.select([self.connection], [], [], 0)
                    if readable and self.connection.recv(1, socket.MSG_PEEK) == b'':
                        cancel_event.set()
                        return
                except (OSError, ValueError):
                    cancel_event.set()
                    return

        thread = threading.Thread(target=monitor, name='bridge-client-monitor', daemon=True)
        thread.start()
        return cancel_event, done_event, thread

    def do_GET(self):
        if self.route == '/health':
            self._send(200, {'ok': True, 'service': 'hermes-windows-bridge'})
            return
        if not self._auth():
            self._send(401, {'ok': False, 'error_code': 'unauthorized', 'error': 'unauthorized'})
            return
        if self.route == '/ready':
            code, body = self.server.runtime.readiness()
            body.update({'service': 'hermes-windows-bridge',
                         'version': self.bridge_version})
            self._send(code, body)
            return
        if self.route == '/status':
            try:
                host_metrics = collect_windows_metrics()
                status = {
                    'ok': True,
                    'service': 'hermes-windows-bridge',
                    'version': self.bridge_version,
                    'uptime_seconds': round(
                        time.time() - self.server.started_at, 3),
                    'runtime': self.server.runtime.snapshot(),
                    'host': host_metrics,
                    'http_requests': self.server.request_snapshot(),
                    'telemetry': (
                        self.server.telemetry.snapshot()
                        if getattr(self.server, 'telemetry', None) else None),
                }
            except Exception:  # noqa: BLE001 - status boundary is stable and sanitized
                guard = self.server.runtime.admission.resource_guard
                if guard:
                    with contextlib.suppress(Exception):
                        guard.observe_failure()
                self._send(503, {
                    'ok': False,
                    'error_code': 'status_unavailable',
                    'error': 'bridge status unavailable',
                })
                return
            self._send(200, status)
            return
        if self.route.startswith('/jobs/') and not self.route.endswith('/cancel'):
            job_id = self.route.split('/', 2)[2]
            try:
                job = self.server.runtime.get_job(job_id)
            except JobStateUnavailable:
                self._send(503, {
                    'ok': False, 'error_code': 'job_state_unavailable',
                    'error': 'persistent job state is unavailable'})
                return
            if job is None:
                self._send(404, {'ok': False, 'error_code': 'not_found', 'error': 'job not found'})
            elif job.get('status') == 'expired':
                self._send(410, job)
            else:
                self._send(200, job)
            return
        self._send(404, {'ok': False, 'error_code': 'not_found', 'error': 'not found'})

    def do_POST(self):
        if not self._auth():
            self._send(401, {'ok': False, 'error_code': 'unauthorized', 'error': 'unauthorized'})
            return
        try:
            if self.route == '/admin/quiesce':
                data = self._read_json()
                action = data.get('action')
                if action == 'begin':
                    if set(data) != {'action'}:
                        raise ValueError('invalid quiesce request')
                    generation = None
                elif action in {'status', 'resume'}:
                    if (set(data) != {'action', 'generation'} or
                            isinstance(data.get('generation'), bool) or
                            not isinstance(data.get('generation'), int) or
                            data['generation'] < 0):
                        raise ValueError('invalid quiesce request')
                    generation = data['generation']
                else:
                    raise ValueError('invalid quiesce request')
                code, body = self.server.runtime.admission.quiesce(
                    action, generation=generation)
                self._send(code, body)
                return
            if self.route in {'/run/terminal', '/run/hermes', '/jobs/terminal', '/jobs/hermes'}:
                data = self._read_json()
                kind = self.route.rsplit('/', 1)[1]
                if self.route.startswith('/run/'):
                    cancel_event, monitor_done, monitor_thread = self._start_disconnect_monitor()
                    try:
                        code, body, headers = self.server.runtime.run_sync(
                            kind, data, self.route, cancel_event=cancel_event)
                    finally:
                        monitor_done.set()
                        monitor_thread.join(timeout=0.2)
                else:
                    code, body, headers = self.server.runtime.start_async(kind, data, self.route)
                self._send(code, body, headers)
                return
            if self.route.startswith('/jobs/') and self.route.endswith('/cancel'):
                parts = self.route.strip('/').split('/')
                if len(parts) != 3:
                    raise ValueError('invalid cancel route')
                code, body = self.server.runtime.cancel_job(parts[1])
                self._send(code, body)
                return
            self._send(404, {'ok': False, 'error_code': 'not_found', 'error': 'not found'})
        except (TypeError, ValueError):
            self._send(400, {'ok': False, 'error_code': 'invalid_request',
                             'error': 'invalid request'})
        except Exception as exc:  # noqa: BLE001 - HTTP boundary must fail closed without killing server
            log(f'HTTP request failed: {type(exc).__name__}')
            self._send(500, {'ok': False, 'error_code': 'internal_error',
                             'error': 'internal server error'})

    def log_message(self, fmt, *args):
        if self.server.quiet:
            return
        route = str(getattr(self, 'path', '')).split('?', 1)[0]
        if route.startswith('/jobs/'):
            route = '/jobs/:id/cancel' if route.endswith('/cancel') else '/jobs/:id'
        elif route not in {'/health', '/ready', '/status', '/admin/quiesce',
                           '/run/terminal', '/run/hermes',
                           '/jobs/terminal', '/jobs/hermes'}:
            route = '/unknown'
        status = str(args[1]) if len(args) > 1 and str(args[1]).isdigit() else 'unknown'
        command = getattr(self, 'command', None)
        method = command if command in {'GET', 'POST', 'HEAD'} else 'OTHER'
        log(f'access method={method} route={route} status={status}')


RELEASE_LAYOUT = [
    ('release-layout.json', 'release-layout'),
    ('hermes_windows_bridge.py', 'bridge-server'),
    ('bridge_child_bootstrap.py', 'child-bootstrap'),
    ('bridge-private-state.ps1', 'private-state-attestor'),
    ('certs/bridge-cert.pem', 'public-certificate'),
    ('client/hermes-windows-bridge', 'controller-client'),
]
RELEASE_EXECUTION_CHAIN = [
    'hermes_windows_bridge.py',
    'bridge_child_bootstrap.py',
    'bridge-private-state.ps1',
]
RELEASE_MANIFEST_FIELDS = {
    'schema_version', 'listen_address', 'port', 'transport', 'layout_path',
    'payloads', 'bridge_sha256', 'certificate_sha256',
    'certificate_der_sha256', 'execution_chain', 'canonical_tree_sha256',
}


def _strict_object(pairs):
    value = {}
    folded = set()
    for key, item in pairs:
        if not isinstance(key, str) or key in value or key.casefold() in folded:
            raise ReleaseValidationError('duplicate release JSON key')
        value[key] = item
        folded.add(key.casefold())
    return value


def _load_release_json(path):
    try:
        return json.loads(path.read_text(encoding='utf-8'),
                          object_pairs_hook=_strict_object)
    except ReleaseValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseValidationError('invalid release JSON document') from exc


def _release_file(root, relative):
    if (not isinstance(relative, str) or not relative or '\\' in relative or
            ':' in relative or '\x00' in relative or relative.startswith('/')):
        raise ReleaseValidationError('unsafe release payload path')
    parts = relative.split('/')
    if (any(part in {'', '.', '..'} for part in parts) or
            pathlib.PurePosixPath(relative).as_posix() != relative):
        raise ReleaseValidationError('noncanonical release payload path')
    current = root
    for part in parts:
        current = current / part
        try:
            item = current.lstat()
        except OSError as exc:
            raise ReleaseValidationError('release payload is missing') from exc
        if current.is_symlink() or (
                getattr(item, 'st_file_attributes', 0) & 0x400):
            raise ReleaseValidationError(
                'symbolic or reparse release payload is forbidden')
    try:
        root_value = os.path.normcase(str(root.resolve(strict=True)))
        file_value = os.path.normcase(str(current.resolve(strict=True)))
        if os.path.commonpath([root_value, file_value]) != root_value:
            raise ReleaseValidationError('release payload escaped release root')
    except (OSError, ValueError) as exc:
        if isinstance(exc, ReleaseValidationError):
            raise
        raise ReleaseValidationError('release payload resolution failed') from exc
    if not current.is_file():
        raise ReleaseValidationError('release payload is not a regular file')
    return current


def _sha256_file(path):
    digest = hashlib.sha256()
    try:
        with path.open('rb') as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(chunk)
    except OSError as exc:
        raise ReleaseValidationError('release payload could not be read') from exc
    return digest.hexdigest()


def _canonical_release_tree(payloads):
    digest = hashlib.sha256()
    for relative in sorted(payloads):
        record = payloads[relative]
        digest.update(relative.encode('utf-8'))
        digest.update(b'\0')
        digest.update(str(record['size']).encode('ascii'))
        digest.update(b'\0')
        digest.update(record['sha256'].encode('ascii'))
        digest.update(b'\n')
    return digest.hexdigest()


def _looks_like_legacy_ipv4_literal(value):
    parts = value.casefold().split('.')
    if not 1 <= len(parts) <= 4 or any(not part for part in parts):
        return False
    return all(
        part.isdigit() or
        (part.startswith('0x') and len(part) > 2 and
         all(character in '0123456789abcdef' for character in part[2:]))
        for part in parts)


def _is_unspecified_address(address):
    if bool(getattr(address, 'is_unspecified', False)):
        return True
    mapped = getattr(address, 'ipv4_mapped', None)
    return mapped is not None and bool(mapped.is_unspecified)


def _normalized_release_dns_name(value):
    if (not isinstance(value, str) or not value or not value.isascii() or
            value.endswith('.') or '*' in value):
        return None
    normalized = value.casefold()
    labels = normalized.split('.')
    if (_looks_like_legacy_ipv4_literal(normalized) or
            len(normalized) > 253 or
            any(not 1 <= len(label) <= 63 or
                label.startswith('-') or label.endswith('-') or
                any(not (character.isalnum() or character == '-')
                    for character in label)
                for label in labels)):
        return None
    return normalized


def _release_certificate_der(path, expected_host):
    try:
        pem = path.read_text(encoding='ascii')
        stripped = pem.strip()
        lines = stripped.splitlines()
        if (len(lines) < 3 or
                lines[0] != '-----BEGIN CERTIFICATE-----' or
                lines[-1] != '-----END CERTIFICATE-----' or
                stripped.count('-----BEGIN CERTIFICATE-----') != 1 or
                stripped.count('-----END CERTIFICATE-----') != 1 or
                any('-----' in line for line in lines[1:-1])):
            raise ValueError('certificate PEM closure is invalid')
        der = ssl.PEM_cert_to_DER_cert(pem)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=stripped + '\n')
        decoder = getattr(getattr(ssl, '_ssl', None), '_test_decode_cert', None)
        if decoder is None:
            raise ValueError('X.509 decoder is unavailable')
        decoded = decoder(str(path))
        if not isinstance(decoded, dict):
            raise ValueError('X.509 decoder returned invalid data')
    except (OSError, UnicodeError, ValueError, ssl.SSLError) as exc:
        raise ReleaseValidationError(
            'release public certificate is invalid') from exc

    try:
        expected_ip = ipaddress.ip_address(expected_host)
    except ValueError:
        expected_ip = None
    expected_dns = (_normalized_release_dns_name(expected_host)
                    if expected_ip is None else None)
    if expected_ip is None and expected_dns is None:
        raise ReleaseValidationError('release listener identity is invalid')
    subject_alt_name = decoded.get('subjectAltName', ())
    if not isinstance(subject_alt_name, (list, tuple)):
        raise ReleaseValidationError('release certificate identity is invalid')
    matched = False
    for entry in subject_alt_name:
        if (not isinstance(entry, (list, tuple)) or len(entry) != 2 or
                not all(isinstance(item, str) for item in entry)):
            raise ReleaseValidationError('release certificate identity is invalid')
        kind, value = entry
        if expected_ip is not None and kind == 'IP Address':
            try:
                matched = ipaddress.ip_address(value) == expected_ip
            except ValueError:
                matched = False
        elif expected_dns is not None and kind == 'DNS':
            certificate_dns = _normalized_release_dns_name(value)
            matched = (certificate_dns is not None and
                       certificate_dns == expected_dns)
        if matched:
            break
    if not matched:
        raise ReleaseValidationError(
            'release certificate identity does not match listener')
    return der


def validate_release_manifest(manifest_path, expected_host, expected_port,
                              tls_cert=None):
    manifest_path = pathlib.Path(manifest_path)
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ReleaseValidationError('release manifest is unavailable')
    root = manifest_path.resolve(strict=True).parent
    manifest = _load_release_json(manifest_path)
    if not isinstance(manifest, dict) or set(manifest) != RELEASE_MANIFEST_FIELDS:
        raise ReleaseValidationError('release manifest field closure is invalid')
    if (isinstance(manifest['schema_version'], bool) or
            manifest['schema_version'] != 2):
        raise ReleaseValidationError('release manifest schema must equal 2')
    if (manifest['listen_address'] != str(expected_host) or
            isinstance(manifest['port'], bool) or
            manifest['port'] != int(expected_port) or
            manifest['transport'] != 'tls-pinned-self-signed' or
            manifest['layout_path'] != 'release-layout.json' or
            manifest['execution_chain'] != RELEASE_EXECUTION_CHAIN):
        raise ReleaseValidationError('release listener or execution-chain pin mismatch')

    layout_path = _release_file(root, 'release-layout.json')
    layout = _load_release_json(layout_path)
    expected_layout = [
        {'path': relative, 'role': role}
        for relative, role in RELEASE_LAYOUT]
    if (not isinstance(layout, dict) or set(layout) != {'schema_version', 'payloads'} or
            isinstance(layout.get('schema_version'), bool) or
            layout.get('schema_version') != 1 or
            layout.get('payloads') != expected_layout):
        raise ReleaseValidationError('release layout closure is invalid')

    payloads = manifest['payloads']
    expected_paths = [relative for relative, _ in RELEASE_LAYOUT]
    roles = dict(RELEASE_LAYOUT)
    if (not isinstance(payloads, dict) or
            list(payloads) != sorted(expected_paths) or
            set(payloads) != set(expected_paths)):
        raise ReleaseValidationError('release payload closure is invalid')
    for relative in expected_paths:
        record = payloads[relative]
        if (not isinstance(record, dict) or
                set(record) != {'role', 'size', 'sha256'} or
                record.get('role') != roles[relative] or
                isinstance(record.get('size'), bool) or
                not isinstance(record.get('size'), int) or
                record['size'] < 0 or
                not isinstance(record.get('sha256'), str) or
                re.fullmatch(r'[0-9a-f]{64}', record['sha256']) is None):
            raise ReleaseValidationError('release payload record is invalid')
        payload_path = _release_file(root, relative)
        try:
            size = payload_path.stat().st_size
        except OSError as exc:
            raise ReleaseValidationError('release payload metadata failed') from exc
        if size != record['size'] or _sha256_file(payload_path) != record['sha256']:
            raise ReleaseValidationError('release payload hash or size mismatch')

    tree_hash = _canonical_release_tree(payloads)
    bridge_hash = payloads['hermes_windows_bridge.py']['sha256']
    certificate_hash = payloads['certs/bridge-cert.pem']['sha256']
    scalar_hashes = (
        manifest['canonical_tree_sha256'], manifest['bridge_sha256'],
        manifest['certificate_sha256'], manifest['certificate_der_sha256'])
    if any(not isinstance(value, str) or
           re.fullmatch(r'[0-9a-f]{64}', value) is None for value in scalar_hashes):
        raise ReleaseValidationError('release manifest contains an invalid hash')
    if (manifest['canonical_tree_sha256'] != tree_hash or
            manifest['bridge_sha256'] != bridge_hash or
            manifest['certificate_sha256'] != certificate_hash or
            bridge_hash != SOURCE_SHA256):
        raise ReleaseValidationError('release manifest aggregate pin mismatch')

    certificate_path = _release_file(root, 'certs/bridge-cert.pem')
    der = _release_certificate_der(certificate_path, manifest['listen_address'])
    if hashlib.sha256(der).hexdigest() != manifest['certificate_der_sha256']:
        raise ReleaseValidationError('release certificate DER pin mismatch')
    if tls_cert is not None:
        try:
            supplied_cert = pathlib.Path(tls_cert).resolve(strict=True)
        except OSError as exc:
            raise ReleaseValidationError('configured public certificate is unavailable') from exc
        if os.path.normcase(str(supplied_cert)) != os.path.normcase(str(certificate_path.resolve())):
            raise ReleaseValidationError(
                'configured public certificate is outside the release closure')

    return {
        'release_manifest_sha256': _sha256_file(manifest_path),
        'release_tree_sha256': tree_hash,
        'payload_hashes': {
            relative: payloads[relative]['sha256'] for relative in payloads},
    }


def _windows_powershell_environment():
    return {
        key: value for key, value in os.environ.items()
        if key.casefold() != 'psmodulepath'
    }


def make_private_path_attestor(lifecycle_path, expected_sha256):
    lifecycle_path = pathlib.Path(lifecycle_path).resolve(strict=True)
    expected_sha256 = str(expected_sha256)

    def attest(paths):
        if _sha256_file(lifecycle_path) != expected_sha256:
            return False
        existing = [str(path) for path in paths if pathlib.Path(path).exists()]
        if not existing:
            return False
        powershell = pathlib.Path(
            os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'
        encoded_paths = base64.b64encode(json.dumps(
            existing, ensure_ascii=False, separators=(',', ':')).encode(
                'utf-8')).decode('ascii')
        try:
            completed = subprocess.run(
                [str(powershell), '-NoProfile', '-NonInteractive',
                 '-ExecutionPolicy', 'Bypass', '-File', str(lifecycle_path),
                 '-AttestPrivatePaths', '-PathListBase64', encoded_paths],
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                timeout=15, check=False, shell=False,
                env=_windows_powershell_environment())  # nosec B603
            lines = [line for line in completed.stdout.splitlines() if line.strip()]
            result = json.loads(lines[-1]) if lines else {}
            return (completed.returncode == 0 and isinstance(result, dict) and
                    result.get('ok') is True and result.get('failed') == 0 and
                    result.get('checked') == len(existing))
        except (OSError, subprocess.TimeoutExpired, UnicodeError,
                json.JSONDecodeError):
            return False

    return attest


def _windows_sid_string(sid):
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    text = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return text.value
    finally:
        kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def _windows_current_user_sid():
    import ctypes
    from ctypes import wintypes

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [('sid', ctypes.c_void_p),
                    ('attributes', wintypes.DWORD)]

    class TokenUser(ctypes.Structure):
        _fields_ = [('user', SidAndAttributes)]

    advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token, 1, None, 0, ctypes.byref(needed))
        if needed.value == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
                token, 1, buffer, needed.value, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        user = ctypes.cast(buffer, ctypes.POINTER(TokenUser)).contents
        return _windows_sid_string(user.user.sid)
    finally:
        kernel32.CloseHandle(token)


def _windows_private_file_dacl_ok(path, allowed_sids):
    import ctypes
    from ctypes import wintypes

    class AclSizeInformation(ctypes.Structure):
        _fields_ = [('ace_count', wintypes.DWORD),
                    ('acl_bytes_in_use', wintypes.DWORD),
                    ('acl_bytes_free', wintypes.DWORD)]

    class AceHeader(ctypes.Structure):
        _fields_ = [('ace_type', wintypes.BYTE),
                    ('ace_flags', wintypes.BYTE),
                    ('ace_size', wintypes.WORD)]

    class AccessAllowedAce(ctypes.Structure):
        _fields_ = [('header', AceHeader),
                    ('mask', wintypes.DWORD),
                    ('sid_start', wintypes.DWORD)]

    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_file():
        return False
    advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetAce.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    sacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = advapi32.GetNamedSecurityInfoW(
        str(path), 1, 0x00000004, ctypes.byref(owner),
        ctypes.byref(group), ctypes.byref(dacl), ctypes.byref(sacl),
        ctypes.byref(descriptor))
    if result != 0:
        raise ctypes.WinError(result)
    try:
        if not dacl:
            return False
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
                descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not control.value & 0x1000:
            return False
        info = AclSizeInformation()
        if not advapi32.GetAclInformation(
                dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.ace_count != 3:
            return False
        found = []
        for index in range(info.ace_count):
            ace_pointer = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace_pointer)):
                raise ctypes.WinError(ctypes.get_last_error())
            ace = ctypes.cast(
                ace_pointer, ctypes.POINTER(AccessAllowedAce)).contents
            if (ace.header.ace_type != 0 or ace.header.ace_flags != 0 or
                    ace.mask != 0x001F01FF):
                return False
            sid_pointer = ctypes.c_void_p(
                ace_pointer.value + AccessAllowedAce.sid_start.offset)
            found.append(_windows_sid_string(sid_pointer))
        return len(found) == len(set(found)) and set(found) == allowed_sids
    finally:
        kernel32.LocalFree(descriptor)


def make_windows_private_path_attestor():
    if os.name != 'nt':
        return lambda _paths: False
    allowed_sids = {
        _windows_current_user_sid(), 'S-1-5-18', 'S-1-5-32-544'}

    def attest(paths):
        try:
            items = [pathlib.Path(path) for path in paths]
            return bool(items) and all(
                _windows_private_file_dacl_ok(path, allowed_sids)
                for path in items)
        except (OSError, TypeError, ValueError):
            return False

    return attest


def load_token():
    try:
        if (TOKEN_FILE.is_symlink() or not TOKEN_FILE.is_file() or
                TOKEN_FILE.stat().st_size > 65536):
            raise OSError('token file is unavailable')
        return TOKEN_FILE.read_text(encoding='utf-8').strip()
    except (OSError, UnicodeError) as exc:
        raise RuntimeError('bridge token is unavailable') from exc


def validate_listener_transport(host, tls_cert=None, tls_key=None):
    if (not isinstance(host, str) or not host or len(host) > 255 or
            any(character.isspace() for character in host)):
        raise ValueError('bridge listener identity is invalid')
    normalized = host.lower()
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        address = None
    if address is not None and _is_unspecified_address(address):
        raise ValueError('wildcard bridge listeners are forbidden')
    if address is None and _normalized_release_dns_name(normalized) is None:
        raise ValueError('bridge listener identity is invalid')
    loopback = normalized == 'localhost' or (
        address is not None and address.is_loopback)
    if not loopback and not (tls_cert and tls_key):
        raise ValueError('non-loopback bridge listeners require a TLS certificate and key')
    if bool(tls_cert) != bool(tls_key):
        raise ValueError('TLS certificate and key must be provided together')


def make_server(host, port, token, runtime=None, quiet=False,
                max_request_threads=32, header_timeout_seconds=5.0,
                body_timeout_seconds=10.0, max_header_bytes=65536,
                tls_cert=None, tls_key=None):
    if not isinstance(token, str) or not token:
        raise ValueError('bridge bearer token must be non-empty')
    validate_listener_transport(host, tls_cert, tls_key)
    context = None
    if tls_cert and tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=str(tls_cert), keyfile=str(tls_key))
    server = BridgeHTTPServer(
        (host, int(port)), Handler, token, runtime or BridgeRuntime(), quiet=quiet,
        max_request_threads=max_request_threads,
        header_timeout_seconds=header_timeout_seconds,
        body_timeout_seconds=body_timeout_seconds,
        max_header_bytes=max_header_bytes)
    server.tls_context = context
    return server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default=HOST)
    parser.add_argument('--port', type=int, default=PORT)
    parser.add_argument('--tls-cert')
    parser.add_argument('--tls-key')
    parser.add_argument('--release-manifest')
    args = parser.parse_args()
    try:
        validate_listener_transport(args.host, args.tls_cert, args.tls_key)
        loopback = str(args.host).strip().lower() in {
            '127.0.0.1', '::1', 'localhost'}
        if not loopback and not args.release_manifest:
            raise ReleaseValidationError(
                'non-loopback listeners require a release manifest')
        release_attestation = None
        if args.release_manifest:
            # This complete schema-2 payload attestation is deliberately before
            # any token-file or private-key access and before socket binding.
            release_attestation = validate_release_manifest(
                args.release_manifest, args.host, args.port,
                tls_cert=args.tls_cert)
    except (ValueError, ReleaseValidationError) as exc:
        parser.error(str(exc))

    state_private_attestor = (
        make_windows_private_path_attestor() if release_attestation else None)
    pressure_state_path = os.environ.get(
        'HERMES_WINDOWS_BRIDGE_PRESSURE_STATE',
        str(PRIVATE_STATE_ROOT / 'jobs' / 'resource-pressure.json'))
    try:
        resource_guard = ResourcePressureGuard(
            min_available_bytes=2 * 1024**3,
            max_commit_fraction=0.80,
            hold_seconds=300,
            state_path=pressure_state_path,
            private_path_attestor=state_private_attestor)
    except ResourcePressureStateError:
        raise SystemExit(_RESOURCE_PRESSURE_STABLE_ERROR) from None

    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not TOKEN_FILE.exists():
        raise SystemExit(f'missing token file: {TOKEN_FILE}')
    token = load_token()
    if not token:
        raise SystemExit('bridge token file is empty')

    admission = AdmissionController(
        global_limit=2,
        class_limits={'hermes': 1, 'terminal': 2},
        resource_guard=resource_guard)
    private_attestor = None
    if release_attestation:
        root = pathlib.Path(args.release_manifest).resolve(strict=True).parent
        private_attestor = make_private_path_attestor(
            root / 'bridge-private-state.ps1',
            release_attestation['payload_hashes']['bridge-private-state.ps1'])
    state_path = os.environ.get(
        'HERMES_WINDOWS_BRIDGE_JOB_STATE',
        str(PRIVATE_STATE_ROOT / 'jobs' / 'jobs.json'))
    jobs = JobStore(
        state_path=state_path, private_path_attestor=state_private_attestor)
    runtime = BridgeRuntime(
        admission=admission, jobs=jobs,
        release_attestation=release_attestation)
    metrics_path = os.environ.get(
        'HERMES_WINDOWS_BRIDGE_METRICS_LOG',
        str(PRIVATE_STATE_ROOT / 'metrics' / 'bridge-metrics.jsonl'))
    telemetry = TelemetryWriter(
        runtime, resource_guard, metrics_path,
        interval_seconds=float(os.environ.get(
            'HERMES_WINDOWS_BRIDGE_METRICS_INTERVAL', '60')),
        max_stale_seconds=float(os.environ.get(
            'HERMES_WINDOWS_BRIDGE_TELEMETRY_MAX_STALE', '180')),
        private_path_attestor=private_attestor)
    runtime.set_telemetry(telemetry)
    runtime.set_lifecycle_sink(telemetry.record_lifecycle)

    # Startup does not bind or serve until a complete, fsync'd and (for a
    # release listener) DACL-attested resource sample exists.
    try:
        telemetry.sample()
        telemetry.start()
        if not telemetry.thread or not telemetry.thread.is_alive():
            raise TelemetryPersistenceError('telemetry worker did not start')
        httpd = make_server(
            args.host, args.port, token=token, runtime=runtime,
            max_request_threads=int(os.environ.get(
                'HERMES_WINDOWS_BRIDGE_HTTP_THREADS', '32')),
            header_timeout_seconds=float(os.environ.get(
                'HERMES_WINDOWS_BRIDGE_HEADER_TIMEOUT', '5')),
            body_timeout_seconds=float(os.environ.get(
                'HERMES_WINDOWS_BRIDGE_BODY_TIMEOUT', '10')),
            max_header_bytes=int(os.environ.get(
                'HERMES_WINDOWS_BRIDGE_MAX_HEADER_BYTES', '65536')),
            tls_cert=args.tls_cert, tls_key=args.tls_key)
    except BaseException:
        telemetry.stop()
        raise
    httpd.telemetry = telemetry
    log(f'starting hardened bridge {Handler.server_version} on {args.host}:{args.port}')
    try:
        httpd.serve_forever(poll_interval=0.25)
    finally:
        telemetry.stop()
        httpd.server_close()


if __name__ == '__main__':
    main()
