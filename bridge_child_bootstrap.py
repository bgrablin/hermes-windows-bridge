#!/usr/bin/env python3
"""Handshake bootstrap: no child is created until the bridge assigns this process to a Job Object."""
import json
import os
import subprocess  # nosec B404
import sys

# Subprocess execution is the authenticated bridge feature; shell parsing is disabled.


def main():
    try:
        spec = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        argv = spec["argv"]
        cwd = spec.get("cwd") or None
        env = os.environ.copy()
        env.update({str(k): str(v) for k, v in spec.get("env_overrides", {}).items()})
        child = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=None,
            stderr=None,
            # argv is intentional authenticated input and is never interpreted by a shell.
            shell=False,  # nosec B603
        )
        return child.wait()
    except Exception as exc:  # noqa: BLE001 - bootstrap converts startup failures to bounded stderr
        print(f"bridge bootstrap failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return 127


if __name__ == "__main__":
    raise SystemExit(main())
