# Contributing

Bug reports, documentation fixes, tests, and focused code improvements are welcome. Contributions must preserve the bridge's security boundary, deterministic release inventory, and public-source privacy checks.

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before starting

- Search existing issues before opening a new one.
- Use a private [GitHub security advisory](https://github.com/bgrablin/hermes-windows-bridge/security/advisories/new) for suspected vulnerabilities. Do not disclose vulnerability details in an issue.
- Open an issue before substantial changes to authentication, transport, process containment, release layout, private-state handling, or controller compatibility.
- Small bug fixes, tests, and documentation corrections can go directly to a pull request.

Maintainer availability varies. The project does not promise a response or release schedule.

## Development setup

Use Python 3.11 or newer. Create an isolated environment and install the verification tools:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install pytest ruff
```

Run the same portable checks used in CI:

```bash
python -m compileall -q hermes_windows_bridge.py bridge_child_bootstrap.py tools scripts tests
python -m ruff check .
python scripts/public_surface_check.py
python -m pytest -q
```

Windows-specific runtime checks run in GitHub Actions. If a change affects Windows process containment, ACLs, PowerShell behavior, or certificate handling, describe any local Windows validation in the pull request.

## Pull requests

Keep each pull request focused. Explain the problem, the chosen approach, and the validation performed. Add or update tests for behavior changes. Update operator or security documentation when the user-visible behavior, trust boundary, deployment procedure, or release inventory changes.

Never include live credentials, tokens, private keys, certificates, host identities, private network details, private paths, or raw operational logs. Use documentation-only examples and reserved addresses.

A maintainer may request changes or decline work that expands the project beyond a secure, portable Windows execution bridge. By submitting a contribution, you agree that it is licensed under the project's [Apache License 2.0](LICENSE).
