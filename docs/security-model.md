# Security model

Hermes Windows Bridge is a privileged execution service for a trusted operator. Its controls limit transport exposure, accidental misuse, process escape, resource exhaustion, state corruption, and information reflection. They do not make arbitrary authenticated shell input safe.

## Trust boundaries

### Controller

The controller holds two trust artifacts:

- a bearer token stored in an owner-controlled private file
- the bridge public certificate used as both a CA input and an exact peer certificate pin

The packager and runtime validator accept exactly one X.509 certificate-only PEM object and require an exact canonical ASCII DNS or normalized IP subject alternative name for the configured listener. Internationalized DNS names use their Punycode A-label form; trailing root dots are rejected. The client rejects plaintext endpoints, redirects, unsafe trust-file permissions, hostname mismatches, and peer certificates whose DER bytes do not match the configured certificate.

### Network

The server binds to loopback by default. A non-loopback listener requires:

- a certificate and private key
- TLS 1.2 or newer
- an exact listener identity in `bridge-release.json`
- a complete release-manifest validation before token access and socket bind

Network reachability must still be restricted by the host firewall, VPN, or equivalent control.

### Request boundary

Operational routes require exactly one bearer-token header. The server rejects duplicate `Authorization` headers, uses constant-time comparison, and returns a stable unauthorized response.

The HTTP layer limits request threads, header time, body time, header size, body size, JSON structure, field count, string length, command length, prompt length, and toolset syntax. Validation errors do not reflect submitted values.

Terminal requests containing these literal blind-automation markers are rejected before execution:

- `SendKeys`
- `WScript.Shell`
- `AppActivate`
- `Set-Clipboard`
- `Get-Clipboard`

This is bounded defense in depth. An authenticated shell remains privileged and can express equivalent behavior through other mechanisms.

### Admission and resource boundary

Global and route-class reservations are atomic. Rejected asynchronous requests do not create job records. Sustained memory or commit pressure closes admission and persists its state. Telemetry failure also closes readiness after the configured stale interval.

### Process boundary

The bridge creates a blocked child bootstrap, assigns it to a Windows Job Object, persists process metadata for asynchronous work, then releases command bytes. Timeouts, cancellation, output limits, natural nonzero exits, and internal failures all enter the same descendant-cleanup path.

If cleanup cannot be certified, the bridge reports bounded evidence and closes readiness and later admission.

### State boundary

Job state, settlement journals, pressure state, logs, and telemetry use owner-controlled Windows DACLs. The attestor permits exactly the running account, Local System, and local Administrators. Inheritance, extra principals, reparse points, and unavailable paths fail validation.

Job state, settlement journals, and pressure state use atomic replacement and re-attest the published file. Logs and telemetry use bounded append and rotation under the same DACL boundary; they are not atomic snapshots.

### Release boundary

The release manifest binds:

- exact payload paths and roles
- file sizes and SHA-256 hashes
- the bridge source hash
- certificate PEM and DER hashes
- execution-chain order
- listener address, port, and transport
- a canonical payload-tree hash

Runtime checks allow unrelated files outside the execution closure. Both modes reject symbolic or reparse manifests and payloads. Package checks additionally require an exact package inventory with no extras.

## Information handling

Server-generated validation and error responses, bridge diagnostics, and HTTP access logs omit submitted values and intentionally avoid:

- bearer tokens
- prompts
- raw command input
- tool input
- private paths
- raw persisted state
- exception details
- query strings and job identifiers in HTTP access logs

Authenticated terminal and Hermes process stdout and stderr are caller-visible and are not redacted. Process output is size-bounded and decoded with replacement for invalid UTF-8. Operators must prevent commands and tools from emitting secrets or other private data.

## Residual risk

- A stolen bearer token and trusted network path provide privileged execution.
- Literal marker filtering is not a command sandbox or malware control.
- The bridge depends on Windows, Python, Hermes, and the operator's host-hardening posture.
- A self-signed certificate is safe only when its distribution and pinning are controlled.
- The service should not be reachable from the public Internet.
- Host compromise can bypass application-layer controls.

Use a dedicated Windows account, narrow firewall policy, full-disk encryption, host patching, and monitored token rotation where the risk warrants them.
