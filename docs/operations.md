# Operations

This guide installs a hash-closed bridge package without placing the bearer token or TLS private key inside that package.

## 1. Create a listener certificate

The certificate subject alternative name must match the listener identity used by the controller. DNS listener identities use canonical ASCII labels: use the Punycode A-label form for an internationalized name and omit the trailing root dot. For a DNS listener:

```bash
mkdir -p local
openssl req -x509 -newkey rsa:3072 -sha256 -nodes \
  -keyout local/bridge-key.pem \
  -out local/bridge-cert.pem \
  -days 397 \
  -subj "/CN=bridge.example" \
  -addext "subjectAltName=DNS:bridge.example"
```

For a literal IP listener, create an IP SAN instead. Do not encode the address as a DNS SAN:

```bash
openssl req -x509 -newkey rsa:3072 -sha256 -nodes \
  -keyout local/bridge-key.pem \
  -out local/bridge-cert.pem \
  -days 397 \
  -subj "/CN=192.0.2.10" \
  -addext "subjectAltName=IP:192.0.2.10"
```

Keep `bridge-key.pem` private. Copy only `bridge-cert.pem` to the controller.

## 2. Build the release

The builder copies exactly six allowlisted payloads and writes `bridge-release.json`. It rejects symbolic links, reparse points, special files, duplicate JSON keys, wildcard or non-canonical listeners, extra package files, and certificate inputs that are not exactly one X.509 certificate-only PEM object with an exact canonical DNS or normalized IP SAN for `--listen-address`.

```bash
python3 tools/build_release.py package \
  --source . \
  --output dist/bridge \
  --certificate local/bridge-cert.pem \
  --listen-address bridge.example \
  --port 8765
```

Verify the package before transfer:

```bash
python3 tools/build_release.py check \
  --root dist/bridge \
  --manifest dist/bridge/bridge-release.json \
  --mode package
```

## 3. Protect Windows state

Run the following in PowerShell as the account that will run the bridge. Set `$Release` and `$TlsKey` to local absolute paths.

```powershell
$Release = (Resolve-Path '.\dist\bridge').Path
$TlsKey = (Resolve-Path '.\local\bridge-key.pem').Path
$StateRoot = Join-Path $env:LOCALAPPDATA 'HermesWindowsBridge'

. (Join-Path $Release 'bridge-private-state.ps1')
$PrivateState = Initialize-BridgePrivateState -StateRoot $StateRoot
$PrivateRoot = $PrivateState.PrivateRoot
$TokenFile = Join-Path $PrivateRoot 'bridge-token'

$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $bytes = New-Object byte[] 32
    $random.GetBytes($bytes)
    [IO.File]::WriteAllText($TokenFile, [Convert]::ToBase64String($bytes))
} finally {
    $random.Dispose()
}

Protect-PrivateFile -Path $TokenFile -RequireExisting
Protect-PrivateFile -Path $TlsKey -RequireExisting
```

The initializer creates the empty job state, settlement journal, pressure state, bridge log, and metrics log with exact non-inherited DACLs. It preserves existing file contents when run again. The bridge then re-attests these files before and after state transitions. If you override any state-file environment variable, create and protect that exact file with `Protect-PrivateFile` before starting the bridge.

## 4. Start the bridge

Set explicit state and executable locations. The host and port must match the release manifest.

```powershell
$env:HERMES_WINDOWS_BRIDGE_STATE_DIR = $StateRoot
$env:HERMES_WINDOWS_BRIDGE_TOKEN_FILE = $TokenFile
$env:HERMES_EXECUTABLE = (Get-Command hermes).Source

python (Join-Path $Release 'hermes_windows_bridge.py') `
  --host bridge.example `
  --port 8765 `
  --tls-cert (Join-Path $Release 'certs\bridge-cert.pem') `
  --tls-key $TlsKey `
  --release-manifest (Join-Path $Release 'bridge-release.json')
```

A non-loopback listener fails before token access and before socket bind when TLS or release attestation is invalid.

## 5. Configure the controller

```bash
install -d -m 700 ~/.config/hermes-windows-bridge
install -m 600 /secure/path/bridge-token ~/.config/hermes-windows-bridge/bridge-token
install -m 644 /secure/path/bridge-cert.pem ~/.config/hermes-windows-bridge/bridge-cert.pem
```

Set a default endpoint when useful:

```bash
export HERMES_WINDOWS_BRIDGE_URL=https://bridge.example:8765
client/hermes-windows-bridge health
```

The client also accepts `--url`, `--token-file`, and `--cert-file` for each invocation.

## 6. Restrict network access

Do not expose the bridge directly to the public Internet. Restrict inbound traffic to the controller or a narrow management network. Use a VPN when the controller crosses an untrusted network.

The application layer does not replace host firewall policy.

## 7. Observe and stop

- `GET /health` confirms the listener without authentication.
- `GET /ready` confirms authenticated readiness and release identity.
- `GET /status` returns authenticated host, admission, job, and telemetry state.
- `POST /admin/quiesce` uses a generation-bound protocol. A body of `{"action":"begin"}` closes admission immediately and returns the generation; it does not wait. Poll with `{"action":"status","generation":1}` using the returned generation until `active_global` is zero. Resume only that generation with `{"action":"resume","generation":1}`.

Stop the hosting process through the service manager or console that started it. Confirm no listener remains before replacing a release package.

## Configuration reference

| Variable | Purpose | Neutral default |
|---|---|---|
| `HERMES_WINDOWS_BRIDGE_STATE_DIR` | State root | user state directory |
| `HERMES_WINDOWS_BRIDGE_TOKEN_FILE` | Bearer token file | private state root |
| `HERMES_WINDOWS_BRIDGE_LOG` | bridge log | private state root |
| `HERMES_WINDOWS_BRIDGE_JOB_STATE` | persistent job state | private state root |
| `HERMES_WINDOWS_BRIDGE_PRESSURE_STATE` | resource-pressure state | private state root |
| `HERMES_WINDOWS_BRIDGE_METRICS_LOG` | bounded telemetry log | private state root |
| `HERMES_EXECUTABLE` | Hermes CLI path | `hermes` from `PATH` |
| `HERMES_UV_PYTHON` | Python executable for Hermes integration | current Python |
| `HERMES_PRIMARY_ROUTE` | Hermes model route | process environment |

The CLI `--host` and `--port` options override their environment defaults.
