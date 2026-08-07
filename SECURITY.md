# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.x | Yes |

## Report a vulnerability

Use a private GitHub security advisory:

https://github.com/bgrablin/hermes-windows-bridge/security/advisories/new

If private vulnerability reporting is unavailable, open a blank repository issue titled `Security contact request`. Include no vulnerability details. A maintainer will use that request to arrange a private channel.

Include the affected version, observed behavior, reproduction conditions, and impact. Do not include live bearer tokens, TLS private keys, private hostnames, network addresses, prompts, raw command input, or private state files.

Do not put undisclosed vulnerability details in a public issue.

## Scope

Security reports should concern the bridge server, controller client, release verifier, process containment, authentication, transport pinning, request validation, state protection, or information handling.

The following are documented trust assumptions, not vulnerabilities by themselves:

- an authenticated caller can request privileged shell execution
- the blind GUI marker guard is bounded defense in depth, not an adversarial command sandbox
- host firewall or VPN policy controls who can reach the listener
- host compromise is outside the application trust boundary
