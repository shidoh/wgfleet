# Security policy

## Reporting a vulnerability

If you discover a security vulnerability in wgfleet, please report it
**privately**. Do not open a public issue for security problems.

- Open a [GitHub security advisory](https://github.com/shidoh/wgfleet/security/advisories/new)
  (preferred), or
- Contact the maintainer privately through the contact listed on the GitHub
  profile.

Please include enough detail to reproduce: affected component, version/commit,
configuration, and impact. We aim to acknowledge reports within a reasonable
time and will coordinate a fix and disclosure timeline with you.

## Scope

wgfleet is a control plane that manages firewalls, routing, kernel networking,
secrets, and remote machines over SSH and mTLS. Security-relevant areas include:

- the controller↔agent gRPC/mTLS channel and the PKI/key broker,
- the SSH provisioning bootstrap,
- the Web UI authentication and session handling,
- secret loading (env / file / SOPS-age),
- rendered firewall (nftables) and routing policy.

## Operating securely

- **Never commit secrets.** WireGuard/AmneziaWG private keys, the CA key, WARP
  credentials, and node identities must stay out of git. The provided
  `.gitignore` excludes the common patterns; verify before pushing.
- **Keep private keys on the node.** By design the controller brokers only
  public keys; node private keys are generated on the node and never leave it.
- **Bind the management plane privately.** Admin UIs and `/metrics` are meant to
  listen on the management overlay (e.g. ZeroTier) only, never the public
  interface.
- **Use mTLS for control traffic.** Each node gets its own client certificate at
  bootstrap; revoking it removes the node from the fleet.
- **Plan before apply.** Use dry-run / plan mode to review rendered configs and
  redacted secrets before any change reaches production.

See [DISCLAIMER.md](DISCLAIMER.md) for legal and operational responsibilities.
