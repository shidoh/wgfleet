# Security policy

## Reporting a vulnerability

If you discover a security vulnerability in wgfleet, please report it
**privately**. Do not open a public issue for security problems.

- Open a [GitHub security advisory](https://github.com/shidoh/wgfleet/security/advisories/new)
  (preferred), or
- Contact the maintainer privately through the contact listed on the GitHub
  profile.

Include enough detail to reproduce: affected component, version, configuration,
and impact. We aim to acknowledge reports within a reasonable time and will
coordinate a fix and disclosure timeline with you.

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
  credentials, and node identities must stay out of version control.
- **Keep node private keys on the node.** The controller brokers only public
  keys for nodes; a node's private key is generated on it and never leaves.
  End-user client credentials are the exception: the controller stores client
  private keys so it can re-issue configs, so the store file is itself key
  material — treat `state.db` with the same care as the CA key.
- **Bind the management plane privately.** Admin UIs and `/metrics` listen on
  the management overlay (e.g. ZeroTier) only, never the public interface.
- **Use mTLS for control traffic.** Each node gets its own client certificate at
  bootstrap and renews it itself over that channel. There is no revocation list:
  decommissioning or deleting a node makes the controller refuse its next renewal,
  but a certificate already issued stays valid until it expires. Cutting a node
  off before then means reissuing the CA.
- **Plan before apply.** Use plan mode to review rendered configs and redacted
  secrets before any change reaches production.

See [DISCLAIMER.md](DISCLAIMER.md) for legal and operational responsibilities.
