# Disclaimer

**wgfleet is research and infrastructure-automation software, provided for
educational, research, and lawful operational use only.**

## No warranty

This software is provided "as is", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. In no event shall the authors or
copyright holders be liable for any claim, damages, or other liability, whether
in an action of contract, tort, or otherwise, arising from, out of, or in
connection with the software or its use.

You run it at your own risk. It manages firewalls, routing, kernel networking,
and remote machines over SSH; a misconfiguration can take a host or a whole fleet
offline. Always use the built-in **plan / dry-run** mode before applying changes
to production, and keep out-of-band access to your nodes.

## Legality is your responsibility

wgfleet automates the operation of VPN and traffic-obfuscation infrastructure
(WireGuard / AmneziaWG, Cloudflare WARP, proxy routing, DNS filtering). The
legality of deploying, operating, or using such tools — and of circumventing
network restrictions — **varies by jurisdiction**. In some countries it is
restricted or prohibited.

You are solely responsible for ensuring that your use of this software complies
with all applicable laws, regulations, and contracts (including the terms of
service of any third party you connect to, such as VPS providers and Cloudflare).
The authors do not endorse or encourage any unlawful use.

## Operator responsibilities

- You are responsible for any traffic that egresses through infrastructure you
  operate, and for the privacy and security of any users you serve.
- Secure your management plane. Admin UIs and metrics are designed to bind to a
  private management overlay only — keep them off the public internet.
- Keep your secrets (CA keys, WARP credentials, node identities) out of version
  control. See [SECURITY.md](SECURITY.md).

## No affiliation

This project is not affiliated with, endorsed by, or sponsored by WireGuard,
AmneziaWG, Cloudflare, ZeroTier, mihomo, or any other third-party project or
company referenced here. All trademarks are the property of their respective
owners. Third-party components are used under their own licenses.
