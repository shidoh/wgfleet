# Encrypting controller secrets with SOPS + age

The controller resolves `secret://NAME` references through a secret provider. By
default that is the env provider (`secret://NAME` → `$WGFLEET_SECRET_<NAME>`).
This runbook sets up the **SOPS/age** provider so secrets — most importantly the
fleet CA private key — live encrypted at rest and are decrypted only in the
controller's memory at startup. See ADR-0018 for the design.

> The decrypted secrets never touch disk. The age private key is supplied to the
> controller via its environment; wgfleet never handles it directly.

## Prerequisites

- [`sops`](https://github.com/getsops/sops) and [`age`](https://github.com/FiloSottile/age)
  installed on the controller host.

## 1. Generate an age identity

```sh
mkdir -p /etc/wgfleet
age-keygen -o /etc/wgfleet/age.key      # prints the public key (age1...)
chmod 600 /etc/wgfleet/age.key
```

Keep `age.key` off git and backed up: losing it means losing the secrets.

## 2. Generate the CA, then move the key into SOPS

Generate the CA to files (the tooling needs a writable path for this step):

```sh
wgfleet-controller --init-pki --config /etc/wgfleet/controller.yaml
# writes ca.crt (0644) and ca.key (0600) at the configured pki paths
```

Create a flat secrets file holding the CA key as a YAML block scalar:

```sh
{
  printf 'ca-key: |\n'
  sed 's/^/  /' /etc/wgfleet/ca.key
} > /etc/wgfleet/secrets.yaml
```

Encrypt it in place with your age recipient (the public key from step 1):

```sh
sops --encrypt --age age1YOUR_PUBLIC_KEY \
  --output /etc/wgfleet/secrets.enc.yaml /etc/wgfleet/secrets.yaml

shred -u /etc/wgfleet/secrets.yaml /etc/wgfleet/ca.key   # remove the plaintext
```

`secrets.enc.yaml` is safe to keep on disk (values are encrypted, keys are
plaintext). `ca.crt` stays a normal file — it is public.

## 3. Point the controller at SOPS

In `controller.yaml`:

```yaml
controller:
  pki:
    ca_cert: "/etc/wgfleet/ca.crt"
    ca_key: "secret://ca-key"          # resolved in memory via the provider
  secrets:
    sops_file: "/etc/wgfleet/secrets.enc.yaml"
```

## 4. Give the controller the age key in its environment

The `sops` CLI reads the age identity from `SOPS_AGE_KEY_FILE`. For systemd:

```ini
# /etc/systemd/system/wgfleet-controller.service.d/secrets.conf
[Service]
Environment=SOPS_AGE_KEY_FILE=/etc/wgfleet/age.key
```

```sh
systemctl daemon-reload
systemctl restart wgfleet-controller
```

On startup the controller decrypts `secrets.enc.yaml` once, resolves
`secret://ca-key` to the CA private key in memory, and loads the CA. A missing or
wrong age key fails fast at startup.

## Adding more secrets

Add keys to the secrets file and reference them with `secret://NAME`:

```sh
sops /etc/wgfleet/secrets.enc.yaml      # opens decrypted in $EDITOR, re-encrypts on save
```

```yaml
ca-key: |
  -----BEGIN EC PRIVATE KEY-----
  ...
warp-token: "abc123..."
```

`secret://warp-token` then resolves to that value.

Two fields are wired through the provider today: `controller.pki.ca_key` and
`fleet.awg3_key`. The second one matters more than it looks — whenever header
protection is on for any node, the controller **refuses to start** until that secret
resolves to at least 32 bytes, so putting it behind a provider makes the provider a
startup dependency of the whole control plane. Other fields are a follow-up (ADR-0018).

⚠️ **Restoring onto a rebuilt host.** `--restore` preflights every destination in the
archive against *this* host's `controller.yaml` and writes nothing if one is not a
place this host keeps files. A fresh host whose config does not yet name
`controller.secrets.sops_file` will therefore refuse the whole restore rather than
land it partially. Put the config in place first, then restore — the "restore, then
configure" order does not work.
