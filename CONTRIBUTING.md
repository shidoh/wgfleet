# Contributing to wgfleet

Thanks for your interest in improving wgfleet. This document covers the workflow,
conventions, and quality bar for changes.

## Ground rules

- **Working language is English.** All code, comments, identifiers, logs, commit
  messages, and documentation are in English.
- **Never commit secrets or real infrastructure details** (private keys, real
  IPs, hostnames, credentials). The example configs use documentation-range
  addresses on purpose.
- Keep changes focused. One logical change per pull request.

## Development setup

You need a recent Go toolchain (see `go.mod` for the version). Common tasks are
in the `Makefile`:

```bash
make fmt      # gofmt -w cmd internal
make vet      # go vet
make test     # unit tests (table-driven)
make race     # tests with the race detector
make build    # build both binaries
make all      # fmt + vet + test + build
```

Cross-compile for Linux deployment targets with `make agent-linux` /
`make controller-linux` (`ARCH=amd64|arm64`).

## Repository layout

```
wgfleet/
├── cmd/
│   ├── wgfleet-controller/     control plane: API + UI + metrics + provisioner + PKI tooling
│   └── wgfleet-agent/          node agent: reconcile daemon (role from config)
├── internal/
│   ├── domain/                 core types: NodeSpec, AWG params, MasterSpec, CustomConfig …
│   ├── config/                 koanf/YAML config + secret references
│   ├── api/                    proto ⇄ domain conversion (+ generated pb)
│   ├── controller/
│   │   ├── store/              SQLite inventory / pubkey registry / status
│   │   ├── pki/                CA + per-node certs + mTLS configs
│   │   ├── keybroker/          pubkey registry + NodeSpec/topology rendering
│   │   ├── grpcapi/            NodeService gRPC server (mTLS)
│   │   ├── provisioner/        SSH bootstrap pipeline (facts, plan, runner+mock)
│   │   ├── provmgr/            provisioning orchestration (sync CLI + async UI)
│   │   ├── sweeper/            demotes silent nodes to Degraded
│   │   └── web/                dashboard + drain/undrain/delete actions
│   ├── agent/
│   │   ├── client/             agent mTLS gRPC client
│   │   ├── reconcile/          plan/apply engine (dry-run core)
│   │   ├── exit/               exit-role planners
│   │   ├── master/             master-role planners (mihomo + NAT + wg-easy AWG)
│   │   └── health/             self-checks → node lifecycle state
│   ├── wg/                     WG/AWG render, key gen, MTU math, AWG param generator
│   ├── netfw/                  nftables render (exit firewall + master NAT)
│   ├── routing/                policy-routing render (ip rule/route, fwmark)
│   ├── egress/                 wgcf / WARP config render
│   ├── dnsfilter/              blocky config render
│   ├── mihomo/                 mihomo config render (+ overrides deep-merge)
│   ├── compose/                master docker-compose render (wg-easy + mihomo)
│   ├── wgeasy/                 wg-easy SQLite AWG configuration
│   └── metrics/                Prometheus collectors (controller store + agent)
├── proto/wgfleet/v1/           gRPC contract
├── deploy/
│   ├── systemd/                unit templates
│   └── examples/               example controller.yaml / agent.yaml
├── internal/version/           build version (stamped via -ldflags at compile)
├── docs/
│   ├── QUICKSTART.md           two blank servers to a working VPN (ships as INSTALL.md)
│   ├── manifest.md             annotated controller.yaml / agent.yaml + secret schemes
│   ├── configuration.md        COMPLETE config reference (every key) + upstream doc links
│   ├── cli.md                  every flag on both binaries
│   ├── operations.md           dashboard, VLESS clients, backup/restore, metrics, health
│   ├── DESIGN.md               full project context + conventions
│   ├── lessons.md              hard-won operational lessons baked into reconcile
│   ├── adr/                    architecture decision records (0001–0032)
│   ├── onboarding.md           node provisioning walkthrough
│   ├── colocated-controller-master.md  co-location on the master (default for small fleets)
│   ├── recipes/                task-oriented config recipes (RU split-tunnel + DNS filter, …)
│   ├── secrets-sops.md         SOPS/age secret provider setup
│   └── upgrade.md              agent binary upgrade procedure + wire-contract versioning
├── DISCLAIMER.md  ·  SECURITY.md  ·  CONTRIBUTING.md
```

## Conventions

- **Commits** follow [Conventional Commits](https://www.conventionalcommits.org/):
  `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `perf:`, `ci:`.
- **Errors** are wrapped (`fmt.Errorf("...: %w", err)`), never silently
  swallowed. `context.Context` is threaded through anything that does I/O.
- **Logging** uses `log/slog` with structured fields, not string concatenation.
- **Reconcilers are idempotent** and must support plan/dry-run: rendering is a
  pure function with no side effects; `Apply` only runs in apply mode; secrets
  are redacted in plan output.
- **Tests** are table-driven; provisioning is tested against SSH mocks, not live
  nodes. Keep `gofmt`, `go vet` and `go test -race ./...` clean — those four steps are the
  gate, and `make lint` is not one of them (there is no such rule).
- **Significant architectural decisions** get an ADR under `docs/adr/`.

## Before opening a pull request

1. `make all` is green (fmt, vet, test, build).
2. New behavior has tests.
3. No secrets, real IPs, or hostnames in the diff.
4. Docs/ADRs updated if behavior or architecture changed.

## Cutting a release

Tag and push — the `release` workflow does the rest:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

It builds **one self-contained archive per architecture** and attaches them,
plus a `SHA256SUMS`, to a GitHub Release:

| Asset | Contents |
|---|---|
| `wgfleet-<version>-linux-amd64.tar.gz` | `wgfleet-controller`, `wgfleet-agent`, `install.sh`, `deploy-master.sh`, `prepare-node.sh`, `client-diag.sh`, `LICENSE`, `DISCLAIMER.md`, `SECURITY.md`, `VERSION`, and the docs the archive renames on the way in: `INSTALL.md` (quickstart), `CONFIGURATION.md`, `MANIFEST.md`, `CLI.md`, `OPERATIONS.md`, `UPGRADE.md`, `ONBOARDING.md`, `COLOCATED-CONTROLLER-MASTER.md`, `MASTER-MIGRATION.md`, `CLIENT-MIGRATION.md`, `SUPPORT-BUNDLE.md`, plus `examples/`, `systemd/`, `monitoring/`. Intra-doc links are rewritten to those names by the `fixlinks` pass — a tester has no repo, so a link that escapes the package root is a dead end, and two tests guard it |
| `wgfleet-<version>-linux-arm64.tar.gz` | same, for ARM |
| `SHA256SUMS` | checksums over the archives |

Tags with a pre-release suffix (`v0.1.0-rc1`) are published as prereleases.
Build the same archive locally with `make release-archive ARCH=amd64` — do that
before tagging if you changed packaging, and smoke-test the installer:

```sh
make release-archive ARCH=amd64
docker run --rm --platform linux/amd64 -v "$PWD/dist/wgfleet-linux-amd64:/pkg:ro" \
  ubuntu:24.04 bash -c 'cp -r /pkg /p && cd /p && SKIP_DEPS=1 ./install.sh'
```

Archive filenames carry the **version** (`wgfleet-<version>-linux-<arch>.tar.gz`),
so `releases/latest/download/...` cannot be used as a fixed URL. In standalone
mode `install.sh` therefore resolves the current tag first — it follows the
`/releases/latest` redirect, reads the version off the effective `/tag/<version>`
URL, and builds the download URL from it. If you change the archive naming, change
that resolution step in `install.sh` in the same commit. The build identity is
also inside the archive (`VERSION`, and `--version` on either binary).

## Background reading

- `README.md` — architecture, configuration, CLI, operations.
- `docs/DESIGN.md` — full project context and conventions.
- `maintainer notes` — hard-won operational lessons the platform must honor.
- `docs/adr/` — architecture decision records.

## License of contributions

wgfleet is licensed under the **AGPL-3.0** (see [LICENSE](LICENSE)). By opening a
pull request you agree that your contribution is licensed under the same terms.
