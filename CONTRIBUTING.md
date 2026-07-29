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
make fmt      # gofumpt formatting
make vet      # go vet
make test     # unit tests (table-driven)
make race     # tests with the race detector
make build    # build both binaries
make all      # fmt + vet + test + build
```

Cross-compile for Linux deployment targets with `make agent-linux` /
`make controller-linux` (`ARCH=amd64|arm64`).

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
  nodes. Keep `golangci-lint` and `gofumpt` clean.
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
| `wgfleet-<version>-linux-amd64.tar.gz` | `wgfleet-controller`, `wgfleet-agent`, `install.sh`, `INSTALL.md` (the quickstart), `CONFIGURATION.md`, `LICENSE`, `DISCLAIMER.md`, `prepare-node.sh`, `examples/`, `systemd/`, `monitoring/`, `VERSION` (unpacks into `wgfleet-linux-amd64/`) |
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
