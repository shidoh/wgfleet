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

## Background reading

- `README.md` — architecture, configuration, CLI, operations.
- `docs/DESIGN.md` — full project context and conventions.
- `maintainer notes` — hard-won operational lessons the platform must honor.
- `docs/adr/` — architecture decision records.
