# wgfleet developer tasks. Tooling (protoc-gen-go, protoc-gen-go-grpc) is pinned
# as Go `tool` directives in go.mod and invoked via `go tool`.

GO        ?= go
PROTO_DIR := proto
PB_OUT    := internal/api/pb
PROTO_SRC := $(shell find $(PROTO_DIR) -name '*.proto')

# Cross-compile target for the node agent installed by `controller --provision
# --agent-bin`. Override ARCH=arm64 for ARM VMs (e.g. Apple-silicon Lima, AWS
# Graviton). Output lands in dist/.
ARCH      ?= amd64
DIST      := dist

# Build identity stamped into both binaries via -ldflags. VERSION comes from the
# nearest git tag (falling back to "dev"); COMMIT is the short SHA with a "-dirty"
# suffix when the tree has uncommitted changes; DATE is a UTC build timestamp.
# This is the human/observability version, NOT the wire-compatibility key (that
# is internal/api.WireContractVersion). See docs/upgrade.md.
VERSION   ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)$(shell git diff --quiet 2>/dev/null || echo -dirty)
DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
VPKG      := github.com/shidoh/wgfleet/internal/version
# EXTRA_LDFLAGS is appended to the link flags; release builds set it to "-s -w"
# to strip the symbol table and DWARF (smaller binaries). Empty for dev builds.
EXTRA_LDFLAGS ?=
LDFLAGS   := -X $(VPKG).Version=$(VERSION) -X $(VPKG).Commit=$(COMMIT) -X $(VPKG).BuildDate=$(DATE) $(EXTRA_LDFLAGS)

.PHONY: all build test race vet fmt lint proto tidy clean agent-linux controller-linux release-archive

all: fmt vet test build

build:
	$(GO) build -ldflags "$(LDFLAGS)" ./...

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w cmd internal

# Regenerate Go from protobuf. Requires protoc on PATH; plugins come from go.mod.
proto: $(PROTO_SRC)
	@mkdir -p $(PB_OUT)
	protoc \
		--proto_path=$(PROTO_DIR) \
		--plugin=protoc-gen-go=$$($(GO) tool -n protoc-gen-go) \
		--plugin=protoc-gen-go-grpc=$$($(GO) tool -n protoc-gen-go-grpc) \
		--go_out=$(PB_OUT) --go_opt=paths=source_relative \
		--go-grpc_out=$(PB_OUT) --go-grpc_opt=paths=source_relative \
		$(PROTO_SRC)

# Build the Linux node agent for installation on a VM. CGO is off (the sqlite
# driver is pure-Go and the agent doesn't use it anyway), so the binary is static
# and portable across distros.
agent-linux:
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=$(ARCH) CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" \
		-o $(DIST)/wgfleet-agent-linux-$(ARCH) ./cmd/wgfleet-agent
	@echo "built $(DIST)/wgfleet-agent-linux-$(ARCH)  (pass to: controller --provision <node> --agent-bin $(DIST)/wgfleet-agent-linux-$(ARCH))"

# Build the Linux controller (useful when co-locating the control plane on a VM).
controller-linux:
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=$(ARCH) CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" \
		-o $(DIST)/wgfleet-controller-linux-$(ARCH) ./cmd/wgfleet-controller
	@echo "built $(DIST)/wgfleet-controller-linux-$(ARCH)"

# Pack a self-contained release archive for one architecture: both binaries, the
# installer, the quickstart, reference configs and the systemd units. This is
# what a GitHub release ships (one tarball per arch, instead of loose binaries)
# — see .github/workflows/release.yml. Hand someone the tarball and INSTALL.md
# inside it walks them from a blank VM to a working fleet.
# PKG is the directory inside the tarball (kept version-free so install.sh and
# the docs can `cd wgfleet-linux-<arch>` regardless of release). ARCHIVE is the
# tarball filename, which DOES carry the version.
PKG     := wgfleet-linux-$(ARCH)
ARCHIVE := wgfleet-$(VERSION)-linux-$(ARCH)
release-archive: agent-linux controller-linux
	@rm -rf $(DIST)/$(PKG) $(DIST)/wgfleet-*-linux-$(ARCH).tar.gz
	@mkdir -p $(DIST)/$(PKG)/examples $(DIST)/$(PKG)/systemd $(DIST)/$(PKG)/monitoring
	cp $(DIST)/wgfleet-controller-linux-$(ARCH) $(DIST)/$(PKG)/wgfleet-controller
	cp $(DIST)/wgfleet-agent-linux-$(ARCH)      $(DIST)/$(PKG)/wgfleet-agent
	cp install.sh                               $(DIST)/$(PKG)/install.sh
	cp LICENSE                                  $(DIST)/$(PKG)/LICENSE
	cp DISCLAIMER.md                            $(DIST)/$(PKG)/DISCLAIMER.md
	cp docs/QUICKSTART.md                       $(DIST)/$(PKG)/INSTALL.md
	cp docs/configuration.md                    $(DIST)/$(PKG)/CONFIGURATION.md
	cp docs/master-migration.md                 $(DIST)/$(PKG)/MIGRATION.md
	cp docs/support-bundle.md                   $(DIST)/$(PKG)/SUPPORT-BUNDLE.md
	cp deploy/prepare-node.sh                   $(DIST)/$(PKG)/prepare-node.sh
	cp deploy/client-diag.sh                    $(DIST)/$(PKG)/client-diag.sh
	cp deploy/examples/controller.yaml deploy/examples/agent.yaml $(DIST)/$(PKG)/examples/
	cp deploy/examples/controller-split-ru.yaml $(DIST)/$(PKG)/examples/
	cp docs/recipes/ru-split-tunnel-dns-filter.md $(DIST)/$(PKG)/examples/RU-SPLIT-TUNNEL.md
	cp deploy/systemd/*.service                 $(DIST)/$(PKG)/systemd/
	cp deploy/monitoring/grafana-dashboard.json deploy/monitoring/README.md $(DIST)/$(PKG)/monitoring/
	cp deploy/monitoring/servicemonitor.yaml deploy/monitoring/scrapeconfig.yaml deploy/monitoring/vmstaticscrape.yaml $(DIST)/$(PKG)/monitoring/
	@echo "$(VERSION) $(COMMIT) $(DATE) linux/$(ARCH)" > $(DIST)/$(PKG)/VERSION
	chmod 0755 $(DIST)/$(PKG)/wgfleet-controller $(DIST)/$(PKG)/wgfleet-agent $(DIST)/$(PKG)/*.sh
	tar -C $(DIST) -czf $(DIST)/$(ARCHIVE).tar.gz $(PKG)
	@echo "packed $(DIST)/$(ARCHIVE).tar.gz"

tidy:
	$(GO) mod tidy

clean:
	rm -rf bin $(DIST)
