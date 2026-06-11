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

.PHONY: all build test race vet fmt lint proto tidy clean agent-linux controller-linux

all: fmt vet test build

build:
	$(GO) build ./...

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
	GOOS=linux GOARCH=$(ARCH) CGO_ENABLED=0 $(GO) build \
		-o $(DIST)/wgfleet-agent-linux-$(ARCH) ./cmd/wgfleet-agent
	@echo "built $(DIST)/wgfleet-agent-linux-$(ARCH)  (pass to: controller --provision <node> --agent-bin $(DIST)/wgfleet-agent-linux-$(ARCH))"

# Build the Linux controller (useful when co-locating the control plane on a VM).
controller-linux:
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=$(ARCH) CGO_ENABLED=0 $(GO) build \
		-o $(DIST)/wgfleet-controller-linux-$(ARCH) ./cmd/wgfleet-controller
	@echo "built $(DIST)/wgfleet-controller-linux-$(ARCH)"

tidy:
	$(GO) mod tidy

clean:
	rm -rf bin $(DIST)
