// Package version carries the build identity stamped into both binaries at link
// time via -ldflags. It is intentionally dependency-free so any package can
// import it without cycles.
//
// The build version (git tag/commit) is for humans and observability; it is NOT
// the compatibility key. Controller↔agent wire compatibility is governed by the
// separate, monotonic api.WireContractVersion, which only changes on breaking
// protocol changes. See docs/upgrade.md.
package version

import (
	"fmt"
	"runtime"
	"strings"
)

// These are overridden at build time:
//
//	go build -ldflags "-X github.com/shidoh/wgfleet/internal/version.Version=v1.2.3 ..."
//
// The Makefile fills them from git. Defaults keep `go run`/`go test` builds
// honest about being un-stamped dev builds.
var (
	Version   = "dev"     // git tag or "dev"
	Commit    = "none"    // short git SHA (suffixed "-dirty" with a dirty tree)
	BuildDate = "unknown" // RFC3339 UTC build timestamp
)

// String renders the full build identity for --version output and logs.
func String() string {
	return fmt.Sprintf("%s (commit %s, built %s, %s)", Version, Commit, BuildDate, runtime.Version())
}

// Short renders just the version+commit, for status fields surfaced in the UI
// and reported to the controller.
func Short() string { return ShortOf(Version, Commit) }

// ShortOf renders the Short() identity for an arbitrary version/commit pair. It
// exists so callers that recover these fields from somewhere else — the
// controller parsing `wgfleet-agent --version` off a node during a rolling
// upgrade — produce byte-identical strings to what that agent reports over gRPC.
// A rolling upgrade gates on those two matching, so a divergence here would
// silently turn every upgrade into a timeout-and-rollback.
func ShortOf(v, commit string) string {
	if commit == "none" || commit == "" {
		return v
	}
	// Without git tags the Makefile stamps both Version and Commit from the same
	// short SHA, so they are identical or differ only by a "-dirty" suffix. Avoid the
	// redundant "sha+sha" — prefer the commit, which carries the dirty marker.
	if commit == v || strings.HasPrefix(commit, v) {
		return commit
	}
	return fmt.Sprintf("%s+%s", v, commit)
}
