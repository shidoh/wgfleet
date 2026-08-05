package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/provisioner"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// alwaysFailDial is a fake Dial: every SSH target it is asked to reach fails,
// so no test in this file ever dials real SSH. It stands in for "SSH to every
// exit fails" — the scenario a support bundle is wanted most.
func alwaysFailDial(domain.SSHTarget) (provisioner.Runner, error) {
	return nil, errors.New("dial refused (test)")
}

// blockingRunner never returns from Run AT ALL — not even once ctx is
// cancelled. It stands in for a wedged SSH session where the wedge is inside
// ssh.Client.NewSession() (see timeoutRunner's doc comment): the real
// SSHRunner.Run only starts watching ctx.Done() AFTER NewSession returns, so
// a connection that wedges there never reaches the code that would honor
// cancellation. A fake that itself selects on <-ctx.Done() would be modeling
// a Runner MORE cooperative than SSHRunner actually is, and would pass even
// against the old, buggy timeoutRunner that simply called through and waited
// — which is exactly how the bug survived review. timeoutRunner must bound
// this on its own, by racing the call in a goroutine rather than trusting
// the Runner underneath to give up.
type blockingRunner struct{}

func (blockingRunner) Run(ctx context.Context, cmd string) (string, error) {
	<-make(chan struct{}) // block forever; deliberately never inspects ctx
	return "", nil        // unreachable
}
func (blockingRunner) Upload(_ context.Context, _ string, _ []byte, _ os.FileMode) error { return nil }
func (blockingRunner) Close() error                                                      { return nil }

var _ provisioner.Runner = blockingRunner{}

// An exit that does not answer must not fail the bundle. The bundle is wanted
// precisely when something is down; a collector that gives up on the first
// unreachable node collects nothing on the day it matters.
func TestFleetBundleRecordsAnUnreachableExit(t *testing.T) {
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	fleet := config.FleetSection{
		Exits: []config.ExitConfig{{
			Name: "exit-de-1",
			SSH:  config.SSHConfig{Host: "198.51.100.7", User: "root", KeyPath: "/tmp/does-not-matter"},
		}},
	}

	err := writeFleetSupportBundle(context.Background(), supportFleetOpts{
		Out:   out,
		Fleet: fleet,
		Dial:  alwaysFailDial,
	})
	if err != nil {
		t.Fatalf("writeFleetSupportBundle: %v (an unreachable exit must not fail the whole bundle)", err)
	}

	body := readTarEntryController(t, out, "exit-de-1/unreachable.txt")
	if !strings.Contains(body, "dial refused") {
		t.Fatalf("exit-de-1's section did not record the unreachable reason:\n%s", body)
	}
}

// The controller's own view is a section in its own right: inventory, per-node
// state and versions, which is available even when SSH to every exit fails.
func TestFleetBundleIncludesInventoryWithoutSSH(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	ctx := context.Background()
	if err := st.UpsertNode(ctx, domain.Node{
		ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit,
		State: domain.StateReady, AgentVersion: "v1.2.3", MgmtAddr: "172.29.3.20",
	}); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	fleet := config.FleetSection{
		Exits: []config.ExitConfig{{
			Name: "exit-de-1",
			SSH:  config.SSHConfig{Host: "198.51.100.7", User: "root", KeyPath: "/tmp/does-not-matter"},
		}},
	}

	err = writeFleetSupportBundle(ctx, supportFleetOpts{
		Out:   out,
		Fleet: fleet,
		Store: st,
		Dial:  alwaysFailDial, // SSH to every exit fails — inventory must not depend on it
	})
	if err != nil {
		t.Fatalf("writeFleetSupportBundle: %v", err)
	}

	inv := readTarEntryController(t, out, "controller/inventory.txt")
	if !strings.Contains(inv, "exit-de-1") || !strings.Contains(inv, "Ready") || !strings.Contains(inv, "v1.2.3") {
		t.Fatalf("inventory did not carry the store's node state/version:\n%s", inv)
	}
}

// A wedged exit — dial succeeds, but every command just hangs — must not stall
// the run past its bounds. Before the fix, context.Background() flowed
// unmodified all the way to the Runner, so nothing ever cancelled it and
// blockingRunner would never return: this test would hang forever without the
// per-command and per-exit timeouts in walkExit. commandTimeout is set LARGER
// than exitTimeout so the assertion only passes if the per-exit cap is what
// actually bounds the run — proving the outer cap is load-bearing, not just
// the per-command one composing with a context that happens to already have a
// short deadline.
func TestFleetBundleTimesOutAWedgedExit(t *testing.T) {
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	fleet := config.FleetSection{
		Exits: []config.ExitConfig{
			{Name: "exit-wedged", SSH: config.SSHConfig{Host: "198.51.100.7", User: "root", KeyPath: "/tmp/does-not-matter"}},
			{Name: "exit-fine", SSH: config.SSHConfig{Host: "198.51.100.8", User: "root", KeyPath: "/tmp/does-not-matter"}},
		},
	}
	fineMock := provisioner.NewMockRunner()
	fineMock.DefaultResponse = "ok"

	dial := func(target domain.SSHTarget) (provisioner.Runner, error) {
		if target.Host == "198.51.100.7" {
			return blockingRunner{}, nil
		}
		return fineMock, nil
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- writeFleetSupportBundle(context.Background(), supportFleetOpts{
			Out:            out,
			Fleet:          fleet,
			Dial:           dial,
			CommandTimeout: 5 * time.Second,        // deliberately larger than ExitTimeout
			ExitTimeout:    100 * time.Millisecond, // must be what actually bounds exit-wedged
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("writeFleetSupportBundle: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("writeFleetSupportBundle did not return — a wedged exit hung the whole run")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("wedged exit was not bounded by ExitTimeout: took %s", elapsed)
	}

	wedged := readTarEntryController(t, out, "exit-wedged/fleet-walk.txt")
	if !strings.Contains(wedged, "timed out") && !strings.Contains(wedged, "budget") {
		t.Fatalf("exit-wedged's section did not record a timeout reason:\n%s", wedged)
	}

	// The other exit, and the inventory, must still be present — the wedged
	// exit's timeout must not have taken the rest of the walk down with it.
	fine := readTarEntryController(t, out, "exit-fine/identity.txt")
	if !strings.Contains(fine, "ok") {
		t.Fatalf("exit-fine's section was not collected:\n%s", fine)
	}
	_ = readTarEntryController(t, out, "controller/inventory.txt") // fails the test itself if absent
}

// readTarEntryController decompresses a gzip+tar archive and returns one
// entry's content as a string, failing the test if the archive or the entry
// cannot be read.
func readTarEntryController(t *testing.T, archivePath, name string) string {
	t.Helper()
	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			t.Fatalf("archive has no entry %q", name)
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		if hdr.Name != name {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(body)
	}
}
