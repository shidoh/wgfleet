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
