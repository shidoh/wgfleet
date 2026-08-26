package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/clientimport"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/wgeasy"
)

// runClientImport moves one master's wg-easy client credentials into the
// controller store. It is a one-shot migration step, not a reconciler: run it
// once per master, with --plan first.
//
// It must run ON the master, because wg-easy's database is a local file there.
// That is also why the default path is wg-easy's own — the operator should not
// have to know where a container we are retiring kept its state.
func runClientImport(ctx context.Context, st store.Store, cfg *config.ControllerConfig, masterID, dbPath string, plan bool) error {
	master, ok := masterByName(cfg, masterID)
	if !ok {
		return fmt.Errorf("import: %q is not a master in this manifest", masterID)
	}
	if dbPath == "" {
		dbPath = wgeasy.DefaultDBPath
	}
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("import: wg-easy database %q: %w (run this on the master, or pass --wg-easy-db)", dbPath, err)
	}

	serverAddr := ""
	if prefix, err := netip.ParsePrefix(master.ClientAWG.AddressPool); err == nil {
		if first := prefix.Masked().Addr().Next(); first.IsValid() {
			serverAddr = first.String()
		}
	}
	in := clientimport.Input{
		MasterID:      masterID,
		DBPath:        dbPath,
		Pool:          master.ClientAWG.AddressPool,
		ServerAddress: serverAddr,
		IDFor:         func(string) string { return randomCredentialID() },
		Now:           func() time.Time { return time.Now().UTC() },
	}

	run := clientimport.Apply
	if plan {
		run = clientimport.Plan
	}
	report, err := run(ctx, st, in)
	if err != nil {
		return err
	}
	fmt.Print(report.Render(!plan))
	if plan {
		fmt.Println("\ndry run: nothing was written. Re-run without --plan to import.")
		return nil
	}
	fmt.Printf("\nimported into %s. The credentials are now the controller's; wg-easy still owns the\n"+
		"interface until you set fleet.masters[].client_awg.managed: true and let the agent reconcile.\n",
		cfg.Controller.Store)
	return nil
}

// masterByName finds a master's manifest entry.
func masterByName(cfg *config.ControllerConfig, name string) (config.MasterConfig, bool) {
	for _, m := range cfg.Fleet.Masters {
		if m.Name == name {
			return m, true
		}
	}
	return config.MasterConfig{}, false
}

// randomCredentialID mints the stable identity of an imported credential. It is
// generated here, before the store write, so the write itself stays a
// deterministic record — the same discipline the issue path follows for the sake
// of replicated state (ADR-0027).
func randomCredentialID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
