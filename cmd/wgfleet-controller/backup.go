package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/backup"
)

// runBackup snapshots the controller (and co-located master, if present) into an
// age-encrypted archive at outPath. Sources are injected so callers (and tests)
// control which on-disk paths are read; production passes backup.DefaultSources.
func runBackup(src backup.Sources, outPath, recipient string, encrypt backup.EncryptFunc, cfg *config.ControllerConfig) error {
	// Say what this archive CANNOT carry before writing it, not after. "backup
	// written to ..." used to mean the same whether the fleet CA was inside it or
	// not, and the difference is discovered during a restore.
	for _, w := range src.Warnings(cfg) {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	if encrypt == nil {
		encrypt = backup.AgeEncryptor(recipient)
	}
	archive, err := backup.Export(context.Background(), backup.ExportOptions{
		Sources:     src,
		WireVersion: int(api.WireContractVersion),
		Encrypt:     encrypt,
	})
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	if err := os.WriteFile(outPath, archive, 0o600); err != nil {
		return fmt.Errorf("write archive %q: %w", outPath, err)
	}
	return nil
}

// runRestore reads an age-encrypted archive and lays it back down (or, in plan
// mode, reports what it would do). In apply mode it first refuses if a
// controller is still serving on listenAddr (spec §4 step 1).
func runRestore(ctx context.Context, archivePath string, plan bool, decrypt backup.DecryptFunc, identityPath string, wire int, listenAddr string, allowedRestoreDests map[string]bool) (backup.RestorePlan, error) {
	if decrypt == nil {
		decrypt = backup.AgeDecryptor(identityPath)
	}
	if !plan && listenAddr != "" && controllerIsLive(listenAddr) {
		return backup.RestorePlan{}, fmt.Errorf("a controller is still serving on %s; stop it before restoring", listenAddr)
	}
	raw, err := os.ReadFile(archivePath)
	if err != nil {
		return backup.RestorePlan{}, fmt.Errorf("read archive %q: %w", archivePath, err)
	}
	// Where THIS host keeps its files. The archive's own manifest says where it
	// wants each item written, and that is untrusted input — `age -r` does not
	// authenticate a sender, so a crafted archive was an arbitrary root-owned write.
	return backup.Restore(ctx, raw, backup.RestoreOptions{
		AllowedDests: allowedRestoreDests,
		Decrypt:      decrypt,
		WireVersion:  wire,
		Plan:         plan,
	})
}

// controllerIsLive reports whether something accepts a TCP connection on addr
// within a short timeout — i.e. a controller is still running.
func controllerIsLive(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// printRestorePlan prints the plan and the post-restore migration checklist.
func printRestorePlan(p backup.RestorePlan, plan bool) {
	verb := "restored"
	if plan {
		verb = "would restore"
	}
	fmt.Printf("%s %d file(s), layers=%v\n", verb, len(p.Writes), p.Layers)
	for _, w := range p.Writes {
		if w.Backup != "" {
			fmt.Printf("  %s (prior moved to %s)\n", w.Dest, w.Backup)
		} else {
			fmt.Printf("  %s\n", w.Dest)
		}
	}
	for _, warn := range p.Warnings {
		fmt.Printf("  WARNING: %s\n", warn)
	}
	if !plan {
		fmt.Println("\nPost-restore checklist:")
		fmt.Println("  1. Ensure this node's ZeroTier mgmt address matches the old controller (or update every agent.yaml `controller:` and re-issue the server cert SAN).")
		fmt.Println("  2. Start wgfleet-controller.")
		fmt.Println("  3. Wait for nodes to reconnect; confirm they return to Ready in the store / Web UI.")
	}
}
