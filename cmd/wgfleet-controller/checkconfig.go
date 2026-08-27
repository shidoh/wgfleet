package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"

	_ "modernc.org/sqlite" // read-only probe of the store's schema version

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
)

// --check-config answers the question a restart otherwise answers destructively.
//
// It reports TWO verdicts, separately and on purpose:
//
//  1. Is the manifest itself good? Answerable anywhere.
//  2. Would a controller actually start with it ON THIS MACHINE? A valid manifest
//     still crash-loops the control plane when the CA is missing, a secret://
//     reference will not resolve, or the store was written by a newer build —
//     none of which config.Load can see, and all of which exit non-zero under the
//     unit's Restart=on-failure.
//
// Keeping them apart matters because validating a manifest from somewhere other
// than the controller's own host is a real and useful thing to do, and the second
// verdict legitimately fails there. Folding them together would report a perfectly
// good file as bad.
//
// Nothing here changes anything — not the file's mode (which startup self-heals),
// not the store (which startup creates and migrates).

// checkManifest runs both verdicts. main wires this to --check-config.
func checkManifest(path string) error {
	cfg, err := checkManifestOnly(path)
	if err != nil {
		return err
	}
	return checkHostReadiness(cfg)
}

// checkManifestOnly is the first verdict: the file parses and validates. It
// prints what the controller would run with, so the answer is not merely "valid"
// but "valid, and here is what you just agreed to".
//
// The digest is of the file as it is on disk — deliberately the same value the
// drift check compares against later, so "is the running controller on this
// manifest" is answerable by comparing two printed strings.
func checkManifestOnly(path string) (*config.ControllerConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest %q: %w", path, err)
	}
	cfg, err := config.Load(path, &config.ControllerConfig{})
	if err != nil {
		// Not wrapped as "load config": the operator asked whether the file is good,
		// and the answer is the validation report, not a stack of prefixes.
		fmt.Fprintf(os.Stderr, "manifest %s is NOT valid:\n\n%v\n", path, err)
		return nil, errCheckFailed
	}

	sum := sha256.Sum256(raw)
	fmt.Printf("manifest %s is valid\n", path)
	fmt.Printf("  sha256   %s\n", hex.EncodeToString(sum[:]))
	fmt.Printf("  masters  %d\n", len(cfg.Fleet.Masters))
	fmt.Printf("  exits    %d\n", len(cfg.Fleet.Exits))

	// The question operations insisted be answerable by ONE command: is the running
	// controller actually on this file? Until now nothing could answer it — you
	// compared timestamps and hoped. The running controller records what it loaded;
	// if that record disagrees with the file in front of us, say so here, where the
	// operator is already looking, rather than leaving it to a metric they may not
	// have wired up yet.
	if running := config.ReadEffectiveDigest(config.EffectiveFile); running != "" && running != hex.EncodeToString(sum[:]) {
		fmt.Printf("\nwarning: the running controller is on a DIFFERENT manifest (%s)\n", running)
		fmt.Printf("         this file has not been applied — restart the controller to apply it\n")
	}

	// A warning, never a failure: the file is readable and valid either way, and an
	// operator running a check should not have a non-zero exit hide behind a
	// permissions nit. But the manifest carries private keys and the wg-easy admin
	// password, so a loose mode is worth saying out loud — the startup self-heal
	// that would have fixed it does not run on a check.
	if fi, statErr := os.Stat(path); statErr == nil {
		if mode := fi.Mode().Perm(); mode&0o077 != 0 {
			fmt.Printf("\nwarning: mode is %04o, and this file holds private keys — starting the controller tightens it to 0600\n", mode)
		}
	}
	return cfg, nil
}

// checkHostReadiness is the second verdict: the things a restart does before it
// serves, each of which exits non-zero on failure.
func checkHostReadiness(cfg *config.ControllerConfig) error {
	var hostErrs []string
	provider, perr := config.NewSecretProvider(context.Background(), cfg)
	if perr != nil {
		hostErrs = append(hostErrs, "secret provider: "+perr.Error())
	} else if _, cerr := loadCA(cfg, provider); cerr != nil {
		hostErrs = append(hostErrs, "CA: "+cerr.Error()+" (run --init-pki first?)")
	}
	if serr := checkStoreOpenable(cfg.Controller.Store); serr != nil {
		hostErrs = append(hostErrs, "store: "+serr.Error())
	}
	if len(hostErrs) == 0 {
		return nil
	}
	fmt.Fprintf(os.Stderr, "\nthe manifest is fine, but a controller would NOT start ON THIS HOST:\n\n")
	for _, e := range hostErrs {
		fmt.Fprintf(os.Stderr, "  %s\n", e)
	}
	fmt.Fprintf(os.Stderr, "\nthese are host-local checks — expected to fail when validating a manifest\n"+
		"from anywhere but the controller's own machine.\n")
	return errCheckFailed
}

// checkStoreOpenable answers "would store.Open succeed" WITHOUT opening it:
// opening creates the database and runs migrations, and this flag promises to
// change nothing. An absent file is fine — that is a first start. A file that is
// there must be readable and must not carry a schema newer than this binary,
// which is the one store failure that is otherwise discovered by crash-looping.
func checkStoreOpenable(path string) error {
	if path == "" {
		return errors.New("controller.store is empty")
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // first start: Open will create it
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if known := store.MigrationCount(); version > known {
		return fmt.Errorf("schema is version %d but this build only knows %d — "+
			"it was written by a newer wgfleet-controller", version, known)
	}
	return nil
}

// errCheckFailed marks the one failure whose message main must NOT log: the
// operator-facing validation report is already on stderr, and a second rendering
// of it through the structured logger buries the part they need to read.
var errCheckFailed = errors.New("manifest is not valid")
