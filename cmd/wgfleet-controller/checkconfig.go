package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/shidoh/wgfleet/internal/config"
)

// checkManifest validates a manifest without starting anything and without
// touching the file. It prints what the controller would run with, so the answer
// is not merely "valid" but "valid, and here is what you just agreed to".
//
// The digest is of the file as it is on disk. That is deliberately the same value
// the drift check will compare against later: "is the running controller on this
// manifest" is answerable by comparing two printed strings.
func checkManifest(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read manifest %q: %w", path, err)
	}
	cfg, err := config.Load(path, &config.ControllerConfig{})
	if err != nil {
		// Not wrapped as "load config": the operator asked whether the file is good,
		// and the answer is the validation report, not a stack of prefixes.
		fmt.Fprintf(os.Stderr, "manifest %s is NOT valid:\n\n%v\n", path, err)
		return errCheckFailed
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
	return nil
}

// errCheckFailed marks the one failure whose message main must NOT log: the
// operator-facing validation report is already on stderr, and a second rendering
// of it through the structured logger buries the part they need to read.
var errCheckFailed = errors.New("manifest is not valid")
