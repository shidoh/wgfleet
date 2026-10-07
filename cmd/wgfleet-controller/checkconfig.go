package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
// storeOverride, when non-empty, is the --store flag: it overrides controller.store
// everywhere else in this binary, so the check has to see the same value the
// controller would actually open.
func checkManifest(path, storeOverride string) error {
	cfg, err := checkManifestOnly(path)
	if err != nil {
		return err
	}
	if storeOverride != "" {
		cfg.Controller.Store = storeOverride
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
	printMasterModel(os.Stdout, cfg.Fleet)

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
	// Advisory, not a load failure: the same warning the running controller logs at
	// startup, surfaced here so a manifest edit can be checked before it is applied.
	for _, w := range config.ClientAWGTunnelWarnings(*cfg) {
		fmt.Printf("\nwarning: %s\n", w)
	}
	return cfg, nil
}

// printMasterModel prints what places every master on every exit: the anchor
// label the exits' interfaces are derived from, the base master, and each
// master's slot. Changing any of them on a running fleet re-keys or re-addresses
// tunnels, and nothing compares them with what the fleet was started on — so the
// check shows them, for the operator to compare before the restart.
func printMasterModel(w io.Writer, f config.FleetSection) {
	orNone := func(s string) string {
		if s == "" {
			return "none"
		}
		return s
	}
	base, _ := f.BaseMaster()
	fmt.Fprintf(w, "  anchor   %s\n", orNone(f.AnchorLabel()))
	fmt.Fprintf(w, "  base     %s\n", orNone(base.Name))
	for _, m := range f.Masters {
		fmt.Fprintf(w, "  master   %s  slot %d\n", m.Name, m.Slot)
	}
	// Without a subnet the management scope is one /32 per node, so every node
	// that comes or goes rewrites the direct routes and the firewall whitelist of
	// every exit — and with several masters, under several masters' traffic.
	if len(f.Masters) > 1 && strings.TrimSpace(f.MgmtSubnet) == "" {
		fmt.Fprintf(w, "\nwarning: fleet.mgmt_subnet is not set — with several masters, adding or removing a node\n"+
			"         changes routing and firewall rules on every exit\n")
	}
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
	// The newest way to crash-loop the control plane, and it was missing: serve()
	// resolves this and returns a fatal error, so a typo'd reference passed this
	// check green and then took the controller down five seconds at a time.
	if perr == nil {
		if _, kerr := resolveAWG3Key(cfg, provider); kerr != nil {
			hostErrs = append(hostErrs, "fleet.awg3_key: "+kerr.Error())
		}
	}
	// `age` is a RUNTIME dependency of --backup and --restore, and nothing installs
	// it: not install.sh, not prepare-node.sh, and no document lists it. An operator
	// reaches for a backup immediately before a risky change, which is exactly the
	// moment to discover it rather than the moment to discover it does not work.
	//
	// A warning and not an error: a controller with no `age` serves the fleet
	// perfectly well, it merely cannot be backed up, and refusing to start over that
	// would be a worse trade than saying so.
	if _, aerr := exec.LookPath("age"); aerr != nil {
		fmt.Fprintf(os.Stderr, "\nwarning: `age` is not installed on this host.\n"+
			"  --backup and --restore shell out to it, so both will fail; the controller itself is fine.\n"+
			"  Install it before you need it (apt install age).\n")
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
		// First start: store.Open will create the file — but only if it can. A
		// directory that does not exist is not a first start, it is a path the
		// controller will fail on at startup with `unable to open database file (14)`,
		// which is the crash loop this whole subcommand exists to catch. Measured: a
		// manifest naming /nonexistent/dir/p.db passed --check-config with rc=0 and
		// then refused to start.
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if _, derr := os.Stat(dir); derr != nil {
				return fmt.Errorf("the directory for the store does not exist: %w", derr)
			}
		}
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	// Same busy tolerance as the real store (store.Open uses busy_timeout(5000)).
	// Without it this check failed instantly on a momentary SQLITE_BUSY — a
	// concurrent --backup, a checkpoint, a monitoring read — and reported that the
	// controller would not start, while the controller it is vouching for would have
	// waited and succeeded. A check that is stricter than the thing it checks gives
	// the wrong answer in the one direction that matters.
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
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
// operator-facing report is already on stderr, and a second rendering of it
// through the structured logger buries the part they need to read.
//
// The text is deliberately about the CHECK, not the manifest: both verdicts
// return this, and "manifest is not valid" was a lie for the host-readiness half —
// which is exactly the half that fails when someone validates a perfectly good
// file from their laptop.
var errCheckFailed = errors.New("--check-config found a problem (see the report above)")
