package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PlannedWrite describes one file restore: its destination, the mode it will be
// written with, and the .bak path the prior file was moved to ("" if none).
type PlannedWrite struct {
	Dest   string
	Mode   os.FileMode
	Backup string
}

// RestorePlan is the outcome of a restore (apply or plan).
type RestorePlan struct {
	Layers   []Layer
	Writes   []PlannedWrite
	Warnings []string
}

// RestoreOptions configures Restore.
type RestoreOptions struct {
	Decrypt     DecryptFunc
	WireVersion int // the running controller's wire-contract version
	Plan        bool
	Now         func() time.Time
	// AllowedDests is the set of absolute paths this host is willing to have written,
	// derived from its OWN configuration (see AllowedDestsFor). Empty disables the
	// check, which exists only so older tests keep compiling; every real caller
	// supplies it.
	AllowedDests map[string]bool
}

// destMode decides a restored file's permissions from THIS host's policy.
//
// The mode used to come out of the archive's manifest.json, which is the same
// untrusted input the destination came from — and closing the path while leaving the
// mode open is not a fix. `age -r` does not authenticate the sender, so an archive is
// a file anyone holding the recipient public key can build; one naming the host's own
// legitimate /etc/wgfleet/ca.key with Mode 0644 passed the allow-list and made the
// fleet CA private key world-readable. Every secret this list can name is 0600 and
// nothing else needs to be, so the policy is: private by default, 0644 only for the
// three artifacts that are not secrets.
func destMode(dest string) os.FileMode {
	switch filepath.Base(dest) {
	case "ca.crt", "node.crt", "controller.yaml", "agent.yaml":
		return 0o644
	default:
		return 0o600
	}
}

// AllowedDestsFor returns the paths a restore of THIS host may write, taken from
// the same Sources that a backup of it would read. Anything an archive asks for
// outside this set is not a restore of this host.
func AllowedDestsFor(src Sources) map[string]bool {
	allowed := map[string]bool{}
	for _, it := range plannedItems(src) {
		if it.dest != "" {
			allowed[absClean(it.dest)] = true
		}
	}
	return allowed
}

// absClean normalises a path for comparison. Absolute, because the two sides come
// from different places: the archive always names absolute destinations, while the
// allow-list is built from whatever -config the operator typed. A disaster-recovery
// run of `cd /etc/wgfleet && wgfleet-controller --config controller.yaml --restore …`
// put the bare string "controller.yaml" in the allowed set and then refused the
// archive's "/etc/wgfleet/controller.yaml" — a hard stop, invented by the guard, in
// the middle of the one procedure that must not surprise anybody.
func absClean(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return filepath.Clean(path)
}

// Restore decrypts and unpacks an archive. In apply mode it moves each existing
// destination aside to <dest>.bak-<ts> then writes the archived file atomically.
// In plan mode it validates and returns the plan without touching disk.
func Restore(ctx context.Context, archive []byte, opts RestoreOptions) (RestorePlan, error) {
	if opts.Decrypt == nil {
		return RestorePlan{}, fmt.Errorf("restore: Decrypt func is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	plaintext, err := opts.Decrypt(ctx, archive)
	if err != nil {
		return RestorePlan{}, fmt.Errorf("decrypt archive: %w", err)
	}
	m, items, err := ParseTar(plaintext)
	if err != nil {
		return RestorePlan{}, err
	}
	if m.WireVersion > opts.WireVersion {
		return RestorePlan{}, fmt.Errorf("archive wire version %d is newer than this controller (%d); upgrade before restoring", m.WireVersion, opts.WireVersion)
	}

	ts := now().UTC().Format("20060102T150405Z")
	plan := RestorePlan{Layers: m.Layers}
	if len(m.Layers) == 1 && m.Layers[0] == LayerController {
		plan.Warnings = append(plan.Warnings, "archive has no master layer: wg-easy clients and node identity are not restored")
	}

	// The archive says where each item goes. That is untrusted input.
	//
	// `age -r` does not authenticate the sender — the recipient is a public key — so
	// an archive is a file anyone who knows the key can construct, and until now
	// restore read `Dest` and `Mode` straight out of its manifest.json with no
	// allowlist, no prefix check and nothing stopping "..". That is arbitrary
	// root-owned write on the control plane host: an authorized_keys, a unit file, a
	// replacement agent.yaml.
	//
	// The fix is not to sanitise the path but to stop asking the archive. THIS host's
	// own configuration already says where each artifact belongs, and a restore that
	// wanted to write anywhere else is, by definition, not a restore of this host.
	// PREFLIGHT, then write. Validating inside the write loop meant a rejected item
	// aborted a restore that had already moved earlier files aside and replaced them:
	// on a disaster-recovery host, with the controller stopped, half the state
	// swapped and no rollback. A hostile archive got every write ahead of its bad
	// entry for free, and the far more common case — a rebuilt host whose
	// controller.yaml names one path differently — took the same damage for a typo.
	// Nothing is touched until every destination has been accepted.
	allowed := opts.AllowedDests
	for _, it := range items {
		if it.Dest == "" {
			return RestorePlan{}, fmt.Errorf("item %q has no restore destination", it.Name)
		}
		if len(allowed) > 0 && !allowed[absClean(it.Dest)] {
			return RestorePlan{}, fmt.Errorf("archive item %q wants to write %q, which is not a place this "+
				"host keeps anything — refusing before writing anything. A restore writes only where this "+
				"controller's own configuration says its files live: check that this host's controller.yaml "+
				"names the same paths the backed-up one did, then run the restore again", it.Name, it.Dest)
		}
		pw := PlannedWrite{Dest: it.Dest, Mode: destMode(it.Dest)}
		if _, err := os.Stat(it.Dest); err == nil {
			pw.Backup = it.Dest + ".bak-" + ts
		}
		plan.Writes = append(plan.Writes, pw)
	}
	if opts.Plan {
		return plan, nil
	}
	for i, it := range items {
		pw := plan.Writes[i]
		if err := os.MkdirAll(filepath.Dir(it.Dest), 0o755); err != nil {
			return RestorePlan{}, fmt.Errorf("mkdir for %q: %w", it.Dest, err)
		}
		if pw.Backup != "" {
			if err := os.Rename(it.Dest, pw.Backup); err != nil {
				return RestorePlan{}, fmt.Errorf("preflight backup %q: %w", it.Dest, err)
			}
		}
		if err := writeAtomic(it.Dest, it.Data, pw.Mode); err != nil {
			return RestorePlan{}, err
		}
		// SQLite keeps its write-ahead log and shared-memory file beside the database.
		// A clean shutdown checkpoints them away, but the only restore anybody performs
		// is onto a host that did NOT shut down cleanly — so the sidecars survive, and
		// they descend from the very database we just replaced. SQLite would then
		// replay a log belonging to a different generation of the same file over the
		// restored snapshot. They are worthless once the database is not theirs.
		if strings.HasSuffix(it.Dest, ".db") {
			for _, suffix := range []string{"-wal", "-shm"} {
				if err := os.Remove(it.Dest + suffix); err != nil && !os.IsNotExist(err) {
					return RestorePlan{}, fmt.Errorf("remove stale %s beside %q: %w", suffix, it.Dest, err)
				}
			}
		}
	}
	return plan, nil
}

// writeAtomic writes data to a temp file in the destination's directory then
// renames it into place, so a crash never leaves a half-written file.
func writeAtomic(dest string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".wgfleet-restore-*")
	if err != nil {
		return fmt.Errorf("temp for %q: %w", dest, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write %q: %w", dest, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp for %q: %w", dest, err)
	}
	if err := os.Chmod(tmpName, mode.Perm()); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("chmod %q: %w", dest, err)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename into %q: %w", dest, err)
	}
	return nil
}
