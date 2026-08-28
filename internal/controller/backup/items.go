package backup

import (
	"fmt"
	"os"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/master"
	"github.com/shidoh/wgfleet/internal/config"
)

// Fixed master-side restore destinations (the agent manages these paths).
const (
	destStateDB     = "/var/lib/wgfleet/state.db"
	destWGEasyAdmin = "/etc/wgfleet/wg-easy-admin-password"
	destNodeCert    = "/etc/wgfleet/node.crt"
	destNodeKey     = "/etc/wgfleet/node.key"
	destAgentYAML   = "/etc/wgfleet/agent.yaml"
	destWGKey       = "/etc/wgfleet/wg.key"
	destClientWGKey = "/etc/wgfleet/client-wg.key"
)

// Sources are the on-disk locations the export reads from.
type Sources struct {
	ControllerYAML string
	StateDB        string // live db path (its snapshot, not the file, is captured)
	CACert         string
	CAKey          string // resolved file path; "" if the CA key is a non-file reference
	SOPSFile       string // "" when secrets.sops_file is unset
	WGEasyDB       string
	WGEasyAdmin    string
	NodeCert       string
	NodeKey        string
	AgentYAML      string
	// WGKey is the master's WireGuard private key. It is the ROOT of every
	// master↔exit tunnel identity: since ADR-0030 each per-tunnel key is derived
	// from it (HKDF over the exit name), so losing it changes not one identity but
	// all of them at once.
	//
	// It was originally left out on the "only capture what cannot be regenerated"
	// rule, and strictly that holds — a restored master mints a fresh key,
	// republishes, and the exits re-peer from the controller-rendered spec. But the
	// cost of exercising that path is a fleet-wide tunnel outage lasting until every
	// exit has reconciled, and with derived keys it is guaranteed to hit every exit
	// rather than possibly none. Capturing 45 bytes turns that reconvergence into a
	// no-op.
	WGKey string
	// ClientWGKey is the master's CLIENT-FACING WireGuard private key — the
	// identity every client config in the field pins. Unlike WGKey it is NOT
	// regenerable: minting a new one silently invalidates every profile at once.
	// It self-heals today by re-adopting from wg-easy's database, but the migration
	// ends with that database deleted, at which point this file is the only copy.
	ClientWGKey string
}

// DefaultSources fills Sources from config plus the fixed master paths.
func DefaultSources(cfg *config.ControllerConfig, configPath string) Sources {
	mp := master.DefaultPaths()
	caKey := ""
	if raw := string(cfg.Controller.PKI.CAKey); strings.HasPrefix(raw, "file://") {
		caKey = strings.TrimPrefix(raw, "file://")
	} else if !cfg.Controller.PKI.CAKey.IsReference() {
		caKey = raw // bare path (dev)
	}
	sops := ""
	if cfg.Controller.Secrets.SOPSFile != "" {
		sops = config.ExpandPath(cfg.Controller.Secrets.SOPSFile)
	}
	return Sources{
		ControllerYAML: configPath,
		StateDB:        config.ExpandPath(cfg.Controller.Store),
		CACert:         config.ExpandPath(cfg.Controller.PKI.CACert),
		CAKey:          config.ExpandPath(caKey),
		SOPSFile:       sops,
		WGEasyDB:       mp.WGEasyDB,
		WGEasyAdmin:    mp.WGEasyAdmin,
		WGKey:          destWGKey,
		ClientWGKey:    destClientWGKey,
		NodeCert:       destNodeCert,
		NodeKey:        destNodeKey,
		AgentYAML:      destAgentYAML,
	}
}

// GatherItems reads each source file and builds the item list. The db snapshot
// (dbSnapshot) is captured in place of the live StateDB. Controller items are
// required; master items are included only when present on this node.
func GatherItems(src Sources, dbSnapshot string, exists func(string) (os.FileInfo, error)) ([]Item, []Layer, error) {
	var items []Item

	// Required controller items.
	required := []struct{ path, name, dest string }{
		{src.ControllerYAML, "controller/controller.yaml", src.ControllerYAML},
		{dbSnapshot, "controller/state.db", firstNonEmpty(src.StateDB, destStateDB)},
		{src.CACert, "controller/ca.crt", src.CACert},
	}
	for _, r := range required {
		it, err := readItem(r.path, r.name, r.dest, LayerController)
		if err != nil {
			return nil, nil, fmt.Errorf("required controller item %q: %w", r.name, err)
		}
		items = append(items, it)
	}
	// Optional controller items (CA key file may be absent if sops-backed).
	for _, o := range []struct{ path, name, dest string }{
		{src.CAKey, "controller/ca.key", src.CAKey},
		{src.SOPSFile, "controller/secrets.sops.yaml", src.SOPSFile},
	} {
		if o.path == "" {
			continue
		}
		if _, err := exists(o.path); err != nil {
			continue
		}
		it, err := readItem(o.path, o.name, o.dest, LayerController)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, it)
	}
	layers := []Layer{LayerController}

	// Master items: include only when present.
	masterItems := []struct{ path, name, dest string }{
		{src.WGEasyDB, "master/wg-easy.db", src.WGEasyDB},
		{src.WGEasyAdmin, "master/wg-easy-admin-password", destWGEasyAdmin},
		{src.WGKey, "master/wg.key", destWGKey},
		{src.ClientWGKey, "master/client-wg.key", destClientWGKey},
		{src.NodeCert, "master/node.crt", destNodeCert},
		{src.NodeKey, "master/node.key", destNodeKey},
		{src.AgentYAML, "master/agent.yaml", destAgentYAML},
	}
	masterPresent := false
	for _, m := range masterItems {
		if m.path == "" {
			continue
		}
		if _, err := exists(m.path); err != nil {
			continue
		}
		it, err := readItem(m.path, m.name, m.dest, LayerMaster)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, it)
		masterPresent = true
	}
	if masterPresent {
		layers = append(layers, LayerMaster)
	}
	return items, layers, nil
}

func readItem(path, name, dest string, layer Layer) (Item, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Item{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Item{}, fmt.Errorf("read %q: %w", path, err)
	}
	return Item{Name: name, Dest: dest, Mode: info.Mode().Perm(), Layer: layer, Data: data}, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// plannedItems lists every (path, name, dest) this host's Sources describe,
// regardless of what exists on disk right now.
//
// GatherItems walks the same three groups but skips what is absent, because a
// backup can only carry what is there. AllowedDestsFor needs the opposite: the full
// set of places a restore of this host is permitted to write, whether or not the
// file happens to exist today. Keeping both readings of one list in one place is
// what stops them drifting — a destination added to the backup and not to the
// allowlist would be refused on restore, which is a very confusing bug.
func plannedItems(src Sources) []struct{ path, name, dest string } {
	out := []struct{ path, name, dest string }{
		{src.ControllerYAML, "controller/controller.yaml", src.ControllerYAML},
		{"", "controller/state.db", firstNonEmpty(src.StateDB, destStateDB)},
		{src.CACert, "controller/ca.crt", src.CACert},
		{src.CAKey, "controller/ca.key", src.CAKey},
		{src.SOPSFile, "controller/secrets.sops.yaml", src.SOPSFile},
		{src.WGEasyDB, "master/wg-easy.db", src.WGEasyDB},
		{src.WGEasyAdmin, "master/wg-easy-admin-password", destWGEasyAdmin},
		{src.WGKey, "master/wg.key", destWGKey},
		{src.ClientWGKey, "master/client-wg.key", destClientWGKey},
		{src.NodeCert, "master/node.crt", destNodeCert},
		{src.NodeKey, "master/node.key", destNodeKey},
		{src.AgentYAML, "master/agent.yaml", destAgentYAML},
	}
	return out
}
