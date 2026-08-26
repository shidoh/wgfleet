// Package clientimport moves a master's client credentials out of wg-easy's
// database and into the controller's store — the one-shot step that makes the
// handover of the client leg invisible to the people using it.
//
// The invariant the whole design rests on: addresses and keys are carried over
// VERBATIM. The server key is adopted separately by the agent; here we preserve
// each client's own keypair and address, so the config already on someone's phone
// keeps working against an interface that is now ours. An import that "fixed up"
// an address or minted a fresh keypair would silently disconnect that phone,
// which is exactly the outcome the migration exists to avoid.
package clientimport

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wgeasy"
)

// Store is the slice of the controller store the import needs.
type Store interface {
	ListWGClients(ctx context.Context, masterID string) ([]domain.WGClient, error)
	AddWGClient(ctx context.Context, masterID string, c domain.WGClient) error
}

// Input describes one import.
type Input struct {
	MasterID string // the master whose credentials these are
	DBPath   string // wg-easy's SQLite database on that master
	Pool     string // the master's client pool, from the manifest
	// ServerAddress is the master's own address in the pool; a credential holding
	// it is a wg-easy artefact, not a client, and is refused rather than imported.
	ServerAddress string
	// IDFor mints the stable credential ID. Injected so the caller (and tests)
	// control identity generation; the store write must stay deterministic, so the
	// ID is chosen before the record is built, never inside it.
	IDFor func(name string) string
	// Now stamps credentials whose wg-easy timestamp is missing or unparseable.
	Now func() time.Time
}

// Report is what an import did, or would do. It is the dry-run output and the
// applied summary both — the operator sees the same list either way, which is the
// point: what you reviewed is what runs.
type Report struct {
	Master   string
	Imported []domain.WGClient // in the order they would be written
	Skipped  []Skip            // already present, or refused with a reason
}

// Skip is one credential the import did not take, and why.
type Skip struct {
	Name   string
	Reason string
}

// Plan reads wg-easy's clients and works out what the import would do, without
// writing anything. Apply runs the same function and then commits the result, so
// a dry-run and a real run cannot drift apart.
func Plan(ctx context.Context, st Store, in Input) (Report, error) {
	if in.MasterID == "" {
		return Report{}, fmt.Errorf("client import: master is required")
	}
	if in.Pool == "" {
		return Report{}, fmt.Errorf("client import: master %q has no client pool configured", in.MasterID)
	}
	pool, err := netip.ParsePrefix(in.Pool)
	if err != nil {
		return Report{}, fmt.Errorf("client import: client pool %q: %w", in.Pool, err)
	}
	idFor, now := in.IDFor, in.Now
	if idFor == nil {
		return Report{}, fmt.Errorf("client import: no ID generator supplied")
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}

	found, ok, err := wgeasy.ReadClients(ctx, in.DBPath)
	if err != nil {
		return Report{}, fmt.Errorf("client import: %w", err)
	}
	if !ok {
		return Report{}, fmt.Errorf("client import: no wg-easy client table found in %q — nothing to import", in.DBPath)
	}

	existing, err := st.ListWGClients(ctx, in.MasterID)
	if err != nil {
		return Report{}, err
	}
	takenName := make(map[string]struct{}, len(existing))
	takenAddr := make(map[netip.Addr]struct{}, len(existing))
	for _, c := range existing {
		takenName[c.Name] = struct{}{}
		if p, perr := netip.ParsePrefix(c.Address); perr == nil {
			takenAddr[p.Addr()] = struct{}{}
		}
	}
	serverAddr, _ := netip.ParseAddr(in.ServerAddress)

	report := Report{Master: in.MasterID}
	for _, c := range found {
		client, skip := convert(c, pool, serverAddr, takenName, takenAddr, idFor, now)
		if skip != nil {
			report.Skipped = append(report.Skipped, *skip)
			continue
		}
		takenName[client.Name] = struct{}{}
		if p, perr := netip.ParsePrefix(client.Address); perr == nil {
			takenAddr[p.Addr()] = struct{}{}
		}
		report.Imported = append(report.Imported, client)
	}
	sort.Slice(report.Skipped, func(i, j int) bool { return report.Skipped[i].Name < report.Skipped[j].Name })
	return report, nil
}

// Apply plans the import and then writes it. It returns the same report Plan
// would have produced, so the caller can print one list whichever mode it ran in.
func Apply(ctx context.Context, st Store, in Input) (Report, error) {
	report, err := Plan(ctx, st, in)
	if err != nil {
		return Report{}, err
	}
	for _, c := range report.Imported {
		if err := st.AddWGClient(ctx, in.MasterID, c); err != nil {
			// Stop at the first failure rather than pressing on: a half-written import
			// with an unexplained gap is worse than one the operator re-runs after
			// fixing the cause. Already-written credentials are simply skipped next time.
			return report, fmt.Errorf("client import: writing %q: %w", c.Name, err)
		}
	}
	return report, nil
}

// convert turns one wg-easy record into a credential, or explains why it cannot.
func convert(c wgeasy.ImportedClient, pool netip.Prefix, serverAddr netip.Addr,
	takenName map[string]struct{}, takenAddr map[netip.Addr]struct{},
	idFor func(string) string, now func() time.Time) (domain.WGClient, *Skip) {

	name := strings.TrimSpace(c.Name)
	if name == "" {
		return domain.WGClient{}, &Skip{Name: "(unnamed)", Reason: "wg-easy record has no name"}
	}
	if _, dup := takenName[name]; dup {
		return domain.WGClient{}, &Skip{Name: name, Reason: "a credential with this name is already in the store"}
	}
	if c.PublicKey == "" || c.PrivateKey == "" {
		return domain.WGClient{}, &Skip{Name: name, Reason: "wg-easy record is missing a key"}
	}

	addr, err := parseClientAddr(c.Address)
	if err != nil {
		return domain.WGClient{}, &Skip{Name: name, Reason: fmt.Sprintf("unusable address %q: %v", c.Address, err)}
	}
	switch {
	case !pool.Contains(addr):
		return domain.WGClient{}, &Skip{Name: name,
			Reason: fmt.Sprintf("address %s is outside the configured pool %s", addr, pool)}
	case serverAddr.IsValid() && addr == serverAddr:
		return domain.WGClient{}, &Skip{Name: name,
			Reason: fmt.Sprintf("address %s is the master's own address", addr)}
	}
	if _, dup := takenAddr[addr]; dup {
		return domain.WGClient{}, &Skip{Name: name,
			Reason: fmt.Sprintf("address %s is already taken in the store", addr)}
	}

	created := c.CreatedAt
	if created.IsZero() {
		created = now()
	}
	return domain.WGClient{
		ID:           idFor(name),
		Name:         name,
		Address:      netip.PrefixFrom(addr, addr.BitLen()).String(),
		PublicKey:    c.PublicKey,
		PrivateKey:   c.PrivateKey,
		PresharedKey: c.PresharedKey,
		Enabled:      c.Enabled,
		CreatedAt:    created.UTC(),
	}, nil
}

// parseClientAddr accepts either shape wg-easy has stored: a bare address or one
// with a mask.
func parseClientAddr(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr, nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Addr{}, err
	}
	return p.Addr(), nil
}

// Render formats a report for the operator: the same text for a dry run and for
// an applied import, so a `--plan` is a literal preview.
func (r Report) Render(applied bool) string {
	var b strings.Builder
	verb := "would import"
	if applied {
		verb = "imported"
	}
	fmt.Fprintf(&b, "client import for master %q: %s %d credential(s)\n", r.Master, verb, len(r.Imported))
	for _, c := range r.Imported {
		state := "enabled"
		if !c.Enabled {
			state = "muted"
		}
		fmt.Fprintf(&b, "  + %-24s %-18s %s\n", c.Name, c.Address, state)
	}
	if len(r.Skipped) > 0 {
		fmt.Fprintf(&b, "skipped %d:\n", len(r.Skipped))
		for _, s := range r.Skipped {
			fmt.Fprintf(&b, "  - %-24s %s\n", s.Name, s.Reason)
		}
	}
	return b.String()
}
