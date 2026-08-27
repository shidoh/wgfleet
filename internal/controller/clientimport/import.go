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
	"github.com/shidoh/wgfleet/internal/wg"
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
	Master string
	// Source and Found are the denominator: "3 imported" means nothing without
	// "out of how many", and a reader approving a migration needs both.
	Source   string
	Found    int
	Imported []domain.WGClient // in the order they would be written
	Skipped  []Skip            // already present, or refused with a reason
}

// Skip is one credential the import did not take, and why.
type Skip struct {
	Name   string
	Reason string
	// Benign marks a skip that costs nothing: the credential is already in the
	// controller, which is what a completed import looks like on a second run.
	// Every other skip means this person's tunnel stops at cutover, and the two
	// must never be summarised the same way.
	Benign bool
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
	byName := make(map[string]domain.WGClient, len(existing))
	takenName := make(map[string]struct{}, len(existing))
	takenAddr := make(map[netip.Addr]struct{}, len(existing))
	for _, c := range existing {
		byName[c.Name] = c
		takenName[c.Name] = struct{}{}
		if p, perr := netip.ParsePrefix(c.Address); perr == nil {
			takenAddr[p.Addr()] = struct{}{}
		}
	}
	serverAddr, _ := netip.ParseAddr(in.ServerAddress)

	report := Report{Master: in.MasterID, Source: in.DBPath, Found: len(found)}
	for _, c := range found {
		client, skip := convert(c, pool, serverAddr, byName, takenName, takenAddr, idFor, now)
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
	for i, c := range report.Imported {
		if err := st.AddWGClient(ctx, in.MasterID, c); err != nil {
			// Stop at the first failure rather than pressing on: a half-written import
			// with an unexplained gap is worse than one the operator re-runs after
			// fixing the cause. Already-written credentials are simply skipped next time.
			//
			// Truncate the report to what was ACTUALLY written first. Report.Imported
			// is the plan, and returning it whole alongside the error told the operator
			// every credential had made it across — so they would read a clean report,
			// believe the migration complete, and flip client_awg.managed on people who
			// are not in the store.
			report.Imported = report.Imported[:i]
			report.Skipped = append(report.Skipped, Skip{
				Name:   c.Name,
				Reason: "NOT MIGRATED: the store refused this credential (" + err.Error() + ") — the import stopped here, so everything after it is unwritten too",
			})
			return report, fmt.Errorf("client import: writing %q: %w", c.Name, err)
		}
	}
	return report, nil
}

// convert turns one wg-easy record into a credential, or explains why it cannot.
func convert(c wgeasy.ImportedClient, pool netip.Prefix, serverAddr netip.Addr,
	byName map[string]domain.WGClient, takenName map[string]struct{}, takenAddr map[netip.Addr]struct{},
	idFor func(string) string, now func() time.Time) (domain.WGClient, *Skip) {

	name := strings.TrimSpace(c.Name)
	if name == "" {
		return domain.WGClient{}, &Skip{Name: "(unnamed)", Reason: "wg-easy record has no name"}
	}
	// The name is rendered verbatim into the master's interface config. A newline
	// in it would not corrupt that file but EXTEND it — an imported credential
	// called "laptop\n[Peer]\nAllowedIPs = 0.0.0.0/0" adds a peer of someone
	// else's choosing to the live client interface. This is the one path fed from a
	// database we no longer control, so it is the one that has to be strict.
	if !domain.ValidClientName(name) {
		return domain.WGClient{}, &Skip{Name: shorten(name),
			Reason: fmt.Sprintf("NOT MIGRATED: the name is not safe to render into a config "+
				"(allowed: letters, digits, '-', '_', '.'; max %d). Rename it in wg-easy and re-run — "+
				"this client's tunnel will stop working at cutover until you do", domain.MaxClientNameLen)}
	}
	if _, dup := takenName[name]; dup {
		// Same name AND same public key ⇒ this exact credential is already here,
		// which is the normal shape of a re-run. A same-name-different-key collision
		// is the dangerous one and keeps the warning.
		if prev, ok := byName[name]; ok && prev.PublicKey == c.PublicKey {
			return domain.WGClient{}, &Skip{Name: name, Benign: true,
				Reason: "already imported (same key and address) — nothing to do"}
		}
		return domain.WGClient{}, &Skip{Name: name,
			Reason: "NOT MIGRATED: a different credential already uses this name in the store. " +
				"This client's wg-easy tunnel will stop working at cutover — rename or remove one of them"}
	}
	if c.PublicKey == "" || c.PrivateKey == "" {
		return domain.WGClient{}, &Skip{Name: name, Reason: "NOT MIGRATED: wg-easy record is missing a key"}
	}
	// Keys are rendered verbatim into the interface config, exactly like the name,
	// and a malformed one has a nastier failure mode than a bad name: the spec is
	// refused on the node, the interface freezes on its last-good config, and every
	// LATER revocation silently stops taking effect while the UI reports success.
	// Catch it here, in the report the operator is already reading.
	for _, k := range []struct{ what, value string }{
		{"public key", c.PublicKey},
		{"preshared key", c.PresharedKey},
	} {
		if k.value == "" {
			continue // an absent preshared key is legitimate
		}
		if !domain.ValidWireGuardKey(k.value) {
			return domain.WGClient{}, &Skip{Name: name,
				Reason: fmt.Sprintf("NOT MIGRATED: the %s in wg-easy is not a valid WireGuard key — "+
					"importing it would freeze this master's client interface", k.what)}
		}
	}
	// The private key gets more than a well-formedness check: derive its public
	// half and compare. A key that parses but does not match its stored public key
	// imports cleanly, renders into that person's .conf, and never completes a
	// handshake — with nothing in the report to say so, because every check above
	// passed. The pair is the only thing here that can be verified rather than
	// merely inspected, and this is a database we have already decided not to trust.
	derived, err := wg.PublicKeyOf(c.PrivateKey)
	switch {
	case err != nil:
		return domain.WGClient{}, &Skip{Name: name,
			Reason: "NOT MIGRATED: the private key in wg-easy is unusable — this client's tunnel will stop working at cutover"}
	case derived != c.PublicKey:
		return domain.WGClient{}, &Skip{Name: name,
			Reason: "NOT MIGRATED: wg-easy's private and public keys for this client do not match — " +
				"the imported config would look correct and never connect"}
	}

	addr, err := parseClientAddr(c.Address)
	if err != nil {
		return domain.WGClient{}, &Skip{Name: name,
			Reason: fmt.Sprintf("NOT MIGRATED: unusable address %q (%v) — this client's tunnel will stop working at cutover", c.Address, err)}
	}
	switch {
	case !pool.Contains(addr):
		return domain.WGClient{}, &Skip{Name: name,
			Reason: fmt.Sprintf("NOT MIGRATED: address %s is outside the configured pool %s — if this is the whole "+
				"list, client_awg.address_pool does not match what wg-easy hands out; fix the manifest before cutting over", addr, pool)}
	case serverAddr.IsValid() && addr == serverAddr:
		return domain.WGClient{}, &Skip{Name: name,
			Reason: fmt.Sprintf("address %s is the master's own address", addr)}
	}
	if _, dup := takenAddr[addr]; dup {
		return domain.WGClient{}, &Skip{Name: name,
			Reason: fmt.Sprintf("NOT MIGRATED: address %s is already taken by another credential. "+
				"This client's wg-easy tunnel will stop working at cutover", addr)}
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
	fmt.Fprintf(&b, "client import for master %q: %d client(s) in %s, %s %d\n",
		r.Master, r.Found, r.Source, verb, len(r.Imported))
	for _, c := range r.Imported {
		state := "enabled"
		if !c.Enabled {
			state = "paused"
		}
		fmt.Fprintf(&b, "  + %-24s %-18s %s\n", c.Name, c.Address, state)
	}
	if len(r.Skipped) > 0 {
		fmt.Fprintf(&b, "skipped %d:\n", len(r.Skipped))
		for _, s := range r.Skipped {
			fmt.Fprintf(&b, "  - %-24s %s\n", s.Name, s.Reason)
		}
	}
	switch {
	case len(r.Imported) > 0:
	case len(r.Skipped) == 0:
		b.WriteString("nothing to import: the wg-easy database holds no clients.\n")
	case r.lostAnyone():
		// Something was refused for a reason that costs a person their tunnel. This
		// is the verdict line, and the operator's next step after a clean import is
		// to hand the interface over — which would now cut those people off.
		b.WriteString("\nNOTHING WAS MIGRATED — every client was skipped, and at least one for a reason " +
			"that costs it its tunnel. Do NOT hand the interface over yet: fix the reasons above and re-run.\n")
	default:
		// A completed import, run again. The normal state, and it must read like one.
		b.WriteString("\nnothing to do: every wg-easy client is already in the controller.\n")
	}
	return b.String()
}

// lostAnyone reports whether any skip means a real client stops working.
func (r Report) lostAnyone() bool {
	for _, s := range r.Skipped {
		if !s.Benign {
			return true
		}
	}
	return false
}

// shorten renders an unusable name in a report without letting its own contents
// wreck the layout.
func shorten(name string) string {
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '~'
		}
		return r
	}, name)
	const max = 24
	if len(name) > max {
		return name[:max] + "…"
	}
	return name
}
