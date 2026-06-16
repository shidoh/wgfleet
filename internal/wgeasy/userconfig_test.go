package wgeasy

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/shidoh/wgfleet/internal/domain"
)

// newUserConfigDB creates a temp SQLite db with a minimal user_configs_table
// matching wg-easy's schema, seeding the wg0 row with migration-like defaults.
func newUserConfigDB(t *testing.T, seedRow bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wg-easy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE user_configs_table (
		id TEXT PRIMARY KEY,
		default_mtu INTEGER NOT NULL DEFAULT 1420,
		default_persistent_keepalive INTEGER NOT NULL DEFAULT 0,
		default_dns TEXT NOT NULL DEFAULT '["1.1.1.1"]',
		default_allowed_ips TEXT NOT NULL DEFAULT '["0.0.0.0/0","::/0"]',
		default_j_c INTEGER DEFAULT 7,
		default_j_min INTEGER DEFAULT 10,
		default_j_max INTEGER DEFAULT 1000,
		default_i1 TEXT, default_i2 TEXT, default_i3 TEXT, default_i4 TEXT, default_i5 TEXT,
		host TEXT NOT NULL DEFAULT '',
		port INTEGER NOT NULL DEFAULT 51820
	)`)
	if err != nil {
		t.Fatal(err)
	}
	if seedRow {
		if _, err := db.Exec(`INSERT INTO user_configs_table (id) VALUES ('wg0')`); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestUserConfigRoundTrip(t *testing.T) {
	ctx := context.Background()
	path := newUserConfigDB(t, true)

	current, found, err := ReadUserConfig(ctx, path, "wg0")
	if err != nil || !found {
		t.Fatalf("read seeded row: found=%v err=%v", found, err)
	}
	// Migration defaults are present (not empty).
	if len(current.DNS) == 0 || len(current.AllowedIPs) == 0 {
		t.Fatalf("seeded defaults should be non-empty: %+v", current)
	}

	w := sampleSpec()
	desired := DesiredUserConfig(current, w, "203.0.113.20",
		[]string{"10.20.4.10"}, []string{"1.0.0.0/8", "8.0.0.0/7"})

	if err := UpdateUserConfig(ctx, path, "wg0", desired); err != nil {
		t.Fatal(err)
	}
	got, found, err := ReadUserConfig(ctx, path, "wg0")
	if err != nil || !found {
		t.Fatalf("re-read: found=%v err=%v", found, err)
	}
	if !got.Equal(desired) {
		t.Errorf("round-trip mismatch:\n got=%+v\nwant=%+v", got, desired)
	}
	// Client junk must equal the master's local AWG (S4-safe), not the schema default.
	if got.Jc != w.AWG.Local.Jc || got.Jmin != w.AWG.Local.Jmin || got.Jmax != w.AWG.Local.Jmax {
		t.Errorf("client junk not taken from spec: got j_c/j_min/j_max=%d/%d/%d want %d/%d/%d",
			got.Jc, got.Jmin, got.Jmax, w.AWG.Local.Jc, w.AWG.Local.Jmin, w.AWG.Local.Jmax)
	}
	if got.Host != "203.0.113.20" || got.Port != 443 || got.MTU != 1360 {
		t.Errorf("host/port/mtu wrong: %+v", got)
	}
	// Behind-NAT clients always get a keepalive (wg-easy default is 0/off).
	if got.Keepalive != ClientKeepaliveSeconds {
		t.Errorf("client keepalive = %d, want %d", got.Keepalive, ClientKeepaliveSeconds)
	}
	// Obfuscation is mandatory in both directions: the client signature packets
	// (I1-I5) must be written, never left empty.
	if got.I1 == "" || got.I1 != w.AWG.Local.I1 || got.I5 != w.AWG.Local.I5 {
		t.Errorf("client I1-I5 not taken from spec: got I1=%q I5=%q want I1=%q I5=%q",
			got.I1, got.I5, w.AWG.Local.I1, w.AWG.Local.I5)
	}
}

func TestDesiredUserConfigPreservesWhenNoIntent(t *testing.T) {
	current := UserConfigColumns{
		Host: "old", Port: 51820, MTU: 1420, Keepalive: ClientKeepaliveSeconds,
		DNS: []string{"1.1.1.1"}, AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		Jc: 7, Jmin: 10, Jmax: 1000,
	}
	// No host, no dns, no allowed-ips, no AWG, zero port/mtu ⇒ host/dns/allowed-ips
	// preserved. Keepalive is always enforced (behind-NAT requirement), so current
	// already carries it here to isolate the preserve behaviour.
	desired := DesiredUserConfig(current, domain.WGServerSpec{}, "", nil, nil)
	if !desired.Equal(current) {
		t.Errorf("no-intent overlay must preserve current:\n got=%+v\nwant=%+v", desired, current)
	}
}

func TestDesiredUserConfigUsesDistinctClientLocal(t *testing.T) {
	w := sampleSpec() // AWG.Local = server-end profile
	// Client end gets its OWN junk/signatures, which must differ from the server's.
	clientLocal := domain.AWGLocal{
		Jc: 9, Jmin: 80, Jmax: 200,
		I1: "<b 0xfeed><r 7>", I2: "<rc 9>", I3: "<rd 11>", I4: "<b 0xcafe>", I5: "<r 3>",
	}
	w.ClientAWGLocal = &clientLocal

	got := DesiredUserConfig(UserConfigColumns{}, w, "1.2.3.4", nil, nil)

	if got.Jc != clientLocal.Jc || got.Jmin != clientLocal.Jmin || got.Jmax != clientLocal.Jmax {
		t.Errorf("client junk must come from ClientAWGLocal: got %d/%d/%d want %d/%d/%d",
			got.Jc, got.Jmin, got.Jmax, clientLocal.Jc, clientLocal.Jmin, clientLocal.Jmax)
	}
	if got.I1 != clientLocal.I1 || got.I5 != clientLocal.I5 {
		t.Errorf("client I1-I5 must come from ClientAWGLocal: got I1=%q I5=%q", got.I1, got.I5)
	}
	// And they must be DISTINCT from the server interface's local profile.
	if got.Jc == w.AWG.Local.Jc && got.I1 == w.AWG.Local.I1 {
		t.Errorf("client decoy must differ from the server interface's (got identical)")
	}
}

func TestDesiredUserConfigFallsBackToServerLocal(t *testing.T) {
	w := sampleSpec() // no ClientAWGLocal ⇒ fall back to AWG.Local
	got := DesiredUserConfig(UserConfigColumns{}, w, "1.2.3.4", nil, nil)
	if got.Jc != w.AWG.Local.Jc || got.I1 != w.AWG.Local.I1 {
		t.Errorf("with no client-end profile, client junk should fall back to AWG.Local")
	}
}

func TestUpdateUserConfigMissingRow(t *testing.T) {
	path := newUserConfigDB(t, false) // no row
	err := UpdateUserConfig(context.Background(), path, "wg0", UserConfigColumns{})
	if err == nil {
		t.Error("expected error updating non-existent user-config row")
	}
}
