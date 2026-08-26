package clientimport

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite" // register the driver used to build the wg-easy fixture

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// wgEasyDB builds a wg-easy-shaped database with the given client rows.
func wgEasyDB(t *testing.T, rows ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wg-easy.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TABLE clients_table (
		name TEXT, ipv4_address TEXT, public_key TEXT, private_key TEXT,
		preshared_key TEXT, enabled INTEGER, created_at TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO clients_table VALUES (` + r + `)`); err != nil {
			t.Fatalf("insert %s: %v", r, err)
		}
	}
	return path
}

func testStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.UpsertNode(context.Background(), domain.Node{
		ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster, State: domain.StateReady,
	}); err != nil {
		t.Fatalf("seed master: %v", err)
	}
	return st
}

func testInput(dbPath string) Input {
	return Input{
		MasterID:      "master-xa-1",
		DBPath:        dbPath,
		Pool:          "10.8.0.0/24",
		ServerAddress: "10.8.0.1",
		IDFor:         func(name string) string { return "id-" + name },
		Now:           func() time.Time { return time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC) },
	}
}

// The migration's whole promise: keys and addresses cross over untouched, so a
// config already on someone's phone keeps working.
func TestApplyPreservesKeysAndAddresses(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	path := wgEasyDB(t,
		`'laptop','10.8.0.2','pub-laptop','priv-laptop','psk-laptop',1,'2026-07-01T09:30:00Z'`,
		`'phone','10.8.0.3','pub-phone','priv-phone','',0,''`,
	)

	report, err := Apply(ctx, st, testInput(path))
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(report.Imported) != 2 || len(report.Skipped) != 0 {
		t.Fatalf("report = %d imported, %d skipped", len(report.Imported), len(report.Skipped))
	}

	stored, err := st.ListWGClients(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("store holds %d credentials, want 2", len(stored))
	}
	laptop := stored[0]
	if laptop.Name != "laptop" || laptop.PublicKey != "pub-laptop" || laptop.PrivateKey != "priv-laptop" {
		t.Fatalf("laptop keys did not survive: %+v", laptop)
	}
	if laptop.Address != "10.8.0.2/32" {
		t.Fatalf("laptop address = %q, want the wg-easy address with a /32", laptop.Address)
	}
	if laptop.PresharedKey != "psk-laptop" {
		t.Errorf("laptop lost its preshared key")
	}
	if laptop.CreatedAt.Year() != 2026 || laptop.CreatedAt.Month() != time.July {
		t.Errorf("laptop lost its original issue date: %v", laptop.CreatedAt)
	}
	// A client wg-easy had disabled must arrive muted, not quietly reactivated.
	if stored[1].Enabled {
		t.Error("a disabled wg-easy client imported as enabled")
	}
	// The phone had no timestamp: it gets the import moment rather than year zero.
	if stored[1].CreatedAt.IsZero() {
		t.Error("missing timestamp was not stamped at import")
	}
}

// Plan must change nothing. It is the only thing standing between the operator
// and a one-way write of every credential on the fleet.
func TestPlanWritesNothing(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	path := wgEasyDB(t, `'laptop','10.8.0.2','pub','priv','',1,''`)

	report, err := Plan(ctx, st, testInput(path))
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(report.Imported) != 1 {
		t.Fatalf("plan = %d imported, want 1", len(report.Imported))
	}
	stored, _ := st.ListWGClients(ctx, "master-xa-1")
	if len(stored) != 0 {
		t.Fatalf("Plan() wrote %d credentials to the store", len(stored))
	}
}

// Re-running an import must be safe: what is already there is skipped, not
// duplicated and not overwritten with a fresh identity.
func TestApplyIsRepeatable(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	path := wgEasyDB(t, `'laptop','10.8.0.2','pub','priv','',1,''`)

	if _, err := Apply(ctx, st, testInput(path)); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	second, err := Apply(ctx, st, testInput(path))
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if len(second.Imported) != 0 {
		t.Fatalf("second run re-imported %d credentials", len(second.Imported))
	}
	if len(second.Skipped) != 1 || !strings.Contains(second.Skipped[0].Reason, "already uses this name") {
		t.Fatalf("second run skipped = %+v", second.Skipped)
	}
	stored, _ := st.ListWGClients(ctx, "master-xa-1")
	if len(stored) != 1 {
		t.Fatalf("store holds %d credentials after two runs, want 1", len(stored))
	}
}

func TestPlanRefusesUnusableRecords(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	path := wgEasyDB(t,
		`'good','10.8.0.2','pub','priv','',1,''`,
		`'','10.8.0.4','pub','priv','',1,''`,         // no name
		`'nokey','10.8.0.5','pub','','',1,''`,        // no private key
		`'outside','10.9.0.9','pub','priv','',1,''`,  // outside the pool
		`'gateway','10.8.0.1','pub','priv','',1,''`,  // the master's own address
		`'garbage','not-an-ip','pub','priv','',1,''`, // unparseable
	)

	report, err := Plan(ctx, st, testInput(path))
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(report.Imported) != 1 || report.Imported[0].Name != "good" {
		t.Fatalf("imported = %+v, want only the good record", report.Imported)
	}
	if len(report.Skipped) != 5 {
		t.Fatalf("skipped %d records, want 5: %+v", len(report.Skipped), report.Skipped)
	}
	// Every refusal must say why — a silent drop is how a client disappears.
	for _, s := range report.Skipped {
		if s.Reason == "" {
			t.Errorf("skip of %q has no reason", s.Name)
		}
	}
}

// Two wg-easy records on one address cannot both be imported: the store's UNIQUE
// constraint would reject the second anyway, and a report that promised it would
// be misleading.
func TestPlanRefusesDuplicateAddresses(t *testing.T) {
	st := testStore(t)
	path := wgEasyDB(t,
		`'first','10.8.0.2','pub-a','priv-a','',1,''`,
		`'second','10.8.0.2','pub-b','priv-b','',1,''`,
	)
	report, err := Plan(context.Background(), st, testInput(path))
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(report.Imported) != 1 {
		t.Fatalf("imported %d, want 1", len(report.Imported))
	}
	if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "already taken") {
		t.Fatalf("skipped = %+v", report.Skipped)
	}
}

func TestPlanRequiresAPool(t *testing.T) {
	st := testStore(t)
	in := testInput(wgEasyDB(t, `'laptop','10.8.0.2','pub','priv','',1,''`))
	in.Pool = ""
	if _, err := Plan(context.Background(), st, in); err == nil {
		t.Fatal("Plan() without a pool = nil error, want a refusal")
	}
}

// An absent wg-easy database is reported as "nothing to import" — and, critically,
// is not brought into existence by the attempt: a file conjured here would look
// to the master's wg-easy planners like a set-up-but-empty install.
func TestPlanReportsAnAbsentDatabase(t *testing.T) {
	st := testStore(t)
	path := filepath.Join(t.TempDir(), "absent.db")
	_, err := Plan(context.Background(), st, testInput(path))
	if err == nil || !strings.Contains(err.Error(), "nothing to import") {
		t.Fatalf("Plan() on an absent database = %v, want a 'nothing to import' error", err)
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Fatal("planning an import created the wg-easy database")
	}
}

// A store that refuses a write must stop the import rather than press on and
// leave an unexplained gap.
func TestApplyStopsAtTheFirstWriteFailure(t *testing.T) {
	st := failingStore{Store: testStore(t), failOn: "phone"}
	path := wgEasyDB(t,
		`'laptop','10.8.0.2','pub-a','priv-a','',1,''`,
		`'phone','10.8.0.3','pub-b','priv-b','',1,''`,
		`'tablet','10.8.0.4','pub-c','priv-c','',1,''`,
	)
	_, err := Apply(context.Background(), st, testInput(path))
	if err == nil {
		t.Fatal("Apply() = nil error, want the store failure surfaced")
	}
	stored, _ := st.ListWGClients(context.Background(), "master-xa-1")
	if len(stored) != 1 {
		t.Fatalf("store holds %d credentials, want only the one written before the failure", len(stored))
	}
}

type failingStore struct {
	store.Store
	failOn string
}

func (f failingStore) AddWGClient(ctx context.Context, masterID string, c domain.WGClient) error {
	if c.Name == f.failOn {
		return errors.New("disk on fire")
	}
	return f.Store.AddWGClient(ctx, masterID, c)
}

func TestReportRender(t *testing.T) {
	r := Report{
		Master: "master-xa-1",
		Imported: []domain.WGClient{
			{Name: "laptop", Address: "10.8.0.2/32", Enabled: true},
			{Name: "phone", Address: "10.8.0.3/32"},
		},
		Skipped: []Skip{{Name: "gateway", Reason: "address 10.8.0.1 is the master's own address"}},
	}
	out := r.Render(false)
	for _, want := range []string{"would import 2", "laptop", "muted", "skipped 1", "gateway"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered report missing %q:\n%s", want, out)
		}
	}
	if applied := r.Render(true); !strings.Contains(applied, "imported 2") {
		t.Errorf("applied report reads as a dry run:\n%s", applied)
	}
}

func ExampleReport_Render() {
	r := Report{
		Master: "m1", Source: "/etc/wireguard/wg-easy.db", Found: 2,
		Imported: []domain.WGClient{{Name: "laptop", Address: "10.8.0.2/32", Enabled: true}},
		Skipped:  []Skip{{Name: "phone", Reason: "NOT MIGRATED: address 10.8.0.3 is already taken by another credential"}},
	}
	fmt.Print(r.Render(false))
	// Output:
	// client import for master "m1": 2 client(s) in /etc/wireguard/wg-easy.db, would import 1
	//   + laptop                   10.8.0.2/32        enabled
	// skipped 1:
	//   - phone                    NOT MIGRATED: address 10.8.0.3 is already taken by another credential
}

// A wg-easy name that cannot be safely rendered is refused with a reason that
// names the consequence, not silently carried into the interface config.
func TestPlanRefusesAnUnsafeName(t *testing.T) {
	st := testStore(t)
	path := wgEasyDB(t,
		`'laptop' || char(10) || '[Peer]' || char(10) || 'AllowedIPs = 0.0.0.0/0','10.8.0.2','pub','priv','',1,''`,
		`'good','10.8.0.3','pub2','priv2','',1,''`,
	)
	report, err := Plan(context.Background(), st, testInput(path))
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(report.Imported) != 1 || report.Imported[0].Name != "good" {
		t.Fatalf("imported = %+v, want only the safe record", report.Imported)
	}
	if len(report.Skipped) != 1 {
		t.Fatalf("skipped = %+v, want the unsafe name", report.Skipped)
	}
	if !strings.Contains(report.Skipped[0].Reason, "not safe to render") {
		t.Fatalf("skip reason = %q", report.Skipped[0].Reason)
	}
	// The refusal itself must not smuggle the newline into the report.
	if strings.Contains(report.Skipped[0].Name, "\n") {
		t.Fatalf("the report reproduced the injected newline: %q", report.Skipped[0].Name)
	}
}
