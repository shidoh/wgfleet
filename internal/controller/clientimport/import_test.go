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
		`'laptop','10.8.0.2','g8hWumES6TwTooNhDC6gtyfK8KgYaqyDrd56qBkg598=','xdpwg7BbhRjWuLK7fiLiYoT7hrhEzcxBjpNVquNmK/w=','R9VA+eJqpkXJkoyErO/lhFKJzOuNgDoJMt9JluYojig=',1,'2026-07-01T09:30:00Z'`,
		`'phone','10.8.0.3','PpGH1Knvq9cYUeXTMu6b+DcE2X+SaIyNAFXJrTLw8x0=','hNIbs3p3aT0Bpi9Hfm7rHQG69ahKlfIXNahvN05AnC0=','',0,''`,
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
	if laptop.Name != "laptop" || laptop.PublicKey != "g8hWumES6TwTooNhDC6gtyfK8KgYaqyDrd56qBkg598=" || laptop.PrivateKey != "xdpwg7BbhRjWuLK7fiLiYoT7hrhEzcxBjpNVquNmK/w=" {
		t.Fatalf("laptop keys did not survive: %+v", laptop)
	}
	if laptop.Address != "10.8.0.2/32" {
		t.Fatalf("laptop address = %q, want the wg-easy address with a /32", laptop.Address)
	}
	if laptop.PresharedKey != "R9VA+eJqpkXJkoyErO/lhFKJzOuNgDoJMt9JluYojig=" {
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
	path := wgEasyDB(t, `'laptop','10.8.0.2','ABfep3cPfs/3qzwgUGVGEp6Wveui9US7jlQU63l4YSI=','O5qhQv76RKq4OrHAkJ9pKf1TZWuJXsL8DkfUEupiulQ=','',1,''`)

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
	path := wgEasyDB(t, `'laptop','10.8.0.2','ABfep3cPfs/3qzwgUGVGEp6Wveui9US7jlQU63l4YSI=','O5qhQv76RKq4OrHAkJ9pKf1TZWuJXsL8DkfUEupiulQ=','',1,''`)

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
		`'good','10.8.0.2','ABfep3cPfs/3qzwgUGVGEp6Wveui9US7jlQU63l4YSI=','O5qhQv76RKq4OrHAkJ9pKf1TZWuJXsL8DkfUEupiulQ=','',1,''`,
		`'','10.8.0.4','ABfep3cPfs/3qzwgUGVGEp6Wveui9US7jlQU63l4YSI=','O5qhQv76RKq4OrHAkJ9pKf1TZWuJXsL8DkfUEupiulQ=','',1,''`,         // no name
		`'nokey','10.8.0.5','ABfep3cPfs/3qzwgUGVGEp6Wveui9US7jlQU63l4YSI=','','',1,''`,                                                // no private key
		`'outside','10.9.0.9','ABfep3cPfs/3qzwgUGVGEp6Wveui9US7jlQU63l4YSI=','O5qhQv76RKq4OrHAkJ9pKf1TZWuJXsL8DkfUEupiulQ=','',1,''`,  // outside the pool
		`'gateway','10.8.0.1','ABfep3cPfs/3qzwgUGVGEp6Wveui9US7jlQU63l4YSI=','O5qhQv76RKq4OrHAkJ9pKf1TZWuJXsL8DkfUEupiulQ=','',1,''`,  // the master's own address
		`'garbage','not-an-ip','ABfep3cPfs/3qzwgUGVGEp6Wveui9US7jlQU63l4YSI=','O5qhQv76RKq4OrHAkJ9pKf1TZWuJXsL8DkfUEupiulQ=','',1,''`, // unparseable
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
		`'first','10.8.0.2','/Qv6EPhS59DGIW3cNs2e5ovW1s2IpvQMyW+ST7b3efA=','TNfU+jfTQVEw7JaBIwRMx7NcrCG98YtbTl8Sml1Y/D4=','',1,''`,
		`'second','10.8.0.2','oZDqpr+FHk9huaRL69Q3OmTND8ay6nQI/so+KJ05BRM=','/z4abiHaqtFoqRWAIGzW65kAujpP0HtvBDCHFQxnOJ4=','',1,''`,
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
	in := testInput(wgEasyDB(t, `'laptop','10.8.0.2','ABfep3cPfs/3qzwgUGVGEp6Wveui9US7jlQU63l4YSI=','O5qhQv76RKq4OrHAkJ9pKf1TZWuJXsL8DkfUEupiulQ=','',1,''`))
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
		`'laptop','10.8.0.2','/Qv6EPhS59DGIW3cNs2e5ovW1s2IpvQMyW+ST7b3efA=','TNfU+jfTQVEw7JaBIwRMx7NcrCG98YtbTl8Sml1Y/D4=','',1,''`,
		`'phone','10.8.0.3','oZDqpr+FHk9huaRL69Q3OmTND8ay6nQI/so+KJ05BRM=','/z4abiHaqtFoqRWAIGzW65kAujpP0HtvBDCHFQxnOJ4=','',1,''`,
		`'tablet','10.8.0.4','IOwUIWXo8tCzGeQcd3iYEZIFjc7SVq25oPcFhmK7vGI=','o7/dcnzurl7JSM+tr5FOQToDNG3QX8ebOPskUay/zMg=','',1,''`,
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
		`'laptop' || char(10) || '[Peer]' || char(10) || 'AllowedIPs = 0.0.0.0/0','10.8.0.2','ABfep3cPfs/3qzwgUGVGEp6Wveui9US7jlQU63l4YSI=','O5qhQv76RKq4OrHAkJ9pKf1TZWuJXsL8DkfUEupiulQ=','',1,''`,
		`'good','10.8.0.3','4q75rTtxEcqf6l/TEYsh4zBzAKNaszVYMIvex0JzwPo=','dd78jznTaWlTnUp/FoaUzEoCxIL+irFGNiVMzcKfG6E=','',1,''`,
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

// The footer is the line an operator reads as the verdict. When everything was
// skipped — the realistic shape of a pool mismatch, where the manifest's
// address_pool does not match what wg-easy hands out — the verdict is "STOP,
// nothing migrated", and saying "everything is accounted for" would send the
// operator on to cut over and disconnect every one of these people.
func TestRenderDoesNotCallAFailedImportComplete(t *testing.T) {
	r := Report{
		Master: "m1", Source: "/etc/wireguard/wg-easy.db", Found: 3,
		Skipped: []Skip{
			{Name: "alice", Reason: "NOT MIGRATED: address 10.9.0.4 is outside the configured pool 10.8.0.0/24"},
			{Name: "bob", Reason: "NOT MIGRATED: address 10.9.0.5 is outside the configured pool 10.8.0.0/24"},
			{Name: "carol", Reason: "NOT MIGRATED: address 10.9.0.6 is outside the configured pool 10.8.0.0/24"},
		},
	}
	out := r.Render(false)
	if strings.Contains(out, "already accounted for") {
		t.Fatalf("a report where NOTHING migrated reads as complete:\n%s", out)
	}
	if !strings.Contains(out, "NOTHING WAS MIGRATED") {
		t.Fatalf("report does not warn that the import achieved nothing:\n%s", out)
	}
}

// A genuine second run — everything already imported, nothing skipped for a bad
// reason — should say so plainly rather than look like a failure.
func TestRenderReportsAnAlreadyCompleteImport(t *testing.T) {
	r := Report{
		Master: "m1", Source: "/etc/wireguard/wg-easy.db", Found: 1,
		Skipped: []Skip{{Name: "alice", Reason: "NOT MIGRATED: a different credential already uses this name in the store. This client's wg-easy tunnel will stop working at cutover — rename or remove one of them"}},
	}
	if out := r.Render(false); !strings.Contains(out, "NOTHING WAS MIGRATED") {
		t.Fatalf("a run that migrated nothing must say so:\n%s", out)
	}

	done := Report{Master: "m1", Source: "/etc/wireguard/wg-easy.db", Found: 0}
	if out := done.Render(false); !strings.Contains(out, "nothing to import") {
		t.Fatalf("an empty source should read as done:\n%s", out)
	}
}

// A malformed key in wg-easy must be refused at import, where the operator is
// reading a report. Carried through, it would pass the store, fail validation on
// the node, and freeze the client interface on its last-good config — at which
// point every later revocation silently stops taking effect while the UI reports
// success. That is a security failure, not a cosmetic one.
func TestPlanRefusesMalformedKeys(t *testing.T) {
	st := testStore(t)
	good := "Z29vZC1wdWJsaWMta2V5LTAwMDAwMDAwMDAwMDAwMDA="
	path := wgEasyDB(t,
		`'badpub','10.8.0.2','not-a-key','`+good+`','',1,''`,
		`'badpsk','10.8.0.3','`+good+`','`+good+`','also-not-a-key',1,''`,
		`'fine','10.8.0.4','`+good+`','`+good+`','',1,''`,
	)
	report, err := Plan(context.Background(), st, testInput(path))
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(report.Imported) != 1 || report.Imported[0].Name != "fine" {
		t.Fatalf("imported = %+v, want only the well-formed record", report.Imported)
	}
	if len(report.Skipped) != 2 {
		t.Fatalf("skipped = %+v, want both malformed records", report.Skipped)
	}
	for _, s := range report.Skipped {
		if !strings.Contains(s.Reason, "not a valid WireGuard key") {
			t.Errorf("skip of %q = %q", s.Name, s.Reason)
		}
	}
}
