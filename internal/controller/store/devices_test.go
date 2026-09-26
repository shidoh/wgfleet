package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

var devT0 = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func devStore(t *testing.T, masters ...string) *SQLiteStore {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for _, m := range masters {
		if err := s.UpsertNode(context.Background(), domain.Node{ID: m, Name: m, Role: domain.RoleMaster, State: domain.StateReady}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func wgCred(id, name, addr string) domain.WGClient {
	return domain.WGClient{ID: id, Name: name, Address: addr, PublicKey: "pub-" + id,
		PrivateKey: "priv-" + id, Enabled: true, CreatedAt: devT0}
}

func mustDevice(t *testing.T, s *SQLiteStore, id, token, name string) {
	t.Helper()
	if err := s.CreateDevice(context.Background(), domain.ClientDevice{ID: id, Token: token, Name: name, CreatedAt: devT0}); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceCreateGetByTokenAndList(t *testing.T) {
	ctx := context.Background()
	s := devStore(t, "m1")
	mustDevice(t, s, "d1", "0123456789abcdef0123456789abcdef", "alice-phone")
	if err := s.AddWGClientToDevice(ctx, "m1", wgCred("c1", "alice-phone", "10.80.0.2/32"), "d1"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddVLESSClientToDevice(ctx, "m1", domain.VLESSClient{Name: "alice-phone", UUID: "u1", ShortID: "aa"}, "d1", devT0); err != nil {
		t.Fatal(err)
	}
	d, err := s.GetDeviceByToken(ctx, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("GetDeviceByToken: %v", err)
	}
	if d.ID != "d1" || d.Name != "alice-phone" || !d.CreatedAt.Equal(devT0) {
		t.Errorf("device = %+v", d)
	}
	if c, ok := d.Credential(domain.CredentialAWG, "m1"); !ok || c.Ref != "c1" {
		t.Errorf("awg credential = %+v ok=%v", c, ok)
	}
	if c, ok := d.Credential(domain.CredentialVLESS, "m1"); !ok || c.Ref != "alice-phone" {
		t.Errorf("vless credential = %+v ok=%v", c, ok)
	}
	if _, err := s.GetDeviceByToken(ctx, "ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown token: err = %v", err)
	}
	all, err := s.ListDevices(ctx)
	if err != nil || len(all) != 1 || len(all[0].Credentials) != 2 {
		t.Fatalf("ListDevices = %+v, %v", all, err)
	}
}

func TestDeviceNameAndTokenAreUnique(t *testing.T) {
	ctx := context.Background()
	s := devStore(t)
	mustDevice(t, s, "d1", "tok1tok1tok1tok1", "laptop")
	if err := s.CreateDevice(ctx, domain.ClientDevice{ID: "d2", Token: "tok2tok2tok2tok2", Name: "laptop", CreatedAt: devT0}); err == nil {
		t.Error("duplicate name accepted")
	}
	if err := s.CreateDevice(ctx, domain.ClientDevice{ID: "d3", Token: "tok1tok1tok1tok1", Name: "other", CreatedAt: devT0}); err == nil {
		t.Error("duplicate token accepted")
	}
	if err := s.CreateDevice(ctx, domain.ClientDevice{ID: "d4", Token: "tok4tok4tok4tok4", Name: "x"}); err == nil {
		t.Error("missing CreatedAt accepted: the store must not read the clock")
	}
}

func TestAttachRefusesSecondSlotAndForeignCredential(t *testing.T) {
	ctx := context.Background()
	s := devStore(t, "m1")
	mustDevice(t, s, "d1", "tok1tok1tok1tok1", "a")
	mustDevice(t, s, "d2", "tok2tok2tok2tok2", "b")
	for _, c := range []domain.WGClient{wgCred("c1", "one", "10.80.0.2/32"), wgCred("c2", "two", "10.80.0.3/32")} {
		if err := s.AddWGClient(ctx, "m1", c); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AttachCredential(ctx, domain.CredentialAWG, "m1", "c1", "d1"); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	if err := s.AttachCredential(ctx, domain.CredentialAWG, "m1", "c2", "d1"); !errors.Is(err, ErrDeviceSlotTaken) {
		t.Errorf("second slot: err = %v, want ErrDeviceSlotTaken", err)
	}
	if err := s.AttachCredential(ctx, domain.CredentialAWG, "m1", "c1", "d2"); !errors.Is(err, ErrCredentialAttached) {
		t.Errorf("foreign credential: err = %v, want ErrCredentialAttached", err)
	}
	if err := s.AttachCredential(ctx, domain.CredentialAWG, "m1", "nope", "d2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown credential: err = %v", err)
	}
	if err := s.AttachCredential(ctx, domain.CredentialAWG, "m1", "c2", "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown device: err = %v", err)
	}
	// c2 was never attached: a refused attach must not have retired its link.
	if _, _, err := s.FindUnattachedWGClient(ctx, "c2"); err != nil {
		t.Errorf("a refused attach retired the credential's link: %v", err)
	}
	d1, _ := s.GetDevice(ctx, "d1")
	if len(d1.Credentials) != 1 || d1.Credentials[0].Ref != "c1" {
		t.Errorf("d1 changed by refused writes: %+v", d1.Credentials)
	}
}

func TestDetachAndDeleteKeepCredentials(t *testing.T) {
	ctx := context.Background()
	s := devStore(t, "m1")
	mustDevice(t, s, "d1", "tok1tok1tok1tok1", "a")
	if err := s.AddWGClientToDevice(ctx, "m1", wgCred("c1", "one", "10.80.0.2/32"), "d1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DetachCredential(ctx, domain.CredentialAWG, "m1", "c1", "tokNtokNtokNtokN"); err != nil {
		t.Fatal(err)
	}
	if d1, _ := s.GetDevice(ctx, "d1"); len(d1.Credentials) != 0 {
		t.Errorf("detach left %+v", d1.Credentials)
	}
	if err := s.AttachCredential(ctx, domain.CredentialAWG, "m1", "c1", "d1"); err != nil {
		t.Fatal(err)
	}
	// Deleting the device unlinks (ON DELETE SET NULL); it does not revoke.
	if err := s.DeleteDevice(ctx, "d1"); err != nil {
		t.Fatal(err)
	}
	clients, _ := s.ListWGClients(ctx, "m1")
	if len(clients) != 1 || !clients[0].LegacyLinkRetired {
		t.Fatalf("after delete: %+v (credential must survive, its link must stay retired)", clients)
	}
	if err := s.DeleteDevice(ctx, "d1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

func TestRetiredLegacyLinkNeverComesBack(t *testing.T) {
	ctx := context.Background()
	s := devStore(t, "m1")
	for i, c := range []domain.WGClient{
		wgCred("attached-then-deleted", "a", "10.80.0.2/32"),
		wgCred("attached-then-detached", "b", "10.80.0.3/32"),
		wgCred("never-attached", "c", "10.80.0.4/32"),
	} {
		if err := s.AddWGClient(ctx, "m1", c); err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
	}
	if err := s.AddWGClientToDevice(ctx, "m1", wgCred("issued-onto-device", "d", "10.80.0.5/32"), "dx"); err == nil {
		t.Fatal("issued onto a device that does not exist")
	}
	mustDevice(t, s, "d1", "tok1tok1tok1tok1", "one")
	mustDevice(t, s, "d2", "tok2tok2tok2tok2", "two")
	mustDevice(t, s, "d3", "tok3tok3tok3tok3", "three")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.AttachCredential(ctx, domain.CredentialAWG, "m1", "attached-then-deleted", "d1"))
	must(s.DeleteDevice(ctx, "d1"))
	must(s.AttachCredential(ctx, domain.CredentialAWG, "m1", "attached-then-detached", "d2"))
	must(s.RotateDeviceToken(ctx, "d2", "tok9tok9tok9tok9"))
	must(s.DetachCredential(ctx, domain.CredentialAWG, "m1", "attached-then-detached", "tokNtokNtokNtokN"))
	must(s.AddWGClientToDevice(ctx, "m1", wgCred("issued-onto-device", "d", "10.80.0.5/32"), "d3"))
	must(s.DeleteDevice(ctx, "d3"))

	for _, id := range []string{"attached-then-deleted", "attached-then-detached", "issued-onto-device"} {
		if _, _, err := s.FindUnattachedWGClient(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: personal link came back (err = %v)", id, err)
		}
	}
	if _, _, err := s.FindUnattachedWGClient(ctx, "never-attached"); err != nil {
		t.Errorf("a credential that never joined a device lost its link: %v", err)
	}
}

func TestDetachRotatesATokenThatIsTheCredentialID(t *testing.T) {
	ctx := context.Background()
	s := devStore(t, "m1")
	// A migrated device: its token IS the credential's ID.
	mustDevice(t, s, "d1", "cred-aaaa-1111", "laptop")
	if err := s.AddWGClientToDevice(ctx, "m1", wgCred("cred-aaaa-1111", "laptop", "10.80.0.2/32"), "d1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DetachCredential(ctx, domain.CredentialAWG, "m1", "cred-aaaa-1111", "fresh0fresh0fresh0fresh0fresh0ff"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDeviceByToken(ctx, "cred-aaaa-1111"); !errors.Is(err, ErrNotFound) {
		t.Errorf("device still answers on the detached credential's ID: %v", err)
	}
	if d, err := s.GetDeviceByToken(ctx, "fresh0fresh0fresh0fresh0fresh0ff"); err != nil || d.ID != "d1" {
		t.Errorf("rotated token: %+v %v", d, err)
	}
	// An ordinary device keeps its token when a credential is detached.
	mustDevice(t, s, "d2", "keepkeepkeepkeep", "other")
	if err := s.AddWGClientToDevice(ctx, "m1", wgCred("c2", "other", "10.80.0.3/32"), "d2"); err != nil {
		t.Fatal(err)
	}
	if err := s.DetachCredential(ctx, domain.CredentialAWG, "m1", "c2", "unusedunusedunus"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDeviceByToken(ctx, "keepkeepkeepkeep"); err != nil {
		t.Errorf("ordinary token rotated by a detach: %v", err)
	}
}

func TestRevokingCredentialDropsItFromDevice(t *testing.T) {
	ctx := context.Background()
	s := devStore(t, "m1")
	mustDevice(t, s, "d1", "tok1tok1tok1tok1", "a")
	if err := s.AddVLESSClientToDevice(ctx, "m1", domain.VLESSClient{Name: "a", UUID: "u", ShortID: "aa"}, "d1", devT0); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeVLESSClient(ctx, "m1", "a"); err != nil {
		t.Fatal(err)
	}
	if d1, err := s.GetDevice(ctx, "d1"); err != nil || len(d1.Credentials) != 0 {
		t.Errorf("device after revoke = %+v, %v", d1, err)
	}
}

func TestRotateAndRenameDevice(t *testing.T) {
	ctx := context.Background()
	s := devStore(t)
	mustDevice(t, s, "d1", "tok1tok1tok1tok1", "a")
	if err := s.RotateDeviceToken(ctx, "d1", "tok9tok9tok9tok9"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDeviceByToken(ctx, "tok1tok1tok1tok1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("old token still resolves: %v", err)
	}
	if err := s.RenameDevice(ctx, "d1", "b"); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateDeviceToken(ctx, "ghost", "tokXtokXtokXtokX"); !errors.Is(err, ErrNotFound) {
		t.Errorf("rotate unknown: %v", err)
	}
}

func TestFindUnattachedWGClientIsOneIndexedQuery(t *testing.T) {
	ctx := context.Background()
	s := devStore(t, "m1", "m2")
	mustDevice(t, s, "d1", "tok1tok1tok1tok1", "a")
	if err := s.AddWGClient(ctx, "m2", wgCred("free", "free", "10.81.0.2/32")); err != nil {
		t.Fatal(err)
	}
	if err := s.AddWGClientToDevice(ctx, "m1", wgCred("owned", "owned", "10.80.0.2/32"), "d1"); err != nil {
		t.Fatal(err)
	}
	if m, c, err := s.FindUnattachedWGClient(ctx, "free"); err != nil || m != "m2" || c.PrivateKey != "priv-free" {
		t.Errorf("free credential: m=%q c=%+v err=%v", m, c, err)
	}
	if _, _, err := s.FindUnattachedWGClient(ctx, "owned"); !errors.Is(err, ErrNotFound) {
		t.Errorf("attached credential found by legacy lookup: %v", err)
	}
	var plan string
	if err := s.db.QueryRowContext(ctx,
		`EXPLAIN QUERY PLAN SELECT master_id FROM client_wg_credentials WHERE id=? AND device_id IS NULL AND legacy_link_retired=0`,
		"free").Scan(new(int), new(int), new(int), &plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "idx_client_wg_id") {
		t.Errorf("legacy lookup is not indexed: %s", plan)
	}
}

func TestAddVLESSClientToDeviceDoesNotRekeyAnExistingName(t *testing.T) {
	ctx := context.Background()
	s := devStore(t, "m1")
	mustDevice(t, s, "d1", "tok1tok1tok1tok1", "a")
	if err := s.AddVLESSClient(ctx, "m1", domain.VLESSClient{Name: "a", UUID: "old", ShortID: "aa"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddVLESSClientToDevice(ctx, "m1", domain.VLESSClient{Name: "a", UUID: "new", ShortID: "bb"}, "d1", devT0); err == nil {
		t.Error("device-bound issue replaced a live credential's UUID")
	}
	if got, _ := s.ListVLESSClients(ctx, "m1"); len(got) != 1 || got[0].UUID != "old" {
		t.Errorf("credential changed: %+v", got)
	}
}
