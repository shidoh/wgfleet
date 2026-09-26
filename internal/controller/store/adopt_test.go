package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestAdoptWrapsEveryCredentialOnceWithItsIDAsToken(t *testing.T) {
	ctx := context.Background()
	s := devStore(t, "m1")
	for _, c := range []domain.WGClient{wgCred("aaaa-1111", "laptop", "10.80.0.2/32"), wgCred("bbbb-2222", "phone", "10.80.0.3/32")} {
		if err := s.AddWGClient(ctx, "m1", c); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.AdoptWGCredentialsAsDevices(ctx, devT0)
	if err != nil || n != 2 {
		t.Fatalf("adopt = %d, %v", n, err)
	}
	d, err := s.GetDeviceByToken(ctx, "aaaa-1111")
	if err != nil {
		t.Fatalf("already-issued portal link no longer resolves: %v", err)
	}
	if d.Name != "laptop" || d.ID != AdoptedDeviceID("m1", "aaaa-1111") || !d.CreatedAt.Equal(devT0) {
		t.Errorf("device = %+v", d)
	}
	if c, ok := d.Credential(domain.CredentialAWG, "m1"); !ok || c.Ref != "aaaa-1111" {
		t.Errorf("credential not attached: %+v", d.Credentials)
	}
}

func TestAdoptRetiresTheCredentialLink(t *testing.T) {
	ctx := context.Background()
	s := devStore(t, "m1")
	if err := s.AddWGClient(ctx, "m1", wgCred("aaaa-1111", "laptop", "10.80.0.2/32")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdoptWGCredentialsAsDevices(ctx, devT0); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDevice(ctx, AdoptedDeviceID("m1", "aaaa-1111")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDeviceByToken(ctx, "aaaa-1111"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted device still resolves: %v", err)
	}
	if _, _, err := s.FindUnattachedWGClient(ctx, "aaaa-1111"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting the migrated device revived the credential's own link: %v", err)
	}
}

func TestAdoptRunsOnlyOnce(t *testing.T) {
	ctx := context.Background()
	s := devStore(t, "m1")
	if err := s.AddWGClient(ctx, "m1", wgCred("c1", "laptop", "10.80.0.2/32")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdoptWGCredentialsAsDevices(ctx, devT0); err != nil {
		t.Fatal(err)
	}
	if err := s.DetachCredential(ctx, domain.CredentialAWG, "m1", "c1", "tokNtokNtokNtokN"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddWGClient(ctx, "m1", wgCred("c2", "tablet", "10.80.0.4/32")); err != nil {
		t.Fatal(err)
	}
	if n, err := s.AdoptWGCredentialsAsDevices(ctx, devT0.Add(time.Hour)); err != nil || n != 0 {
		t.Fatalf("second run adopted %d (err %v): a restart must not re-wrap credentials", n, err)
	}
	all, _ := s.ListDevices(ctx)
	if len(all) != 1 || len(all[0].Credentials) != 0 {
		t.Errorf("devices after restart = %+v", all)
	}
}

func TestAdoptSuffixesNameCollisionsAcrossMasters(t *testing.T) {
	ctx := context.Background()
	s := devStore(t, "m1", "m2")
	_ = s.AddWGClient(ctx, "m1", wgCred("c1", "laptop", "10.80.0.2/32"))
	_ = s.AddWGClient(ctx, "m2", wgCred("c2", "laptop", "10.81.0.2/32"))
	if _, err := s.AdoptWGCredentialsAsDevices(ctx, devT0); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	all, _ := s.ListDevices(ctx)
	for _, d := range all {
		names[d.Name] = true
	}
	if !names["laptop"] || !names["laptop-m2"] {
		t.Errorf("names = %v, want laptop and laptop-m2", names)
	}
}

func TestAdoptNameSuffixStaysValid(t *testing.T) {
	ctx := context.Background()
	long := strings.Repeat("x", domain.MaxClientNameLen)
	s := devStore(t, "m1", "master-with-a-long-name")
	_ = s.AddWGClient(ctx, "m1", wgCred("c1", long, "10.80.0.2/32"))
	_ = s.AddWGClient(ctx, "master-with-a-long-name", wgCred("c2", long, "10.81.0.2/32"))
	mustDevice(t, s, "pre", "tokPtokPtokPtokP", "laptop-master-with-a-long-name")
	_ = s.AddWGClient(ctx, "master-with-a-long-name", wgCred("c3", "laptop", "10.81.0.3/32"))
	_ = s.AddWGClient(ctx, "m1", wgCred("c4", "laptop", "10.80.0.3/32"))
	if _, err := s.AdoptWGCredentialsAsDevices(ctx, devT0); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	all, _ := s.ListDevices(ctx)
	seen := map[string]bool{}
	for _, d := range all {
		if !domain.ValidClientName(d.Name) {
			t.Errorf("invalid device name %q (len %d)", d.Name, len(d.Name))
		}
		if seen[d.Name] {
			t.Errorf("duplicate name %q", d.Name)
		}
		seen[d.Name] = true
	}
	if len(all) != 5 {
		t.Errorf("devices = %d, want 5", len(all))
	}
}

func TestAdoptIsDeterministic(t *testing.T) {
	ctx := context.Background()
	build := func() []domain.ClientDevice {
		s := devStore(t, "m1", "m2")
		_ = s.AddWGClient(ctx, "m2", wgCred("c2", "laptop", "10.81.0.2/32"))
		_ = s.AddWGClient(ctx, "m1", wgCred("c1", "laptop", "10.80.0.2/32"))
		if _, err := s.AdoptWGCredentialsAsDevices(ctx, devT0); err != nil {
			t.Fatal(err)
		}
		all, _ := s.ListDevices(ctx)
		return all
	}
	a, b := build(), build()
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Name != b[i].Name || a[i].Token != b[i].Token {
			t.Errorf("replica divergence: %+v vs %+v", a[i], b[i])
		}
	}
}
