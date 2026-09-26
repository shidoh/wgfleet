package keybroker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// Devices (ADR-0035). The broker mints — IDs, tokens, keys, time — and the store
// records; the same split as IssueWGClient and for the same reason: a replicated
// write has to be a decision already made.

// newDeviceToken is 16 random bytes in hex: 32 characters, inside what
// portal.validToken admits.
func newDeviceToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Masters names the fleet's masters in manifest order — the order a device's
// proxies appear in, and the list the portal walks.
func (b *Broker) Masters() []string {
	out := make([]string, 0, len(b.fleet.Masters))
	for _, m := range b.fleet.Masters {
		out = append(out, m.Name)
	}
	return out
}

// CreateDevice mints and records a device.
func (b *Broker) CreateDevice(ctx context.Context, name string) (domain.ClientDevice, error) {
	if !domain.ValidClientName(name) {
		return domain.ClientDevice{}, errBadClientName
	}
	d := domain.ClientDevice{ID: newDeviceToken(), Token: newDeviceToken(), Name: name, CreatedAt: time.Now().UTC()}
	if err := b.store.CreateDevice(ctx, d); err != nil {
		return domain.ClientDevice{}, err
	}
	b.log.Info("client device created", "device", name)
	return d, nil
}

func (b *Broker) GetDevice(ctx context.Context, id string) (domain.ClientDevice, error) {
	return b.store.GetDevice(ctx, id)
}

func (b *Broker) GetDeviceByToken(ctx context.Context, token string) (domain.ClientDevice, error) {
	return b.store.GetDeviceByToken(ctx, token)
}

func (b *Broker) ListDevices(ctx context.Context) ([]domain.ClientDevice, error) {
	return b.store.ListDevices(ctx)
}

func (b *Broker) FindUnattachedWGClient(ctx context.Context, id string) (string, domain.WGClient, error) {
	return b.store.FindUnattachedWGClient(ctx, id)
}

// RenameDevice changes the label only; the token and the credentials stay.
func (b *Broker) RenameDevice(ctx context.Context, id, name string) error {
	if !domain.ValidClientName(name) {
		return errBadClientName
	}
	return b.store.RenameDevice(ctx, id, name)
}

// RotateDeviceToken cuts off a leaked link: the old URL stops resolving at once;
// the credentials — and the tunnels already configured — are untouched.
func (b *Broker) RotateDeviceToken(ctx context.Context, id string) (domain.ClientDevice, error) {
	if err := b.store.RotateDeviceToken(ctx, id, newDeviceToken()); err != nil {
		return domain.ClientDevice{}, err
	}
	b.log.Info("client device link rotated", "device_id", id)
	return b.store.GetDevice(ctx, id)
}

// DeleteDevice unlinks the device's credentials; it revokes nothing.
func (b *Broker) DeleteDevice(ctx context.Context, id string) error {
	return b.store.DeleteDevice(ctx, id)
}

func (b *Broker) AttachCredential(ctx context.Context, kind domain.CredentialKind, masterID, ref, deviceID string) error {
	return b.store.AttachCredential(ctx, kind, masterID, ref, deviceID)
}

// DetachCredential empties a slot. The replacement token is minted here and
// used by the store only when the device's token is this credential's ID.
func (b *Broker) DetachCredential(ctx context.Context, kind domain.CredentialKind, masterID, ref string) error {
	return b.store.DetachCredential(ctx, kind, masterID, ref, newDeviceToken())
}

// IssueWGClientForDevice mints an AWG credential named after the device and
// stores it already attached — one insert.
func (b *Broker) IssueWGClientForDevice(ctx context.Context, masterID, deviceID string) (domain.WGClient, error) {
	d, err := b.store.GetDevice(ctx, deviceID)
	if err != nil {
		return domain.WGClient{}, err
	}
	c, err := b.mintWGClient(ctx, masterID, d.Name)
	if err != nil {
		return domain.WGClient{}, err
	}
	if err := b.store.AddWGClientToDevice(ctx, masterID, c, deviceID); err != nil {
		return domain.WGClient{}, err
	}
	b.log.Info("client WG credential issued", "master", masterID, "client", c.Name, "device_id", deviceID, "address", c.Address)
	return c, nil
}

// IssueVLESSClientForDevice is the VLESS twin.
func (b *Broker) IssueVLESSClientForDevice(ctx context.Context, masterID, deviceID string) (domain.VLESSClient, error) {
	d, err := b.store.GetDevice(ctx, deviceID)
	if err != nil {
		return domain.VLESSClient{}, err
	}
	c := domain.VLESSClient{Name: d.Name, UUID: randomUUID(), ShortID: randomShortID()}
	if err := b.store.AddVLESSClientToDevice(ctx, masterID, c, deviceID, time.Now().UTC()); err != nil {
		return domain.VLESSClient{}, err
	}
	return c, nil
}

// ClientMasterMeta is one master's routing metadata for a device profile.
// Resolvers come from clientResolvers — the derivation behind the .conf's DNS
// line — and are resolved even without the AWG leg, because a VLESS-only device
// needs the same blocky.
func (b *Broker) ClientMasterMeta(ctx context.Context, masterID string) (domain.ClientMasterMeta, error) {
	m, ok := b.masterConfig(masterID)
	if !ok {
		return domain.ClientMasterMeta{}, fmt.Errorf("keybroker: %q is not a configured master: %w", masterID, store.ErrNotFound)
	}
	var through []string
	seen := map[string]bool{}
	for _, c := range append(append([]string(nil), m.ClientAWG.RouteThroughCIDRs...), m.ClientVLESS.RouteThroughCIDRs...) {
		if !seen[c] {
			seen[c] = true
			through = append(through, c)
		}
	}
	return domain.ClientMasterMeta{
		RouteThrough: through,
		Resolvers:    b.clientResolvers(ctx, m),
		ClientPool:   m.ClientAWG.AddressPool,
		MgmtCIDRs:    b.fleet.MgmtCIDRs(),
	}, nil
}
