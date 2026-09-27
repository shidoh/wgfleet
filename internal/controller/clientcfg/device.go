package clientcfg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/mihomo"
	"github.com/shidoh/wgfleet/internal/wg"
)

// ErrNoActiveCredential: nothing on this device would connect — every credential
// paused, or none attached. The portal answers it as "paused", like a paused .conf.
var ErrNoActiveCredential = errors.New("clientcfg: the device has no active credential")

// ErrNoAWG: the device has no AWG credential at all — a VLESS-only device, or one
// with nothing attached. Distinct from ErrNoActiveCredential (which means "you had
// one and it is paused") and from store.ErrNotFound (which means "this token names
// nothing"): a device token IS real and IS a device, it simply has no .conf to
// hand out. The portal maps it to 404 without charging the rate limiter — asking
// for a format the device does not have is not a grind.
var ErrNoAWG = errors.New("clientcfg: the device has no AWG credential")

// DeviceLookup is what turning a portal token into a device needs, and nothing
// more: two indexed lookups.
type DeviceLookup interface {
	GetDeviceByToken(ctx context.Context, token string) (domain.ClientDevice, error)
	FindUnattachedWGClient(ctx context.Context, id string) (string, domain.WGClient, error)
}

// ProfileSource is what building a device's profile needs: the credential source
// plus the VLESS credentials and each master's routing metadata.
type ProfileSource interface {
	Source
	ListVLESSClients(ctx context.Context, masterID string) ([]domain.VLESSClient, error)
	ClientMasterMeta(ctx context.Context, masterID string) (domain.ClientMasterMeta, error)
}

// PortalSource is the portal's whole dependency.
type PortalSource interface {
	DeviceLookup
	ProfileSource
}

// ResolveDevice turns a token into a device: a device token first, then the ID
// of a credential that has never belonged to a device. Both are single indexed
// lookups across the fleet; neither walks the masters.
func ResolveDevice(ctx context.Context, src DeviceLookup, token string) (domain.ClientDevice, error) {
	d, err := src.GetDeviceByToken(ctx, token)
	if err == nil || !errors.Is(err, store.ErrNotFound) {
		return d, err
	}
	master, c, err := src.FindUnattachedWGClient(ctx, token)
	if err != nil {
		return domain.ClientDevice{}, err
	}
	return domain.ClientDevice{Token: token, Name: c.Name, CreatedAt: c.CreatedAt,
		Credentials: []domain.DeviceCredential{{Kind: domain.CredentialAWG, MasterID: master, Ref: c.ID, Name: c.Name}}}, nil
}

// wgState is one AWG credential's standing, decided in ONE place — the page, the
// .conf routes and the profile all read it.
type wgState int

const (
	wgAbsent   wgState = iota // revoked since, or never on this master
	wgPaused                  // exists, switched off
	wgNotReady                // enabled, but its master cannot hand out a config yet
	wgReady
)

func wgFor(ctx context.Context, src Source, masterID, ref string) (wg.ClientConfigInput, domain.Node, wgState, error) {
	in, node, err := BuildInput(ctx, src, masterID, ref)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return in, node, wgAbsent, nil
	case errors.Is(err, ErrNotReady):
		// BuildInput says "not ready" before it reads the credentials, so whether
		// this one is enabled is asked here — and a store failure while asking is a
		// store failure, not a reason to thin anything.
		c, ferr := findClient(ctx, src, masterID, ref)
		switch {
		case errors.Is(ferr, store.ErrNotFound):
			return in, node, wgAbsent, nil
		case ferr != nil:
			return in, node, wgAbsent, ferr
		case !c.Enabled:
			return in, node, wgPaused, nil
		}
		return in, node, wgNotReady, nil
	case err != nil:
		return in, node, wgAbsent, err
	case !in.Client.Enabled:
		return in, node, wgPaused, nil
	}
	return in, node, wgReady, nil
}

// WGSelection is the one AWG credential the portal hands out as a .conf.
type WGSelection struct {
	MasterID string
	Input    wg.ClientConfigInput
	Master   domain.Node
}

// SelectWG picks the device's AWG credential for the page, /config, /qr and the
// reserve doors: the first ENABLED and READY one in master order. One function,
// so the page cannot show one credential while the download hands out another.
func SelectWG(ctx context.Context, src Source, masters []string, dev domain.ClientDevice) (WGSelection, error) {
	var sawPaused, sawNotReady bool
	for _, m := range masters {
		cred, ok := dev.Credential(domain.CredentialAWG, m)
		if !ok {
			continue
		}
		in, node, st, err := wgFor(ctx, src, m, cred.Ref)
		if err != nil {
			return WGSelection{}, err
		}
		switch st {
		case wgReady:
			return WGSelection{MasterID: m, Input: in, Master: node}, nil
		case wgPaused:
			sawPaused = true
		case wgNotReady:
			sawNotReady = true
		}
	}
	switch {
	case sawNotReady:
		return WGSelection{}, fmt.Errorf("device %q: %w", dev.Name, ErrNotReady)
	case sawPaused:
		return WGSelection{}, ErrNoActiveCredential
	}
	return WGSelection{}, ErrNoAWG
}

// deviceParts is one walk over a device's credentials, shared by page and profile.
type deviceParts struct {
	masters []mihomo.ClientProfileMaster
	mgmt    []string
	sites   []domain.ClientSite
	links   []string
	active  int
}

func collectDevice(ctx context.Context, src ProfileSource, masters []string, dev domain.ClientDevice) (deviceParts, error) {
	var p deviceParts
	for _, m := range masters {
		pm := mihomo.ClientProfileMaster{Name: m}
		if cred, ok := dev.Credential(domain.CredentialAWG, m); ok {
			in, _, st, err := wgFor(ctx, src, m, cred.Ref)
			if err != nil {
				return deviceParts{}, err
			}
			switch st {
			case wgReady:
				p.active++
				pm.AWG = &in
			case wgNotReady:
				p.active++
			}
		}
		if cred, ok := dev.Credential(domain.CredentialVLESS, m); ok {
			if err := addVLESS(ctx, src, m, cred.Ref, &pm, &p); err != nil {
				return deviceParts{}, err
			}
		}
		if pm.AWG == nil && pm.VLESS == nil {
			continue
		}
		meta, err := src.ClientMasterMeta(ctx, m)
		if err != nil {
			return deviceParts{}, fmt.Errorf("clientcfg: routing metadata of %q: %w", m, err)
		}
		pm.RouteThrough, pm.DNS, pm.ClientPool = meta.RouteThrough, meta.Resolvers, meta.ClientPool
		p.mgmt, p.sites = meta.MgmtCIDRs, meta.Sites
		p.masters = append(p.masters, pm)
	}
	return p, nil
}

// addVLESS adds one master's VLESS proxy. A VLESS credential has no pause, so
// one that exists always counts as active; a master not ready is skipped.
func addVLESS(ctx context.Context, src ProfileSource, m, ref string, pm *mihomo.ClientProfileMaster, p *deviceParts) error {
	clients, err := src.ListVLESSClients(ctx, m)
	if err != nil {
		return fmt.Errorf("clientcfg: vless credentials of %q: %w", m, err)
	}
	var found *domain.VLESSClient
	for i := range clients {
		if clients[i].Name == ref {
			found = &clients[i]
		}
	}
	if found == nil {
		return nil
	}
	p.active++
	// A master missing from the store — GetNode returns store.ErrNotFound — is not
	// ready, not absent: node deletion cascades its credentials, so a device can
	// only ever reference a master that once existed, and the same master routinely
	// coming back is a store race, not a lost credential. Skip it exactly like the
	// unpublished-key / no-endpoint cases below, and let it surface as ErrNotReady
	// only if nothing else on the device contributes either — never as a raw error.
	node, err := src.GetNode(ctx, m)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return err
	}
	spec, err := src.RenderNodeSpec(ctx, m)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return err
	}
	host := EndpointHost(node, spec)
	if spec.Master == nil || spec.Master.ClientVLESS == nil || host == "" || node.ClientVLESSPublicKey == "" {
		return nil
	}
	e := spec.Master.ClientVLESS.EndpointFor(host, node.ClientVLESSPublicKey, *found)
	pm.VLESS = &e
	p.links = append(p.links, e.Link(node.Name+"-"+found.Name))
	return nil
}

// BuildDeviceProfile renders the device's mihomo profile. A store failure fails
// it whole: a profile missing a proxy is cached by the app for a day as truth.
func BuildDeviceProfile(ctx context.Context, src ProfileSource, masters []string, dev domain.ClientDevice) (string, error) {
	p, err := collectDevice(ctx, src, masters, dev)
	if err != nil {
		return "", err
	}
	switch {
	case p.active == 0:
		return "", ErrNoActiveCredential
	case len(p.masters) == 0:
		return "", fmt.Errorf("device %q: %w", dev.Name, ErrNotReady)
	}
	return mihomo.RenderClientProfile(mihomo.ClientProfileInput{Masters: p.masters, MgmtCIDRs: p.mgmt, Sites: p.sites})
}

// DeviceView is what the portal page shows.
type DeviceView struct {
	Device     domain.ClientDevice
	WG         *WGSelection
	VLESSLinks []string
	Active     bool
}

// ViewDevice resolves the page from the same walk and the same AWG selection
// the routes use.
func ViewDevice(ctx context.Context, src ProfileSource, masters []string, dev domain.ClientDevice) (DeviceView, error) {
	p, err := collectDevice(ctx, src, masters, dev)
	if err != nil {
		return DeviceView{}, err
	}
	v := DeviceView{Device: dev, VLESSLinks: p.links, Active: p.active > 0}
	sel, err := SelectWG(ctx, src, masters, dev)
	switch {
	case err == nil:
		v.WG = &sel
	case errors.Is(err, ErrNoAWG), errors.Is(err, ErrNotReady), errors.Is(err, ErrNoActiveCredential):
	default:
		return DeviceView{}, err
	}
	return v, nil
}

// ProfileFileName is what a client app names the imported profile.
func ProfileFileName(dev domain.ClientDevice) string { return dev.Name + ".yaml" }

// AttachmentHeader builds a Content-Disposition: attachment header for name,
// which — unlike a WGClient's or a legacy device's name — is not bounded by
// domain.ValidClientName here: a device synthesised from an imported (wg-easy)
// credential carries whatever name that import gave it. An embedded quote or
// backslash would let the value escape its own quoted-string, a raw CR/LF could
// inject a header line of its own, and a "/" could smuggle a path segment into
// wherever the browser ends up saving it — all four are stripped before the
// value is quoted, so the familiar `filename="name.ext"` shape is unchanged for
// every name that was already safe.
//
// Shared by the portal and the operator panel: both hand a device's profile out
// under this header, and a plain %q on the panel side would let a "/" or a
// control character through that the portal's own route already refuses.
func AttachmentHeader(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7f: // control chars, including CR and LF: dropped outright
			continue
		case r == '"', r == '\\', r == '/':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	safe := b.String()
	if safe == "" {
		safe = "profile"
	}
	// Both forms, as RFC 6266 §4.3 recommends: filename* carries the name exactly
	// (UTF-8, percent-encoded), filename stays for anything that knows only that.
	// Clash Verge Rev needs the extended one — it reads the plain form through
	// Rust's Debug formatting and keeps the escaped quotes in the profile name.
	return fmt.Sprintf("attachment; filename=%q; filename*=UTF-8''%s", safe, rfc5987Escape(safe))
}

// rfc5987Escape percent-encodes s as an RFC 5987 ext-value: everything but the
// attr-char set is written as %XX of its UTF-8 bytes.
func rfc5987Escape(s string) string {
	const attrPunct = "!#$&+-.^_`|~"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte(attrPunct, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}
