package wgeasy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/shidoh/wgfleet/internal/domain"
)

// UserConfigColumns is the managed subset of wg-easy's user_configs_table — the
// per-client defaults wg-easy bakes into every generated client config (endpoint
// host/port, MTU, DNS, allowed-IPs, and the client-side AmneziaWG obfuscation:
// junk sizes j_c/j_min/j_max and signature packets I1-I5).
//
// Like InterfaceColumns these must track the desired state declaratively. The
// INIT_* env vars seed only host/port/DNS/allowed-ips, and only at first DB
// creation, so a running node would never pick up a manifest change. The full AWG
// obfuscation is not seedable by INIT_* at all:
//   - j_c/j_min/j_max default to 7/10/1000 in wg-easy's schema — j_min=10 is far
//     below our derived transport-junk size S4, so client junk would underflow the
//     master kernel's AWG 2.0 S4-strip and the obfuscated handshake would break;
//   - I1-I5 are left NULL, so clients would emit NO signature packets while the
//     server interface emits its own — obfuscation is then asymmetric.
//
// Obfuscation is mandatory in BOTH directions, so we enforce every AWG column by
// direct DB write here (the per-end I1-I5 / Jc/Jmin/Jmax are NOT shared from the
// server interface — wg-easy copies them from these defaults into each client row
// at client creation), mirroring the interface reconciler (ADR-0008).
//
// DNS and AllowedIPs are stored by wg-easy as JSON text arrays; I1-I5 as text.
// ClientKeepaliveSeconds is the PersistentKeepalive baked into every client
// config. Clients sit behind NAT and the master is the server side, so without a
// keepalive the client's NAT mapping expires on idle and the master can no longer
// reach it (return traffic / rekey stalls). wg-easy's schema default is 0 (off);
// we enforce 25s, the conventional WireGuard NAT-keepalive interval.
const ClientKeepaliveSeconds = 25

// DefaultClientAllowedIPs is the client-facing AllowedIPs the platform pins when
// the operator has not set one explicitly. It is IPv4-only ON PURPOSE: the
// wgfleet data plane carries no IPv6 (the master runs with net.ipv6 forwarding
// off, mihomo with ipv6:false, and WARP egress has no working IPv6). wg-easy's
// schema default is ["0.0.0.0/0","::/0"], i.e. it hands clients an IPv6 default
// route into a tunnel that black-holes every v6 packet — happy-eyeballs then
// prefers IPv6 to dual-stack hosts (Instagram, Google, most CDNs) and stalls
// (pages start then stop loading, video freezes after a few seconds; an earlier finding).
// Pinning IPv4-only keeps clients off the dead v6 path. An operator who later
// adds real IPv6 egress can override via the manifest's client_allowed_ips.
var DefaultClientAllowedIPs = []string{"0.0.0.0/0"}

type UserConfigColumns struct {
	Host               string
	Port               int
	MTU                int
	Keepalive          int
	DNS                []string
	AllowedIPs         []string
	Jc, Jmin, Jmax     int
	I1, I2, I3, I4, I5 string
}

// Equal reports whether two column sets are identical (slice-aware).
func (c UserConfigColumns) Equal(o UserConfigColumns) bool {
	return c.Host == o.Host && c.Port == o.Port && c.MTU == o.MTU &&
		c.Keepalive == o.Keepalive &&
		c.Jc == o.Jc && c.Jmin == o.Jmin && c.Jmax == o.Jmax &&
		c.I1 == o.I1 && c.I2 == o.I2 && c.I3 == o.I3 && c.I4 == o.I4 && c.I5 == o.I5 &&
		equalStrings(c.DNS, o.DNS) && equalStrings(c.AllowedIPs, o.AllowedIPs)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// DesiredUserConfig overlays the desired client-facing values from the master's
// spec onto the current columns, leaving a column untouched when there is no
// intent for it (empty host/dns, zero port/mtu, nil AWG). This avoids clobbering
// wg-easy's sane migration defaults with empty values when the operator has not
// specified DNS. AllowedIPs is the exception: when the operator sets none we pin
// IPv4-only (DefaultClientAllowedIPs) instead of inheriting wg-easy's ::/0
// default, which is wrong for this IPv4-only data plane.
func DesiredUserConfig(current UserConfigColumns, w domain.WGServerSpec, host string, dns, allowedIPs []string) UserConfigColumns {
	desired := current
	if host != "" {
		desired.Host = host
	}
	if w.ListenPort > 0 {
		desired.Port = w.ListenPort
	}
	if w.MTU > 0 {
		desired.MTU = w.MTU
	}
	// Clients are behind NAT to the master server side, so a keepalive is always
	// required to keep the NAT mapping alive (wg-easy defaults it to 0/off).
	desired.Keepalive = ClientKeepaliveSeconds
	if len(dns) > 0 {
		desired.DNS = dns
	}
	if len(allowedIPs) > 0 {
		desired.AllowedIPs = allowedIPs
	} else {
		// No operator override: pin client AllowedIPs to IPv4-only rather than
		// inherit wg-easy's ["0.0.0.0/0","::/0"] default, which routes IPv6 into a
		// dead tunnel and stalls dual-stack traffic (see DefaultClientAllowedIPs,
		// an earlier finding). This DOES overwrite the wg-easy default — that default is
		// wrong for an IPv4-only data plane, so we assert intent here.
		desired.AllowedIPs = append([]string(nil), DefaultClientAllowedIPs...)
	}
	// Obfuscation is MANDATORY in both directions — clients must emit the full AWG
	// decoy, never a bare WireGuard handshake. wg-easy bakes these client defaults
	// into every generated client config (they are NOT shared from the server
	// interface — I1-I5 and Jc/Jmin/Jmax are per-end, so where they MAY differ they
	// MUST). We therefore use the dedicated CLIENT-end profile (ClientAWGLocal),
	// distinct from the server interface's AWG.Local, falling back to the server
	// profile only for older controllers that don't send a client-end one.
	//
	// Jc/Jmin/Jmax come from the S4-floored local params so no client junk packet
	// underflows the master kernel's S4-strip (see DeriveAWGParamsForEnd's Jmin
	// floor). I1-I5 are the userspace-safe signature packets (no <c>/<t> tags),
	// which Amnezia/userspace clients require.
	if local := clientLocal(w); local != nil {
		desired.Jc = local.Jc
		desired.Jmin = local.Jmin
		desired.Jmax = local.Jmax
		desired.I1 = local.I1
		desired.I2 = local.I2
		desired.I3 = local.I3
		desired.I4 = local.I4
		desired.I5 = local.I5
	}
	return desired
}

// clientLocal returns the per-end AWG decoy the CLIENT side must emit: the
// dedicated client-end profile when the controller provides one, else the server
// interface's local params (back-compat with controllers that predate the
// distinct client-end derivation). nil ⇒ no AWG at all (vanilla WG leg).
func clientLocal(w domain.WGServerSpec) *domain.AWGLocal {
	if w.ClientAWGLocal != nil {
		return w.ClientAWGLocal
	}
	if w.AWG != nil {
		return &w.AWG.Local
	}
	return nil
}

// RenderUserConfigUpdateSQL renders the UPDATE for dry-run plan output. None of
// these columns are secret (client-facing defaults + obfuscation sizes).
func RenderUserConfigUpdateSQL(name string, c UserConfigColumns) string {
	return fmt.Sprintf(
		"UPDATE user_configs_table SET\n"+
			"  host='%s', port=%d, default_mtu=%d, default_persistent_keepalive=%d,\n"+
			"  default_dns='%s', default_allowed_ips='%s',\n"+
			"  default_j_c=%d, default_j_min=%d, default_j_max=%d,\n"+
			"  default_i1='%s', default_i2='%s', default_i3='%s', default_i4='%s', default_i5='%s'\n"+
			"WHERE id='%s';",
		c.Host, c.Port, c.MTU, c.Keepalive,
		mustJSON(c.DNS), mustJSON(c.AllowedIPs),
		c.Jc, c.Jmin, c.Jmax,
		c.I1, c.I2, c.I3, c.I4, c.I5, name)
}

// ReadUserConfig returns the interface's current managed user-config columns.
// found is false (no error) when the row does not exist yet.
func ReadUserConfig(ctx context.Context, dbPath, name string) (cols UserConfigColumns, found bool, err error) {
	db, err := open(dbPath)
	if err != nil {
		return UserConfigColumns{}, false, err
	}
	defer func() { _ = db.Close() }()

	const q = `SELECT
		COALESCE(host,''), COALESCE(port,0), COALESCE(default_mtu,0),
		COALESCE(default_persistent_keepalive,0),
		COALESCE(default_dns,'[]'), COALESCE(default_allowed_ips,'[]'),
		COALESCE(default_j_c,0), COALESCE(default_j_min,0), COALESCE(default_j_max,0),
		COALESCE(default_i1,''), COALESCE(default_i2,''), COALESCE(default_i3,''),
		COALESCE(default_i4,''), COALESCE(default_i5,'')
		FROM user_configs_table WHERE id = ?`
	var dnsJSON, allowedJSON string
	row := db.QueryRowContext(ctx, q, name)
	err = row.Scan(&cols.Host, &cols.Port, &cols.MTU, &cols.Keepalive, &dnsJSON, &allowedJSON,
		&cols.Jc, &cols.Jmin, &cols.Jmax,
		&cols.I1, &cols.I2, &cols.I3, &cols.I4, &cols.I5)
	if errors.Is(err, sql.ErrNoRows) {
		return UserConfigColumns{}, false, nil
	}
	if err != nil {
		return UserConfigColumns{}, false, fmt.Errorf("read wg-easy user config %q: %w", name, err)
	}
	if cols.DNS, err = parseJSONArray(dnsJSON); err != nil {
		return UserConfigColumns{}, false, fmt.Errorf("parse default_dns for %q: %w", name, err)
	}
	if cols.AllowedIPs, err = parseJSONArray(allowedJSON); err != nil {
		return UserConfigColumns{}, false, fmt.Errorf("parse default_allowed_ips for %q: %w", name, err)
	}
	return cols, true, nil
}

// UpdateUserConfig applies the managed user-config columns. It errors if the row
// does not exist (wg-easy must be set up first).
func UpdateUserConfig(ctx context.Context, dbPath, name string, c UserConfigColumns) error {
	db, err := open(dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	const q = `UPDATE user_configs_table SET
		host=?, port=?, default_mtu=?, default_persistent_keepalive=?,
		default_dns=?, default_allowed_ips=?,
		default_j_c=?, default_j_min=?, default_j_max=?,
		default_i1=?, default_i2=?, default_i3=?, default_i4=?, default_i5=?
		WHERE id=?`
	res, err := db.ExecContext(ctx, q,
		c.Host, c.Port, c.MTU, c.Keepalive, mustJSON(c.DNS), mustJSON(c.AllowedIPs),
		c.Jc, c.Jmin, c.Jmax,
		c.I1, c.I2, c.I3, c.I4, c.I5, name)
	if err != nil {
		return fmt.Errorf("update wg-easy user config %q: %w", name, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update wg-easy user config %q: %w", name, err)
	}
	if n == 0 {
		return fmt.Errorf("wg-easy user config %q not found (set up wg-easy first)", name)
	}
	return nil
}

func parseJSONArray(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// mustJSON marshals a string slice to a JSON array. A []string never fails to
// marshal, so an error here is impossible; fall back to "[]" defensively.
func mustJSON(v []string) string {
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}
