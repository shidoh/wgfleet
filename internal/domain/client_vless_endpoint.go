package domain

import (
	"net"
	"net/url"
	"strconv"
)

// Client-leg XMUX (XHTTP connection reuse) tuning. The three ranges came from the
// operator's original buildClashConfig YAML and are exported here so that YAML —
// and every other renderer of a client's endpoint — reads ONE copy: a second
// hand-typed copy of these numbers is how they drift apart.
const (
	ClientVLESSXMUXMaxConcurrency   = "16-32"
	ClientVLESSXMUXHMaxRequestTimes = "600-900"
	ClientVLESSXMUXHMaxReusableSecs = "1800-3000"
)

// ClientVLESSEndpoint is every field a client needs to dial one VLESS credential,
// resolved ONCE. The vless:// link, the operator's Clash download and the device
// profile all read it, so a default decided in one place (xhttp path, mode,
// fingerprint, empty SNI) cannot be decided differently in another.
type ClientVLESSEndpoint struct {
	Host      string
	Port      int
	UUID      string
	PublicKey string
	ShortID   string
	// ServerName is the camouflage SNI; EmptySNI asks the client to send none. The
	// spelling of "none" differs by format (an empty sni= in a link, the server's
	// IP as servername in mihomo), so the intent is carried, not a spelling.
	ServerName string
	EmptySNI   bool
	// Fingerprint is the uTLS fingerprint; "" = omit (operator chose "none").
	Fingerprint string
	Vision      bool
	XHTTPPath   string
	XHTTPMode   string
	// Mux is XMUX; a vless:// link has no parameter for it, the YAML formats do.
	Mux bool
}

// EndpointFor resolves one credential's endpoint on this inbound.
func (c ClientVLESSServerSpec) EndpointFor(host, publicKey string, cl VLESSClient) ClientVLESSEndpoint {
	fp := c.ResolvedFingerprint()
	if fp == ClientVLESSFingerprintNone {
		fp = ""
	}
	path := c.XHTTPPath
	if path == "" {
		path = "/"
	}
	mode := c.XHTTPMode
	if mode == "" {
		mode = "packet-up"
	}
	return ClientVLESSEndpoint{
		Host: host, Port: c.ListenPort, UUID: cl.UUID, PublicKey: publicKey, ShortID: cl.ShortID,
		ServerName: c.ServerName, EmptySNI: c.AllowEmptySNI, Fingerprint: fp,
		Vision: c.Mode == RealityModeVision, XHTTPPath: path, XHTTPMode: mode, Mux: c.ResolvedMux(),
	}
}

// MihomoServerName is the servername a mihomo proxy sends: the camouflage SNI,
// or — for empty SNI — the server's own IP, for which uTLS omits the extension.
func (e ClientVLESSEndpoint) MihomoServerName() string {
	if e.EmptySNI {
		return e.Host
	}
	return e.ServerName
}

// Link renders the vless:// share link; label is the fragment the app shows.
func (e ClientVLESSEndpoint) Link(label string) string {
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", "reality")
	q.Set("pbk", e.PublicKey)
	if e.Fingerprint != "" {
		q.Set("fp", e.Fingerprint)
	}
	q.Set("sid", e.ShortID)
	// Empty-SNI (the client-leg default): send no SNI, the reported RU-TSPU bypass.
	if e.EmptySNI {
		q.Set("sni", "")
	} else {
		q.Set("sni", e.ServerName)
	}
	if e.Vision {
		q.Set("type", "tcp")
		q.Set("flow", "xtls-rprx-vision")
	} else {
		q.Set("type", "xhttp")
		q.Set("path", e.XHTTPPath)
		q.Set("mode", e.XHTTPMode)
	}
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(e.UUID),
		Host:     net.JoinHostPort(e.Host, strconv.Itoa(e.Port)),
		RawQuery: q.Encode(),
		Fragment: label,
	}
	return u.String()
}
