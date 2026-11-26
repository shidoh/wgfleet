package domain

// WARPIPFamily selects which address family the exit's WARP tunnel uses to reach
// Cloudflare's endpoint. The endpoint host has both A and AAAA records, and a
// host that resolves AAAA first while its IPv6 goes nowhere past the provider's
// gateway gets no WARP handshake at all — so the agent dials address literals of
// a chosen family instead of handing the name to wg-quick.
type WARPIPFamily string

const (
	// WARPIPFamilyAuto tries IPv4 first, then IPv6, then the profile's name.
	WARPIPFamilyAuto WARPIPFamily = "auto"
	// WARPIPFamilyIPv4 dials only IPv4 addresses.
	WARPIPFamilyIPv4 WARPIPFamily = "ipv4"
	// WARPIPFamilyIPv6 dials only IPv6 addresses.
	WARPIPFamilyIPv6 WARPIPFamily = "ipv6"
)

// Valid reports whether f is a known family; the empty value means auto.
func (f WARPIPFamily) Valid() bool {
	switch f {
	case "", WARPIPFamilyAuto, WARPIPFamilyIPv4, WARPIPFamilyIPv6:
		return true
	default:
		return false
	}
}

// OrAuto returns f, or auto when f is empty.
func (f WARPIPFamily) OrAuto() WARPIPFamily {
	if f == "" {
		return WARPIPFamilyAuto
	}
	return f
}
