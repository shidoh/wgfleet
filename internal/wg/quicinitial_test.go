package wg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The key schedule must match the published test vectors (RFC 9001 Appendix A),
// or no QUIC parser will open the cover packet.
func TestQUICInitialKeysMatchRFC9001Vectors(t *testing.T) {
	keys, err := clientInitialKeys(mustHex(t, "8394c8f03e515708"))
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ got, want []byte }{
		"key": {keys.key, mustHex(t, "1f369613dd76d5467730efcbe3b1a22d")},
		"iv":  {keys.iv, mustHex(t, "fa044b2f42a3fd3b46fb255c")},
		"hp":  {keys.hp, mustHex(t, "9f50449e04a0e810283a1e9933adedd2")},
	} {
		if !bytes.Equal(c.got, c.want) {
			t.Errorf("client %s = %x, want %x", name, c.got, c.want)
		}
	}
	mask, err := quicHeaderMask(keys.hp, mustHex(t, "d1b1c98dd7689fb8ec11d242b123dc9b"))
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex(t, "437b9aec36"); !bytes.Equal(mask[:5], want) {
		t.Errorf("header-protection mask = %x, want %x", mask[:5], want)
	}
}

// openedInitial is what a QUIC-aware filter recovers from a client Initial.
type openedInitial struct {
	dcid, scid []byte
	random     []byte
	sni        string
	alpn       string
}

// openClientInitial plays the filter: it removes header protection, decrypts the
// payload with the Initial keys of the packet's own DCID, and reads the
// ClientHello out of the CRYPTO frame.
func openClientInitial(t *testing.T, pkt []byte) openedInitial {
	t.Helper()
	if pkt[0]&0xf0 != 0xc0 || !bytes.Equal(pkt[1:5], []byte{0, 0, 0, 1}) {
		t.Fatalf("not a QUIC v1 Initial long header: %x", pkt[:5])
	}
	s := cryptobyte.String(pkt[5:])
	var dcid, scid, token cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&dcid) || !s.ReadUint8LengthPrefixed(&scid) {
		t.Fatal("connection IDs do not parse")
	}
	if len(dcid) < quicDCIDLen {
		t.Fatalf("client DCID %d B, RFC 9000 §7.2 requires at least 8", len(dcid))
	}
	tokenLen, n := readVarint(t, s)
	s = s[n:]
	if !s.ReadBytes((*[]byte)(&token), int(tokenLen)) {
		t.Fatal("token does not parse")
	}
	length, n := readVarint(t, s)
	s = s[n:]
	pnOffset := len(pkt) - len(s)
	if int(length) != len(s) {
		t.Fatalf("Length field %d != remaining %d (coalesced or truncated packet)", length, len(s))
	}

	keys, err := clientInitialKeys(dcid)
	if err != nil {
		t.Fatal(err)
	}
	sample := pkt[pnOffset+4 : pnOffset+20]
	mask, err := quicHeaderMask(keys.hp, sample)
	if err != nil {
		t.Fatal(err)
	}
	hdr := slices.Clone(pkt[:pnOffset+4])
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x03) + 1
	hdr = hdr[:pnOffset+pnLen]
	var pn uint32
	for i := 0; i < pnLen; i++ {
		hdr[pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint32(hdr[pnOffset+i])
	}
	block, _ := aes.NewCipher(keys.key)
	aead, _ := cipher.NewGCM(block)
	nonce := slices.Clone(keys.iv)
	var pnb [4]byte
	binary.BigEndian.PutUint32(pnb[:], pn)
	for i := 0; i < 4; i++ {
		nonce[len(nonce)-1-i] ^= pnb[3-i]
	}
	plain, err := aead.Open(nil, nonce, pkt[pnOffset+pnLen:], hdr)
	if err != nil {
		t.Fatalf("Initial does not decrypt with its own DCID's keys: %v", err)
	}

	// CRYPTO frame at offset 0, then PADDING only.
	if plain[0] != 0x06 || plain[1] != 0x00 {
		t.Fatalf("payload does not open with a CRYPTO frame at offset 0: %x", plain[:2])
	}
	cryptoLen, n := readVarint(t, plain[2:])
	hello := plain[2+n : 2+n+int(cryptoLen)]
	if rest := plain[2+n+int(cryptoLen):]; slices.ContainsFunc(rest, func(b byte) bool { return b != 0 }) {
		t.Fatal("bytes after the CRYPTO frame are not PADDING")
	}
	out := openedInitial{dcid: dcid, scid: scid, random: slices.Clone(hello[6:38])}
	out.sni, out.alpn = parseClientHello(t, hello, scid)
	return out
}

func readVarint(t *testing.T, b []byte) (uint64, int) {
	t.Helper()
	l := 1 << (b[0] >> 6)
	v := uint64(b[0] & 0x3f)
	for i := 1; i < l; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, l
}

// parseClientHello reads a TLS 1.3 ClientHello the way a filter extracting SNI
// does, and checks the QUIC-specific parts a client must send.
func parseClientHello(t *testing.T, msg []byte, scid []byte) (sni, alpn string) {
	t.Helper()
	s := cryptobyte.String(msg)
	var typ uint8
	var body cryptobyte.String
	if !s.ReadUint8(&typ) || typ != 1 || !s.ReadUint24LengthPrefixed(&body) || !s.Empty() {
		t.Fatal("not a single ClientHello handshake message")
	}
	var ver uint16
	var random, sid, suites, comp, exts cryptobyte.String
	if !body.ReadUint16(&ver) || !body.ReadBytes((*[]byte)(&random), 32) ||
		!body.ReadUint8LengthPrefixed(&sid) || !body.ReadUint16LengthPrefixed(&suites) ||
		!body.ReadUint8LengthPrefixed(&comp) || !body.ReadUint16LengthPrefixed(&exts) || !body.Empty() {
		t.Fatal("ClientHello body does not parse")
	}
	if len(sid) != 0 {
		t.Error("QUIC forbids a legacy_session_id (RFC 9001 §8.4)")
	}
	seen := map[uint16]bool{}
	for !exts.Empty() {
		var et uint16
		var ed cryptobyte.String
		if !exts.ReadUint16(&et) || !exts.ReadUint16LengthPrefixed(&ed) {
			t.Fatal("extension list does not parse")
		}
		seen[et] = true
		switch et {
		case 0x0000:
			var list, name cryptobyte.String
			var nt uint8
			if !ed.ReadUint16LengthPrefixed(&list) || !list.ReadUint8(&nt) || !list.ReadUint16LengthPrefixed(&name) {
				t.Fatal("server_name does not parse")
			}
			sni = string(name)
		case 0x0010:
			var list, p cryptobyte.String
			if !ed.ReadUint16LengthPrefixed(&list) || !list.ReadUint8LengthPrefixed(&p) {
				t.Fatal("ALPN does not parse")
			}
			alpn = string(p)
		case 0x0039:
			if !bytes.Contains(ed, append([]byte{0x0f, byte(len(scid))}, scid...)) {
				t.Error("transport parameters lack initial_source_connection_id = SCID")
			}
		}
	}
	for _, need := range []uint16{0x0000, 0x000a, 0x000d, 0x0010, 0x002b, 0x0033, 0x0039} {
		if !seen[need] {
			t.Errorf("ClientHello lacks extension %#04x", need)
		}
	}
	return sni, alpn
}

func decodeStaticTemplate(t *testing.T, tmpl string) []byte {
	t.Helper()
	if !strings.HasPrefix(tmpl, "<b 0x") || !strings.HasSuffix(tmpl, ">") || strings.Count(tmpl, "<") != 1 {
		t.Fatalf("I2 is not one static <b> template: %.40q", tmpl)
	}
	return mustHex(t, tmpl[5:len(tmpl)-1])
}

// The cover passes the stateless checks a QUIC-aware filter runs on a client
// Initial: the datagram is 1200 bytes, it opens with the keys of its own DCID,
// and it parses to a real-browser ClientHello (server name + h3). The per-end
// fields (client random, DCID) vary across the fleet, and the transport
// parameters' initial_source_connection_id stays equal to the SCID.
func TestQUICCoverPassesTheFiltersInitialChecks(t *testing.T) {
	coverSNIs := []string{"cloudflare-quic.com", "www.cloudflare.com"}
	randoms := map[string]bool{}
	dcids := map[string]bool{}
	for i := 0; i < 200; i++ {
		loc := DeriveAWGLocal(fmt.Sprintf("tunnel-%d", i), true)
		pkt := decodeStaticTemplate(t, loc.I2)
		if len(pkt) != 1200 {
			t.Fatalf("Initial datagram %d B, want 1200 (RFC 9000 §14.1)", len(pkt))
		}
		got := openClientInitial(t, pkt)
		if !slices.Contains(coverSNIs, got.sni) {
			t.Errorf("SNI %q not from the captured cover templates", got.sni)
		}
		if got.alpn != "h3" {
			t.Errorf("ALPN %q, want h3", got.alpn)
		}
		randoms[string(got.random)] = true
		dcids[string(got.dcid)] = true
	}
	// Ephemeral fields must not repeat across the fleet, or ends are correlatable.
	if len(randoms) < 200 {
		t.Errorf("client random repeats: %d distinct of 200 ends", len(randoms))
	}
	if len(dcids) < 200 {
		t.Errorf("DCID repeats: %d distinct of 200 ends", len(dcids))
	}
}

// Every embedded template must build and seal for many seeds: deriveSignatures
// panics on a builder error, so this is the guard that none of them can.
func TestEveryQUICCoverTemplateBuilds(t *testing.T) {
	if len(chromeClientHellos) == 0 {
		t.Fatal("no embedded ClientHello templates")
	}
	for ti, tmpl := range chromeClientHellos {
		raw, err := hex.DecodeString(tmpl)
		if err != nil {
			t.Fatalf("template %d is not hex: %v", ti, err)
		}
		if _, err := parseCHFields(raw); err != nil {
			t.Fatalf("template %d does not parse as a ClientHello: %v", ti, err)
		}
	}
	for i := 0; i < 300; i++ {
		cover, err := quicInitialCover(fmt.Sprintf("seed-%d", i))
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		openClientInitial(t, decodeStaticTemplate(t, cover))
	}
}

// The header-protected first byte is what a filter keys on without decrypting;
// it must not be one fleet-wide constant.
func TestQUICCoverFirstByteVariesAcrossTheFleet(t *testing.T) {
	first := map[byte]bool{}
	for i := 0; i < 100; i++ {
		first[decodeStaticTemplate(t, DeriveAWGLocal(fmt.Sprintf("tunnel-%d", i), true).I2)[0]] = true
	}
	if len(first) < 4 {
		t.Errorf("only %d distinct first bytes across 100 ends", len(first))
	}
}
