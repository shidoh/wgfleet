package wg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// A full QUIC v1 client Initial for the I2 cover packet.
//
// A filter that reads QUIC can tell a header-only imitation from a real Initial
// with two stateless checks: a client Initial is padded to at least 1200 bytes
// (RFC 9000 §14.1), and its payload opens with the Initial keys derived from its
// own Destination Connection ID (RFC 9001 §5.2). A per-packet classifier goes one
// further and fingerprints the TLS ClientHello (JA4): a hand-built hello has an
// extension set and order that no shipping browser emits, and that is a 0-FP tell.
//
// So the ClientHello is not synthesised. It is a real one captured from a current
// Chromium browser (its JA4 is the common desktop-Chrome QUIC value, identical to
// ordinary background HTTP/3). The template is stored with its ephemeral fields
// (client random, key-share public keys) zeroed; this builder fills them per end
// from the seed, picks a per-end Destination and Source Connection ID, keeps the
// transport parameters' initial_source_connection_id equal to the SCID, and seals
// and header-protects the packet with the real Initial keys. The result decrypts,
// parses to that ClientHello, and is padded to the browser's datagram size.
//
// What still differs from a live browser, and is not fixable in a static cover:
// the same bytes repeat on every handshake from one end (a replay cache spots it),
// and the server never answers as a QUIC server would. Those are inherent to a
// cover packet in front of a non-QUIC handshake; the per-packet fingerprint is the
// part this closes.

// quicV1InitialSalt is the QUIC v1 Initial salt (RFC 9001 §5.2).
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

const (
	quicAEADTagLen     = 16
	quicHPSampleLen    = 16
	quicHPSampleOffset = 4 // the sample starts 4 bytes past the packet-number offset
	quicDCIDLen        = 8 // Chrome uses an 8-byte DCID on a fresh connection
	quicInitialBytes   = 1200
	quicInitialPN      = 0 // a fresh Chrome Initial starts at packet number 0
	quicInitialPNLen   = 2 // two-byte packet number: first byte 0xc1
)

// chromeClientHellos are real QUIC ClientHello messages captured from a current
// Chromium desktop browser (JA4 q13d0308h3_55b375c5d22e_a06176d7f541), one per
// connection, with the 32-byte client random and the four key-share public keys
// zeroed — this builder fills them per end. Keeping two lets ends differ in the
// static tail (SNI, SCID position) as well; both carry the same JA4.
var chromeClientHellos = []string{
	"010001e203030000000000000000000000000000000000000000000000000000000000000000000006130213011303010001b30033010c010a0017004100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018006100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d00200000000000000000000000000000000000000000000000000000000000000000001e00380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002b0003020304000d00140012040308040401050308050501020108070808000a000a000800170018001d001e002d00020101000000180016000013636c6f7564666c6172652d717569632e636f6d0010000500030268330039004701048000ea6004048010000005048010000006048010000007048010000008024080090240800a01030b01190e01080f083152ae05ada9a4c7110c00000001000000016b3343cf",
	"010001e103030000000000000000000000000000000000000000000000000000000000000000000006130213011303010001b20033010c010a0017004100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018006100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d00200000000000000000000000000000000000000000000000000000000000000000001e00380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002b0003020304000d00140012040308040401050308050501020108070808000a000a000800170018001d001e002d000201010000001700150000127777772e636c6f7564666c6172652e636f6d0010000500030268330039004701048000ea6004048010000005048010000006048010000007048010000008024080090240800a01030b01190e01080f08fbb7d563436f8afe110c00000001000000016b3343cf",
}

// chField is a byte range inside a ClientHello that this builder overwrites per end.
type chField struct{ off, len int }

// chFields are the variable spans of one ClientHello: the 32-byte client random,
// the key-share public keys, and the transport parameters' initial_source_connection_id.
type chFields struct {
	random    chField
	keyShares []chField
	iscid     chField
}

// parseCHFields walks a TLS 1.3 ClientHello (RFC 8446 §4.1.2) wrapped for QUIC and
// locates the spans the cover builder fills per end. It parses structure only; the
// template is trusted (captured and embedded), so this is not a hardening boundary.
func parseCHFields(ch []byte) (chFields, error) {
	var f chFields
	if len(ch) < 39 || ch[0] != 0x01 {
		return f, fmt.Errorf("not a ClientHello")
	}
	body := int(ch[1])<<16 | int(ch[2])<<8 | int(ch[3])
	i := 4
	end := i + body
	i += 2 // legacy_version
	f.random = chField{i, 32}
	i += 32
	i += 1 + int(ch[i]) // legacy_session_id
	i += 2 + (int(ch[i])<<8 | int(ch[i+1]))
	i += 1 + int(ch[i]) // compression methods
	extTotal := int(ch[i])<<8 | int(ch[i+1])
	i += 2
	extEnd := i + extTotal
	for i+4 <= extEnd {
		et := int(ch[i])<<8 | int(ch[i+1])
		el := int(ch[i+2])<<8 | int(ch[i+3])
		b := i + 4
		switch et {
		case 0x0033: // key_share: list length, then group(2)+len(2)+key entries
			j := b + 2
			for j+4 <= b+el {
				kl := int(ch[j+2])<<8 | int(ch[j+3])
				f.keyShares = append(f.keyShares, chField{j + 4, kl})
				j += 4 + kl
			}
		case 0x0039: // quic_transport_parameters: find initial_source_connection_id (0x0f)
			j := b
			for j < b+el {
				pid, n := quicVarint(ch, j)
				j += n
				plen, n := quicVarint(ch, j)
				j += n
				if pid == 0x0f {
					f.iscid = chField{j, int(plen)}
				}
				j += int(plen)
			}
		}
		i = b + el
	}
	if i != extEnd || extEnd != end {
		return f, fmt.Errorf("ClientHello extensions do not close cleanly")
	}
	if f.random.len == 0 || len(f.keyShares) == 0 || f.iscid.len != quicDCIDLen {
		return f, fmt.Errorf("ClientHello missing random, key_share or 8-byte ISCID")
	}
	return f, nil
}

// quicVarint reads a QUIC variable-length integer (RFC 9000 §16) at b[i].
func quicVarint(b []byte, i int) (uint64, int) {
	l := 1 << (b[i] >> 6)
	v := uint64(b[i] & 0x3f)
	for j := 1; j < l; j++ {
		v = v<<8 | uint64(b[i+j])
	}
	return v, l
}

// quicInitialKeys are one direction's Initial packet-protection keys.
type quicInitialKeys struct {
	key, iv, hp []byte
}

// hkdfExpandLabel is TLS 1.3 HKDF-Expand-Label with an empty context (RFC 8446 §7.1).
func hkdfExpandLabel(secret []byte, label string, length int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // empty context
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

// clientInitialKeys derives the client Initial keys from the DCID (RFC 9001 §5.2).
func clientInitialKeys(dcid []byte) (quicInitialKeys, error) {
	initial, err := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	if err != nil {
		return quicInitialKeys{}, err
	}
	secret, err := hkdfExpandLabel(initial, "client in", sha256.Size)
	if err != nil {
		return quicInitialKeys{}, err
	}
	var k quicInitialKeys
	if k.key, err = hkdfExpandLabel(secret, "quic key", 16); err != nil {
		return k, err
	}
	if k.iv, err = hkdfExpandLabel(secret, "quic iv", 12); err != nil {
		return k, err
	}
	if k.hp, err = hkdfExpandLabel(secret, "quic hp", 16); err != nil {
		return k, err
	}
	return k, nil
}

// quicHeaderMask is the header-protection mask for a sample (RFC 9001 §5.4.3).
func quicHeaderMask(hp, sample []byte) ([]byte, error) {
	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, aes.BlockSize)
	block.Encrypt(mask, sample)
	return mask, nil
}

// appendQUICVarint appends v as a QUIC variable-length integer (RFC 9000 §16).
func appendQUICVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(b, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(b, uint32(v)|0x80000000)
	default:
		return binary.BigEndian.AppendUint64(b, v|0xc0<<56)
	}
}

// sealQUICInitial wraps a ClientHello in a CRYPTO frame, pads the datagram to
// quicInitialBytes, and seals and header-protects it as a client Initial with the
// RFC 9001 keys of dcid. pnLen/PN are the browser's (0, 2 bytes).
func sealQUICInitial(hello, dcid, scid []byte) ([]byte, error) {
	keys, err := clientInitialKeys(dcid)
	if err != nil {
		return nil, err
	}
	hdr := []byte{0xc0 | byte(quicInitialPNLen-1), 0x00, 0x00, 0x00, 0x01}
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = append(hdr, 0) // token length

	const lengthFieldBytes = 2
	plainLen := quicInitialBytes - len(hdr) - lengthFieldBytes - quicInitialPNLen - quicAEADTagLen

	frame := []byte{0x06, 0x00} // CRYPTO, offset 0
	frame = appendQUICVarint(frame, uint64(len(hello)))
	frame = append(frame, hello...)
	if len(frame) > plainLen {
		return nil, fmt.Errorf("quic cover: ClientHello (%d B) does not fit %d B datagram", len(frame), quicInitialBytes)
	}
	plain := make([]byte, plainLen) // the tail stays zero: PADDING frames
	copy(plain, frame)

	payloadLen := uint64(quicInitialPNLen + plainLen + quicAEADTagLen)
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(payloadLen)|0x4000)
	pnOffset := len(hdr)
	var pn [4]byte
	binary.BigEndian.PutUint32(pn[:], quicInitialPN)
	hdr = append(hdr, pn[4-quicInitialPNLen:]...)

	block, err := aes.NewCipher(keys.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, len(keys.iv))
	copy(nonce, keys.iv)
	for i := 0; i < 4; i++ {
		nonce[len(nonce)-1-i] ^= pn[3-i]
	}
	packet := aead.Seal(hdr, nonce, plain, hdr)

	sampleAt := pnOffset + quicHPSampleOffset
	mask, err := quicHeaderMask(keys.hp, packet[sampleAt:sampleAt+quicHPSampleLen])
	if err != nil {
		return nil, err
	}
	packet[0] ^= mask[0] & 0x0f
	for i := 0; i < quicInitialPNLen; i++ {
		packet[pnOffset+i] ^= mask[1+i]
	}
	return packet, nil
}

// quicInitialCover renders the per-end QUIC Initial cover as a static CPS template.
func quicInitialCover(seed string) (string, error) {
	d := newDetStream(seed + "|I2quic-chrome")
	tmplHex := chromeClientHellos[d.intn(len(chromeClientHellos))]
	tmpl, err := hex.DecodeString(tmplHex)
	if err != nil {
		return "", err
	}
	hello := make([]byte, len(tmpl))
	copy(hello, tmpl)
	f, err := parseCHFields(hello)
	if err != nil {
		return "", err
	}
	fill := func(fld chField) {
		for i := 0; i < fld.len; i++ {
			hello[fld.off+i] = d.next()
		}
	}
	fill(f.random)
	for _, ks := range f.keyShares {
		fill(ks)
	}
	// SCID = the connection ID the client advertises; it must equal the
	// transport parameters' initial_source_connection_id, or a QUIC-aware filter
	// sees an inconsistent Initial.
	scid := make([]byte, f.iscid.len)
	for i := range scid {
		scid[i] = d.next()
		hello[f.iscid.off+i] = scid[i]
	}
	dcid := make([]byte, quicDCIDLen)
	for i := range dcid {
		dcid[i] = d.next()
	}
	pkt, err := sealQUICInitial(hello, dcid, scid)
	if err != nil {
		return "", err
	}
	return "<b 0x" + hex.EncodeToString(pkt) + ">", nil
}
