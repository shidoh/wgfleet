package clientcfg

import (
	"errors"

	qrcode "github.com/skip2/go-qrcode"
)

// ErrTooLargeForQR reports a config that does not fit in one QR code. An AWG
// profile with a full-size QUIC cover in I2 runs to roughly 3 KB, past what a QR
// holds at the recovery level a phone camera reads reliably — and a QR that did
// hold it would be too dense to scan off a screen. Such a profile is handed out
// as a file only.
var ErrTooLargeForQR = errors.New("clientcfg: the profile is too large for a QR code; download the file instead")

// qrSizePx is the side of the served image. A config that fits packs up to about
// 137x137 modules, and pages show the image at half this size, which still puts
// about 4 pixels on each module — the least an ordinary phone camera resolves.
const qrSizePx = 1024

// qrRecovery is Medium, not Low: the image is scanned off a screen, often at an
// angle and with glare, and Low gives up the margin that makes that work.
const qrRecovery = qrcode.Medium

// QRPNG encodes a config as a PNG QR code, or returns ErrTooLargeForQR. Every QR
// of a config goes through here, so the page deciding whether to show one and
// the endpoint serving it can never disagree.
func QRPNG(cfg string) ([]byte, error) {
	q, err := qrcode.New(cfg, qrRecovery)
	if err != nil {
		return nil, ErrTooLargeForQR
	}
	return q.PNG(qrSizePx)
}

// FitsQR reports whether cfg can be shown as a QR code. Pages call it to offer a
// QR only where one exists, instead of an image that fails to load.
func FitsQR(cfg string) bool {
	_, err := qrcode.New(cfg, qrRecovery)
	return err == nil
}
