package clientcfg

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestQRPNG(t *testing.T) {
	tests := []struct {
		name    string
		cfg     string
		wantErr error
	}{
		{"a plain config fits", strings.Repeat("x", 600), nil},
		{"a config past QR capacity does not", strings.Repeat("x", 3000), ErrTooLargeForQR},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			png, err := QRPNG(tt.cfg)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("QRPNG error = %v, want %v", err, tt.wantErr)
			}
			if got := FitsQR(tt.cfg); got != (tt.wantErr == nil) {
				t.Errorf("FitsQR = %v, but QRPNG error = %v: the page and the endpoint disagree", got, err)
			}
			if tt.wantErr == nil && !bytes.HasPrefix(png, []byte("\x89PNG")) {
				t.Errorf("not a PNG: %q", png[:4])
			}
		})
	}
}
