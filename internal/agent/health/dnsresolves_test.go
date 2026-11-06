package health

import (
	"context"
	"errors"
	"testing"
)

func digReturning(out string, err error) runner {
	return func(context.Context, string, ...string) (string, error) { return out, err }
}

func TestDNSResolvesProbe(t *testing.T) {
	cases := []struct {
		name   string
		out    string
		err    error
		wantOK bool
	}{
		{"answers with an address", "104.16.132.229\n104.16.133.229\n", nil, true},
		{"answers with an IPv6 address", "2606:4700::6810:84e5\n", nil, true},
		// dig exits 0 on SERVFAIL and NXDOMAIN and prints nothing under +short.
		{"SERVFAIL or NXDOMAIN", "", nil, false},
		{"only a CNAME, no address", "alias.example.\n", nil, false},
		{"no server reply", ";; communications error to 10.0.0.1#53: timed out\n", errors.New("exit status 9"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dnsResolvesProbeWith("10.0.0.1:53", digReturning(tc.out, tc.err))(context.Background())
			if got.OK != tc.wantOK {
				t.Errorf("OK = %v, want %v (detail %q)", got.OK, tc.wantOK, got.Detail)
			}
		})
	}
}
