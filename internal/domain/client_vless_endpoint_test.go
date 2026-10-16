package domain

import (
	"net/url"
	"testing"
)

func TestEndpointForResolvesDefaults(t *testing.T) {
	cv := ClientVLESSServerSpec{ListenPort: 49443, ServerName: "www.python.org", AllowEmptySNI: true}
	e := cv.EndpointFor("203.0.113.1", "PBK", VLESSClient{Name: "a", UUID: "u", ShortID: "sid"})
	if e.Port != 49443 || e.XHTTPPath != "/" || e.XHTTPMode != "packet-up" || e.Vision {
		t.Errorf("defaults not resolved: %+v", e)
	}
	if e.Fingerprint != ClientVLESSFingerprintDefault {
		t.Errorf("fingerprint = %q", e.Fingerprint)
	}
	if e.MihomoServerName() != "203.0.113.1" {
		t.Errorf("empty SNI must be spelled as the server IP for mihomo, got %q", e.MihomoServerName())
	}
}

func TestEndpointLinkVision(t *testing.T) {
	cv := ClientVLESSServerSpec{ListenPort: 1, ServerName: "sni.example", Mode: RealityModeVision}
	u, err := url.Parse(cv.EndpointFor("h", "p", VLESSClient{Name: "b", UUID: "u", ShortID: "s"}).Link("m-b"))
	if err != nil {
		t.Fatal(err)
	}
	if q := u.Query(); q.Get("type") != "tcp" || q.Get("flow") != "xtls-rprx-vision" || q.Get("sni") != "sni.example" {
		t.Errorf("vision link: %v", q)
	}
	if u.Fragment != "m-b" {
		t.Errorf("fragment = %q", u.Fragment)
	}
}
