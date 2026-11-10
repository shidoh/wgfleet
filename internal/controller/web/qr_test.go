package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// realAWG is what the fleet actually derives for a client interface, header
// protection included. The plain fixtures carry no AWG, so their configs fit any
// QR — which is how a profile too large for one went unnoticed.
func realAWG() *domain.AWGParams {
	p := wg.WithAWG3(wg.DeriveAWGParamsForEnd("master-xa-1/clients", "server", true), "master-xa-1/clients", "fleet-secret")
	return &p
}

// wgLifelineHandlerWith is wgLifelineHandler with the master's and the exits'
// client-facing specs passed in.
func wgLifelineHandlerWith(t *testing.T, clients *[]domain.WGClient, master, exit domain.NodeSpec) *Handler {
	t.Helper()
	h, st := newTestHandler(t, stubRenderer{
		spec:      master,
		wgClients: clients,
		specs:     map[string]domain.NodeSpec{"exit-ready": exit},
		lifelines: []string{"exit-ready"},
		exitHosts: map[string]string{"exit-ready": "203.0.113.9"},
	})
	seed(t, st, domain.Node{
		ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster,
		PublicIP: "203.0.113.1", State: domain.StateReady,
		ClientWGPublicKey: "c2VydmVyLXB1YmxpYy0wMDAwMDAwMDAwMDAwMDAwMDA=",
	})
	seed(t, st, domain.Node{
		ID: "exit-ready", Name: "exit-ready", Role: domain.RoleExit,
		PublicIP: "203.0.113.9", State: domain.StateReady,
		LifelinePublicKey: "ZXhpdC1saWZlbGluZS1rZXktMDAwMDAwMDAwMDAwMDA=",
	})
	return h
}

const (
	mainQRSrc    = `src="/nodes/master-xa-1/wg-clients/a/qr"`
	reserveQRSrc = `src="/nodes/master-xa-1/wg-clients/a/lifeline/exit-ready/qr"`
)

func TestWGClientsPageOffersNoQRForAnOversizedConfig(t *testing.T) {
	master, exit := managedMasterSpec(), lifelineExitSpec()
	master.Master.ClientWG.AWG = realAWG()
	exit.Lifeline.ClientWGSpec.AWG = realAWG()
	clients := lifelineClients()
	h := wgLifelineHandlerWith(t, &clients, master, exit)

	res, body := get(t, h, "/nodes/master-xa-1/wg-clients")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	for _, src := range []string{mainQRSrc, reserveQRSrc} {
		if strings.Contains(body, src) {
			t.Errorf("the page offers a QR image that cannot be encoded: %s", src)
		}
	}
	if !strings.Contains(body, "too large for one") {
		t.Error("the card does not say why there is no QR")
	}

	for _, path := range []string{"/nodes/master-xa-1/wg-clients/a/qr", "/nodes/master-xa-1/wg-clients/a/lifeline/exit-ready/qr"} {
		res, body := get(t, h, path)
		if res.StatusCode != http.StatusNotFound || !strings.Contains(body, "too large for a QR code") {
			t.Errorf("%s = %d %q, want 404 explaining the size", path, res.StatusCode, body)
		}
	}
}

func TestWGClientsPageKeepsTheQRForAConfigThatFits(t *testing.T) {
	clients := lifelineClients()
	h := wgLifelineHandlerWith(t, &clients, managedMasterSpec(), lifelineExitSpec())

	_, body := get(t, h, "/nodes/master-xa-1/wg-clients")
	for _, src := range []string{mainQRSrc, reserveQRSrc} {
		if !strings.Contains(body, src) {
			t.Errorf("a config that fits lost its QR: missing %s", src)
		}
	}
	if strings.Contains(body, "too large for one") {
		t.Error("a config that fits is said to be too large")
	}
}
