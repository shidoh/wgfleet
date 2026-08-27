package api

import (
	"reflect"
	"strings"
	"testing"

	pb "github.com/shidoh/wgfleet/internal/api/pb/wgfleet/v1"
	"github.com/shidoh/wgfleet/internal/domain"
)

func clientWGSpec() *domain.ClientWGSpec {
	return &domain.ClientWGSpec{
		ListenPort:    443,
		AddressPool:   "10.80.0.0/24",
		ServerAddress: "10.80.0.1",
		MTU:           1360,
		DNS:           []string{"10.80.0.1"},
		AllowedIPs:    []string{"0.0.0.0/0"},
		Backend:       domain.ClientWGBackendUserspace,
		AWG: &domain.AWGParams{
			Shared: domain.AWGShared{S1: 30, S2: 40, S3: 20, S4: 26},
			Local:  domain.AWGLocal{Jc: 4, Jmin: 40, Jmax: 70, I1: "<b 0x11>"},
		},
		Clients: []domain.WGClientPeer{
			{Name: "laptop", PublicKey: "pub-1", Address: "10.80.0.2/32", PresharedKey: "psk-1"},
			{Name: "phone", PublicKey: "pub-2", Address: "10.80.0.3/32"},
		},
	}
}

func TestClientWGSpecRoundTrip(t *testing.T) {
	spec := domain.NodeSpec{
		Role:   domain.RoleMaster,
		Master: &domain.MasterSpec{ClientWG: clientWGSpec()},
	}
	got := SpecFromProto(SpecToProto(spec))
	if got.Master == nil || got.Master.ClientWG == nil {
		t.Fatal("client WG spec did not survive the round trip")
	}
	if !reflect.DeepEqual(*got.Master.ClientWG, *spec.Master.ClientWG) {
		t.Fatalf("round trip changed the spec:\n got %+v\nwant %+v", *got.Master.ClientWG, *spec.Master.ClientWG)
	}
}

// A master with no managed client interface must round-trip as nil rather than as
// an empty struct: nil is what tells the agent "wg-easy still owns this leg".
func TestClientWGSpecNilRoundTrip(t *testing.T) {
	spec := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}}
	got := SpecFromProto(SpecToProto(spec))
	if got.Master.ClientWG != nil {
		t.Fatalf("ClientWG = %+v, want nil", got.Master.ClientWG)
	}
}

// The wire type must be structurally incapable of carrying a client's private
// key. This is the boundary the whole credential design rests on (design §3.1),
// so it is asserted against the generated struct itself, not against a value.
func TestWGClientPeerProtoHasNoPrivateKeyField(t *testing.T) {
	rt := reflect.TypeOf(pb.WGClientPeer{})
	for i := range rt.NumField() {
		name := strings.ToLower(rt.Field(i).Name)
		if strings.Contains(name, "private") || name == "key" {
			t.Fatalf("pb.WGClientPeer has field %q: the peer view must never carry a private key", rt.Field(i).Name)
		}
	}
}

// Keepalive is controller-side and must stay off the wire.
//
// It has no field in the proto message, so a round-trip drops it. That is the
// intended design — the node renders the interface, the controller renders client
// configs, and PersistentKeepalive only ever appears in the latter — but a lossy
// round-trip looks exactly like a bug to the next reader, and the existing
// round-trip test passes only because its fixture leaves the field empty.
func TestClientWGSpecKeepaliveStaysOffTheWire(t *testing.T) {
	in := domain.ClientWGSpec{
		ListenPort: 443, AddressPool: "10.80.0.0/24", ServerAddress: "10.80.0.1",
		AllowedIPs: []string{"0.0.0.0/0"},
		Keepalive:  "15-25",
	}
	out := clientWGFromProto(clientWGToProto(&in))
	if out == nil {
		t.Fatal("round-trip produced nothing")
	}
	if out.Keepalive != "" {
		t.Errorf("Keepalive = %q after a round-trip; it must not cross the wire", out.Keepalive)
	}
	// Everything the NODE needs still survives, so this is a deliberate omission
	// rather than a broken conversion.
	if out.ListenPort != in.ListenPort || out.AddressPool != in.AddressPool {
		t.Errorf("the round-trip lost more than the keepalive: %+v", out)
	}
}
