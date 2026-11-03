package api

import (
	"testing"

	pb "github.com/shidoh/wgfleet/internal/api/pb/wgfleet/v1"
	"github.com/shidoh/wgfleet/internal/domain"
	"google.golang.org/protobuf/proto"
)

func TestAWGModuleBuildRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		build domain.AWGModuleBuild
	}{
		{name: "known", build: domain.AWGModuleBuild{PackageVersion: "1.0.0-0~202609061402+4569c4c", SrcVersion: "A1B2C3D4E5F60718293A4B5"}},
		{name: "reload pending", build: domain.AWGModuleBuild{PackageVersion: "1.0.0-0~202609061402+4569c4c", SrcVersion: "0123456789ABCDEF0123456", ReloadPending: true}},
		{name: "unknown", build: domain.AWGModuleBuild{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Through the bytes, as it crosses the wire.
			raw, err := proto.Marshal(&pb.RegisterRequest{Role: "exit", AwgModule: AWGModuleBuildToProto(tc.build)})
			if err != nil {
				t.Fatal(err)
			}
			var req pb.RegisterRequest
			if err := proto.Unmarshal(raw, &req); err != nil {
				t.Fatal(err)
			}
			if got := AWGModuleBuildFromProto(req.GetAwgModule()); got != tc.build {
				t.Errorf("round trip = %+v, want %+v", got, tc.build)
			}
		})
	}
}

// An agent that predates the field sends no message at all; that must read as
// an unknown build, never as some default that could pass a gate.
func TestAWGModuleBuildFromOldAgent(t *testing.T) {
	got := AWGModuleBuildFromProto((&pb.RegisterRequest{Role: "exit"}).GetAwgModule())
	if got != (domain.AWGModuleBuild{}) || got.Label() != "unknown" || got.AtLeast(1) {
		t.Errorf("old agent's build = %+v (label %q), want the unknown zero value", got, got.Label())
	}
}
