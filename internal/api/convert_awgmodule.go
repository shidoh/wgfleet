package api

import (
	pb "github.com/shidoh/wgfleet/internal/api/pb/wgfleet/v1"
	"github.com/shidoh/wgfleet/internal/domain"
)

// AWGModuleBuildToProto converts the agent's view of its module build for
// RegisterRequest.awg_module.
func AWGModuleBuildToProto(b domain.AWGModuleBuild) *pb.AWGModuleBuild {
	return &pb.AWGModuleBuild{
		PackageVersion: b.PackageVersion,
		Srcversion:     b.SrcVersion,
		ReloadPending:  b.ReloadPending,
	}
}

// AWGModuleBuildFromProto converts a reported build. A nil message — an agent
// that predates the field — is the zero build, which reads as unknown.
func AWGModuleBuildFromProto(p *pb.AWGModuleBuild) domain.AWGModuleBuild {
	return domain.AWGModuleBuild{
		PackageVersion: p.GetPackageVersion(),
		SrcVersion:     p.GetSrcversion(),
		ReloadPending:  p.GetReloadPending(),
	}
}
