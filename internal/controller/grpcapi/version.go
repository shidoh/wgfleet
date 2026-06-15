package grpcapi

import (
	"context"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/domain"
)

// UpgradeTrigger pushes a fresh agent binary to a node and restarts it. It is
// satisfied by *provmgr.Manager. The gate calls it (best-effort, async) when it
// refuses a too-old agent, so an incompatible node self-heals without operator
// action — provided the controller still has SSH reach to it.
type UpgradeTrigger interface {
	TriggerUpgrade(nodeID string) error
}

// SetUpgradeTrigger wires the auto-upgrade hook. Optional: with no trigger the
// gate still records the incompatibility and refuses, just without rolling the
// agent forward automatically.
func (s *Service) SetUpgradeTrigger(t UpgradeTrigger) { s.trigger = t }

// reportedVersions extracts the agent's wire + build version from request
// metadata. A pre-versioning agent (no metadata) yields wire 0, classified as
// WireUnknown by api.CheckWire.
func reportedVersions(ctx context.Context) (wire uint32, agentVersion string) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return 0, ""
	}
	if v := firstMD(md, api.MDWireVersion); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			wire = uint32(n)
		}
	}
	return wire, firstMD(md, api.MDAgentVersion)
}

func firstMD(md metadata.MD, key string) string {
	if vals := md.Get(key); len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// gateVersion enforces wire compatibility for a node before the controller acts
// on its behalf. On incompatibility it records the node Degraded with a precise
// reason, fires an auto-upgrade when the agent is behind (and a trigger is wired),
// and returns FailedPrecondition so the agent backs off and keeps its last-good
// spec (pull-based resilience: control-plane refusal must not break the data
// plane). nil means the agent may proceed.
func (s *Service) gateVersion(ctx context.Context, nodeID string) error {
	wire, agentVersion := reportedVersions(ctx)
	compat := api.CheckWire(wire)
	if compat == api.WireCompatible {
		return nil
	}

	detail := api.IncompatibilityDetail(compat, wire)
	s.log.Warn("rejecting incompatible agent",
		"node", nodeID, "agent_wire", wire, "agent_version", agentVersion,
		"compat", compat.String())

	// Surface the skew on the node row so the UI/metrics show why it is stuck.
	if err := s.store.SetNodeState(ctx, nodeID, domain.StateDegraded, detail); err != nil {
		s.log.Error("failed to mark incompatible node degraded", "node", nodeID, "err", err)
	}

	if compat.AutoUpgradable() && s.trigger != nil {
		if err := s.trigger.TriggerUpgrade(nodeID); err != nil {
			s.log.Warn("auto-upgrade not started", "node", nodeID, "err", err)
		} else {
			s.log.Info("auto-upgrade triggered for incompatible agent", "node", nodeID)
		}
	}
	return status.Error(codes.FailedPrecondition, detail)
}
