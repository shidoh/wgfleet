package keybroker

import "github.com/shidoh/wgfleet/internal/domain"

// awgTrackBMinBuild is the oldest AmneziaWG kernel module build (amneziawg-dkms
// revision timestamp, YYYYMMDDhhmm) that carries the header-protection and
// random-trailer changes of the 2026-09-06 upstream build. Older builds of the
// same release line report the same module version, so only the build tells them
// apart.
const awgTrackBMinBuild uint64 = 202609060000

// awgModuleBuildsAtLeast reports whether every kernel end of a tunnel is known to
// run module build min or newer. It is the build-level counterpart of the wire
// gate in awg3Enabled: the wire version says the AGENT understands a setting,
// this says the MODULE under it will put the same bytes on the wire as the other
// end. An end with a too-old build would bring its interface up happily and then
// never complete a handshake, the same split tunnel the wire gate prevents.
//
// Pass only the ends whose AmneziaWG runs in the kernel (an exit's awg0 or
// lifeline interface, a master's client-facing interface). The master's end of a
// master↔exit tunnel is mihomo's userspace implementation, which ships with the
// agent and has no module build to check.
//
// Unknown is "too old": a node that never reported, an agent too old to report,
// a module not installed from the package, or a package upgraded without the
// module being reloaded. No ends at all is false too — nothing proves the build.
//
// Not yet wired into awg3Enabled: that gate takes every end of the tunnel,
// userspace ones included, so the build check cannot ride on its arguments; the
// caller that enables a build-dependent feature calls this with the kernel ends.
func awgModuleBuildsAtLeast(min uint64, kernelEnds ...domain.Node) bool {
	for _, n := range kernelEnds {
		if !n.AWGModule.AtLeast(min) {
			return false
		}
	}
	return len(kernelEnds) > 0
}
