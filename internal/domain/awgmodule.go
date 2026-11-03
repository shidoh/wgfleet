package domain

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AWGModuleBuild is which build of the AmneziaWG kernel module a node runs, as
// its agent last reported it. Observed, not desired, like Node.AgentVersion.
//
// It exists because the module's own version string cannot tell builds apart:
// upstream rebuilds the PPA package from its main branch without bumping
// MODULE_VERSION, so modules that differ in what they put on the wire all print
// the same `modinfo -F version`. What does move is the Debian revision of the
// amneziawg-dkms package (1.0.0-0~<YYYYMMDDhhmm>+<commit>) and the module's
// srcversion hash. A feature that both kernel ends of a tunnel must speak has
// to be gated on the build, not on the generation.
//
// The zero value means "unknown": a node that has not reported yet, an agent too
// old to report it, or a node whose module did not come from the package.
type AWGModuleBuild struct {
	// PackageVersion is the installed amneziawg-dkms package version, e.g.
	// "1.0.0-0~202609061402+4569c4c". Empty when the package is not installed or
	// could not be read.
	PackageVersion string
	// SrcVersion is the srcversion hash of the module the kernel has loaded, or of
	// the one on disk when none is loaded yet. Shown to the operator because it is
	// the only identity two hand-built modules can be told apart by.
	SrcVersion string
	// ReloadPending is set when the module on disk is not the one loaded: the
	// package was upgraded and the kernel still runs the previous build. The
	// package version then describes code that is not running, so the build counts
	// as unknown until the module is reloaded (or the node rebooted).
	ReloadPending bool
}

// awgBuildStampRe finds the build timestamp the PPA puts in the Debian revision:
// "~" followed by exactly twelve digits, ended by the commit suffix, another
// "~" suffix, or the end of the string.
var awgBuildStampRe = regexp.MustCompile(`~(\d{12})(?:[+~]|$)`)

// awgBuildStampLayout is the YYYYMMDDhhmm layout of that timestamp.
const awgBuildStampLayout = "200601021504"

// ParseAWGBuildStamp extracts the build timestamp from an amneziawg-dkms package
// version as a YYYYMMDDhhmm number (202609061402), so builds compare with plain
// integer ordering. Anything it cannot read with certainty — an empty string, an
// upstream-only version, a stamp that is not a real date — yields 0, which every
// gate treats as "too old". A misread must never pass a gate.
func ParseAWGBuildStamp(packageVersion string) uint64 {
	m := awgBuildStampRe.FindStringSubmatch(strings.TrimSpace(packageVersion))
	if m == nil {
		return 0
	}
	if _, err := time.Parse(awgBuildStampLayout, m[1]); err != nil {
		return 0
	}
	stamp, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return 0
	}
	return stamp
}

// Stamp is the build timestamp the node is actually running, or 0 when that is
// unknown — including when a newer package waits for a module reload.
func (b AWGModuleBuild) Stamp() uint64 {
	if b.ReloadPending {
		return 0
	}
	return ParseAWGBuildStamp(b.PackageVersion)
}

// AtLeast reports whether the node is known to run build min or newer. Unknown
// is never "at least" anything: a gate that opened on missing data would split
// exactly the tunnels it exists to protect.
func (b AWGModuleBuild) AtLeast(min uint64) bool {
	s := b.Stamp()
	return s != 0 && s >= min
}

// Label is the running build for display and metric labels: the timestamp, or
// "unknown".
func (b AWGModuleBuild) Label() string {
	if s := b.Stamp(); s != 0 {
		return strconv.FormatUint(s, 10)
	}
	return "unknown"
}
