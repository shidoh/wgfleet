// Package awgmod probes the AmneziaWG kernel module installed on a node and
// gates configs that the module could not apply. It is shared by the exit's
// tunnel interface and the master's client-facing interface: both would take a
// live data plane down if they wrote a 3.x config for a 1.x module.
package awgmod

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// ErrGenerationUnknown is returned by awgModuleGeneration when the node's AmneziaWG
// kernel module generation cannot be read at all.
var ErrGenerationUnknown = errors.New("amneziawg kernel module generation unknown")

// versionRe pulls the leading major component out of a modinfo version string
// such as "1.0.20260611" or "3.0.20260805".
var versionRe = regexp.MustCompile(`^\s*(\d+)\.`)

// awgModuleGeneration reports the MAJOR version of the AmneziaWG kernel module
// installed on this node — 1 for the 1.x line, 3 for 3.x.
//
// The generation, not the exact version, is what matters: AmneziaWG 3.0 changed
// the netlink attribute layout between the userspace tools and the module, so a
// 3.0 config handed to a 1.x module fails `awg setconf` outright with "attribute
// type 14 has an invalid length" and the interface never comes up.
func ModuleGeneration() (int, error) {
	out, err := exec.Command("modinfo", "-F", "version", "amneziawg").Output()
	if err != nil {
		return 0, fmt.Errorf("%w: modinfo: %v", ErrGenerationUnknown, err)
	}
	m := versionRe.FindStringSubmatch(strings.TrimSpace(string(out)))
	if m == nil {
		return 0, fmt.Errorf("%w: unparseable modinfo version %q", ErrGenerationUnknown, strings.TrimSpace(string(out)))
	}
	gen, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrGenerationUnknown, err)
	}
	return gen, nil
}

// awg3MinGeneration is the kernel-module major version that understands the
// AmneziaWG 3.0 netlink attributes.
const awg3MinGeneration = 3

// CheckAWG3Supported is the node-local half of the AmneziaWG 3.0 gate. The
// controller gates on what IT can see — the operator's opt-in and the agent's wire
// version — but only the node knows which kernel module it actually has, and the
// fleet does not run one generation everywhere.
//
// Refusing BEFORE the config is written is the point. Writing it and running
// awg-quick anyway would tear a live exit's interface down and fail to bring it
// back, which is a data-plane outage; refusing leaves the previous good config in
// place and surfaces the reason in the reconcile error. Same fail-toward-the-cheap-
// mistake asymmetry as awgTransportDisabled.
//
// It gates ONLY 3.0 configs. A 2.0 config runs on either generation, so a node
// whose generation cannot be read must keep converging exactly as it did before
// this gate existed.
func CheckAWG3Supported(gen func() (int, error)) error {
	if gen == nil {
		gen = ModuleGeneration
	}
	g, err := gen()
	if err != nil {
		return fmt.Errorf("spec asks for AmneziaWG 3.0 but this node's kernel module generation could not be determined (%w) — refusing to apply a config that would not come up", err)
	}
	if g < awg3MinGeneration {
		return fmt.Errorf("spec asks for AmneziaWG 3.0 but this node runs a %d.x kernel module — its netlink attribute layout predates 3.0, so awg setconf would reject the config and leave the interface down; upgrade the amneziawg module and tools together, then re-run", g)
	}
	return nil
}
