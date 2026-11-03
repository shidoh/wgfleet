package awgmod

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// dkmsPackage is the package both install paths (install.sh and
// deploy/prepare-node.sh) take the module from. Its Debian revision is the only
// place the build is written down: the module itself reports the same version
// for every build of a release line.
const dkmsPackage = "amneziawg-dkms"

// loadedSrcVersionPath is where the kernel publishes the srcversion of the module
// it has loaded. modinfo reads the file on disk instead, which after a package
// upgrade is no longer the code that runs.
const loadedSrcVersionPath = "/sys/module/amneziawg/srcversion"

// buildProbeTimeout bounds each probe. They run on every reconcile pass ahead of
// registration, and a dpkg database held by a long apt run must not stall it.
const buildProbeTimeout = 5 * time.Second

// BuildProbe reads the three facts a module build is made of. A nil field uses
// the real probe; tests substitute their own.
type BuildProbe struct {
	// Package returns `dpkg-query -W -f='${db:Status-Abbrev} ${Version}'` output
	// for the DKMS package.
	Package func(ctx context.Context) (string, error)
	// LoadedSrcVersion returns the srcversion of the module the kernel runs.
	LoadedSrcVersion func(ctx context.Context) (string, error)
	// DiskSrcVersion returns the srcversion of the module modprobe would load.
	DiskSrcVersion func(ctx context.Context) (string, error)
}

// ReadModuleBuild reports which AmneziaWG module build this node runs. It never
// fails: whatever cannot be read is left empty, and an empty or unparseable build
// reads as "unknown" to every gate on the controller. Reporting nothing is safer
// than reporting a guess, and a node must keep registering either way.
func ReadModuleBuild(ctx context.Context, p BuildProbe) domain.AWGModuleBuild {
	if p.Package == nil {
		p.Package = dpkgQueryPackage
	}
	if p.LoadedSrcVersion == nil {
		p.LoadedSrcVersion = readLoadedSrcVersion
	}
	if p.DiskSrcVersion == nil {
		p.DiskSrcVersion = modinfoSrcVersion
	}

	var b domain.AWGModuleBuild
	if out, err := p.Package(ctx); err == nil {
		b.PackageVersion = parseDpkgPackageVersion(out)
	}
	loaded := probeString(ctx, p.LoadedSrcVersion)
	disk := probeString(ctx, p.DiskSrcVersion)
	switch {
	case loaded != "":
		b.SrcVersion = loaded
		// Only a positive mismatch counts. An unreadable disk srcversion proves
		// nothing about a pending reload.
		b.ReloadPending = disk != "" && disk != loaded
	default:
		// Not loaded yet: awg-quick will modprobe the one on disk, so that is the
		// build this node is about to run.
		b.SrcVersion = disk
	}
	return b
}

// parseDpkgPackageVersion takes the "${db:Status-Abbrev} ${Version}" line and
// returns the version only when the package is fully installed. dpkg keeps
// printing the version of a package that was removed with its config left behind
// ("rc"), and that version describes nothing on disk.
func parseDpkgPackageVersion(out string) string {
	f := strings.Fields(out)
	if len(f) != 2 {
		return ""
	}
	// Two letters: desired action (install or hold) and state (installed). A third
	// letter is dpkg's error flag, which means the install did not finish.
	status := f[0]
	if len(status) != 2 || (status[0] != 'i' && status[0] != 'h') || status[1] != 'i' {
		return ""
	}
	return f[1]
}

func probeString(ctx context.Context, fn func(context.Context) (string, error)) string {
	s, err := fn(ctx)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

func dpkgQueryPackage(ctx context.Context) (string, error) {
	return runProbe(ctx, "dpkg-query", "-W", "-f=${db:Status-Abbrev} ${Version}", dkmsPackage)
}

func modinfoSrcVersion(ctx context.Context) (string, error) {
	return runProbe(ctx, "modinfo", "-F", "srcversion", "amneziawg")
}

func readLoadedSrcVersion(context.Context) (string, error) {
	b, err := os.ReadFile(loadedSrcVersionPath)
	if err != nil {
		return "", fmt.Errorf("read loaded srcversion: %w", err)
	}
	return string(b), nil
}

func runProbe(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, buildProbeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return string(out), nil
}
