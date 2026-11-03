package awgmod

import (
	"context"
	"errors"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestParseDpkgPackageVersion(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want string
	}{
		{name: "installed", out: "ii  1.0.0-0~202609061402+4569c4c", want: "1.0.0-0~202609061402+4569c4c"},
		{name: "installed and held", out: "hi  1.0.0-0~202609061402+4569c4c\n", want: "1.0.0-0~202609061402+4569c4c"},
		// Removed with its config left behind: dpkg still prints the old version,
		// which describes nothing on disk any more.
		{name: "removed, config remains", out: "rc  1.0.0-0~202608121130+0a1b2c3", want: ""},
		{name: "half installed", out: "iH  1.0.0-0~202609061402+4569c4c", want: ""},
		{name: "empty", out: "", want: ""},
		{name: "status only", out: "ii  ", want: ""},
		{name: "garbled", out: "\x00\x01 dpkg-query: no packages found matching amneziawg-dkms", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseDpkgPackageVersion(tc.out); got != tc.want {
				t.Errorf("parseDpkgPackageVersion(%q) = %q, want %q", tc.out, got, tc.want)
			}
		})
	}
}

func TestReadModuleBuild(t *testing.T) {
	const (
		pkg    = "ii  1.0.0-0~202609061402+4569c4c"
		newSrc = "A1B2C3D4E5F60718293A4B5"
		oldSrc = "0123456789ABCDEF0123456"
	)
	fail := errors.New("not available")
	tests := []struct {
		name   string
		probe  BuildProbe
		want   domain.AWGModuleBuild
		wantLb string
	}{
		{
			name: "loaded module matches the package on disk",
			probe: BuildProbe{
				Package: ok(pkg), LoadedSrcVersion: ok(newSrc + "\n"), DiskSrcVersion: ok(newSrc + "\n"),
			},
			want:   domain.AWGModuleBuild{PackageVersion: "1.0.0-0~202609061402+4569c4c", SrcVersion: newSrc},
			wantLb: "202609061402",
		},
		{
			name: "package upgraded, old module still loaded",
			probe: BuildProbe{
				Package: ok(pkg), LoadedSrcVersion: ok(oldSrc), DiskSrcVersion: ok(newSrc),
			},
			want: domain.AWGModuleBuild{
				PackageVersion: "1.0.0-0~202609061402+4569c4c", SrcVersion: oldSrc, ReloadPending: true,
			},
			wantLb: "unknown",
		},
		{
			// awg-quick loads the module from disk, so the disk build is what will run.
			name: "module not loaded yet",
			probe: BuildProbe{
				Package: ok(pkg), LoadedSrcVersion: errFn(fail), DiskSrcVersion: ok(newSrc),
			},
			want:   domain.AWGModuleBuild{PackageVersion: "1.0.0-0~202609061402+4569c4c", SrcVersion: newSrc},
			wantLb: "202609061402",
		},
		{
			name: "package not installed (module built by hand)",
			probe: BuildProbe{
				Package: errFn(fail), LoadedSrcVersion: ok(newSrc), DiskSrcVersion: ok(newSrc),
			},
			want:   domain.AWGModuleBuild{SrcVersion: newSrc},
			wantLb: "unknown",
		},
		{
			name:   "nothing readable",
			probe:  BuildProbe{Package: errFn(fail), LoadedSrcVersion: errFn(fail), DiskSrcVersion: errFn(fail)},
			want:   domain.AWGModuleBuild{},
			wantLb: "unknown",
		},
		{
			// A disk srcversion that cannot be read proves nothing about a reload.
			name: "disk srcversion unreadable",
			probe: BuildProbe{
				Package: ok(pkg), LoadedSrcVersion: ok(newSrc), DiskSrcVersion: errFn(fail),
			},
			want:   domain.AWGModuleBuild{PackageVersion: "1.0.0-0~202609061402+4569c4c", SrcVersion: newSrc},
			wantLb: "202609061402",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ReadModuleBuild(context.Background(), tc.probe)
			if got != tc.want {
				t.Errorf("ReadModuleBuild() = %+v, want %+v", got, tc.want)
			}
			if lb := got.Label(); lb != tc.wantLb {
				t.Errorf("Label() = %q, want %q", lb, tc.wantLb)
			}
		})
	}
}

func ok(s string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return s, nil }
}

func errFn(err error) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return "", err }
}
