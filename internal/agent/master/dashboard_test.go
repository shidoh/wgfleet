package master

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
)

// tarGz builds a .tar.gz with the given path→content entries (paths "./"-prefixed
// like the real metacubexd tarball) for the injected fetcher.
func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func dashSpec(url string, disabled bool) domain.NodeSpec {
	return domain.NodeSpec{Master: &domain.MasterSpec{
		ExternalController: "10.20.3.10:9090",
		DashboardURL:       url,
		DashboardDisabled:  disabled,
	}}
}

func TestDashboardPlannerDownloadsAndUnpacks(t *testing.T) {
	uiDir := filepath.Join(t.TempDir(), "ui")
	archive := tarGz(t, map[string]string{
		"./index.html":   "<html>metacubexd</html>",
		"./_nuxt/app.js": "console.log(1)",
		"./config.js":    "window.x=1",
	})
	called := 0
	p := dashboardPlanner{uiDir: uiDir, fetch: func(_ context.Context, _ string) ([]byte, error) {
		called++
		return archive, nil
	}}
	eng := reconcile.NewEngine(nil, p)
	spec := dashSpec("https://x/metacubexd.tgz", false)

	// Plan mode must not download or write anything (dry-run is side-effect-free).
	if _, err := eng.Reconcile(context.Background(), spec, reconcile.ModePlan); err != nil {
		t.Fatal(err)
	}
	if called != 0 {
		t.Fatalf("plan mode fetched the dashboard (%d) — must be side-effect-free", called)
	}
	if _, err := os.Stat(uiDir); !os.IsNotExist(err) {
		t.Fatalf("plan mode created the ui dir")
	}

	// Apply: downloads + unpacks.
	if _, err := eng.Reconcile(context.Background(), spec, reconcile.ModeApply); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"index.html", "_nuxt/app.js", "config.js", dashboardMarker} {
		if _, err := os.Stat(filepath.Join(uiDir, want)); err != nil {
			t.Errorf("missing unpacked %q: %v", want, err)
		}
	}
	if got, _ := os.ReadFile(filepath.Join(uiDir, "index.html")); string(got) != "<html>metacubexd</html>" {
		t.Errorf("index.html content = %q", got)
	}

	// Idempotent: a second apply with the same URL is a no-op, no re-download.
	rep, err := eng.Reconcile(context.Background(), spec, reconcile.ModeApply)
	if err != nil {
		t.Fatal(err)
	}
	if rep.ChangeCount() != 0 {
		t.Errorf("second apply not idempotent: %d changes", rep.ChangeCount())
	}
	if called != 1 {
		t.Errorf("fetch called %d times, want 1", called)
	}
}

func TestDashboardPlannerReinstallsOnURLChange(t *testing.T) {
	uiDir := filepath.Join(t.TempDir(), "ui")
	if err := installDashboard(uiDir, "https://x/v1.tgz", tarGz(t, map[string]string{"./index.html": "v1", "./old.js": "old"})); err != nil {
		t.Fatal(err)
	}
	p := dashboardPlanner{uiDir: uiDir, fetch: func(_ context.Context, _ string) ([]byte, error) {
		return tarGz(t, map[string]string{"./index.html": "v2"}), nil
	}}
	if _, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), dashSpec("https://x/v2.tgz", false), reconcile.ModeApply); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(uiDir, "index.html")); string(got) != "v2" {
		t.Errorf("index.html not updated: %q", got)
	}
	if _, err := os.Stat(filepath.Join(uiDir, "old.js")); !os.IsNotExist(err) {
		t.Errorf("stale file from the old dashboard survived re-install")
	}
}

func TestDashboardPlannerNotServed(t *testing.T) {
	p := dashboardPlanner{uiDir: t.TempDir(), fetch: func(context.Context, string) ([]byte, error) {
		t.Fatal("must not fetch when the dashboard is not served")
		return nil, nil
	}}
	for name, spec := range map[string]domain.NodeSpec{
		"disabled":      dashSpec("https://x/d.tgz", true),
		"no-controller": {Master: &domain.MasterSpec{DashboardURL: "https://x/d.tgz"}},
	} {
		rep, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), spec, reconcile.ModeApply)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rep.ChangeCount() != 0 {
			t.Errorf("%s: expected no changes, got %d", name, rep.ChangeCount())
		}
	}
}

func TestSafeJoinRejectsTraversal(t *testing.T) {
	dest := filepath.FromSlash("/etc/mihomo/ui")
	if _, ok := safeJoin(dest, "./index.html"); !ok {
		t.Error("normal entry rejected")
	}
	// "../" is anchored away, never escaping dest.
	got, ok := safeJoin(dest, "../../etc/passwd")
	if !ok {
		t.Fatalf("entry unexpectedly rejected")
	}
	if got != dest && !filepathHasPrefix(got, dest) {
		t.Errorf("traversal escaped dest: %q", got)
	}
}

func filepathHasPrefix(p, prefix string) bool {
	return p == prefix || (len(p) > len(prefix) && p[:len(prefix)+1] == prefix+string(os.PathSeparator))
}
