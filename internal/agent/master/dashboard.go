package master

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/mihomo"
)

// dashboardMarker records, inside the UI dir, which dashboard URL is installed so
// the planner is idempotent (re-download only when the URL changes).
const dashboardMarker = ".wgfleet-dashboard-url"

const (
	dashboardFetchTimeout = 60 * time.Second
	maxDashboardArchive   = 64 << 20 // 64 MiB: a dashboard tarball is ~1 MiB; cap abuse.
	maxDashboardFile      = 64 << 20
)

// dashboardPlanner downloads the mihomo web dashboard and unpacks it into the
// external-ui directory, so mihomo serves it as static files without ever
// downloading anything itself.
//
// Why the agent and not mihomo: mihomo's own external-ui download follows the
// proxy rules (the master's catch-all MATCH → wg-best → exit → WARP), and its
// external-ui-download-detour is NOT honored by the running build — so on a master
// behind filtering the download TLS-times-out even though the host reaches GitHub
// directly in well under a second. The agent runs on that host
// with the direct path, so it fetches and unpacks the dashboard; the renderer
// then emits external-ui (the dir) WITHOUT external-ui-url, and mihomo only serves.
type dashboardPlanner struct {
	uiDir string
	// fetch downloads url and returns the archive bytes; nil ⇒ a real HTTP GET.
	// Injected in tests so they neither hit the network nor need the binary.
	fetch func(ctx context.Context, url string) ([]byte, error)
}

func (dashboardPlanner) Component() string { return "mihomo dashboard (static UI)" }

func (p dashboardPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("dashboard: node has no master spec")
	}
	// No dashboard is served unless the Clash API is exposed and the dashboard is
	// enabled — mirror the renderer's external-ui condition.
	if spec.Master.ExternalController == "" || spec.Master.DashboardDisabled {
		return []reconcile.Action{reconcile.NoChangeAction("dashboard", "not served")}, nil
	}
	url := spec.Master.DashboardURL
	if url == "" {
		url = mihomo.DefaultDashboardURL
	}
	if p.installed(url) {
		return []reconcile.Action{reconcile.NoChangeAction(p.uiDir, "dashboard up to date")}, nil
	}

	kind := reconcile.ActionCreate
	if _, err := os.Stat(filepath.Join(p.uiDir, "index.html")); err == nil {
		kind = reconcile.ActionUpdate // replacing a previously installed dashboard
	}
	uiDir, fetch := p.uiDir, p.fetch
	if fetch == nil {
		fetch = httpFetchArchive
	}
	action := reconcile.CustomAction(
		kind, p.uiDir,
		"download + unpack the mihomo dashboard",
		fmt.Sprintf("download %s and unpack into %s (served statically; mihomo does not download it)", url, p.uiDir),
		func(ctx context.Context) error {
			data, err := fetch(ctx, url)
			if err != nil {
				return fmt.Errorf("download dashboard %q: %w", url, err)
			}
			return installDashboard(uiDir, url, data)
		},
	)
	return []reconcile.Action{action}, nil
}

// installed reports whether the UI dir already holds the dashboard for url (its
// marker matches and index.html is present).
func (p dashboardPlanner) installed(url string) bool {
	got, err := os.ReadFile(filepath.Join(p.uiDir, dashboardMarker))
	if err != nil || strings.TrimSpace(string(got)) != url {
		return false
	}
	_, err = os.Stat(filepath.Join(p.uiDir, "index.html"))
	return err == nil
}

// installDashboard unpacks archive data into uiDir (cleared first so a version
// change leaves no stale files) and records url in the marker file.
func installDashboard(uiDir, url string, data []byte) error {
	if err := os.RemoveAll(uiDir); err != nil {
		return fmt.Errorf("clear ui dir %q: %w", uiDir, err)
	}
	if err := os.MkdirAll(uiDir, 0o755); err != nil {
		return fmt.Errorf("mkdir ui dir %q: %w", uiDir, err)
	}
	var err error
	if strings.HasSuffix(url, ".zip") {
		err = extractZip(uiDir, data)
	} else { // .tgz / .tar.gz / .gz (metacubexd ships compressed-dist.tgz)
		err = extractTarGz(uiDir, data)
	}
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(uiDir, dashboardMarker), []byte(url), 0o644)
}

// safeJoin resolves an archive entry name under destDir, anchoring at the root so
// "../" cannot escape (zip-slip safe). Leading "./" (as in the metacubexd tarball)
// is normalized away. ok is false for an entry that would land outside destDir.
func safeJoin(destDir, name string) (target string, ok bool) {
	clean := filepath.Clean("/" + strings.ReplaceAll(name, "\\", "/"))
	target = filepath.Join(destDir, clean)
	if target != destDir && !strings.HasPrefix(target, destDir+string(os.PathSeparator)) {
		return "", false
	}
	return target, true
}

func extractTarGz(destDir string, data []byte) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("dashboard gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("dashboard tar: %w", err)
		}
		target, ok := safeJoin(destDir, hdr.Name)
		if !ok {
			return fmt.Errorf("dashboard tar: unsafe path %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := writeFileFrom(target, io.LimitReader(tr, maxDashboardFile)); err != nil {
				return err
			}
		}
	}
	return nil
}

func extractZip(destDir string, data []byte) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("dashboard zip: %w", err)
	}
	for _, f := range zr.File {
		target, ok := safeJoin(destDir, f.Name)
		if !ok {
			return fmt.Errorf("dashboard zip: unsafe path %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		err = writeFileFrom(target, io.LimitReader(rc, maxDashboardFile))
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func writeFileFrom(target string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// httpFetchArchive is the real downloader: a plain GET on the host's direct path
// (GitHub release downloads 30x-redirect to a CDN — http.DefaultClient follows).
func httpFetchArchive(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, dashboardFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDashboardArchive))
}
