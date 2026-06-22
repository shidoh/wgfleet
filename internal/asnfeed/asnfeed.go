// Package asnfeed fetches and parses scanner-ASN blacklists (the daily-updated
// C24Be/AS_Network_List feeds) into canonical IPv4/IPv6 prefixes the exit
// firewall drops, so active VPN scanners never see the WG port or SSH.
//
// The package is split into a pure parser/codec (no I/O) and a thin Fetch/Refresh
// layer (HTTP). The agent's reconcile engine drives refreshes Apply-side only, so
// dry-run never touches the network; the firewall renderer re-validates every
// element before it reaches `nft -f`, so a corrupt or hostile cache can never
// inject ruleset syntax.
package asnfeed

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Default feed sources (C24Be/AS_Network_List, refreshed daily) and cadence. The
// URLs are overridable per node (agent-local config); the interval governs how
// often a stale cache is refreshed.
const (
	DefaultV4URL    = "https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist-v4.txt"
	DefaultV6URL    = "https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist-v6.txt"
	DefaultInterval = 24 * time.Hour
)

const (
	// maxEntriesPerFamily bounds a parsed feed against a corrupt/hostile source so
	// it can neither exhaust memory nor render a multi-megabyte ruleset. The real
	// feeds are well under this.
	maxEntriesPerFamily = 250_000
	// maxFeedBytes caps a single downloaded feed body.
	maxFeedBytes = 32 << 20 // 32 MiB
	// fetchTimeout bounds one feed download.
	fetchTimeout = 30 * time.Second
	// maxLineBytes is the scanner buffer ceiling for one feed line.
	maxLineBytes = 1 << 16
)

// Parse reads a blacklist feed — one IP or CIDR per line, '#' comments and blank
// lines ignored — and returns canonical IPv4 and IPv6 prefixes, de-duplicated and
// sorted. Invalid lines are skipped and counted (a single bad line never voids
// the whole feed); every returned element is re-emitted from its parsed form, so
// nothing un-parseable survives. Each family is capped at maxEntriesPerFamily.
func Parse(r io.Reader) (v4, v6 []string, skipped int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), maxLineBytes)

	seen4 := make(map[string]struct{})
	seen6 := make(map[string]struct{})
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		canon, is4, perr := canonicalElem(line)
		if perr != nil {
			skipped++
			continue
		}
		if is4 {
			if _, dup := seen4[canon]; dup || len(seen4) >= maxEntriesPerFamily {
				continue
			}
			seen4[canon] = struct{}{}
		} else {
			if _, dup := seen6[canon]; dup || len(seen6) >= maxEntriesPerFamily {
				continue
			}
			seen6[canon] = struct{}{}
		}
	}
	if serr := sc.Err(); serr != nil {
		return nil, nil, skipped, fmt.Errorf("asnfeed parse: %w", serr)
	}
	return sortedKeys(seen4), sortedKeys(seen6), skipped, nil
}

// canonicalElem parses one token as a bare IP (→ /32 or /128) or a CIDR prefix and
// returns its canonical masked string plus whether it is IPv4. Re-emitting the
// parsed value (never the raw token) is the injection guard.
func canonicalElem(tok string) (canonical string, isV4 bool, err error) {
	if strings.Contains(tok, "/") {
		p, perr := netip.ParsePrefix(tok)
		if perr != nil {
			return "", false, perr
		}
		return p.Masked().String(), p.Addr().Is4(), nil
	}
	a, aerr := netip.ParseAddr(tok)
	if aerr != nil {
		return "", false, aerr
	}
	if a.Is4() {
		return a.String() + "/32", true, nil
	}
	return a.String() + "/128", false, nil
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// cacheHeader prefixes the on-disk cache. The body is "v4 <cidr>" / "v6 <cidr>"
// lines; the firewall renderer re-parses and re-validates them, so this format is
// a debuggable convenience, not a trust boundary.
const cacheHeader = "# wgfleet AS-blacklist cache — generated, do not edit\n"

// EncodeCache renders parsed prefixes to the on-disk cache format.
func EncodeCache(v4, v6 []string, updated time.Time) []byte {
	var b strings.Builder
	b.WriteString(cacheHeader)
	fmt.Fprintf(&b, "# updated: %s\n", updated.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "# v4=%d v6=%d\n", len(v4), len(v6))
	for _, p := range v4 {
		b.WriteString("v4 ")
		b.WriteString(p)
		b.WriteByte('\n')
	}
	for _, p := range v6 {
		b.WriteString("v6 ")
		b.WriteString(p)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// DecodeCache reads the cache format back into prefix lists. Malformed lines are
// skipped; the renderer validates again before emitting nft elements.
func DecodeCache(r io.Reader) (v4, v6 []string, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), maxLineBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fam, val, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch fam {
		case "v4":
			v4 = append(v4, val)
		case "v6":
			v6 = append(v6, val)
		}
	}
	if serr := sc.Err(); serr != nil {
		return nil, nil, fmt.Errorf("asnfeed decode cache: %w", serr)
	}
	return v4, v6, nil
}

// Fetch downloads url with a bounded timeout and body size and returns the raw
// feed bytes. A non-200 status or oversized body is an error.
func Fetch(ctx context.Context, hc *http.Client, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("asnfeed request %q: %w", url, err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("asnfeed fetch %q: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("asnfeed fetch %q: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("asnfeed read %q: %w", url, err)
	}
	if len(body) > maxFeedBytes {
		return nil, fmt.Errorf("asnfeed fetch %q: body exceeds %d bytes", url, maxFeedBytes)
	}
	return body, nil
}

// Refresh fetches the (non-empty) v4 and v6 feed URLs, parses and merges them, and
// returns the cache bytes to persist plus the per-family element counts. It is
// all-or-nothing: if any configured feed fails to download or parse, it returns an
// error and NO cache, so the caller keeps the last-good list (fail-safe). An empty
// URL skips that family.
func Refresh(ctx context.Context, hc *http.Client, v4URL, v6URL string, now time.Time) (cache []byte, v4n, v6n int, err error) {
	var v4, v6 []string
	if v4URL != "" {
		body, ferr := Fetch(ctx, hc, v4URL)
		if ferr != nil {
			return nil, 0, 0, ferr
		}
		got4, _, skipped, perr := Parse(strings.NewReader(string(body)))
		if perr != nil {
			return nil, 0, 0, perr
		}
		if len(got4) == 0 {
			return nil, 0, 0, fmt.Errorf("asnfeed v4 %q parsed to 0 entries (%d skipped)", v4URL, skipped)
		}
		v4 = got4
	}
	if v6URL != "" {
		body, ferr := Fetch(ctx, hc, v6URL)
		if ferr != nil {
			return nil, 0, 0, ferr
		}
		_, got6, skipped, perr := Parse(strings.NewReader(string(body)))
		if perr != nil {
			return nil, 0, 0, perr
		}
		if len(got6) == 0 {
			return nil, 0, 0, fmt.Errorf("asnfeed v6 %q parsed to 0 entries (%d skipped)", v6URL, skipped)
		}
		v6 = got6
	}
	return EncodeCache(v4, v6, now), len(v4), len(v6), nil
}
