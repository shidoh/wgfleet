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
	// ScannerListURL is sngvy/AntiScanner: a hand-kept list of the scanners
	// themselves (GRCHC/CyberOK, Censys, Shodan, Shadowserver …), both families in
	// one file. C24Be covers state networks by registry name and misses most of
	// these; this list adds ~29 000 IPv4 addresses on top of it (2026-10-31).
	ScannerListURL = "https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/blacklist.txt"
)

// DefaultExtraURLs are the sources fetched beside the v4/v6 pair. A built-in
// default rather than a manifest key, so agents already in the field pick it up
// without being re-provisioned.
func DefaultExtraURLs() []string { return []string{ScannerListURL} }

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

// sourcePrefix starts a per-source header line in the cache.
const sourcePrefix = "# source "

// EncodeCache renders parsed prefixes to the on-disk cache format.
func EncodeCache(v4, v6 []string, updated time.Time) []byte {
	return EncodeCacheWithSources(v4, v6, nil, updated)
}

// EncodeCacheWithSources is EncodeCache plus one header line per source, read
// back by DecodeSources. Header lines are comments to DecodeCache.
func EncodeCacheWithSources(v4, v6 []string, sources []SourceCount, updated time.Time) []byte {
	var b strings.Builder
	b.WriteString(cacheHeader)
	fmt.Fprintf(&b, "# updated: %s\n", updated.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "# v4=%d v6=%d\n", len(v4), len(v6))
	for _, s := range sources {
		fmt.Fprintf(&b, "%sv4=%d v6=%d v4_addresses=%d %s\n", sourcePrefix, s.V4, s.V6, s.V4Addresses, s.URL)
	}
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

// DecodeSources reads the per-source header lines back. A cache written before
// they existed, or without sources, yields none.
func DecodeSources(r io.Reader) ([]SourceCount, error) {
	var out []SourceCount
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), maxLineBytes)
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), sourcePrefix)
		if !ok {
			continue
		}
		var s SourceCount
		if _, err := fmt.Sscanf(rest, "v4=%d v6=%d v4_addresses=%d %s", &s.V4, &s.V6, &s.V4Addresses, &s.URL); err != nil {
			continue
		}
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("asnfeed decode sources: %w", err)
	}
	return out, nil
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

// SourceCount is what one source contributed to the last good cache: prefixes
// per family and how many IPv4 addresses they cover (overlaps counted once).
// Recorded in the cache header so a source that silently shrinks shows up in a
// metric instead of only in a smaller ruleset.
type SourceCount struct {
	URL         string
	V4, V6      int
	V4Addresses uint64
}

// source is one URL and the families taken from it.
type source struct {
	url        string
	want4      bool
	want6      bool
	familyName string // for the "parsed to 0 entries" error
}

// Refresh fetches every configured source, merges them, and returns the cache
// bytes to persist. The v4 URL contributes only IPv4 prefixes and the v6 URL only
// IPv6 (as before); each extra URL contributes both. It is all-or-nothing: if any
// source fails to download, fails to parse, or yields nothing, it returns an
// error and NO cache, so the caller keeps the last good list. An empty v4/v6 URL
// skips that source.
func Refresh(ctx context.Context, hc *http.Client, v4URL, v6URL string, extra []string, now time.Time) ([]byte, error) {
	var sources []source
	if v4URL != "" {
		sources = append(sources, source{url: v4URL, want4: true, familyName: "v4"})
	}
	if v6URL != "" {
		sources = append(sources, source{url: v6URL, want6: true, familyName: "v6"})
	}
	for _, u := range extra {
		if u = strings.TrimSpace(u); u != "" {
			sources = append(sources, source{url: u, want4: true, want6: true, familyName: "extra"})
		}
	}
	all4 := make(map[string]struct{})
	all6 := make(map[string]struct{})
	counts := make([]SourceCount, 0, len(sources))
	for _, src := range sources {
		got4, got6, err := fetchSource(ctx, hc, src)
		if err != nil {
			return nil, err
		}
		for _, p := range got4 {
			all4[p] = struct{}{}
		}
		for _, p := range got6 {
			all6[p] = struct{}{}
		}
		counts = append(counts, SourceCount{URL: src.url, V4: len(got4), V6: len(got6), V4Addresses: V4AddressCount(got4)})
	}
	return EncodeCacheWithSources(capped(sortedKeys(all4)), capped(sortedKeys(all6)), counts, now), nil
}

func fetchSource(ctx context.Context, hc *http.Client, src source) (v4, v6 []string, err error) {
	body, err := Fetch(ctx, hc, src.url)
	if err != nil {
		return nil, nil, err
	}
	got4, got6, skipped, err := Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, nil, err
	}
	if src.want4 {
		v4 = got4
	}
	if src.want6 {
		v6 = got6
	}
	if len(v4)+len(v6) == 0 {
		return nil, nil, fmt.Errorf("asnfeed %s %q parsed to 0 entries (%d skipped)", src.familyName, src.url, skipped)
	}
	return v4, v6, nil
}

// capped keeps a merged family within the same bound Parse applies to one feed.
func capped(prefixes []string) []string {
	if len(prefixes) > maxEntriesPerFamily {
		return prefixes[:maxEntriesPerFamily]
	}
	return prefixes
}

// V4AddressCount is how many IPv4 addresses the prefixes cover, overlaps and
// duplicates counted once. Non-IPv4 and unparseable entries are ignored.
func V4AddressCount(prefixes []string) uint64 {
	type span struct{ lo, hi uint64 }
	spans := make([]span, 0, len(prefixes))
	for _, s := range prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		b := p.Addr().As4()
		lo := uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
		spans = append(spans, span{lo, lo + (uint64(1) << (32 - p.Bits())) - 1})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].lo < spans[j].lo })
	var total uint64
	var cur span
	for i, s := range spans {
		switch {
		case i == 0:
			cur = s
		case s.lo <= cur.hi+1:
			if s.hi > cur.hi {
				cur.hi = s.hi
			}
		default:
			total += cur.hi - cur.lo + 1
			cur = s
		}
	}
	if len(spans) > 0 {
		total += cur.hi - cur.lo + 1
	}
	return total
}
