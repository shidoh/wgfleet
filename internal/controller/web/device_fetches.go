package web

import (
	"context"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/controller/clientcfg"
	"github.com/shidoh/wgfleet/internal/domain"
)

// ProfileFetchLister reads each device's latest portal downloads.
type ProfileFetchLister interface {
	ListProfileFetches(ctx context.Context) ([]domain.ProfileFetch, error)
}

// SetProfileFetches wires the download record. Optional: without it the Devices
// list has no "Last download" column.
func (h *Handler) SetProfileFetches(s ProfileFetchLister) { h.fetches = s }

// fetchStaleAfter is two of the apps' daily refreshes: a device past it has
// missed one for a reason worth a look before a change it must follow.
const fetchStaleAfter = 48 * time.Hour

// fetchView is one download as the Devices list shows it.
type fetchView struct {
	Kind, Ago, Software string
	Stale               bool
}

// deviceFetches groups the downloads by device. A read error leaves the column
// empty rather than failing the page: the list is how devices are managed.
func (h *Handler) deviceFetches(ctx context.Context) map[string][]fetchView {
	if h.fetches == nil {
		return nil
	}
	all, err := h.fetches.ListProfileFetches(ctx)
	if err != nil {
		return nil
	}
	out := map[string][]fetchView{}
	for _, f := range all {
		since := time.Since(f.At)
		out[f.DeviceID] = append(out[f.DeviceID], fetchView{
			Kind: string(f.Kind), Ago: formatSince(since),
			Software: softwareLabel(clientcfg.ParseUserAgent(f.UserAgent), f.UserAgent),
			Stale:    since > fetchStaleAfter,
		})
	}
	return out
}

// softwareLabel names the app and the core when the User-Agent says them, the raw
// header otherwise.
func softwareLabel(a clientcfg.ClientAgent, raw string) string {
	var parts []string
	if a.App != "" {
		parts = append(parts, strings.TrimSpace(a.App+" "+a.AppVersion))
	}
	if a.CoreVersion != "" {
		parts = append(parts, "core "+a.CoreVersion)
	}
	if len(parts) == 0 {
		return clientcfg.SanitizeUserAgent(raw)
	}
	return strings.Join(parts, ", ")
}
