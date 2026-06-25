package metrics

import (
	"encoding/json"
	"fmt"
)

// nftBlacklistV4 / nftBlacklistV6 are the AS-blacklist set names rendered by
// internal/netfw (set as_blacklist / as_blacklist_v6 in table inet wgfleet).
const (
	nftBlacklistV4 = "as_blacklist"
	nftBlacklistV6 = "as_blacklist_v6"
)

// nftDoc is the top-level shape of `nft -j list table inet wgfleet`. Each entry
// in the array is a single-key object identifying the object kind (set, counter,
// rule, chain, table, ...). We decode each entry's union and pick out sets and
// counters; everything else is ignored.
type nftDoc struct {
	Nftables []nftEntry `json:"nftables"`
}

type nftEntry struct {
	Set     *nftSet     `json:"set"`
	Counter *nftCounter `json:"counter"`
}

// nftSet is an nftables set. elem is present only when the set has elements;
// for interval sets each element may itself be an object, so it is decoded as a
// raw list and only its length is used.
type nftSet struct {
	Name string            `json:"name"`
	Elem []json.RawMessage `json:"elem"`
}

// nftCounter is a named nftables counter object.
type nftCounter struct {
	Name    string  `json:"name"`
	Packets float64 `json:"packets"`
	Bytes   float64 `json:"bytes"`
}

// nftStats is the parsed firewall telemetry: AS-blacklist set sizes keyed by
// address family ("v4"/"v6") and named drop counters keyed by counter name.
type nftStats struct {
	blacklistSize map[string]int     // family -> element count
	counters      map[string]float64 // counter name -> packets dropped
}

// parseNFTTable parses `nft -j list table inet wgfleet` JSON into firewall stats.
// It returns an error on malformed JSON; absent sets/counters simply yield empty
// maps (the collector then emits no series for them — fail-soft).
func parseNFTTable(jsonOut []byte) (nftStats, error) {
	var doc nftDoc
	if err := json.Unmarshal(jsonOut, &doc); err != nil {
		return nftStats{}, fmt.Errorf("parse nft json: %w", err)
	}
	stats := nftStats{
		blacklistSize: map[string]int{},
		counters:      map[string]float64{},
	}
	for _, e := range doc.Nftables {
		switch {
		case e.Set != nil:
			switch e.Set.Name {
			case nftBlacklistV4:
				stats.blacklistSize["v4"] = len(e.Set.Elem)
			case nftBlacklistV6:
				stats.blacklistSize["v6"] = len(e.Set.Elem)
			}
		case e.Counter != nil && e.Counter.Name != "":
			stats.counters[e.Counter.Name] = e.Counter.Packets
		}
	}
	return stats, nil
}
