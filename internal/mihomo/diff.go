package mihomo

import (
	"fmt"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// DescribeChange says WHAT differs between two rendered configs, as key paths
// only — never values, so it is safe in a journal that also holds the redacted
// plan. Empty when the documents are equal.
//
// It exists because on 2026-09-07 the master rewrote mihomo's config four times
// in seven minutes, each rewrite a hot reload, each reload leaking a WireGuard
// device, each leak a restart — and the journal recorded "update
// /etc/mihomo/config.yaml" four times and nothing else. The rendered config is
// not kept, the trigger was gone with the previous bytes, and the only honest
// answer afterwards was "something in the render input was flapping". This is
// what turns that sentence into a name.
//
// Sections that are lists of named entries — proxies, proxy-groups, listeners —
// are described per entry, with the fields that moved: `proxies: vn1 (server,
// port)`. Maps are described one level down: `dns: nameserver`. Anything else
// by its top-level key.
func DescribeChange(oldCfg, newCfg []byte) string {
	var oldDoc, newDoc map[string]any
	oldErr := yaml.Unmarshal(oldCfg, &oldDoc)
	newErr := yaml.Unmarshal(newCfg, &newDoc)
	if oldErr != nil || newErr != nil {
		if (oldErr != nil) == (newErr != nil) && string(oldCfg) == string(newCfg) {
			return ""
		}
		return "<unparseable>"
	}
	var parts []string
	for _, key := range unionKeys(oldDoc, newDoc) {
		o, n := oldDoc[key], newDoc[key]
		if canonical(o) == canonical(n) {
			continue
		}
		if entries := describeNamedList(o, n); entries != "" {
			parts = append(parts, key+": "+entries)
			continue
		}
		om, ook := o.(map[string]any)
		nm, nok := n.(map[string]any)
		if ook && nok {
			var sub []string
			for _, k := range unionKeys(om, nm) {
				if canonical(om[k]) != canonical(nm[k]) {
					sub = append(sub, k)
				}
			}
			parts = append(parts, key+": "+strings.Join(sub, ", "))
			continue
		}
		parts = append(parts, key)
	}
	return strings.Join(parts, "; ")
}

// describeNamedList handles a list whose entries carry a `name`: it names the
// entries added, removed or altered, and for an altered one the fields that moved.
// Returns "" when either side is not such a list.
func describeNamedList(o, n any) string {
	oldL, ook := namedEntries(o)
	newL, nok := namedEntries(n)
	if !ook && !nok {
		return ""
	}
	var out []string
	for _, name := range unionKeys(oldL, newL) {
		oe, inOld := oldL[name]
		ne, inNew := newL[name]
		switch {
		case !inOld:
			out = append(out, name+" (added)")
		case !inNew:
			out = append(out, name+" (removed)")
		default:
			var fields []string
			for _, k := range unionKeys(oe, ne) {
				if canonical(oe[k]) != canonical(ne[k]) {
					fields = append(fields, k)
				}
			}
			if len(fields) > 0 {
				out = append(out, name+" ("+strings.Join(fields, ", ")+")")
			}
		}
	}
	if len(out) == 0 {
		// The lists differ only in order. Say so rather than nothing: an entry that
		// moved is still a rewrite mihomo was asked to reload.
		return "order"
	}
	return strings.Join(out, ", ")
}

// namedEntries indexes a []map entry list by its `name`; ok is false when v is
// not a list of maps (nil counts as an empty list so a section that appeared or
// vanished still describes its entries).
func namedEntries(v any) (map[string]map[string]any, bool) {
	if v == nil {
		return map[string]map[string]any{}, true
	}
	list, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make(map[string]map[string]any, len(list))
	for i, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, false
		}
		name, _ := m["name"].(string)
		if name == "" {
			name = fmt.Sprintf("<unnamed-%d>", i)
		}
		out[name] = m
	}
	return out, true
}

func canonical(v any) string {
	b, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Sprintf("<unmarshalable %T>", v)
	}
	return string(b)
}

func unionKeys[V any](a, b map[string]V) []string {
	seen := map[string]bool{}
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
