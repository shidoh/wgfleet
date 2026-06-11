package mihomo

// deepMerge merges over into base and returns base. Semantics:
//   - when both base[k] and over[k] are maps, merge recursively;
//   - otherwise over[k] replaces base[k] (scalars and lists replace wholesale).
//
// This is the customization rule for CustomConfig.Overrides: operators refine
// nested structure (e.g. add a "sniffer.skip-domain" entry by replacing the
// list, or tweak "dns") without re-specifying the whole tree. A nil over is a
// no-op.
func deepMerge(base, over map[string]any) map[string]any {
	if base == nil {
		base = map[string]any{}
	}
	for k, ov := range over {
		if bv, ok := base[k]; ok {
			if bm, ok1 := asMap(bv); ok1 {
				if om, ok2 := asMap(ov); ok2 {
					base[k] = deepMerge(bm, om)
					continue
				}
			}
		}
		base[k] = ov
	}
	return base
}

// asMap normalizes the two map shapes that show up: map[string]any (our base and
// JSON-decoded overrides) and map[any]any (yaml.v3-decoded overrides).
func asMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			ks, ok := k.(string)
			if !ok {
				return nil, false
			}
			out[ks] = val
		}
		return out, true
	default:
		return nil, false
	}
}
