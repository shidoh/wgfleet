package dnsfilter

// deepMerge layers operator overrides onto the rendered base config: maps merge
// recursively, while scalars and lists replace. This lets an operator inject the
// rich blocky surface (denylists, conditional mappings, caching tuning) without
// the renderer growing a field per option. Mirrors the mihomo renderer's merge.
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

// asMap coerces YAML-decoded maps (map[string]any or map[any]any) to
// map[string]any so overrides loaded from either source merge uniformly.
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
