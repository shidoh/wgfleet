package mihomo

// AmneziaWG 3.x proxies go before 2.0 ones in the fleet-wide groups, masters in
// manifest order within each generation. A fleet moves its masters' client
// interfaces to 3.x one at a time; while it does, a device whose profile is
// already new should use the moved master first, and a device whose profile is
// still old fails its 3.x proxy and falls through to the 2.0 one behind it —
// which is how the move costs nobody a manual step.

// speaksAWG3 reports whether the master's client interface runs AmneziaWG 3.x
// header protection — the change a 2.0 peer cannot follow.
func speaksAWG3(m ClientProfileMaster) bool {
	return m.AWG != nil && m.AWG.Spec.AWG != nil && m.AWG.Spec.AWG.Shared.HeaderProtectionKey != ""
}

// mastersAWGFirst is masters with the 3.x ones first, otherwise in order.
func mastersAWGFirst(masters []ClientProfileMaster) []ClientProfileMaster {
	out := make([]ClientProfileMaster, 0, len(masters))
	for _, m := range masters {
		if speaksAWG3(m) {
			out = append(out, m)
		}
	}
	for _, m := range masters {
		if !speaksAWG3(m) {
			out = append(out, m)
		}
	}
	return out
}

// awgFirstByGeneration orders proxy names "<master>-awg" as mastersAWGFirst
// orders their masters.
func awgFirstByGeneration(names []string, masters []ClientProfileMaster) []string {
	present := make(map[string]bool, len(names))
	for _, n := range names {
		present[n] = true
	}
	out := make([]string, 0, len(names))
	for _, m := range mastersAWGFirst(masters) {
		if n := m.Name + "-awg"; present[n] {
			out = append(out, n)
		}
	}
	return out
}
