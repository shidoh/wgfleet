package health

// ScanUDPReturn is the whole check in one call: for every UDP service port this
// namespace holds, whether a transparent reply socket can still be opened there.
// Ports the probe cannot answer for are omitted rather than guessed at.
func ScanUDPReturn() (map[int]bool, error) {
	ports, err := HeldUDPPorts()
	if err != nil {
		return nil, err
	}
	out := make(map[int]bool, len(ports))
	for _, p := range ports {
		ok, perr := UDPReturnBindable(p)
		if perr != nil {
			continue
		}
		out[p] = ok
	}
	return out, nil
}
