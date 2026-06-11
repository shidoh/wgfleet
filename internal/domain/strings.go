package domain

import "strconv"

// joinHostPort renders host:port without pulling in net just for the helper,
// and keeps IPv6 hosts bracketed.
func joinHostPort(host string, port int) string {
	if containsByte(host, ':') {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

func containsByte(s string, b byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return true
		}
	}
	return false
}
