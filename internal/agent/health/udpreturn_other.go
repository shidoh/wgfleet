//go:build !linux

package health

import "errors"

// UDPReturnBindable is Linux-only: it asks a question about IP_TRANSPARENT
// sockets, which exist nowhere else. On other platforms it reports "could not
// look" rather than inventing an answer, so a dev build on macOS compiles and the
// check says it is blind instead of saying the node is fine.
func UDPReturnBindable(int) (bool, error) {
	return false, errors.New("udp return probe: unsupported on this platform")
}
