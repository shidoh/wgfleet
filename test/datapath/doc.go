// Package datapath rehearses the one mechanism that broke: a transparently
// intercepted client datagram, and the reply that has to find its way back.
//
// It exists because the August 2026 rehearsal was green while client QUIC was
// dead. That rehearsal drove client UDP through the tunnel on ports 5353 and
// 4433 and never touched 443 — the port the client interface itself listens on —
// so the collision it was meant to find could not appear. These tests drive the
// SAME port the node holds — 443 — which is the only version of the question
// worth asking, and they assert both halves of it: that the collision is real on
// a namespace holding that port, and that it is GONE in a namespace that does
// not. The second half is the whole claim this migration rests on, and it is the
// half that can go red.
//
// The tests are Linux-only and need CAP_NET_ADMIN (IP_TRANSPARENT); unprivileged
// they skip. CI runs them deliberately under sudo, because a test that always
// skips is a test nobody has. This file carries no build tag so that `go test
// ./...` on a developer's macOS still resolves the package instead of failing on
// "build constraints exclude all Go files".
package datapath
