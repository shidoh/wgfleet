// Package certrenew decides when a node should renew its control-plane
// certificate.
//
// The model is kubelet's: the node renews ITSELF, over the channel its current
// certificate already authenticates, well before that certificate expires. No
// operator step, no approval, no pending-request object — asking requires a valid
// certificate and the answer is scoped to the asker, so there is nothing left to
// decide.
//
// The corollary is that an EXPIRED certificate cannot be renewed this way: the
// handshake fails before the request is made. That is the property that makes the
// model safe rather than a hole in it, and it is exactly why renewal starts early
// enough that a node gets many chances and needs only one.
package certrenew

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// Renewal window, as a fraction of the certificate's total lifetime. kubelet uses
// 70-90%; the same shape suits a fleet that reconciles every 30 seconds, because a
// node gets thousands of attempts inside the window.
//
// On a 365-day certificate that is roughly day 255 to day 328 — two months of
// runway before expiry, longer than any holiday and longer than most outages.
const (
	windowLow  = 0.70
	windowHigh = 0.90
)

// DueAt returns the moment this node should start trying to renew.
//
// The point inside the window is DERIVED from the node's name rather than drawn at
// random, for two reasons. It is stable, so a node that restarts does not roll a new
// date and drift. And it is spread: a fleet provisioned in one afternoon has
// certificates expiring in one afternoon, and without jitter it would renew in one
// afternoon too — turning a routine rotation back into the fleet-wide event that
// made expiry dangerous in the first place.
func DueAt(nodeID string, notBefore, notAfter time.Time) time.Time {
	life := notAfter.Sub(notBefore)
	if life <= 0 {
		// A certificate whose validity does not run forwards tells us nothing about
		// when to renew; treat it as due now rather than as never.
		return notAfter
	}
	sum := sha256.Sum256([]byte("wgfleet|cert-renewal|v1|" + nodeID))
	frac := float64(binary.BigEndian.Uint32(sum[:4])) / float64(1<<32) // [0,1)
	at := windowLow + frac*(windowHigh-windowLow)
	return notBefore.Add(time.Duration(float64(life) * at))
}

// Due reports whether now is at or past the renewal moment.
func Due(nodeID string, notBefore, notAfter, now time.Time) bool {
	return !now.Before(DueAt(nodeID, notBefore, notAfter))
}
