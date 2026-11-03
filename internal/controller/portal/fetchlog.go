package portal

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/shidoh/wgfleet/internal/controller/clientcfg"
	"github.com/shidoh/wgfleet/internal/domain"
)

// FetchRecorder stores a device's latest portal download (store.Store has it).
type FetchRecorder interface {
	RecordProfileFetch(ctx context.Context, f domain.ProfileFetch) error
}

// fetchRecordEvery bounds the store writes one device causes. An app that
// refreshes every few seconds would otherwise turn the subscription into a write
// stream, and under a replicated store every write is replayed everywhere. The
// cost is that "last fetched" can lag by this much — nothing that waits on it
// is measured in minutes.
const fetchRecordEvery = 10 * time.Minute

// fetchRecordTimeout keeps a slow store from holding the request: the profile has
// already been sent by then.
const fetchRecordTimeout = 2 * time.Second

type fetchKey struct {
	device string
	kind   domain.ProfileFetchKind
}

type fetchSeen struct {
	at time.Time
	ua string
}

// fetchLog remembers what this portal last wrote, so it can skip a write that
// would say nothing new. Bounded by the number of devices: only a token that
// resolved to a device reaches it.
type fetchLog struct {
	mu   sync.Mutex
	last map[fetchKey]fetchSeen
}

// claim reports whether this fetch should be written, and marks it written. A
// changed User-Agent is always written: an app or core upgrade is exactly what
// the operator watches for.
func (l *fetchLog) claim(k fetchKey, ua string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if prev, ok := l.last[k]; ok && prev.ua == ua && now.Sub(prev.at) < fetchRecordEvery {
		return false
	}
	if l.last == nil {
		l.last = map[fetchKey]fetchSeen{}
	}
	l.last[k] = fetchSeen{at: now, ua: ua}
	return true
}

// release forgets a claim whose write failed, so the next fetch tries again.
func (l *fetchLog) release(k fetchKey) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.last, k)
}

// recordFetch notes that dev downloaded kind. A failure is logged and swallowed:
// bookkeeping must never cost a device its profile. A token that is a legacy
// credential link has no device row to attach the fetch to and is skipped.
func (h *Handler) recordFetch(r *http.Request, dev domain.ClientDevice, kind domain.ProfileFetchKind) {
	if h.opts.Fetches == nil || dev.ID == "" {
		return
	}
	now := h.now()
	ua := clientcfg.SanitizeUserAgent(r.UserAgent())
	k := fetchKey{device: dev.ID, kind: kind}
	if !h.fetches.claim(k, ua, now) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), fetchRecordTimeout)
	defer cancel()
	err := h.opts.Fetches.RecordProfileFetch(ctx, domain.ProfileFetch{DeviceID: dev.ID, Kind: kind, At: now, UserAgent: ua})
	if err != nil {
		h.fetches.release(k)
		h.log.Warn("portal: could not record a profile download", "device", dev.Name, "kind", kind, "err", err)
	}
}

func (h *Handler) now() time.Time {
	if h.opts.Now != nil {
		return h.opts.Now()
	}
	return time.Now()
}
