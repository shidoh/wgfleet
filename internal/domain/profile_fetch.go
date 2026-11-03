package domain

import "time"

// ProfileFetchKind is what a device downloaded from the portal.
type ProfileFetchKind string

const (
	// FetchProfile is the whole mihomo profile — what the app imports and
	// refreshes on its own schedule.
	FetchProfile ProfileFetchKind = "profile"
	// FetchProvider is a proxy provider the profile points at — what the core
	// refreshes on the provider's interval, whether or not the app refreshes the
	// profile.
	FetchProvider ProfileFetchKind = "provider"
)

// ProfileFetch is the most recent download of one kind by one device. It is how
// the operator knows a device picked up a changed profile before switching
// something a stale profile cannot follow. At is stamped by the caller, never by
// the store: a replica applying the same write must record the same time.
type ProfileFetch struct {
	DeviceID  string
	Kind      ProfileFetchKind
	At        time.Time
	UserAgent string
}
