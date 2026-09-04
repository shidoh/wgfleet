package domain

import (
	"errors"
	"fmt"
	"testing"
)

func TestAllocateClientAddressTakesTheFirstFree(t *testing.T) {
	got, err := AllocateClientAddress("10.8.0.0/24", []string{"10.8.0.1"}, nil)
	if err != nil {
		t.Fatalf("AllocateClientAddress() error = %v", err)
	}
	if want := "10.8.0.2/32"; got != want {
		t.Fatalf("AllocateClientAddress() = %q, want %q", got, want)
	}
}

func TestAllocateClientAddressSkipsTaken(t *testing.T) {
	taken := []string{"10.8.0.2/32", "10.8.0.3/32"}
	got, err := AllocateClientAddress("10.8.0.0/24", []string{"10.8.0.1"}, taken)
	if err != nil {
		t.Fatalf("AllocateClientAddress() error = %v", err)
	}
	if want := "10.8.0.4/32"; got != want {
		t.Fatalf("AllocateClientAddress() = %q, want %q", got, want)
	}
}

// A revoked credential leaves a hole; the next issue fills it rather than
// growing the pool forever.
func TestAllocateClientAddressReusesHoles(t *testing.T) {
	taken := []string{"10.8.0.2/32", "10.8.0.4/32"}
	got, err := AllocateClientAddress("10.8.0.0/24", []string{"10.8.0.1"}, taken)
	if err != nil {
		t.Fatalf("AllocateClientAddress() error = %v", err)
	}
	if want := "10.8.0.3/32"; got != want {
		t.Fatalf("AllocateClientAddress() = %q, want %q", got, want)
	}
}

// The network and broadcast addresses of the pool are never handed out.
func TestAllocateClientAddressSkipsNetworkAndBroadcast(t *testing.T) {
	// 10.8.0.0/29 spans .0-.7: .0 network, .7 broadcast, .1 reserved for the
	// server, so the usable range is .2-.6.
	got, err := AllocateClientAddress("10.8.0.0/29", []string{"10.8.0.1"}, nil)
	if err != nil {
		t.Fatalf("AllocateClientAddress() error = %v", err)
	}
	if want := "10.8.0.2/32"; got != want {
		t.Fatalf("AllocateClientAddress() = %q, want %q", got, want)
	}

	taken := []string{"10.8.0.2/32", "10.8.0.3/32", "10.8.0.4/32", "10.8.0.5/32"}
	got, err = AllocateClientAddress("10.8.0.0/29", []string{"10.8.0.1"}, taken)
	if err != nil {
		t.Fatalf("AllocateClientAddress() error = %v", err)
	}
	if want := "10.8.0.6/32"; got != want {
		t.Fatalf("AllocateClientAddress() = %q, want %q (broadcast .7 must not be used)", got, want)
	}
}

func TestAllocateClientAddressExhausted(t *testing.T) {
	taken := []string{"10.8.0.2/32", "10.8.0.3/32", "10.8.0.4/32", "10.8.0.5/32", "10.8.0.6/32"}
	_, err := AllocateClientAddress("10.8.0.0/29", []string{"10.8.0.1"}, taken)
	if !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("AllocateClientAddress() error = %v, want ErrPoolExhausted", err)
	}
}

// Determinism is a hard requirement, not a nicety: under multi-master (ADR-0027)
// the same allocation must produce the same answer on every replica, so the
// function may depend on nothing but its arguments.
func TestAllocateClientAddressIsDeterministic(t *testing.T) {
	taken := []string{"10.8.0.5/32", "10.8.0.2/32"} // deliberately unsorted
	first, err := AllocateClientAddress("10.8.0.0/24", []string{"10.8.0.1"}, taken)
	if err != nil {
		t.Fatalf("AllocateClientAddress() error = %v", err)
	}
	for i := range 5 {
		again, err := AllocateClientAddress("10.8.0.0/24", []string{"10.8.0.1"}, taken)
		if err != nil {
			t.Fatalf("AllocateClientAddress() error = %v", err)
		}
		if again != first {
			t.Fatalf("AllocateClientAddress() = %q on call %d, want %q every time", again, i, first)
		}
	}
}

// Reserved and taken entries arrive from two different sources (the spec and the
// store), so both forms — bare address and address with mask — must be accepted.
func TestAllocateClientAddressAcceptsBothAddressForms(t *testing.T) {
	got, err := AllocateClientAddress("10.8.0.0/24", []string{"10.8.0.1/32"}, []string{"10.8.0.2"})
	if err != nil {
		t.Fatalf("AllocateClientAddress() error = %v", err)
	}
	if want := "10.8.0.3/32"; got != want {
		t.Fatalf("AllocateClientAddress() = %q, want %q", got, want)
	}
}

func TestAllocateClientAddressRejectsMalformedPool(t *testing.T) {
	if _, err := AllocateClientAddress("10.8.0.0/33", nil, nil); err == nil {
		t.Fatal("AllocateClientAddress() with a malformed pool = nil error, want an error")
	}
}

// The synthetic client takes the top of the pool and must never be handed to a
// real one. Collision here would give two peers the same address on the client
// interface — the failure the store's UNIQUE constraint exists to prevent, arrived
// at from the one direction the store cannot see.
func TestSyntheticClientAddressIsReservedAndAtTheTop(t *testing.T) {
	const pool = "10.73.0.0/24"
	synth, err := SyntheticClientAddress(pool)
	if err != nil {
		t.Fatalf("SyntheticClientAddress: %v", err)
	}
	if synth != "10.73.0.254/32" {
		t.Errorf("synthetic address = %q, want the last usable address 10.73.0.254/32", synth)
	}

	// Reserved: the allocator must skip it even when everything below is taken.
	var taken []string
	for i := 2; i < 254; i++ {
		taken = append(taken, fmt.Sprintf("10.73.0.%d/32", i))
	}
	_, err = AllocateClientAddress(pool, []string{"10.73.0.1/32", synth}, taken)
	if !errors.Is(err, ErrPoolExhausted) {
		t.Errorf("the allocator handed out the synthetic address instead of reporting the pool full: %v", err)
	}
}

// A pool with no room must say so rather than return the gateway's own address.
func TestSyntheticClientAddressRefusesATinyPool(t *testing.T) {
	if _, err := SyntheticClientAddress("10.73.0.0/30"); !errors.Is(err, ErrPoolExhausted) {
		t.Errorf("a /30 pool yielded a synthetic address: %v", err)
	}
}
