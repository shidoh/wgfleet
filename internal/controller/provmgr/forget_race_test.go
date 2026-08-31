package provmgr

import (
	"log/slog"
	"sync"
	"testing"
	"time"
)

// ManifestNodes() holds fleetMu for reading and calls findNode() inside the loop,
// which takes the same RLock again. sync.RWMutex forbids recursive read locking for
// exactly this reason: Go's RWMutex is writer-preferring, so once ForgetExit()'s
// Lock() is queued it blocks NEW readers — including the second RLock on the
// goroutine that already holds the first one. That goroutine cannot release the
// outer lock until the inner one is granted, and the inner one waits for the
// writer, which waits for the outer. Nothing moves again.
//
// It wedges the whole dashboard, not one request: every page render calls
// ManifestNodes(), and they all queue behind the stuck writer. The trigger is one
// click of Delete racing any page load.
//
// This is a STRESS guard, not a deterministic proof: the window between the two
// RLocks is a few instructions, so a re-introduced recursion escapes it more often
// than it is caught. It is here to fail loudly some of the time rather than never;
// the invariant it guards is stated on findNodeLocked.
func TestManifestNodesDoesNotDeadlockAgainstForgetExit(t *testing.T) {
	m := New(nil, nil, testFleet(), Options{}, slog.New(slog.DiscardHandler))

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { // readers: the dashboard
			defer wg.Done()
			for i := 0; i < 20000; i++ {
				_ = m.ManifestNodes()
			}
		}()
		go func() { // writer: the operator deleting a node
			defer wg.Done()
			for i := 0; i < 20000; i++ {
				m.ForgetExit("exit-de-1")
			}
		}()
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock: ManifestNodes() recursively read-locks fleetMu, so a queued ForgetExit() writer wedges both")
	}
}
