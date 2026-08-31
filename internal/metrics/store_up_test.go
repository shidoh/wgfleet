package metrics

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

type failingStore struct{ store.Store }

func (failingStore) ListNodes(context.Context) ([]domain.Node, error) {
	return nil, errors.New("database is locked")
}

// A store read error used to emit NOTHING, so /metrics still answered 200, `up`
// stayed 1, and every fleet-wide rule read the silence as fact — WgfleetNoReadyExit
// paging "every exit is out of rotation" for a locked database, data plane fine.
func TestStoreUpReportsZeroWhenTheStoreCannotBeRead(t *testing.T) {
	reg := prometheus.NewRegistry()
	NewStoreCollector(reg, failingStore{})

	if got := gatherValue(t, reg, "wgfleet_controller_store_up", nil); got != 0 {
		t.Errorf("store_up = %v, want 0 when the store errors", got)
	}
}
