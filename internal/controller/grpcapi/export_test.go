package grpcapi

import (
	"context"

	"github.com/shidoh/wgfleet/internal/domain"
)

// FailRendersForTest makes every spec render fail with err, leaving the rest of
// the renderer as it was, so a test can choose HOW a render fails.
func (s *Service) FailRendersForTest(err error) {
	s.renderer = failingRenders{SpecRenderer: s.renderer, err: err}
}

type failingRenders struct {
	SpecRenderer
	err error
}

func (f failingRenders) RenderNodeSpec(context.Context, string) (domain.NodeSpec, error) {
	return domain.NodeSpec{}, f.err
}
