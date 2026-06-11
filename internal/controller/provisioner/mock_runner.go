package provisioner

import (
	"context"
	"os"
	"sync"
)

// MockRunner is an in-memory Runner for tests. It returns canned responses for
// commands (by exact match or prefix) and records every command run and file
// uploaded, so tests can assert on what a provisioning pass did.
type MockRunner struct {
	mu sync.Mutex

	// Responses maps an exact command to its stdout. PrefixResponses matches by
	// command prefix when no exact match exists.
	Responses       map[string]string
	PrefixResponses map[string]string
	// Errors maps an exact command to an error to return.
	Errors map[string]error
	// DefaultResponse is returned for unmatched commands (default "").
	DefaultResponse string

	Ran      []string          // commands run, in order
	Uploaded map[string][]byte // remote path -> content
	closed   bool
}

// NewMockRunner returns a ready-to-use mock.
func NewMockRunner() *MockRunner {
	return &MockRunner{
		Responses:       map[string]string{},
		PrefixResponses: map[string]string{},
		Errors:          map[string]error{},
		Uploaded:        map[string][]byte{},
	}
}

// Run records the command and returns the configured response/error.
func (m *MockRunner) Run(_ context.Context, cmd string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Ran = append(m.Ran, cmd)
	if err, ok := m.Errors[cmd]; ok {
		return m.Responses[cmd], err
	}
	if out, ok := m.Responses[cmd]; ok {
		return out, nil
	}
	for prefix, out := range m.PrefixResponses {
		if len(cmd) >= len(prefix) && cmd[:len(prefix)] == prefix {
			return out, nil
		}
	}
	return m.DefaultResponse, nil
}

// Upload records the uploaded content.
func (m *MockRunner) Upload(_ context.Context, remotePath string, content []byte, _ os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Uploaded[remotePath] = append([]byte(nil), content...)
	return nil
}

// Close marks the runner closed.
func (m *MockRunner) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// RanCommand reports whether a command containing substr was run.
func (m *MockRunner) RanCommand(substr string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.Ran {
		if containsStr(c, substr) {
			return true
		}
	}
	return false
}

func containsStr(s, sub string) bool {
	if sub == "" {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

var _ Runner = (*MockRunner)(nil)
