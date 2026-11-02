// Package provisioner turns a blank SSH-reachable VM into a Ready fleet node.
// It is the controller's bootstrap pipeline: collect facts over
// SSH, render an ordered bootstrap plan, and — only in apply mode — execute it.
// Like the agent reconcile engine, plan mode renders every step and changes
// nothing, so an operator can review exactly what an autoprovision would do.
//
// SSH is used ONLY during bootstrap; once the agent is installed the controller
// talks to the node over mTLS and SSH management is no longer needed.
package provisioner

import (
	"context"
	"os"
)

// Runner executes commands and uploads files on a remote host. It abstracts the
// SSH transport so the provisioner can be driven by a real SSH client in
// production and a mock in tests (provisioning is tested on SSH mocks/containers,
// never live nodes).
type Runner interface {
	// Run executes cmd and returns its combined stdout/stderr. A non-zero exit
	// status is returned as an error with the captured output.
	Run(ctx context.Context, cmd string) (string, error)
	// Upload writes content to remotePath with the given mode, creating parent
	// directories as needed.
	Upload(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error
	// Close releases the underlying connection.
	Close() error
}
