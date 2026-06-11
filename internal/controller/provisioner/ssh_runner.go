package provisioner

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/shidoh/wgfleet/internal/domain"
)

// syncBuffer is a mutex-guarded bytes.Buffer. crypto/ssh copies a session's
// stdout and stderr in SEPARATE goroutines; pointing both at a plain bytes.Buffer
// races and silently drops/corrupts output (intermittent empty `uname -s`,
// lost "yes", etc.). This mirrors what ssh's own CombinedOutput does internally.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *syncBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *syncBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// SSHRunner is the production Runner backed by golang.org/x/crypto/ssh. It is
// used only during bootstrap, with a one-off key-based login; afterwards the
// node is managed over mTLS.
type SSHRunner struct {
	client *ssh.Client
}

var _ Runner = (*SSHRunner)(nil)

// DialSSH connects to the SSH target using the private key at target.KeyPath.
//
// hostKey, when non-nil, pins the server's host key explicitly (used by tests).
// When nil, the callback is derived from target.HostKey: a pinned key is enforced
// (FixedHostKey), and only an EMPTY target.HostKey falls back to trust-on-first-use
// — and that fallback is logged loudly, because bootstrap ships the node's mTLS
// private key over this channel (a MITM on an unpinned dial can steal the node's
// identity). Pin ssh.host_key in the fleet manifest in production.
func DialSSH(target domain.SSHTarget, hostKey ssh.HostKeyCallback) (*SSHRunner, error) {
	keyPEM, err := os.ReadFile(target.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("read ssh key %q: %w", target.KeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse ssh key: %w", err)
	}
	if hostKey == nil {
		hostKey, err = hostKeyCallback(target)
		if err != nil {
			return nil, err
		}
	}
	cfg := &ssh.ClientConfig{
		User:            target.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKey,
		Timeout:         15 * time.Second,
	}
	addr := net.JoinHostPort(target.Host, strconv.Itoa(sshPort(target.Port)))
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	return &SSHRunner{client: client}, nil
}

// hostKeyCallback builds the SSH host-key verification callback for a target.
// A pinned target.HostKey (an authorized_keys-style public-key line) is enforced
// with FixedHostKey; an empty one degrades to trust-on-first-use, logged at WARN
// so the insecure path is never silent.
func hostKeyCallback(target domain.SSHTarget) (ssh.HostKeyCallback, error) {
	if hk := strings.TrimSpace(target.HostKey); hk != "" {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hk))
		if err != nil {
			return nil, fmt.Errorf("parse pinned ssh host key for %q: %w", target.Host, err)
		}
		return ssh.FixedHostKey(pub), nil
	}
	slog.Warn("ssh bootstrap host key is not pinned; accepting any host key (trust-on-first-use). "+
		"A MITM on this dial could capture the node's mTLS identity — set ssh.host_key in the fleet manifest to pin it.",
		"host", target.Host)
	return ssh.InsecureIgnoreHostKey(), nil //nolint:gosec // explicit, logged TOFU fallback; see doc comment
}

// Run executes cmd and returns combined output.
func (s *SSHRunner) Run(ctx context.Context, cmd string) (string, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new ssh session: %w", err)
	}
	defer session.Close()

	buf := &syncBuffer{}
	session.Stdout = buf
	session.Stderr = buf

	done := make(chan error, 1)
	go func() { done <- session.Run(cmd) }()
	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return buf.String(), ctx.Err()
	case err := <-done:
		if err != nil {
			return buf.String(), fmt.Errorf("remote command failed: %w", err)
		}
		return buf.String(), nil
	}
}

// Upload writes content to remotePath (0…mode) over an SSH session, creating the
// parent directory first. It streams to a temp file in the same directory, then
// renames it over the target. Using `mv` (rename) is both atomic and the only way
// to replace a file that is a RUNNING executable: writing the target directly
// truncates it and fails with ETXTBSY ("text file busy") — exactly what
// re-provisioning a live agent binary hit. Avoids requiring SFTP.
func (s *SSHRunner) Upload(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	dir := path.Dir(remotePath)
	if _, err := s.Run(ctx, fmt.Sprintf("mkdir -p %s", shellQuote(dir))); err != nil {
		return fmt.Errorf("mkdir %q: %w", dir, err)
	}

	session, err := s.client.NewSession()
	if err != nil {
		return fmt.Errorf("new ssh session: %w", err)
	}
	defer session.Close()

	tmp := remotePath + ".wgfleet-upload.tmp"
	session.Stdin = bytes.NewReader(content)
	cmd := fmt.Sprintf("cat > %s && chmod %o %s && mv -f %s %s",
		shellQuote(tmp), mode.Perm(), shellQuote(tmp), shellQuote(tmp), shellQuote(remotePath))
	if err := session.Run(cmd); err != nil {
		_, _ = s.Run(ctx, fmt.Sprintf("rm -f %s", shellQuote(tmp))) // best-effort cleanup
		return fmt.Errorf("upload %q: %w", remotePath, err)
	}
	return nil
}

// Close closes the SSH connection.
func (s *SSHRunner) Close() error { return s.client.Close() }

func sshPort(p int) int {
	if p == 0 {
		return 22
	}
	return p
}

// shellQuote wraps s in single quotes, escaping embedded single quotes, so paths
// are safe to interpolate into a remote shell command.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
