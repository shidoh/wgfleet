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

	"github.com/shidoh/wgfleet/internal/config"
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
	// Expand a leading ~ here, at the single point every dial path funnels through
	// (provision, facts, AND the UI/auto upgrade) — os.ReadFile does not understand
	// the shell ~ convention, so an operator's "~/.ssh/id_ed25519" would otherwise
	// fail with "no such file or directory" on the upgrade path, which dials with the
	// node's raw manifest KeyPath rather than a pre-expanded one.
	keyPath := config.ExpandPath(target.KeyPath)
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ssh key %q: %w", keyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse ssh key: %w", err)
	}
	var hostKeyAlgos []string
	if hostKey == nil {
		hostKey, hostKeyAlgos, err = hostKeyCallback(target)
		if err != nil {
			return nil, err
		}
	}
	cfg := &ssh.ClientConfig{
		User: target.User,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		// HostKeyCallback pins/verifies the server key; HostKeyAlgorithms constrains
		// negotiation to the pinned key's type. Without the latter, crypto/ssh
		// advertises every host-key algorithm and the server may present a different
		// key type (its RSA/ECDSA host key) than the pinned ed25519 one — which
		// FixedHostKey then rejects as "host key mismatch" though the pin is correct.
		// nil ⇒ crypto/ssh defaults (unpinned/TOFU and injected-callback paths).
		HostKeyCallback:   hostKey,
		HostKeyAlgorithms: hostKeyAlgos,
		Timeout:           sshConnectTimeout,
	}
	addr := net.JoinHostPort(target.Host, strconv.Itoa(sshPort(target.Port)))

	// NOT ssh.Dial. ClientConfig.Timeout bounds the TCP connect and NOTHING after
	// it, so a path that completes the handshake's three-way and then swallows every
	// packet leaves this call blocked forever — and every caller with it.
	//
	// That is not a thought experiment: it is what the fleet's public master→exit
	// path does when it wedges (2026-09-09, and again 2026-09-11 with the fix for
	// the first one in place). The socket sits ESTABLISHED with a dozen bytes in
	// Send-Q and no movement; the rolling upgrade sat 13 minutes on its first node
	// under a five-minute per-node deadline, because a deadline can only be noticed
	// by a call that comes back. Bounding the handshake here fixes it for every dial
	// path at once — provision, facts, support bundle, upgrade — rather than asking
	// each caller to wrap this one in a goroutine.
	conn, err := net.DialTimeout("tcp", addr, sshConnectTimeout)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(sshHandshakeTimeout)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh dial %s: set handshake deadline: %w", addr, err)
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	// Cleared once the handshake is through: the deadline is absolute, and leaving
	// it set would kill the session mid-command a few seconds later — an upgrade
	// uploads 30MB over this connection.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = sc.Close()
		return nil, fmt.Errorf("ssh dial %s: clear handshake deadline: %w", addr, err)
	}
	return &SSHRunner{client: ssh.NewClient(sc, chans, reqs)}, nil
}

// sshConnectTimeout bounds the TCP connect; sshHandshakeTimeout bounds everything
// between the connect and a usable session (version exchange, key exchange, auth).
// Generous enough for a slow satellite link, short enough that a black-holed path
// is a failure an operator can act on rather than a hang nobody can interrupt.
//
// A var, not a const, so the test can drive a wedged server without waiting out
// the real bound.
var (
	sshConnectTimeout   = 15 * time.Second
	sshHandshakeTimeout = 20 * time.Second
)

// hostKeyCallback builds the SSH host-key verification callback for a target,
// plus the host-key algorithms to advertise. A pinned target.HostKey (an
// authorized_keys-style public-key line) is enforced with FixedHostKey AND
// constrains negotiation to that key's algorithm; an empty one — or an explicit
// opt-out (target.InsecureIgnoreHostKey / WGFLEET_SSH_INSECURE_HOST_KEY) —
// degrades to trust-on-first-use, logged at WARN so the insecure path is never
// silent. The returned algorithm list is nil for the insecure/TOFU paths
// (crypto/ssh defaults apply).
func hostKeyCallback(target domain.SSHTarget) (ssh.HostKeyCallback, []string, error) {
	if target.InsecureIgnoreHostKey || sshInsecureHostKeyEnv() {
		slog.Warn("ssh host-key verification DISABLED for bootstrap "+
			"(ssh.insecure_ignore_host_key or WGFLEET_SSH_INSECURE_HOST_KEY). The node's mTLS key is "+
			"shipped over an unverified channel — a MITM could capture it. Pin ssh.host_key instead.",
			"host", target.Host)
		return ssh.InsecureIgnoreHostKey(), nil, nil //nolint:gosec // explicit, logged opt-out
	}
	if hk := strings.TrimSpace(target.HostKey); hk != "" {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hk))
		if err != nil {
			return nil, nil, fmt.Errorf("parse pinned ssh host key for %q: %w", target.Host, err)
		}
		return ssh.FixedHostKey(pub), hostKeyAlgorithmsFor(pub.Type()), nil
	}
	slog.Warn("ssh bootstrap host key is not pinned; accepting any host key (trust-on-first-use). "+
		"A MITM on this dial could capture the node's mTLS identity — set ssh.host_key in the fleet manifest to pin it.",
		"host", target.Host)
	return ssh.InsecureIgnoreHostKey(), nil, nil //nolint:gosec // explicit, logged TOFU fallback; see doc comment
}

// hostKeyAlgorithmsFor maps a pinned host key's type to the host-key algorithms
// the client should advertise. For most types this is just the type itself; an
// RSA key is expanded to the SHA-2 signature variants because modern servers
// disable the SHA-1 "ssh-rsa" algorithm, which would otherwise fail negotiation.
func hostKeyAlgorithmsFor(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}

// sshInsecureHostKeyEnv reports the fleet-wide host-key-verification opt-out.
func sshInsecureHostKeyEnv() bool {
	switch os.Getenv("WGFLEET_SSH_INSECURE_HOST_KEY") {
	case "1", "true", "TRUE", "yes":
		return true
	default:
		return false
	}
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
