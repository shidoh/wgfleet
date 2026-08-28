package backup

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// EncryptFunc encrypts plaintext to the archive envelope. It is injectable so
// the export/restore orchestrators can be tested without the age binary,
// mirroring the DecryptFunc seam in internal/config/sops.go.
type EncryptFunc func(ctx context.Context, plaintext []byte) ([]byte, error)

// DecryptFunc reverses EncryptFunc.
type DecryptFunc func(ctx context.Context, ciphertext []byte) ([]byte, error)

// AgeEncryptor returns an EncryptFunc backed by the age CLI. With a non-empty
// recipient it encrypts to that age recipient (`age -r`); otherwise it uses
// passphrase mode (`age -p`), which prompts on the controlling terminal.
func AgeEncryptor(recipient string) EncryptFunc {
	return func(ctx context.Context, plaintext []byte) ([]byte, error) {
		args := []string{"-a"} // ascii-armored output for portability
		if recipient != "" {
			args = append(args, "-r", recipient)
		} else {
			args = append(args, "-p")
		}
		return runAge(ctx, args, plaintext, recipient == "")
	}
}

// AgeDecryptor returns a DecryptFunc backed by `age -d`, reading identity from
// the file at identityPath when one is given.
//
// An empty path means passphrase mode, where age prompts on the terminal. It used
// to be the ONLY mode: this ran a bare `age -d` and its comment claimed age would
// "resolve the identity itself (interactively or via AGE env vars)". age does no
// such thing — an identity comes from -i and nowhere else. So every archive made
// with --age-recipient, which is the form the Web UI's button produces and the form
// the operations runbook documents first, decrypted to
// "age: error: no identity matched any of the recipients" and could not be
// restored at all. A backup you cannot restore is not a backup, and the way that
// was discovered is the way it would have been discovered in production.
func AgeDecryptor(identityPath string) DecryptFunc {
	return func(ctx context.Context, ciphertext []byte) ([]byte, error) {
		args := []string{"-d"}
		if identityPath != "" {
			args = append(args, "-i", identityPath)
		}
		// Only passphrase mode needs the terminal; with an identity file there is
		// nothing to prompt for and stderr stays captured for the error message.
		return runAge(ctx, args, ciphertext, identityPath == "")
	}
}

// runAge pipes input through `age args...`. When interactive is true, age's
// stderr is connected to the terminal so passphrase prompts work; output is
// still captured from stdout.
func runAge(ctx context.Context, args []string, input []byte, interactive bool) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "age", args...)
	cmd.Stdin = bytes.NewReader(input)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	if interactive {
		cmd.Stderr = stderrPassthrough()
	} else {
		cmd.Stderr = &errBuf
	}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("age %v: %w: %s", args, err, errBuf.String())
	}
	return out.Bytes(), nil
}
