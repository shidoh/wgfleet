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

// AgeDecryptor returns a DecryptFunc backed by `age -d`. age resolves the
// identity or passphrase itself (interactively or via AGE env vars).
func AgeDecryptor() DecryptFunc {
	return func(ctx context.Context, ciphertext []byte) ([]byte, error) {
		return runAge(ctx, []string{"-d"}, ciphertext, true)
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
