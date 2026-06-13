package compose

import (
	"os/exec"
	"strings"
)

// StackUp reports whether every service defined in the docker-compose file is
// currently running. It is used to gate `docker compose up -d` so the reconcile
// loop issues it only on a definition change or when the stack is (partially)
// down — a crash, reboot, or a prior up that failed — never on a timer. Returns
// false on any error (missing/unreadable file, docker absent), treated as "not
// up" so the reconcile re-issues the bring-up.
func StackUp(file string) bool {
	defined := stackLineCount(file, "config", "--services")
	if defined == 0 {
		return false // no services parsed (missing/unreadable file) ⇒ not up
	}
	running := stackLineCount(file, "ps", "--status", "running", "--quiet")
	return running >= defined
}

// stackLineCount runs `docker compose -f <file> <args...>` and counts the
// non-empty output lines. Returns 0 on any error.
func stackLineCount(file string, args ...string) int {
	full := append([]string{"compose", "-f", file}, args...)
	out, err := exec.Command("docker", full...).Output()
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}
