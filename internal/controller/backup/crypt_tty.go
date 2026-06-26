package backup

import (
	"io"
	"os"
)

// stderrPassthrough connects age's prompts to the real terminal so passphrase
// entry works during CLI runs. Isolated here so the rest of the package stays
// free of os.Stderr coupling.
func stderrPassthrough() io.Writer { return os.Stderr }
