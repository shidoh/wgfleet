package clientcfg

import (
	"strings"
	"testing"
)

// Clash Verge Rev reads the header through Rust's Debug formatting, which escapes
// the quotes of filename="…", and names the profile `\"name.yaml\`. It looks for
// the RFC 6266 extended form first and reads that one correctly, so the header
// carries both — which is what the RFC recommends of any server anyway.
func TestAttachmentHeaderCarriesTheExtendedFilename(t *testing.T) {
	cases := map[string]string{
		"alice-mbp1-wgf0.yaml": `attachment; filename="alice-mbp1-wgf0.yaml"; filename*=UTF-8''alice-mbp1-wgf0.yaml`,
		"телефон.yaml":         `filename*=UTF-8''%D1%82%D0%B5%D0%BB%D0%B5%D1%84%D0%BE%D0%BD.yaml`,
		"a b%c.yaml":           `filename*=UTF-8''a%20b%25c.yaml`,
	}
	for name, want := range cases {
		if got := AttachmentHeader(name); !strings.Contains(got, want) {
			t.Errorf("AttachmentHeader(%q) = %s, want it to contain %s", name, got, want)
		}
	}
}

// The extended value is built from the already-sanitised name: a "/" or a quote
// must not come back through the percent-encoding.
func TestAttachmentHeaderExtendedFormStaysSanitised(t *testing.T) {
	got := AttachmentHeader("a/b\"c\r\n.yaml")
	i := strings.Index(got, "filename*=")
	if i < 0 {
		t.Fatalf("no extended form in %s", got)
	}
	ext := got[i:]
	if want := `filename*=UTF-8''a_b_c.yaml`; ext != want {
		t.Errorf("extended form = %s, want %s", ext, want)
	}
}
