package config

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// referenceDoc is the operator-facing configuration reference. Every configurable
// key must appear in it.
const referenceDoc = "../../docs/configuration.md"

// TestConfigurationReferenceIsComplete fails when a koanf key exists in the config
// structs but is not documented in docs/configuration.md.
//
// The config used to be poorly documented: the annotated example covered roughly half the surface, with no way to
// tell what was missing. Documentation that is merely *intended* to be complete
// drifts on the next feature; this makes completeness a build failure instead.
//
// Adding a config key? Document it. The failure message names the missing paths.
func TestConfigurationReferenceIsComplete(t *testing.T) {
	doc, err := os.ReadFile(referenceDoc)
	if err != nil {
		t.Fatalf("read reference doc: %v", err)
	}
	text := string(doc)

	var missing []string
	for _, key := range AllConfigKeys() {
		// Keys are written in the doc as `full.dotted.path` in backticks, so an exact
		// substring match is unambiguous even where leaf names repeat (image, mode,
		// enabled appear under half a dozen sections).
		if !strings.Contains(text, "`"+key+"`") {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d config key(s) missing from %s:\n  %s",
			len(missing), referenceDoc, strings.Join(missing, "\n  "))
	}
}

// TestConfigurationReferenceHasNoStaleKeys catches the opposite drift: a key that
// was renamed or removed in code but left behind in the reference, which is worse
// than an undocumented key — the operator writes it and it silently does nothing.
func TestConfigurationReferenceHasNoStaleKeys(t *testing.T) {
	doc, err := os.ReadFile(referenceDoc)
	if err != nil {
		t.Fatalf("read reference doc: %v", err)
	}
	real := make(map[string]struct{})
	for _, k := range AllConfigKeys() {
		real[k] = struct{}{}
	}
	// Only audit fully-qualified paths (they start with a documented root and carry a
	// dot), so prose backticks like `warp` or `awg-quick` are not mistaken for keys.
	// Filenames are excluded explicitly: `controller.yaml` and `agent.yaml` are named
	// constantly in the prose and would otherwise look like bogus keys.
	var stale []string
	for _, tok := range backtickTokens(string(doc)) {
		if !strings.HasPrefix(tok, "controller.") && !strings.HasPrefix(tok, "fleet.") && !strings.HasPrefix(tok, "agent.") {
			continue
		}
		if isFilename(tok) || isSectionRef(tok) {
			continue
		}
		if _, ok := real[tok]; !ok {
			stale = append(stale, tok)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("%s documents %d key(s) that no longer exist in the config structs:\n  %s",
			referenceDoc, len(stale), strings.Join(stale, "\n  "))
	}
}

// isSectionRef reports whether a token refers to a group of keys rather than one
// key: a list section ("fleet.exits[]") or a wildcard ("...dns.*"). Both are
// legitimate prose in the reference and have no single struct field behind them.
func isSectionRef(tok string) bool {
	return strings.HasSuffix(tok, "[]") || strings.HasSuffix(tok, ".*")
}

// isFilename reports whether a backtick token is a file name rather than a config
// path — `controller.yaml`, `agent.yaml` and friends share the key prefixes.
func isFilename(tok string) bool {
	for _, ext := range []string{".yaml", ".yml", ".md", ".json", ".db", ".service", ".sh"} {
		if strings.HasSuffix(tok, ext) {
			return true
		}
	}
	return false
}

// backtickTokens returns the distinct `code spans` in a markdown document.
func backtickTokens(text string) []string {
	seen := make(map[string]struct{})
	var out []string
	parts := strings.Split(text, "`")
	// Odd indices are the spans between backtick pairs.
	for i := 1; i < len(parts); i += 2 {
		tok := strings.TrimSpace(parts[i])
		if tok == "" {
			continue
		}
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}
		out = append(out, tok)
	}
	return out
}

// AllConfigKeys returns every configurable key across controller.yaml and
// agent.yaml as a fully-qualified dotted path, with `[]` marking a list of
// objects (e.g. "fleet.exits[].transports.reality.mode"). Sorted, deduplicated.
func AllConfigKeys() []string {
	var keys []string
	keys = append(keys, koanfKeys(reflect.TypeOf(ControllerConfig{}), "")...)
	keys = append(keys, koanfKeys(reflect.TypeOf(AgentConfig{}), "")...)
	sort.Strings(keys)
	return keys
}

// koanfKeys walks a config struct and returns the koanf paths of its leaves.
// A struct field recurses; anything else (scalar, duration, string list, free-form
// map) is a leaf. A slice-of-struct field contributes "[]" to the path.
func koanfKeys(t reflect.Type, prefix string) []string {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	var out []string
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("koanf")
		if tag == "" {
			continue
		}
		path := tag
		if prefix != "" {
			path = prefix + "." + tag
		}

		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Slice {
			// A list of objects is addressed per element; a list of scalars is a leaf.
			elem := ft.Elem()
			if elem.Kind() == reflect.Struct {
				out = append(out, koanfKeys(elem, path+"[]")...)
				continue
			}
			out = append(out, path)
			continue
		}
		// time.Duration is a named int64, and `overrides` is map[string]any — both are
		// leaves the operator sets directly, not structs to descend into.
		if ft.Kind() == reflect.Struct {
			nested := koanfKeys(ft, path)
			out = append(out, nested...)
			continue
		}
		out = append(out, path)
	}
	return out
}
