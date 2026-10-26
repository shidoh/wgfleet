package config

import (
	"fmt"
	"sort"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// validateSSH checks one node's ssh block: absent, or complete. Without a block
// the controller never dials the node (the master beside it lives that way). With
// one, it dials it to provision, upgrade and roll back, and every one of those
// needs host, user and key_path — a missing one fails them all, at the moment
// they are needed, with "has no ssh target". Port defaults to 22.
func validateSSH(where string, s SSHConfig) []error {
	if s == (SSHConfig{}) {
		return nil
	}
	var errs []error
	for _, f := range []struct{ key, val string }{
		{"host", s.Host}, {"user", s.User}, {"key_path", s.KeyPath},
	} {
		if f.val == "" {
			errs = append(errs, fmt.Errorf("%s: ssh.%s is required when ssh is set — the controller dials this node with it "+
				"to provision, upgrade and roll back (or remove the ssh block if the controller never does that); "+
				"a misspelled key is ignored, see the unknown keys --check-config lists", where, f.key))
		}
	}
	if s.Port < 0 || s.Port > 65535 {
		errs = append(errs, fmt.Errorf("%s: ssh.port %d is out of range", where, s.Port))
	}
	return errs
}

func validateNodeSSH(c ControllerConfig) []error {
	var errs []error
	for i, m := range c.Fleet.Masters {
		errs = append(errs, validateSSH(fmt.Sprintf("fleet.masters[%d] (%s)", i, m.Name), m.SSH)...)
	}
	for i, e := range c.Fleet.Exits {
		errs = append(errs, validateSSH(fmt.Sprintf("fleet.exits[%d] (%s)", i, e.Name), e.SSH)...)
	}
	return errs
}

// UnknownKeys lists the keys of the YAML file at path that no field of out reads,
// as dotted paths ("fleet.masters[0].ssh.key"). The decoder drops them silently,
// so a misspelled or mis-indented key reads as an absent one and the manifest
// still validates. Only the file is read: WGFLEET_ environment overrides are
// switches, not manifest keys, and the loader's mapping would turn every one of
// them into a key nothing reads.
func UnknownKeys[T any](path string, out T) ([]string, error) {
	k := koanf.New(".")
	if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("load config %q: %w", path, err)
	}
	var md mapstructure.Metadata
	err := k.UnmarshalWithConf("", out, koanf.UnmarshalConf{
		Tag: "koanf",
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				mapstructure.StringToSliceHookFunc(","),
			),
			Result:           out,
			WeaklyTypedInput: true,
			Metadata:         &md,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("decode config %q: %w", path, err)
	}
	sort.Strings(md.Unused)
	return md.Unused, nil
}
