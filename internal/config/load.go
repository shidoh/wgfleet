package config

import (
	"fmt"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// envPrefix is the prefix for environment overrides. Example:
//
//	WGFLEET_CONTROLLER_LISTEN=0.0.0.0:9443
//
// maps to controller.listen and overrides the file value.
const envPrefix = "WGFLEET_"

// Validatable is implemented by every config type so loading and validation
// share one code path.
type Validatable interface {
	Validate() error
}

// Load reads a YAML config file into out, applies WGFLEET_-prefixed environment
// overrides, then validates. It is generic so controller and agent configs load
// identically. Flags are layered by callers on top of the returned struct.
func Load[T Validatable](path string, out T) (T, error) {
	k := koanf.New(".")

	if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
		return out, fmt.Errorf("load config %q: %w", path, err)
	}

	// Environment overrides: WGFLEET_CONTROLLER_LISTEN -> controller.listen.
	err := k.Load(env.Provider(".", env.Opt{
		Prefix: envPrefix,
		TransformFunc: func(key, value string) (string, any) {
			key = strings.ReplaceAll(
				strings.ToLower(strings.TrimPrefix(key, envPrefix)),
				"_", ".")
			return key, value
		},
	}), nil)
	if err != nil {
		return out, fmt.Errorf("load env overrides: %w", err)
	}

	if err := unmarshal(k, out); err != nil {
		return out, fmt.Errorf("decode config %q: %w", path, err)
	}
	if err := out.Validate(); err != nil {
		return out, fmt.Errorf("invalid config %q: %w", path, err)
	}
	return out, nil
}

// unmarshal decodes the koanf tree into out with a duration-aware hook so
// values like "60s" map onto time.Duration fields.
func unmarshal[T any](k *koanf.Koanf, out T) error {
	return k.UnmarshalWithConf("", out, koanf.UnmarshalConf{
		Tag: "koanf",
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				mapstructure.StringToSliceHookFunc(","),
			),
			Result:           out,
			WeaklyTypedInput: true,
		},
	})
}
