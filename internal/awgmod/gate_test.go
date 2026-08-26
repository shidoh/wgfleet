package awgmod

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckAWG3Supported(t *testing.T) {
	tests := []struct {
		name    string
		gen     int
		genErr  error
		wantErr string
	}{
		{name: "3.x module applies", gen: 3},
		{name: "4.x module applies", gen: 4},
		{name: "1.x module refused", gen: 1, wantErr: "1.x kernel module"},
		{name: "unknown generation refused", genErr: ErrGenerationUnknown, wantErr: "could not be determined"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAWG3Supported(func() (int, error) { return tc.gen, tc.genErr })
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckAWG3Supported() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("CheckAWG3Supported() = nil, want an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("CheckAWG3Supported() = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// The probe on this machine is allowed to fail — no AmneziaWG module here — but
// it must fail as ErrGenerationUnknown rather than panicking or reporting a bogus
// generation, because "unknown" is what the gate turns into a refusal.
func TestModuleGenerationOnAHostWithoutTheModule(t *testing.T) {
	gen, err := ModuleGeneration()
	if err == nil {
		if gen < 1 {
			t.Fatalf("ModuleGeneration() = %d with no error, want a real generation", gen)
		}
		return
	}
	if !errors.Is(err, ErrGenerationUnknown) {
		t.Fatalf("ModuleGeneration() error = %v, want ErrGenerationUnknown", err)
	}
}
