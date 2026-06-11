package domain

import (
	"strings"
	"testing"
)

func validAWG() AWGParams {
	return AWGParams{
		Shared: AWGShared{
			H1: AWGHeader{15384729, 145384729},
			H2: AWGHeader{412847193, 542847193},
			H3: AWGHeader{983471628, 1113471628},
			H4: AWGHeader{1524719384, 1654719384},
			S1: 102, S2: 67, S3: 143, S4: 38,
		},
		Local: AWGLocal{Jc: 5, Jmin: 60, Jmax: 900},
	}
}

// TestAWGGoldenExample is the exact client config from the wg-easy docs. It MUST
// validate — it is the authoritative reference for the parameter model.
func TestAWGGoldenExample(t *testing.T) {
	p := AWGParams{
		Shared: AWGShared{
			H1: AWGHeader{15384729, 145384729},
			H2: AWGHeader{412847193, 542847193},
			H3: AWGHeader{983471628, 1113471628},
			H4: AWGHeader{1524719384, 1654719384},
			S1: 102, S2: 67, S3: 143, S4: 38,
		},
		Local: AWGLocal{
			Jc: 5, Jmin: 60, Jmax: 900,
			I1: "<r 2><b 0xcd0000000108b3e46d92f075a81c00485de2a9f145b68c73920de4a8715bf3c86d29e0b4af573681cde90246fa8517c3b9e4d6a0283f71c5b4968ea032d149bf86e5d74b20a3cf8e917025db4c6a139bf58e4726d03af815ec9b7482f1a5c30d9b76e4f82>",
			I2: "<b 0xb6><rd 10><r 8>",
			I3: "<r 22><rd 4>",
			I4: "<b 0x05><r 16><rd 6>",
			I5: "<rc 8><b 0x33><r 6>",
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("golden wg-easy example must validate, got: %v", err)
	}
}

func TestAWGParamsValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*AWGParams)
		wantErr string
	}{
		{name: "valid", mutate: func(*AWGParams) {}},
		{
			name:    "Jc too high",
			mutate:  func(p *AWGParams) { p.Local.Jc = 200 },
			wantErr: "Jc",
		},
		{
			name:    "Jmin not less than Jmax",
			mutate:  func(p *AWGParams) { p.Local.Jmin = 900; p.Local.Jmax = 900 },
			wantErr: "Jmin",
		},
		{
			name:    "Jmax over 1280",
			mutate:  func(p *AWGParams) { p.Local.Jmax = 2000 },
			wantErr: "Jmax",
		},
		{
			name:    "S1 over limit",
			mutate:  func(p *AWGParams) { p.Shared.S1 = 2000 },
			wantErr: "S1",
		},
		{
			name:    "S1+56 == S2 forbidden",
			mutate:  func(p *AWGParams) { p.Shared.S1 = 50; p.Shared.S2 = 106 },
			wantErr: "S1+56",
		},
		{
			name:    "inverted header range",
			mutate:  func(p *AWGParams) { p.Shared.H1 = AWGHeader{200, 100} },
			wantErr: "inverted",
		},
		{
			name:    "overlapping header ranges",
			mutate:  func(p *AWGParams) { p.Shared.H2 = AWGHeader{100000000, 200000000} }, // overlaps H1
			wantErr: "overlap",
		},
		{
			name:    "non-hex non-template I value rejected",
			mutate:  func(p *AWGParams) { p.Local.I2 = "not-hex-zz" },
			wantErr: "hex blob or CPS",
		},
		{
			name:    "CPS template I value ok",
			mutate:  func(p *AWGParams) { p.Local.I1 = "<b 0xf6020201><r 50>" },
			wantErr: "",
		},
		{
			name:    "single-value header (Min==Max) ok",
			mutate:  func(p *AWGParams) { p.Shared.H1 = AWGHeader{10, 10} },
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validAWG()
			tt.mutate(&p)
			err := p.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestAWGHeaderString(t *testing.T) {
	if got := (AWGHeader{100, 200}).String(); got != "100-200" {
		t.Errorf("range string = %q, want 100-200", got)
	}
	if got := (AWGHeader{42, 42}).String(); got != "42" {
		t.Errorf("single-value string = %q, want 42", got)
	}
}
