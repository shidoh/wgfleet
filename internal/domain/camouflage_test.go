package domain

import "testing"

func TestCamouflageSpecValidate(t *testing.T) {
	good := CamouflageSpec{Domain: "e1.example.net", PublicIP: "198.51.100.20", ACMEEmail: "ops@example.net",
		ACMECA: "https://ca.example.net/directory"}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	bad := map[string]func(*CamouflageSpec){
		"quote in domain":   func(c *CamouflageSpec) { c.Domain = `e1.example.net"` },
		"cr in domain":      func(c *CamouflageSpec) { c.Domain = "e1.example.net\r" },
		"comma in domain":   func(c *CamouflageSpec) { c.Domain = "e1.example.net,x.example.net" },
		"single label":      func(c *CamouflageSpec) { c.Domain = "localhost" },
		"brace in email":    func(c *CamouflageSpec) { c.ACMEEmail = "ops@example.net}" },
		"no at in email":    func(c *CamouflageSpec) { c.ACMEEmail = "ops" },
		"backslash in ca":   func(c *CamouflageSpec) { c.ACMECA = `https://ca.example.net\x` },
		"plain http ca":     func(c *CamouflageSpec) { c.ACMECA = "http://ca.example.net" },
		"bad ip":            func(c *CamouflageSpec) { c.PublicIP = "x" },
		"privileged port":   func(c *CamouflageSpec) { c.LocalPort = 443 },
		"comment in domain": func(c *CamouflageSpec) { c.Domain = "e1.example.net#x" },
	}
	for name, mutate := range bad {
		c := good
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted %+v", name, c)
		}
	}
}
