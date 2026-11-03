package clientcfg

import "strings"

// maxUserAgent bounds what the portal stores and shows of a caller-written header.
const maxUserAgent = 200

// ClientAgent is what a portal download says about the software that made it.
// App is the program that fetched a profile (clash-verge, ClashMetaForAndroid…);
// Core is the mihomo version, which is what decides whether a device can follow a
// change in the profile. Either may be empty: the header is the caller's to write.
type ClientAgent struct {
	App, AppVersion string
	CoreVersion     string
}

// coreProducts are the product names a mihomo core sends for its own requests
// (a proxy provider refresh sends "clash.meta/v1.19.33").
var coreProducts = map[string]bool{"clash.meta": true, "mihomo": true}

// SanitizeUserAgent keeps printable ASCII and caps the length: the value is stored,
// shown on a page and put into a metric label.
func SanitizeUserAgent(ua string) string {
	var b strings.Builder
	for _, r := range ua {
		if b.Len() >= maxUserAgent {
			break
		}
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// ParseUserAgent reads "product/version" tokens. The first token that is not a
// core is the app; a core token gives the core version. No table of known apps:
// a new client shows up under its own name instead of as unknown.
func ParseUserAgent(ua string) ClientAgent {
	var a ClientAgent
	for tok := range strings.FieldsSeq(SanitizeUserAgent(ua)) {
		name, ver, ok := strings.Cut(tok, "/")
		if !ok || name == "" {
			continue
		}
		ver = strings.TrimPrefix(strings.TrimPrefix(ver, "v"), "V")
		switch {
		case coreProducts[strings.ToLower(name)]:
			if a.CoreVersion == "" {
				a.CoreVersion = ver
			}
		case a.App == "":
			a.App, a.AppVersion = name, ver
		}
	}
	return a
}
