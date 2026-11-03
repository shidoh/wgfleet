package mihomo

import (
	"reflect"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// While masters move their client interfaces to AmneziaWG 3.x one at a time, the
// moved master leads every fleet-wide group; a stale profile fails it and falls
// through to the 2.0 one. Timers alone are no 3.x a peer must follow.
func TestAWG3MasterLeadsTheFallbackInBothForms(t *testing.T) {
	in := ClientProfileInput{Masters: []ClientProfileMaster{
		{Name: "m1", AWG: profileAWG(t, "2.0"), VLESS: profileVLESS(domain.RealityModeXHTTP)},
		{Name: "m2", AWG: profileAWG(t, "timers")},
		{Name: "m3", AWG: profileAWG(t, "full")},
	}}
	want := []string{"m3-awg", "m1-awg", "m2-awg", "m1-vless"}

	inline := renderProfile(t, in)
	if got := toStrings(groupNamed(t, inline, ClientProfileAutoGroup)["proxies"].([]any)); !reflect.DeepEqual(got, want) {
		t.Errorf("inline auto = %v, want %v", got, want)
	}
	if got := toStrings(groupNamed(t, inline, ClientProfileSelectGroup)["proxies"].([]any)); strings.Join(got, ",") != "auto,"+strings.Join(want, ",") {
		t.Errorf("inline select = %v", got)
	}

	in.ProviderURL = testProviderURL
	prov := renderProfile(t, in)
	if got := expand(t, prov, providerAWG(t, in), ClientProfileAutoGroup); !reflect.DeepEqual(got, append(want, ClientProfileBlockedProxy)) {
		t.Errorf("provider auto = %v, want %v", got, want)
	}
}

func TestAWGOrderUnchangedWithoutAWG3(t *testing.T) {
	doc := renderProfile(t, ClientProfileInput{Masters: []ClientProfileMaster{
		{Name: "m2", AWG: profileAWG(t, "2.0")},
		{Name: "m1", AWG: profileAWG(t, "timers")},
	}})
	if got := strings.Join(toStrings(groupNamed(t, doc, ClientProfileAutoGroup)["proxies"].([]any)), ","); got != "m2-awg,m1-awg" {
		t.Errorf("auto = %s, want manifest order", got)
	}
}
