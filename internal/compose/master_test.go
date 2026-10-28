package compose

import (
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/shidoh/wgfleet/internal/domain"
)

func sampleInput() RenderInput {
	return RenderInput{
		Compose: domain.ComposeSpec{
			MihomoImage:      "metacubex/mihomo:v1.18",
			PublicIP:         "203.0.113.20",
			ClientDNS:        []string{"10.20.4.10", "10.20.4.15"},
			ClientAllowedIPs: "1.0.0.0/8,8.0.0.0/7",
		},
	}
}

func TestRenderMasterComposeStructure(t *testing.T) {
	out, err := RenderMasterCompose(sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("rendered compose is not valid YAML: %v\n%s", err, out)
	}
	services, _ := doc["services"].(map[string]any)
	mi, _ := services["mihomo"].(map[string]any)
	if mi == nil {
		t.Fatalf("missing mihomo service: %+v", services)
	}
	if len(services) != 1 {
		t.Errorf("without a namespace holder the stack is mihomo alone, got %d services: %+v", len(services), services)
	}
	if mi["image"] != "metacubex/mihomo:v1.18" || mi["command"] != "-d /etc/mihomo" || mi["network_mode"] != "host" {
		t.Errorf("mihomo service wrong: %+v", mi)
	}
	if _, ok := mi["depends_on"]; ok {
		t.Errorf("mihomo depends on something without a namespace holder: %+v", mi["depends_on"])
	}
}

func TestRenderMasterComposeDefaults(t *testing.T) {
	out, err := RenderMasterCompose(RenderInput{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, DefaultMihomoImage) {
		t.Errorf("default mihomo image not used:\n%s", out)
	}
}

func TestRenderMasterComposeDeterministic(t *testing.T) {
	a, _ := RenderMasterCompose(sampleInput())
	b, _ := RenderMasterCompose(sampleInput())
	if a != b {
		t.Error("compose render must be deterministic")
	}
}

// The agent owns the client interface; nothing in the stack may claim wg0 or its
// UDP port, whatever the input.
func TestRenderMasterComposeNeverShipsWGEasy(t *testing.T) {
	for _, in := range []RenderInput{
		sampleInput(),
		{},
		{NetnsHolderImage: "busybox:1.36", NetnsAttachMihomo: true},
	} {
		out, err := RenderMasterCompose(in)
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		if strings.Contains(out, "wg-easy") || strings.Contains(out, "/etc/wireguard") {
			t.Fatalf("the stack still ships wg-easy:\n%s", out)
		}
	}
}

// The noisiest container on the master must not write an unbounded log.
//
// Docker's json-file driver does not rotate by default. Measured on the live
// master 2026-09-04: 97787 error lines in 18 days, all of one kind, in a file
// nothing truncates — a slow disk leak on a 2 vCPU box, and the reason reading
// recent lines is expensive (json-file has no index, so `--since` scans from the
// start of the file).
func TestMihomoLogIsRotated(t *testing.T) {
	out, err := RenderMasterCompose(sampleInput())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{"logging:", "max-size", "10m", "max-file"} {
		if !strings.Contains(out, want) {
			t.Errorf("the mihomo service has no log bound (%q missing):\n%s", want, out)
		}
	}
}

// The namespace holder must be a SEPARATE container that mihomo joins, not a
// property of mihomo itself. mihomo restarts several times a day; a namespace it
// owned would take the veth and the interception rules with it every time.
func TestNetnsHolderOwnsTheNamespaceAndMihomoJoinsIt(t *testing.T) {
	in := sampleInput()
	in.NetnsHolderImage = "busybox:1.36"
	in.NetnsAttachMihomo = true

	out, err := RenderMasterCompose(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{"wgfleet-netns:", "network_mode: none", "network_mode: container:wgfleet-netns"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "network_mode: host") {
		t.Errorf("something is still on host networking, so the collision remains:\n%s", out)
	}
}

// With no holder image the stack must render exactly as before: this is the path
// every existing node takes until it is ready to move.
func TestWithoutAHolderMihomoStaysOnHostNetworking(t *testing.T) {
	in := sampleInput()
	out, err := RenderMasterCompose(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(out, "wgfleet-netns") {
		t.Errorf("a namespace holder was rendered without being asked for:\n%s", out)
	}
	if !strings.Contains(out, "network_mode: host") {
		t.Errorf("mihomo left host networking without a namespace to join:\n%s", out)
	}
}

// Phase A: the holder exists, mihomo does not move. This is what makes the
// namespace inspectable on a live master at no risk — the container and its veth
// are inert until the interception rules move, and mihomo keeps serving clients
// from the host namespace the whole time.
func TestHolderAloneDoesNotMoveMihomo(t *testing.T) {
	in := sampleInput()
	in.NetnsHolderImage = "busybox:1.36"

	out, err := RenderMasterCompose(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(out, "wgfleet-netns:") {
		t.Errorf("the holder was not rendered:\n%s", out)
	}
	if strings.Contains(out, "network_mode: container:wgfleet-netns") {
		t.Errorf("mihomo was moved into the namespace before anything routes there:\n%s", out)
	}
	if !strings.Contains(out, "network_mode: host") {
		t.Errorf("mihomo left host networking during phase A:\n%s", out)
	}
}
