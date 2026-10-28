package backup

import (
	"testing"
)

func TestBuildParseTarRoundTrip(t *testing.T) {
	items := []Item{
		{Name: "controller/state.db", Dest: "/var/lib/wgfleet/state.db", Mode: 0o600, Layer: LayerController, Data: []byte("dbbytes")},
		{Name: "master/client-wg.key", Dest: "/etc/wgfleet/client-wg.key", Mode: 0o600, Layer: LayerMaster, Data: []byte("key")},
	}
	m := Manifest{
		Schema:      ArchiveSchema,
		WireVersion: 7,
		Layers:      []Layer{LayerController, LayerMaster},
		CreatedAt:   "2026-06-26T00:00:00Z",
	}
	for _, it := range items {
		m.Entries = append(m.Entries, Entry{Name: it.Name, Dest: it.Dest, Mode: uint32(it.Mode), Layer: it.Layer})
	}

	raw, err := BuildTar(m, items)
	if err != nil {
		t.Fatalf("BuildTar: %v", err)
	}
	gotM, gotItems, err := ParseTar(raw)
	if err != nil {
		t.Fatalf("ParseTar: %v", err)
	}
	if gotM.WireVersion != 7 || gotM.Schema != ArchiveSchema || len(gotM.Entries) != 2 {
		t.Fatalf("manifest mismatch: %+v", gotM)
	}
	if len(gotItems) != 2 {
		t.Fatalf("want 2 items, got %d", len(gotItems))
	}
	if gotItems[0].Name != "controller/state.db" || string(gotItems[0].Data) != "dbbytes" || gotItems[0].Mode != 0o600 {
		t.Fatalf("item0 mismatch: %+v", gotItems[0])
	}
}

func TestParseTarRejectsMissingManifest(t *testing.T) {
	// A tar with no manifest.json must fail.
	raw, err := BuildTar(Manifest{Schema: ArchiveSchema}, nil)
	if err != nil {
		t.Fatalf("BuildTar: %v", err)
	}
	_ = raw
	if _, _, err := ParseTar([]byte("not a tar")); err == nil {
		t.Fatal("expected error parsing garbage")
	}
}
