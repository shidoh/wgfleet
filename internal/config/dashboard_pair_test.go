package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Grafana 13 changed the dashboard wire format, and the two forms are not
// interchangeable: the classic file cannot be pasted into the new JSON editor to
// replace a dashboard, and the v2 file cannot be imported by an older Grafana.
// So the repository ships BOTH — and two hand-maintained copies of the same
// dashboard is a promise nobody keeps. `deploy/monitoring/dashboard-to-v2.py`
// regenerates the v2 file from the classic one; this test is what makes
// forgetting to run it fail loudly instead of shipping a dashboard whose two
// halves quietly disagree about which panels exist.
//
// It compares MEANING, not bytes: panel identity, viz type, queries and row
// layout. The formats legitimately differ everywhere else (Grafana fills panel
// options with its own defaults on export), and a byte comparison would fail on
// every Grafana release for no reason.

const (
	classicDashboard = "deploy/monitoring/grafana-dashboard.json"
	v2Dashboard      = "deploy/monitoring/grafana-dashboard-v2.json"
	regenerateHint   = "run: python3 deploy/monitoring/dashboard-to-v2.py"
)

type classicPanel struct {
	ID          int    `json:"id"`
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	GridPos     struct {
		H, W, X, Y int
	} `json:"gridPos"`
	Targets []struct {
		Expr string `json:"expr"`
	} `json:"targets"`
	// A collapsed classic row carries its panels INSIDE itself rather than after
	// it in the flat list, so a reader that only walks the top level silently
	// loses every panel of every collapsed row.
	Collapsed bool           `json:"collapsed"`
	Panels    []classicPanel `json:"panels"`
}

// vizPanels lists every visualisation, including those nested in collapsed rows.
func (c classicDash) vizPanels() []classicPanel {
	var out []classicPanel
	for _, p := range c.Panels {
		if p.Type != "row" {
			out = append(out, p)
			continue
		}
		out = append(out, p.Panels...)
	}
	return out
}

type classicDash struct {
	Title  string         `json:"title"`
	UID    string         `json:"uid"`
	Panels []classicPanel `json:"panels"`
}

type v2Dash struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Title    string `json:"title"`
		Elements map[string]struct {
			Spec struct {
				ID          int    `json:"id"`
				Title       string `json:"title"`
				Description string `json:"description"`
				Data        struct {
					Spec struct {
						Queries []struct {
							Spec struct {
								Query struct {
									Spec struct {
										Expr string `json:"expr"`
									} `json:"spec"`
								} `json:"query"`
							} `json:"spec"`
						} `json:"queries"`
					} `json:"spec"`
				} `json:"data"`
				VizConfig struct {
					Group string `json:"group"`
				} `json:"vizConfig"`
			} `json:"spec"`
		} `json:"elements"`
		Layout struct {
			Spec struct {
				Rows []struct {
					Spec struct {
						Title    string `json:"title"`
						Collapse bool   `json:"collapse"`
						Layout   struct {
							Spec struct {
								Items []struct {
									Spec struct {
										Element struct {
											Name string `json:"name"`
										} `json:"element"`
										Height, Width, X, Y int
									} `json:"spec"`
								} `json:"items"`
							} `json:"spec"`
						} `json:"layout"`
					} `json:"spec"`
				} `json:"rows"`
			} `json:"spec"`
		} `json:"layout"`
	} `json:"spec"`
}

func readJSON(t *testing.T, rel string, into any) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(repoRoot, rel))
	if err != nil {
		t.Fatalf("%s is unreadable: %v", rel, err)
	}
	if err := json.Unmarshal(body, into); err != nil {
		t.Fatalf("%s is not valid JSON: %v", rel, err)
	}
}

func TestDashboardV2MatchesClassic(t *testing.T) {
	var c classicDash
	var v v2Dash
	readJSON(t, classicDashboard, &c)
	readJSON(t, v2Dashboard, &v)

	if v.APIVersion != "dashboard.grafana.app/v2" || v.Kind != "Dashboard" {
		t.Errorf("v2 file is not a v2 Dashboard resource: apiVersion=%q kind=%q", v.APIVersion, v.Kind)
	}
	if v.Spec.Title != c.Title {
		t.Errorf("title differs: classic %q, v2 %q — %s", c.Title, v.Spec.Title, regenerateHint)
	}
	// The v2 identity lives in metadata.name, which is what decides whether pasting
	// the file REPLACES the existing dashboard or creates a second one beside it.
	if v.Metadata.Name != c.UID {
		t.Errorf("v2 metadata.name %q must equal the classic uid %q, or pasting it creates a duplicate dashboard instead of replacing the old one",
			v.Metadata.Name, c.UID)
	}

	for _, p := range c.vizPanels() {
		key := fmt.Sprintf("panel-%d", p.ID)
		el, ok := v.Spec.Elements[key]
		if !ok {
			t.Errorf("panel %d (%q) is missing from the v2 dashboard — %s", p.ID, p.Title, regenerateHint)
			continue
		}
		if el.Spec.Title != p.Title {
			t.Errorf("panel %d title differs: classic %q, v2 %q", p.ID, p.Title, el.Spec.Title)
		}
		if el.Spec.Description != p.Description {
			t.Errorf("panel %d description differs — %s", p.ID, regenerateHint)
		}
		// vizConfig.group is where the classic `type` went. Getting it wrong renders
		// the panel as something else entirely rather than failing visibly.
		if el.Spec.VizConfig.Group != p.Type {
			t.Errorf("panel %d viz type differs: classic %q, v2 %q", p.ID, p.Type, el.Spec.VizConfig.Group)
		}
		if len(el.Spec.Data.Spec.Queries) != len(p.Targets) {
			t.Errorf("panel %d has %d queries in classic and %d in v2 — %s",
				p.ID, len(p.Targets), len(el.Spec.Data.Spec.Queries), regenerateHint)
			continue
		}
		for i, tgt := range p.Targets {
			if got := el.Spec.Data.Spec.Queries[i].Spec.Query.Spec.Expr; got != tgt.Expr {
				t.Errorf("panel %d query %d differs:\n classic: %s\n     v2: %s", p.ID, i, tgt.Expr, got)
			}
		}
	}

	// No panel may exist only in v2 — that direction is how a hand-edit sneaks a
	// panel into one file and not the other.
	classicIDs := map[int]bool{}
	for _, p := range c.vizPanels() {
		classicIDs[p.ID] = true
	}
	for key, el := range v.Spec.Elements {
		if !classicIDs[el.Spec.ID] {
			t.Errorf("%s (%q) exists only in the v2 dashboard — %s", key, el.Spec.Title, regenerateHint)
		}
	}
}

// The formats disagree about what a coordinate means: classic gridPos.y counts
// from the top of the whole dashboard, v2 counts from the top of its own row.
// Converting one to the other by copying y through is the mistake that looks
// right in a diff and puts every row after the first off the bottom of its row,
// so it gets its own test rather than riding along with the parity check.
func TestDashboardV2RowCoordinatesAreRowRelative(t *testing.T) {
	var c classicDash
	var v v2Dash
	readJSON(t, classicDashboard, &c)
	readJSON(t, v2Dashboard, &v)

	var classicRows []classicPanel
	for _, p := range c.Panels {
		if p.Type == "row" {
			classicRows = append(classicRows, p)
		}
	}
	if len(v.Spec.Layout.Spec.Rows) != len(classicRows) {
		t.Fatalf("classic has %d rows, v2 has %d — %s", len(classicRows), len(v.Spec.Layout.Spec.Rows), regenerateHint)
	}
	for i, row := range v.Spec.Layout.Spec.Rows {
		if row.Spec.Title != classicRows[i].Title {
			t.Errorf("row %d differs: classic %q, v2 %q", i, classicRows[i].Title, row.Spec.Title)
		}
		if row.Spec.Collapse != classicRows[i].Collapsed {
			t.Errorf("row %q: collapsed is %v in classic and %v in v2 — %s",
				row.Spec.Title, classicRows[i].Collapsed, row.Spec.Collapse, regenerateHint)
		}

		items := row.Spec.Layout.Spec.Items
		if len(items) == 0 {
			t.Errorf("row %q has no panels", row.Spec.Title)
			continue
		}
		top := items[0].Spec.Y
		occupied := map[[2]int]string{}
		for _, it := range items {
			s := it.Spec
			if s.Y < top {
				top = s.Y
			}
			if s.X+s.Width > 24 {
				t.Errorf("row %q: %s overflows the 24-column grid (x=%d w=%d)",
					row.Spec.Title, s.Element.Name, s.X, s.Width)
			}
			for y := s.Y; y < s.Y+s.Height; y++ {
				for x := s.X; x < s.X+s.Width; x++ {
					if prev, dup := occupied[[2]int{y, x}]; dup {
						t.Errorf("row %q: %s overlaps %s at (%d,%d)",
							row.Spec.Title, s.Element.Name, prev, x, y)
					}
					occupied[[2]int{y, x}] = s.Element.Name
				}
			}
		}
		if top != 0 {
			t.Errorf("row %q starts at y=%d; v2 coordinates are relative to the row, so its first panel must sit at y=0 — %s",
				row.Spec.Title, top, regenerateHint)
		}
	}

	// Every element must be placed exactly once: an orphan renders nowhere, a
	// double placement renders twice.
	placed := map[string]int{}
	for _, row := range v.Spec.Layout.Spec.Rows {
		for _, it := range row.Spec.Layout.Spec.Items {
			placed[it.Spec.Element.Name]++
		}
	}
	for key := range v.Spec.Elements {
		switch placed[key] {
		case 1:
		case 0:
			t.Errorf("%s is defined but placed in no row", key)
		default:
			t.Errorf("%s is placed %d times", key, placed[key])
		}
	}
	for key := range placed {
		if _, ok := v.Spec.Elements[key]; !ok {
			t.Errorf("layout references %s, which no element defines", key)
		}
	}
}
