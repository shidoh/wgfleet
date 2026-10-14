#!/usr/bin/env python3
"""Regenerate grafana-dashboard-v2.json from grafana-dashboard.json.

Grafana 13 changed the dashboard wire format, and the two are not
interchangeable: the classic file cannot be pasted into the new JSON editor to
replace a dashboard, and the new one cannot be imported by an older Grafana. So
the repository ships BOTH, and this script is what keeps them the same
dashboard rather than two that merely started out alike.

`grafana-dashboard.json` is the source of truth. Edit that one, then run:

    python3 deploy/monitoring/dashboard-to-v2.py

TestDashboardV2MatchesClassic (internal/config) fails if the pair drifts.

What actually differs between the formats
-----------------------------------------
*Classic* (`schemaVersion: 39`) is a flat document: `panels[]` holds both the
visualisations and the section headers (`type: "row"`) in one list, each carrying
an ABSOLUTE `gridPos` measured from the top of the whole dashboard. Layout and
content are the same array.

*v2* (`apiVersion: dashboard.grafana.app/v2`) is a Kubernetes-style resource that
splits the two apart:

  - `spec.elements` — a MAP of `panel-<id>` → panel, with no position in it at
    all. A panel's viz type moves from `type` to `vizConfig.group`, and its
    queries move into `data.spec.queries[]`, each wrapped as a typed
    `PanelQuery`/`DataQuery` instead of a bare target.
  - `spec.layout` — rows, each holding a grid of ElementReferences. Coordinates
    here are RELATIVE TO THE ROW, and `w`/`h` are renamed `width`/`height`. This
    is the conversion's one real trap: copying absolute y values through leaves
    every row after the first pushed off the bottom of its own row.

Smaller renames, each of which Grafana rejects if left in the old form:
`templating.list` → `variables` (with `hide: 0` → `"dontHide"`, numeric
`refresh`/`sort` → named constants), `time`+`timepicker`+`refresh` →
`timeSettings`, `graphTooltip` → `cursorSync`, `uid` → `metadata.name`, and
threshold steps whose base value was `null` must become `0`.
"""

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE / "grafana-dashboard.json"
DST = HERE / "grafana-dashboard-v2.json"

# The Grafana build whose schema this output is written against. It is stamped on
# every vizConfig; Grafana uses it to decide which panel-option migrations to run.
VIZ_VERSION = "13.2.0"

CURSOR_SYNC = {0: "Off", 1: "Crosshair", 2: "Tooltip"}
VAR_REFRESH = {0: "never", 1: "onDashboardLoad", 2: "onTimeRangeChanged"}
VAR_SORT = {
    0: "disabled",
    1: "alphabeticalAsc",
    2: "alphabeticalDesc",
    3: "numericalAsc",
    4: "numericalDesc",
}
# Grafana's default picker list; classic dashboards leave `timepicker` empty and
# inherit it, but the v2 document has to state it.
REFRESH_INTERVALS = ["5s", "10s", "30s", "1m", "5m", "15m", "30m", "1h", "2h", "1d"]


def zero_null_thresholds(node):
    """v2 types threshold steps as numbers; classic uses null for the base step."""
    if isinstance(node, dict):
        steps = node.get("steps")
        if isinstance(steps, list):
            for s in steps:
                if isinstance(s, dict) and s.get("value") is None:
                    s["value"] = 0
        for v in node.values():
            zero_null_thresholds(v)
    elif isinstance(node, list):
        for v in node:
            zero_null_thresholds(v)
    return node


def query(target):
    """One classic target → a v2 PanelQuery."""
    spec = {"expr": target["expr"]}
    # Carried through only when the classic target set them, so the v2 file does
    # not acquire defaults the source never stated.
    for key in ("instant", "range", "format", "legendFormat"):
        if key in target:
            spec[key] = target[key]
    return {
        "kind": "PanelQuery",
        "spec": {
            "refId": target.get("refId", "A"),
            "hidden": False,
            "query": {
                "kind": "DataQuery",
                "group": "prometheus",
                "version": "v0",
                "datasource": {"name": target.get("datasource", {}).get("uid", "${datasource}")},
                "spec": spec,
            },
        },
    }


def element(panel):
    return {
        "kind": "Panel",
        "spec": {
            "id": panel["id"],
            "title": panel.get("title", ""),
            "description": panel.get("description", ""),
            "links": [],
            "data": {
                "kind": "QueryGroup",
                "spec": {
                    "queries": [query(t) for t in panel.get("targets", [])],
                    "queryOptions": {},
                    "transformations": [
                        {
                            "kind": "Transformation",
                            "group": t["id"],
                            "spec": {"options": t.get("options", {})},
                        }
                        for t in panel.get("transformations", [])
                    ],
                },
            },
            "vizConfig": {
                "kind": "VizConfig",
                # The classic `type` field: what Grafana should draw.
                "group": panel["type"],
                "version": VIZ_VERSION,
                "spec": {
                    "fieldConfig": zero_null_thresholds(
                        json.loads(json.dumps(panel.get("fieldConfig", {"defaults": {}, "overrides": []})))
                    ),
                    "options": panel.get("options", {}),
                },
            },
        },
    }


def variable(v):
    if v["type"] == "datasource":
        return {
            "kind": "DatasourceVariable",
            "spec": {
                "allowCustomValue": True,
                "current": {"text": "", "value": ""},
                "hide": "dontHide" if not v.get("hide") else "hideVariable",
                "includeAll": v.get("includeAll", False),
                "label": v.get("label", ""),
                "multi": v.get("multi", False),
                "name": v["name"],
                "options": [],
                "pluginId": v.get("query", "prometheus"),
                "refresh": VAR_REFRESH.get(v.get("refresh", 1), "onDashboardLoad"),
                "regex": v.get("regex", ""),
                "skipUrlSync": False,
            },
        }
    if v["type"] == "query":
        q = v.get("query")
        expr = q.get("query") if isinstance(q, dict) else q
        return {
            "kind": "QueryVariable",
            "spec": {
                "allValue": v.get("allValue", ""),
                "allowCustomValue": True,
                "current": {"text": "All", "value": ["$__all"]} if v.get("includeAll") else {"text": "", "value": ""},
                "definition": v.get("definition", expr),
                "hide": "dontHide" if not v.get("hide") else "hideVariable",
                "includeAll": v.get("includeAll", False),
                "label": v.get("label", ""),
                "multi": v.get("multi", False),
                "name": v["name"],
                "options": [],
                "query": {
                    "kind": "DataQuery",
                    "group": "prometheus",
                    "version": "v0",
                    "datasource": {"name": v.get("datasource", {}).get("uid", "${datasource}")},
                    "spec": {"query": expr, "refId": (q or {}).get("refId", v["name"]) if isinstance(q, dict) else v["name"]},
                },
                "refresh": VAR_REFRESH.get(v.get("refresh", 1), "onDashboardLoad"),
                "regex": v.get("regex", ""),
                "regexApplyTo": "value",
                "skipUrlSync": False,
                "sort": VAR_SORT.get(v.get("sort", 0), "disabled"),
            },
        }
    raise SystemExit(f"unsupported variable type {v['type']!r} — teach the converter about it")


# Classic Prometheus annotation fields that v2 does not type: they ride in
# legacyOptions, which Grafana hands back to the datasource untouched.
ANNOTATION_LEGACY = ("titleFormat", "textFormat", "tagKeys", "useValueForTime", "step")


def annotation(a):
    ds = a.get("datasource", {})
    spec = {}
    if "expr" in a:
        # Without this the annotation imports with an empty query and draws nothing —
        # the classic file states it at the top level, v2 inside the DataQuery.
        spec = {"expr": a["expr"], "refId": "Anno"}
    legacy = {k: a[k] for k in ANNOTATION_LEGACY if k in a}
    out = {
        "kind": "AnnotationQuery",
        "spec": {
            "builtIn": bool(a.get("builtIn")),
            "enable": a.get("enable", True),
            "hide": a.get("hide", False),
            "iconColor": a.get("iconColor", "red"),
            "name": a.get("name", ""),
            "query": {
                "kind": "DataQuery",
                "group": "grafana" if ds.get("type") == "grafana" else "prometheus",
                "version": "v0",
                "datasource": {"name": ds.get("uid", "${datasource}")},
                "spec": spec,
            },
        },
    }
    if legacy:
        out["spec"]["legacyOptions"] = legacy
    return out


def flatten(panels):
    """Classic keeps a COLLAPSED row's panels inside the row (`row.panels`), not after
    it in the flat list. Lay them back out in order so every consumer sees one list."""
    out = []
    for p in panels:
        out.append(p)
        if p["type"] == "row":
            out.extend(p.get("panels", []))
    return out


def rows(panels):
    """Split the flat classic panel list into v2 rows with row-relative coordinates."""
    out, current = [], None
    for p in flatten(panels):
        if p["type"] == "row":
            current = {
                "kind": "RowsLayoutRow",
                "spec": {
                    "collapse": bool(p.get("collapsed")),
                    "layout": {"kind": "GridLayout", "spec": {"items": []}},
                    "title": p.get("title", ""),
                    # The row header occupies one grid unit; panels under it start
                    # directly below, and their y is measured from THERE, not from
                    # the top of the dashboard.
                    "_origin": p["gridPos"]["y"] + 1,
                },
            }
            out.append(current)
            continue
        if current is None:
            # Panels above the first row header: give them an untitled row rather
            # than dropping them, which is what a naive converter does.
            current = {
                "kind": "RowsLayoutRow",
                "spec": {
                    "collapse": False,
                    "layout": {"kind": "GridLayout", "spec": {"items": []}},
                    "title": "",
                    "_origin": 0,
                },
            }
            out.append(current)
        g = p["gridPos"]
        current["spec"]["layout"]["spec"]["items"].append({
            "kind": "GridLayoutItem",
            "spec": {
                "element": {"kind": "ElementReference", "name": f"panel-{p['id']}"},
                "height": g["h"],
                "width": g["w"],
                "x": g["x"],
                "y": g["y"] - current["spec"]["_origin"],
            },
        })
    for r in out:
        del r["spec"]["_origin"]
    return out


def convert(src):
    panels = src["panels"]
    viz = [p for p in flatten(panels) if p["type"] != "row"]
    return {
        "apiVersion": "dashboard.grafana.app/v2",
        "kind": "Dashboard",
        "metadata": {"name": src.get("uid", "wgfleet-fleet")},
        "spec": {
            "annotations": [annotation(a) for a in src.get("annotations", {}).get("list", [])],
            "cursorSync": CURSOR_SYNC.get(src.get("graphTooltip", 0), "Off"),
            "editable": src.get("editable", True),
            "elements": {f"panel-{p['id']}": element(p) for p in viz},
            "layout": {"kind": "RowsLayout", "spec": {"rows": rows(panels)}},
            "links": src.get("links", []),
            "liveNow": src.get("liveNow", False),
            "preload": False,
            "tags": src.get("tags", []),
            "timeSettings": {
                "autoRefresh": src.get("refresh", ""),
                "autoRefreshIntervals": REFRESH_INTERVALS,
                "fiscalYearStartMonth": src.get("fiscalYearStartMonth", 0),
                "from": src.get("time", {}).get("from", "now-6h"),
                "hideTimepicker": bool(src.get("timepicker", {}).get("hidden", False)),
                "timezone": src.get("timezone", "browser"),
                "to": src.get("time", {}).get("to", "now"),
            },
            "title": src["title"],
            "variables": [variable(v) for v in src.get("templating", {}).get("list", [])],
        },
    }


def nulls(node, path="spec"):
    """Paths holding JSON null. The v2 schema types every field, and Grafana 13's
    JSON editor rejects a null where it expects a string or number (`noValue: null`
    imported through the API but not through the editor)."""
    if node is None:
        return [path]
    if isinstance(node, dict):
        return [p for k, v in node.items() for p in nulls(v, f"{path}.{k}")]
    if isinstance(node, list):
        return [p for i, v in enumerate(node) for p in nulls(v, f"{path}[{i}]")]
    return []


def check(src, out):
    """Nothing may be lost in translation — the point of shipping both files."""
    bad = nulls(out["spec"])
    assert not bad, f"null values the v2 editor rejects: {bad[:5]}"
    viz = [p for p in flatten(src["panels"]) if p["type"] != "row"]
    assert len(out["spec"]["elements"]) == len(viz), "panel count changed"

    referenced = [
        i["spec"]["element"]["name"]
        for r in out["spec"]["layout"]["spec"]["rows"]
        for i in r["spec"]["layout"]["spec"]["items"]
    ]
    assert sorted(referenced) == sorted(out["spec"]["elements"]), "layout and elements disagree"
    assert len(referenced) == len(set(referenced)), "a panel is placed twice"

    for p in viz:
        e = out["spec"]["elements"][f"panel-{p['id']}"]["spec"]
        assert e["title"] == p.get("title", ""), f"title lost on panel {p['id']}"
        assert e["vizConfig"]["group"] == p["type"], f"viz type lost on panel {p['id']}"
        got = [q["spec"]["query"]["spec"]["expr"] for q in e["data"]["spec"]["queries"]]
        want = [t["expr"] for t in p.get("targets", [])]
        assert got == want, f"queries changed on panel {p['id']}"

    for r in out["spec"]["layout"]["spec"]["rows"]:
        for i in r["spec"]["layout"]["spec"]["items"]:
            s = i["spec"]
            assert s["y"] >= 0, f"{s['element']['name']} sits above its own row — origin maths is wrong"
            assert s["x"] + s["width"] <= 24, f"{s['element']['name']} overflows the 24-column grid"


def main():
    src = json.loads(SRC.read_text())
    out = convert(src)
    check(src, out)
    DST.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    rows_n = len(out["spec"]["layout"]["spec"]["rows"])
    print(f"wrote {DST.name}: {len(out['spec']['elements'])} panels in {rows_n} rows")


if __name__ == "__main__":
    sys.exit(main())
