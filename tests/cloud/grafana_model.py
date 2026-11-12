"""A small model of the Grafana transformations the backups and point-in-time logs tiles and the sign-in row use, so a
test can feed a tile the frames a scenario would return and read what it shows. It models Grafana 12.4's behaviour as
far as these tiles need it, and no further: `reduce` (reduceFields: sum, max, lastNotNull; seriesToRows: sum, as
"Total"), `filterByValue` (include, greater, lower), `calculateField` (binary + - * /, unary floor ceil abs, reduceRow
sum max), `joinByField` (outer, by Time: every time any frame has, ascending, a missing cell None), `sortBy`, `limit`,
`concatenate` and `organize` (include, order, rename), each with the per-query `filter` (byRefId). The model is held to Grafana itself by the same scenarios rendered in a throwaway
Grafana with testdata (tasks/todo.md, BK): a scenario that reads differently there is a fault in this file.

A frame is {"refId": str, "fields": [{"name": str, "time": bool, "values": [...]}]}; a field's name is its display
name (the query's alias; Cloud Monitoring's time field is "Time"). A missing value is None.
"""

from __future__ import annotations

import math

UNARY = {"floor": math.floor, "ceil": math.ceil, "abs": abs}
# Each binary calculation that met a missing value (see _apply): where this model and Grafana could differ.
NONE_IN_ARITHMETIC: list[str] = []
BINARY = {"+": lambda a, b: a + b, "-": lambda a, b: a - b, "*": lambda a, b: a * b, "/": lambda a, b: a / b}


def frame(ref: str, alias: str, values: list, times: list | None = None) -> dict:
    times = times if times is not None else list(range(len(values)))
    return {"refId": ref, "fields": [{"name": "Time", "time": True, "values": list(times)},
                                     {"name": alias, "time": False, "values": list(values)}]}


def _reduce(values: list, reducer: str):
    present = [v for v in values if v is not None]
    if reducer == "sum":
        return sum(present)
    if reducer == "max":
        return max(present) if present else None
    if reducer == "lastNotNull":
        return present[-1] if present else None
    raise ValueError(reducer)


def _field(f: dict, name: str):
    return next((x for x in f["fields"] if x["name"] == name), None)


def _rows(f: dict) -> int:
    return max((len(x["values"]) for x in f["fields"]), default=0)


def _operand(f: dict, side: dict):
    if "fixed" in side:
        return [float(side["fixed"])] * _rows(f)
    found = _field(f, side["matcher"]["options"])
    return None if found is None else found["values"]


def _apply(f: dict, t: dict) -> dict | None:
    """One transformation on one frame (None: the frame is dropped)."""
    o = t["options"]
    if t["id"] == "sortBy":
        (rule,) = o["sort"]
        key = _field(f, rule["field"])
        if key is None:
            return f
        order = sorted(range(_rows(f)), key=lambda i: (key["values"][i] is None, key["values"][i]),
                       reverse=rule.get("desc", False))
        return {"refId": f["refId"], "fields": [{**x, "values": [x["values"][i] for i in order]} for x in f["fields"]]}
    if t["id"] == "limit":
        return {"refId": f["refId"], "fields": [{**x, "values": x["values"][:o["limitField"]]} for x in f["fields"]]}
    if t["id"] == "reduce" and o["mode"] == "seriesToRows":
        assert o["reducers"] == ["sum"] and not o.get("includeTimeField"), o
        fields = [x for x in f["fields"] if not x["time"]]
        return {"refId": f["refId"], "fields": [{"name": "Field", "time": False, "values": [x["name"] for x in fields]},
                                                {"name": "Total", "time": False,
                                                 "values": [_reduce(x["values"], "sum") for x in fields]}]}
    if t["id"] == "reduce":
        assert o["mode"] == "reduceFields" and len(o["reducers"]) == 1, o
        fields = [x for x in f["fields"] if o.get("includeTimeField") or not x["time"]]
        return {"refId": f["refId"], "fields": [{"name": x["name"], "time": False,
                                                 "values": [_reduce(x["values"], o["reducers"][0])]} for x in fields]}
    if t["id"] == "filterByValue":
        assert o["type"] == "include" and o["match"] == "any", o
        keep = []
        for i in range(_rows(f)):
            hit = False
            for flt in o["filters"]:
                assert flt["config"]["id"] in ("greater", "lower"), flt
                x = _field(f, flt["fieldName"])
                v = x["values"][i] if x else None
                bar = flt["config"]["options"]["value"]
                hit = hit or (v is not None and (v > bar if flt["config"]["id"] == "greater" else v < bar))
            if hit:
                keep.append(i)
        return {"refId": f["refId"], "fields": [{**x, "values": [x["values"][i] for i in keep]} for x in f["fields"]]}
    if t["id"] == "calculateField":
        mode, alias = o["mode"], o["alias"]
        if mode == "binary":
            left, right = _operand(f, o["binary"]["left"]), _operand(f, o["binary"]["right"])
            if left is None or right is None:
                return f
            op = BINARY[o["binary"]["operator"]]
            if any(a is None or b is None for a, b in zip(left, right)):
                # Grafana's JavaScript would compute with it (null as 0, undefined as NaN); this model says None.
                # A tile whose arithmetic meets one depends on that difference: the test reading it asserts none.
                NONE_IN_ARITHMETIC.append(alias)
            values = [None if a is None or b is None else op(a, b) for a, b in zip(left, right)]
        elif mode == "unary":
            source = _field(f, o["unary"]["fieldName"])
            if source is None:
                return f
            values = [None if v is None else UNARY[o["unary"]["operator"]](v) for v in source["values"]]
        elif mode == "reduceRow":
            fields = [x for x in f["fields"] if x["name"] in o["reduce"]["include"]]
            values = [_reduce([x["values"][i] for x in fields], o["reduce"]["reducer"]) for i in range(_rows(f))]
        else:
            raise ValueError(mode)
        return {"refId": f["refId"], "fields": [*f["fields"], {"name": alias, "time": False, "values": values}]}
    raise ValueError(t["id"])


def _join(frames: list[dict]) -> list[dict]:
    """joinByField, outer, by Time: one frame, a row for every time any frame has, ascending."""
    if not frames:
        return []
    times = sorted({v for f in frames for v in _field(f, "Time")["values"]})
    fields = [{"name": "Time", "time": True, "values": times}]
    for f in frames:
        at = dict(zip(_field(f, "Time")["values"], range(_rows(f))))
        for x in f["fields"]:
            if not x["time"]:
                fields.append({"name": x["name"], "time": False,
                               "values": [x["values"][at[t]] if t in at else None for t in times]})
    return [{"refId": "", "fields": fields}]


def apply(frames: list[dict], transformations: list[dict]) -> list[dict]:
    for t in transformations:
        if t["id"] == "joinByField":
            assert t["options"] == {"byField": "Time", "mode": "outer"}, t
            frames = _join(frames)
            continue
        if t["id"] == "concatenate":
            frames = [{"refId": "", "fields": [x for f in frames for x in f["fields"]]}] if frames else []
            continue
        if t["id"] == "organize":
            keep = t["options"].get("includeByName")
            order = t["options"].get("indexByName", {})
            rename = t["options"].get("renameByName", {})
            frames = [{"refId": f["refId"], "fields": [{**x, "name": rename.get(x["name"], x["name"])} for x in sorted(
                [x for x in f["fields"] if not keep or keep.get(x["name"])],
                key=lambda x: order.get(x["name"], len(order)))]} for f in frames]
            continue
        ref = (t.get("filter") or {}).get("options")
        assert not t.get("filter") or t["filter"]["id"] == "byRefId", t
        frames = [f if ref is not None and f["refId"] != ref else _apply(f, t) for f in frames]
        frames = [f for f in frames if f is not None]
    return frames


def shows(panel: dict, frames: list[dict]) -> dict:
    """What a stat tile shows: each remaining field's last value by its name, the status as its mapped word (None:
    nothing arrived, the tile's no-value text)."""
    out = apply(frames, panel.get("transformations", []))
    if not out or not out[0]["fields"]:
        return {}
    shown = {x["name"]: x["values"][-1] for x in out[0]["fields"]}
    words = next((x["value"][0]["options"] for o in panel["fieldConfig"]["overrides"]
                  if o["matcher"]["options"] == "status" for x in o["properties"] if x["id"] == "mappings"), {})
    if shown.get("status") is not None:
        shown["status"] = words.get(str(int(shown["status"])), {}).get("text")
    return shown
