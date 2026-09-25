#!/usr/bin/env python3
"""Lint the trellis-watchtower dashboards. Standard library only.

A dashboard fails when:
  1. it names an identifier or a raw URL field (`requestUrl`, `uri`, `tid`, `tenant`, `tenant_id`, `request_id`,
     `principal_id`, `sid`) in a query, a legend, a transformation, a template variable or a field override.
     Monitoring labels come from a closed allowlist (docs/SPEC.md, "Rules the implementation must keep"), so a
     panel that groups or filters on one of these is charting an id;
  2. it uses a datasource uid outside the known set: `prometheus`, `loki`, `fly` (local, grafana/provisioning)
     and every uid declared under cloud/provisioning/datasources/ (the production image);
  3. it has no uid, or a uid another dashboard already uses;
  4. it is not valid JSON.

Usage:
  scripts/dashboard_lint.py                 lint grafana/dashboards/ and cloud/dashboards/
  scripts/dashboard_lint.py PATH [PATH ...] lint these files or directories instead

Exit 0 when clean, 1 when anything fails (each failure printed as `file: panel "title": message`).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DIRS = [ROOT / "grafana" / "dashboards", ROOT / "cloud" / "dashboards"]
CLOUD_DATASOURCES = ROOT / "cloud" / "provisioning" / "datasources"

LOCAL_UIDS = {"prometheus", "loki", "fly"}
# Grafana's own pseudo-datasources: the built-in annotation query and mixed/dashboard panels.
BUILTIN_UIDS = {"-- Grafana --", "grafana", "-- Mixed --", "-- Dashboard --"}

FORBIDDEN = ["requestUrl", "uri", "tid", "tenant", "tenant_id", "request_id", "principal_id", "sid"]
# Whole identifiers only: `tenants_total` and `sidebar` are fine, `tenant` and `sid` are not.
FORBIDDEN_RE = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(sorted(FORBIDDEN, key=len, reverse=True)) + r")(?![A-Za-z0-9_])")


def cloud_uids(directory: Path = CLOUD_DATASOURCES) -> set[str]:
    """The `uid:` values declared in the cloud image's datasource provisioning (no YAML parser needed)."""
    uids: set[str] = set()
    if directory.is_dir():
        for path in sorted(directory.glob("*.y*ml")):
            for line in path.read_text().splitlines():
                m = re.match(r"^\s*uid:\s*['\"]?([A-Za-z0-9_.-]+)['\"]?\s*(#.*)?$", line)
                if m:
                    uids.add(m.group(1))
    return uids


def strings(node):
    """Every string inside a JSON value, recursively, dict keys included (organize's renameByName and
    excludeByName name fields by key)."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from strings(value)


def panels(dashboard: dict):
    """Every panel, including those nested inside collapsed rows."""
    for panel in dashboard.get("panels", []) or []:
        yield panel
        for inner in panel.get("panels", []) or []:
            yield inner


def datasource_uids(node):
    """Every datasource reference below `node`, as a uid string (a legacy string reference is taken as-is)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "datasource":
                if isinstance(value, dict):
                    if value.get("uid") is not None:
                        yield str(value["uid"])
                elif isinstance(value, str):
                    yield value
            else:
                yield from datasource_uids(value)
    elif isinstance(node, list):
        for value in node:
            yield from datasource_uids(value)


def lint_dashboard(path: Path, dashboard: dict, allowed_uids: set[str]) -> list[str]:
    errors: list[str] = []

    def fail(where: str, message: str) -> None:
        errors.append(f"{path}: {where}: {message}")

    # 1. Forbidden identifiers in queries, legends, transformations, variables and overrides.
    places = []
    for panel in panels(dashboard):
        where = f'panel "{panel.get("title", "?")}"'
        places.append((where, panel.get("targets", [])))
        places.append((where, panel.get("transformations", [])))
        places.append((where, (panel.get("fieldConfig") or {}).get("overrides", [])))
        places.append((where, ((panel.get("fieldConfig") or {}).get("defaults") or {}).get("displayName", "")))
    for var in (dashboard.get("templating") or {}).get("list", []) or []:
        places.append((f'variable "{var.get("name", "?")}"',
                       [var.get("query", ""), var.get("definition", ""), var.get("regex", "")]))
    found: set[tuple[str, str]] = set()
    for where, node in places:
        for text in strings(node):
            for match in FORBIDDEN_RE.finditer(text):
                if (where, match.group(1)) not in found:
                    found.add((where, match.group(1)))
                    fail(where, f"references the forbidden field `{match.group(1)}`")

    # 2. Datasource uids.
    for uid in sorted(set(datasource_uids(dashboard))):
        if uid.startswith("$"):
            fail("datasource", f"uses a datasource variable `{uid}`; name a known uid instead")
        elif uid not in allowed_uids and uid not in BUILTIN_UIDS:
            fail("datasource", f"uses unknown datasource uid `{uid}` (allowed: {', '.join(sorted(allowed_uids))})")
    return errors


def collect(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        elif path.exists():
            files.append(path)
    return files


def main(argv: list[str]) -> int:
    targets = [Path(a) for a in argv] if argv else DEFAULT_DIRS
    missing = [str(t) for t in targets if argv and not t.exists()]
    if missing:
        print("dashboard_lint: no such path: " + ", ".join(missing), file=sys.stderr)
        return 1
    files = collect(targets)
    allowed = LOCAL_UIDS | cloud_uids()
    errors: list[str] = []
    seen_uids: dict[str, Path] = {}
    for path in files:
        try:
            dashboard = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{path}: not valid JSON ({exc})")
            continue
        if not isinstance(dashboard, dict):
            errors.append(f"{path}: not a dashboard object")
            continue
        # 3. uid present and unique.
        uid = dashboard.get("uid")
        if not isinstance(uid, str) or not uid.strip():
            errors.append(f"{path}: dashboard has no uid")
        elif uid in seen_uids:
            errors.append(f"{path}: uid `{uid}` is already used by {seen_uids[uid]}")
        else:
            seen_uids[uid] = path
        errors.extend(lint_dashboard(path, dashboard, allowed))
    for line in errors:
        print(line)
    print(f"dashboard_lint: {len(files)} dashboard(s), {len(errors)} problem(s)", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
