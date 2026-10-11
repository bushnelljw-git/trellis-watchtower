"""Read the vendored metric catalogue (cloud/catalogue/monitoring.yml) far enough to check the cloud dashboards
against it. Standard library only: the system Python here has no YAML parser, and the catalogue's shape is fixed by
tpa-platform's own shape test (block mappings, block scalars for filters and descriptions, lists only inside alert
policies). tests/cloud/test_catalogue.py checks this reader against the file's known facts.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
CATALOGUE = ROOT / "cloud" / "catalogue" / "monitoring.yml"
SOURCE = ROOT / "cloud" / "catalogue" / "SOURCE"

KEY_RE = re.compile(r"^(?P<key>[A-Za-z0-9_.-]+):(?:\s+(?P<value>.*?))?\s*$")
BLOCK_SCALAR_RE = re.compile(r"^[|>][-+]?\s*(#.*)?$")


def git_blob_sha(data: bytes) -> str:
    """What `git hash-object` prints for these bytes."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def source() -> dict[str, str]:
    pin = {}
    for line in SOURCE.read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            pin[key] = value
    return pin


def mapping_tree(text: str) -> dict:
    """The catalogue's mapping keys as nested dicts; a key's scalar value is kept as a string. Block scalars are
    skipped whole, and list items are kept as dicts under a `-N` key, which nothing here reads."""
    root: dict = {}
    stack: list[tuple[int, dict]] = [(-1, root)]
    skip_deeper_than: int | None = None
    items: dict[int, int] = {}
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if skip_deeper_than is not None:
            if indent > skip_deeper_than:
                continue
            skip_deeper_than = None
        while stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        if stripped.startswith("- "):
            n = items.get(id(parent), 0)
            items[id(parent)] = n + 1
            item: dict = {}
            parent[f"-{n}"] = item
            stack.append((indent, item))
            indent += 2
            stripped = stripped[2:]
            parent = item
        m = KEY_RE.match(stripped)
        if not m:
            continue
        key, value = m.group("key"), m.group("value")
        if value is None or value == "":
            child: dict = {}
            parent[key] = child
            stack.append((indent, child))
        elif BLOCK_SCALAR_RE.match(value):
            parent[key] = "<block>"
            skip_deeper_than = indent
        else:
            parent[key] = value
    return root


class Catalogue:
    def __init__(self, path: Path = CATALOGUE):
        self.text = path.read_text()
        self.data = path.read_bytes()
        tree = mapping_tree(self.text)
        self.shared = self._metrics(tree["shared"]["log_metrics"])
        self.roles = {role: self._metrics(body.get("log_metrics", {})) for role, body in tree["projects"].items()}

    @staticmethod
    def _metrics(section: dict) -> dict[str, dict]:
        """name -> {labels: set of label keys, distribution: bool}"""
        return {name: {"labels": set((body.get("labels") or {}).keys()),
                       "distribution": "value_extractor" in body}
                for name, body in section.items()}

    def metric(self, role: str, name: str) -> dict | None:
        return self.roles.get(role, {}).get(name) or self.shared.get(name)

    def jobs_named(self) -> set[str]:
        """Every Cloud Run job the catalogue's alert filters name (`job_name = one_of(...)` or `= "..."`)."""
        return self._named("job_name")

    def schedules_named(self) -> set[str]:
        return self._named("job_id")

    def databases_named(self) -> set[str]:
        return set(re.findall(r'database_id = ends_with\(":([a-z0-9-]+)"\)', self.text))

    def _named(self, label: str) -> set[str]:
        found: set[str] = set()
        for args in re.findall(rf"resource\.labels\.{label} = one_of\(([^)]*)\)", self.text):
            found.update(re.findall(r'"([^"]+)"', args))
        found.update(re.findall(rf'resource\.labels\.{label}\s*=\s*"([^"]+)"', self.text))
        return found


# Where each role's metrics live, by environment root (tpa-platform docs/infra/monitoring.md §1): beta merges the
# CRM into the app project (R282) and gives the call centre its own; production-full gives the CRM its own and has no
# call centre. In a shared project the first role in the order app, phi, crm keeps a name, and a later role's
# colliding one takes its role as a prefix (infra/envs/beta/main.tf, local.metric_names): `crm_errors` in beta.
LAYOUTS = {
    "beta": {"app": ["app", "crm"], "phi": ["phi"], "cc": ["cc"]},
    "production-full": {"app": ["app"], "phi": ["phi"], "crm": ["crm"]},
}


def project_names(catalogue: Catalogue, layout: dict[str, list[str]]) -> dict[str, dict[str, str]]:
    """role -> {the name its metric has in its project: the catalogue's name}, for one environment's layout."""
    names: dict[str, dict[str, str]] = {}
    for roles in layout.values():
        taken = set(catalogue.shared)
        for role in roles:
            mine = {}
            for name in catalogue.roles[role]:
                mine[f"{role}_{name}" if name in taken else name] = name
            names[role] = mine
            taken |= set(catalogue.roles[role])
    return names
