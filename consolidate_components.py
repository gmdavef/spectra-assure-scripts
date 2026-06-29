#!/usr/bin/env python3
"""Consolidate duplicate components in a CycloneDX 1.6 or 1.7 BOM.

Two top-level components are considered duplicates when:

  1. All of their data is identical *except* their ``bom-ref`` and their
     ``evidence.occurrences`` (the per-location evidence is exactly what is
     expected to differ between copies), and
  2. Their resolved dependencies are the same -- i.e. they depend on the same
     set of components, where two depended-on components count as "the same" if
     they are themselves duplicates. This is computed by iterative
     color-refinement (a fixpoint / bisimulation) so that chains of duplicates
     collapse consistently.

Each group of duplicates is replaced by a single component that:

  * gets a new, unique ``bom-ref``,
  * carries an ``evidence.occurrences`` array that is the union of every
    member's occurrences, deduped by full content, with a fresh ``bom-ref`` on
    each occurrence.

Every ``bom-ref`` reference elsewhere in the document (dependency graph,
metadata.component, compositions, vulnerability affects, annotation subjects,
etc.) is rewritten to point at the consolidated component, and the dependency
graph is then collapsed (duplicate entries merged, ``dependsOn`` deduped,
self-loops removed).

Only the root ``components`` array is deduplicated (nested components are left
untouched).

Usage:
    python consolidate_components.py input.json [-o output.json]
    python consolidate_components.py input.json --dry-run -v
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import uuid
from typing import Any, Dict, List, Optional, Tuple

# Spec versions this tool understands. The consolidation logic only touches
# fields (components, dependencies, evidence.occurrences, and bom-ref
# references) that are structurally identical across these versions.
SUPPORTED_SPEC_VERSIONS = {"1.6", "1.7"}


# --------------------------------------------------------------------------- #
# Canonicalization / comparison helpers
# --------------------------------------------------------------------------- #

def canonical(obj: Any) -> str:
    """Stable, order-independent string form of a JSON value, for comparison."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_key(component: Dict[str, Any], occurrence_match: str) -> str:
    """Build the comparison key for a component.

    Strips the fields that are allowed to differ between duplicates:
      * the top-level ``bom-ref``
      * ``evidence.occurrences`` (mode "ignore-occurrences", the default), or
        just the ``location``/``bom-ref`` of each occurrence (mode
        "location-only").
    """
    c = copy.deepcopy(component)
    c.pop("bom-ref", None)

    evidence = c.get("evidence")
    if isinstance(evidence, dict) and "occurrences" in evidence:
        if occurrence_match == "ignore-occurrences":
            evidence.pop("occurrences", None)
        else:  # "location-only"
            occ_list = evidence.get("occurrences") or []
            stripped = []
            for occ in occ_list:
                if isinstance(occ, dict):
                    o = copy.deepcopy(occ)
                    o.pop("location", None)
                    o.pop("bom-ref", None)
                    stripped.append(o)
                else:
                    stripped.append(occ)
            evidence["occurrences"] = stripped
        # Normalize an emptied evidence object away so it matches components
        # that never had an evidence block at all.
        if not evidence:
            c.pop("evidence", None)

    return canonical(c)


# --------------------------------------------------------------------------- #
# Dependency-aware grouping (color refinement to a fixpoint)
# --------------------------------------------------------------------------- #

def _normalize(labels: List[str]) -> Tuple[List[int], int]:
    """Map an arbitrary list of string labels to dense ints; return (ids, count)."""
    mapping: Dict[str, int] = {}
    out: List[int] = []
    for lab in labels:
        if lab not in mapping:
            mapping[lab] = len(mapping)
        out.append(mapping[lab])
    return out, len(mapping)


def group_duplicates(
    components: List[Dict[str, Any]],
    dependencies: List[Dict[str, Any]],
    occurrence_match: str,
) -> List[List[int]]:
    """Return groups of component indices that are duplicates of one another.

    Uses color refinement: a component's "color" starts from its content key and
    is iteratively refined by the multiset of colors of the components it
    depends on, until the partition stops changing.
    """
    n = len(components)

    # Map bom-ref -> component index (only components that declare one).
    ref_to_idx: Dict[str, int] = {}
    for i, comp in enumerate(components):
        ref = comp.get("bom-ref")
        if isinstance(ref, str):
            ref_to_idx[ref] = i

    # Outgoing dependency targets per component index, taken from the
    # dependency graph (deduped).
    deps_of: List[List[str]] = [[] for _ in range(n)]
    for entry in dependencies or []:
        ref = entry.get("ref")
        if ref not in ref_to_idx:
            continue
        idx = ref_to_idx[ref]
        targets: List[str] = []
        for key in ("dependsOn", "provides"):
            for t in entry.get(key, []) or []:
                if isinstance(t, str):
                    targets.append(t)
        deps_of[idx] = sorted(set(targets))

    # Initial colors come purely from content.
    colors, ncolors = _normalize(
        [content_key(comp, occurrence_match) for comp in components]
    )

    def color_token(dep_ref: str) -> str:
        # Internal targets refine by their current color; unknown/external
        # targets are leaves keyed by the ref string itself.
        if dep_ref in ref_to_idx:
            return "i:%d" % colors[ref_to_idx[dep_ref]]
        return "e:" + dep_ref

    for _ in range(n + 5):
        sigs = []
        for i in range(n):
            dep_colors = sorted(color_token(d) for d in deps_of[i])
            sigs.append(canonical(["c:%d" % colors[i], dep_colors]))
        new_colors, n_new = _normalize(sigs)
        colors = new_colors
        if n_new == ncolors:
            break
        ncolors = n_new

    # Group indices by final color, preserving first-seen order.
    groups: Dict[int, List[int]] = {}
    order: List[int] = []
    for i in range(n):
        c = colors[i]
        if c not in groups:
            groups[c] = []
            order.append(c)
        groups[c].append(i)
    return [groups[c] for c in order]


# --------------------------------------------------------------------------- #
# Consolidation
# --------------------------------------------------------------------------- #

class RefMinter:
    """Generates bom-ref values that are guaranteed unique within the document."""

    def __init__(self, used: set, prefix: Optional[str] = None):
        self.used = used
        self.prefix = prefix
        self.counter = 0

    def mint(self) -> str:
        while True:
            if self.prefix:
                self.counter += 1
                candidate = f"{self.prefix}{self.counter}"
            else:
                candidate = str(uuid.uuid4())
            if candidate not in self.used:
                self.used.add(candidate)
                return candidate


def collect_all_bomrefs(node: Any, acc: set) -> None:
    """Walk the document and collect every value stored under a 'bom-ref' key."""
    if isinstance(node, dict):
        ref = node.get("bom-ref")
        if isinstance(ref, str):
            acc.add(ref)
        for v in node.values():
            collect_all_bomrefs(v, acc)
    elif isinstance(node, list):
        for v in node:
            collect_all_bomrefs(v, acc)


def merge_occurrences(members: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Union the distinct occurrence locations of all members.

    Each consolidated occurrence carries only its ``location`` (the only
    required occurrence field); the optional ``bom-ref`` and any other fields
    are dropped.
    """
    merged: List[Dict[str, Any]] = []
    seen: set = set()
    for comp in members:
        evidence = comp.get("evidence")
        if not isinstance(evidence, dict):
            continue
        for occ in evidence.get("occurrences", []) or []:
            if not isinstance(occ, dict) or "location" not in occ:
                continue
            location = occ["location"]
            if location in seen:
                continue
            seen.add(location)
            merged.append({"location": location})
    return merged


def consolidate_group(
    members: List[Dict[str, Any]],
    minter: RefMinter,
) -> Dict[str, Any]:
    """Build the single component that represents a group of duplicates."""
    consolidated = copy.deepcopy(members[0])
    consolidated["bom-ref"] = minter.mint()

    occurrences = merge_occurrences(members)
    if occurrences:
        evidence = consolidated.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
            consolidated["evidence"] = evidence
        evidence["occurrences"] = occurrences
    elif isinstance(consolidated.get("evidence"), dict):
        consolidated["evidence"].pop("occurrences", None)
        if not consolidated["evidence"]:
            consolidated.pop("evidence", None)

    return consolidated


# --------------------------------------------------------------------------- #
# Reference rewriting
# --------------------------------------------------------------------------- #

def remap_refs(node: Any, mapping: Dict[str, str]) -> None:
    """Rewrite every bom-ref *reference* in the document to its new value.

    A reference is any string equal to an old bom-ref, anywhere except where it
    is the value of a 'bom-ref' key (that is a definition, not a reference).
    bom-ref values are unique identifiers, so matching by string value is safe.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "bom-ref":
                continue  # definition, leave it alone
            if isinstance(value, str):
                if value in mapping:
                    node[key] = mapping[value]
            else:
                remap_refs(value, mapping)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            if isinstance(value, str):
                if value in mapping:
                    node[i] = mapping[value]
            else:
                remap_refs(value, mapping)


def collapse_dependencies(dependencies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """After remapping, merge dependency entries that now share a ref."""
    merged: Dict[str, Dict[str, List[str]]] = {}
    order: List[str] = []
    for entry in dependencies or []:
        ref = entry.get("ref")
        if not isinstance(ref, str):
            continue
        if ref not in merged:
            merged[ref] = {"dependsOn": [], "provides": []}
            order.append(ref)
        for key in ("dependsOn", "provides"):
            for t in entry.get(key, []) or []:
                if isinstance(t, str) and t != ref and t not in merged[ref][key]:
                    merged[ref][key].append(t)

    result: List[Dict[str, Any]] = []
    for ref in order:
        out: Dict[str, Any] = {"ref": ref}
        if merged[ref]["dependsOn"]:
            out["dependsOn"] = merged[ref]["dependsOn"]
        if merged[ref]["provides"]:
            out["provides"] = merged[ref]["provides"]
        result.append(out)
    return result


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #

def consolidate(bom: Dict[str, Any], occurrence_match: str,
                prefix: Optional[str], verbose: bool) -> Dict[str, Any]:
    components = bom.get("components")
    if not isinstance(components, list) or not components:
        print("No top-level 'components' array found; nothing to do.", file=sys.stderr)
        return bom

    dependencies = bom.get("dependencies") or []

    groups = group_duplicates(components, dependencies, occurrence_match)

    used_refs: set = set()
    collect_all_bomrefs(bom, used_refs)
    minter = RefMinter(used_refs, prefix=prefix)

    mapping: Dict[str, str] = {}      # old bom-ref -> new consolidated bom-ref
    new_components: List[Dict[str, Any]] = []
    n_dups = 0

    for group in groups:
        members = [components[i] for i in group]
        if len(members) == 1:
            new_components.append(members[0])
            continue

        n_dups += len(members) - 1
        consolidated = consolidate_group(members, minter)
        new_ref = consolidated["bom-ref"]
        for comp in members:
            old = comp.get("bom-ref")
            if isinstance(old, str):
                mapping[old] = new_ref
        new_components.append(consolidated)

        if verbose:
            name = consolidated.get("name", "<unnamed>")
            version = consolidated.get("version", "")
            olds = ", ".join(m.get("bom-ref", "<none>") for m in members)
            occ = len((consolidated.get("evidence") or {}).get("occurrences", []))
            print(f"  merged {len(members)}x {name}@{version} "
                  f"-> {new_ref} ({occ} occurrences)\n    from: {olds}",
                  file=sys.stderr)

    bom["components"] = new_components

    if mapping:
        remap_refs(bom, mapping)

    if isinstance(bom.get("dependencies"), list):
        bom["dependencies"] = collapse_dependencies(bom["dependencies"])

    print(
        f"Components: {len(components)} -> {len(new_components)} "
        f"({n_dups} duplicate node(s) removed across "
        f"{sum(1 for g in groups if len(g) > 1)} group(s)).",
        file=sys.stderr,
    )
    return bom


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Consolidate duplicate components in a CycloneDX 1.6 or 1.7 BOM."
    )
    parser.add_argument("input", help="Path to the input CycloneDX JSON file.")
    parser.add_argument(
        "-o", "--output",
        help="Path for the consolidated output (default: <input>.dedup.json).",
    )
    parser.add_argument(
        "--occurrence-match",
        choices=["ignore-occurrences", "location-only"],
        default="ignore-occurrences",
        help="How occurrences factor into duplicate comparison. "
             "'ignore-occurrences' (default) treats the whole occurrences array "
             "as the per-copy evidence to ignore; 'location-only' ignores just "
             "the location/bom-ref of each occurrence.",
    )
    parser.add_argument(
        "--bomref-prefix",
        help="If set, new bom-refs are PREFIX1, PREFIX2, ... instead of UUIDs.",
    )
    parser.add_argument("--indent", type=int, default=2, help="Output JSON indent.")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Report what would change without writing an output file.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Print each consolidated group.",
    )
    args = parser.parse_args(argv)

    try:
        with open(args.input, "r", encoding="utf-8") as fh:
            bom = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Failed to read '{args.input}': {exc}", file=sys.stderr)
        return 1

    fmt = bom.get("bomFormat")
    spec = bom.get("specVersion")
    if fmt != "CycloneDX":
        print(f"Warning: bomFormat is {fmt!r}, expected 'CycloneDX'.", file=sys.stderr)
    if spec not in SUPPORTED_SPEC_VERSIONS:
        print(f"Warning: specVersion is {spec!r}, expected one of "
              f"{', '.join(sorted(SUPPORTED_SPEC_VERSIONS))}. Proceeding anyway.",
              file=sys.stderr)

    bom = consolidate(bom, args.occurrence_match, args.bomref_prefix, args.verbose)

    if args.dry_run:
        print("Dry run: no output written.", file=sys.stderr)
        return 0

    output = args.output
    if not output:
        if args.input.lower().endswith(".json"):
            output = args.input[:-5] + ".dedup.json"
        else:
            output = args.input + ".dedup.json"

    try:
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(bom, fh, indent=args.indent, ensure_ascii=False)
            fh.write("\n")
    except OSError as exc:
        print(f"Failed to write '{output}': {exc}", file=sys.stderr)
        return 1

    print(f"Wrote consolidated BOM to '{output}'.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
