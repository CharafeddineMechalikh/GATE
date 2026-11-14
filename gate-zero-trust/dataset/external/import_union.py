"""Freeze the externally sourced rows of the GATE-Union corpus.

The GATE benchmark is not authored end to end: cases that already exist in
public datasets are imported instead of being re-invented. This script selects
the non-authored rows of the union corpus, keeps their provenance, and freezes
them into ``union_external.jsonl`` so that ``build.py`` can rebuild the dataset
offline and byte-identically.

Selection rules (see ``union_external.manifest.json`` for the exact counts):
  * ``source_dataset`` is one of injecagent, gate_original, safeclawbench;
  * rows flagged ``label_conflict`` are dropped: the union could not reconcile
    their layer with the source's own stage, so they carry no trustworthy label;
  * AgentDojo is excluded on purpose. It is the held-out test suite and must not
    appear in a corpus the monitor is evaluated on.

The frozen rows are the raw union records, unmodified. Conversion to the GATE
case schema happens in ``adapter.py`` at build time.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).resolve().parent
DEFAULT_UNION = HERE.parents[2] / "gate-union"
SOURCES = ("injecagent", "gate_original", "safeclawbench")
EXCLUDED = ("agentdojo", "agent_dojo")
SPLITS = ("calibration", "dev", "test")
OUT_ROWS = HERE / "union_external.jsonl"
OUT_MANIFEST = HERE / "union_external.manifest.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_union(union_root: Path) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    digests: Dict[str, str] = {}
    counts: Dict[str, Dict[str, int]] = {}
    for split in SPLITS:
        path = union_root / "splits" / f"{split}.jsonl"
        if not path.exists():
            raise SystemExit(f"missing union split: {path}")
        digests[split] = _sha256(path)
        seen = 0
        split_rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            seen += 1
            row = json.loads(line)
            split_rows.append(row)
        counts[split] = {"rows": seen}
        for row in split_rows:
            row["_split"] = split
        rows.extend(split_rows)
    return rows, {"split_sha256": digests, "split_rows": counts}


def select(rows: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    excluded_present = sorted({r["source_dataset"] for r in rows
                               if str(r["source_dataset"]).lower() in EXCLUDED})
    if excluded_present:
        raise SystemExit(f"held-out sources present in the union splits: {excluded_present}")
    by_source = Counter(r["source_dataset"] for r in rows)
    selected: List[Dict[str, Any]] = []
    dropped_conflict = Counter()
    for row in rows:
        if row["source_dataset"] not in SOURCES:
            continue
        if row.get("label_conflict"):
            dropped_conflict[row["source_dataset"]] += 1
            continue
        selected.append(row)
    selected.sort(key=lambda r: r["case_id"])
    audit = {
        "union_rows": len(rows),
        "by_source_all": dict(sorted(by_source.items())),
        "selected": len(selected),
        "by_source_selected": dict(sorted(Counter(r["source_dataset"] for r in selected).items())),
        "dropped_label_conflict": dict(sorted(dropped_conflict.items())),
        "by_outcome": dict(sorted(Counter(r["expected_outcome"] for r in selected).items())),
        "by_primary_layer": dict(sorted(Counter(r["primary_layer"] or "none" for r in selected).items())),
        "excluded_heldout": list(EXCLUDED),
        "rules": [
            "keep source_dataset in " + ", ".join(SOURCES),
            "drop label_conflict rows",
            "never import the held-out AgentDojo suite",
            "frozen rows are raw union records; the only addition is the _split key",
        ],
    }
    return selected, audit


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Freeze external union rows for the GATE dataset")
    parser.add_argument("--union", type=Path, default=DEFAULT_UNION)
    args = parser.parse_args(argv)

    rows, file_info = load_union(args.union)
    selected, audit = select(rows)
    payload = "\n".join(json.dumps(r, sort_keys=True, ensure_ascii=True) for r in selected) + "\n"
    OUT_ROWS.write_text(payload, encoding="utf-8", newline="\n")
    manifest = {
        **file_info,
        "union_root": str(args.union),
        "output": OUT_ROWS.name,
        "output_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "output_rows": len(selected),
        **audit,
    }
    OUT_MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8", newline="\n")
    print(json.dumps({k: manifest[k] for k in
                      ("output_rows", "by_source_selected", "dropped_label_conflict",
                       "by_outcome", "by_primary_layer", "output_sha256")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
