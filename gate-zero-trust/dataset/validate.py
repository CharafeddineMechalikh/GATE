"""Validation and reporting for the GATE Zero-Trust benchmark dataset.

Runs the twelve checks required by the Phase-1 completion gate and writes both a
machine-readable report (``out/validation.json``) and a human-readable one
(``out/validation.md``). Exit code 1 if any hard check fails.

    python dataset/validate.py
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, List, Tuple

import jsonschema

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

from dataset.external.adapter import EXTERNAL_SUBTYPES  # noqa: E402
from dataset.generator.build import build_dataset, serialise  # noqa: E402
from dataset.generator.taxonomy import CATEGORIES, GENERATOR_VERSION, LAYERS, SCHEMA_VERSION, load_specs  # noqa: E402

DATASET = ROOT / "out" / "dataset.jsonl"
MANIFEST = ROOT / "out" / "manifest.json"
SCHEMA = ROOT / "schema" / "attack_case.schema.json"
REPORT_JSON = ROOT / "out" / "validation.json"
REPORT_MD = ROOT / "out" / "validation.md"

ID_RE = re.compile(r"^ZT-([A-KX]\d{2}|BEN)-L([123])-(\d{4})$")
LAYER_VALUES = {"must_deny", "must_require_approval", "must_allow", "not_required"}
DECISION_TO_LABEL = {"DENY": "must_deny", "REQUIRE_APPROVAL": "must_require_approval", "ALLOW": "must_allow"}
EXECUTION_BY_DECISION = {"DENY": "not_executed", "REQUIRE_APPROVAL": "withheld", "ALLOW": "executed"}


def load() -> List[Dict[str, Any]]:
    return [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines() if line.strip()]


def is_imported(row: Dict[str, Any]) -> bool:
    return (row.get("provenance") or {}).get("source") == "external_import"


def _norm_text(value: Any) -> str:
    return re.sub(r"[^a-z0-9 ]+", " ", str(value).lower()).strip()


def _shingles(text: str, k: int = 3) -> set:
    words = _norm_text(text).split()
    if len(words) < k:
        return {tuple(words)}
    return {tuple(words[i:i + k]) for i in range(len(words) - k + 1)}


class Report:
    def __init__(self) -> None:
        self.checks: List[Dict[str, Any]] = []

    def add(self, name: str, passed: bool, detail: str, evidence: Any = None) -> None:
        self.checks.append({"check": name, "passed": bool(passed), "detail": detail, "evidence": evidence})

    @property
    def failures(self) -> List[Dict[str, Any]]:
        return [c for c in self.checks if not c["passed"]]


def check_schema(rows, schema, rep: Report) -> None:
    validator = jsonschema.Draft7Validator(schema)
    errors = []
    for row in rows:
        for err in validator.iter_errors(row):
            errors.append({"case_id": row.get("case_id"), "path": list(err.path), "message": err.message})
            if len(errors) >= 50:
                break
        if len(errors) >= 50:
            break
    rep.add("schema_correctness", not errors, f"{len(rows)} rows checked against {SCHEMA.name}; {len(errors)} violations",
            {"violations": errors[:10]})


def check_unique_ids(rows, rep: Report) -> None:
    ids = [r["case_id"] for r in rows]
    dupes = sorted({i for i, n in Counter(ids).items() if n > 1})
    rep.add("unique_ids", not dupes, f"{len(ids)} ids, {len(set(ids))} distinct, {len(dupes)} duplicated",
            {"duplicates": dupes[:20]})


def check_id_encoding(rows, rep: Report) -> None:
    bad = []
    for r in rows:
        m = ID_RE.match(r["case_id"])
        if not m:
            bad.append({"case_id": r["case_id"], "error": "pattern"})
            continue
        code, level = m.group(1), int(m.group(2))
        if r["execution_level"] != level:
            bad.append({"case_id": r["case_id"], "error": f"level {r['execution_level']} != id {level}"})
        if r["is_malicious"]:
            if code == "BEN" or code != r["subtype"]:
                bad.append({"case_id": r["case_id"], "error": f"id code {code} != subtype {r['subtype']}"})
        elif code != "BEN":
            bad.append({"case_id": r["case_id"], "error": "benign case without BEN id"})
    rep.add("id_encoding", not bad, f"{len(rows)} ids decoded; {len(bad)} inconsistent", {"violations": bad[:20]})


def check_mandatory_fields(rows, schema, rep: Report) -> None:
    required = set(schema["required"])
    missing = defaultdict(list)
    empty = []
    for r in rows:
        for key in required - set(r):
            missing[key].append(r["case_id"])
        for key in required & set(r):
            if r[key] is None and key != "contextual_constraint":
                empty.append({"case_id": r["case_id"], "field": key})
    ok = not missing and not empty
    rep.add("mandatory_fields", ok,
            f"{len(required)} required fields; {sum(len(v) for v in missing.values())} missing, {len(empty)} null",
            {"missing": {k: v[:5] for k, v in missing.items()}, "null": empty[:10]})


def check_taxonomy(rows, rep: Report) -> None:
    specs = {s.code: s for s in load_specs()}
    bad = []
    for r in rows:
        if is_imported(r):
            # Imported rows keep their source family code instead of being
            # forced into an authored subtype. They are single calls, and the
            # subtype's layer must be the one the source label names.
            if r["category"] != "X":
                bad.append({"case_id": r["case_id"], "error": "imported row outside category X"})
            if not r["is_malicious"]:
                if r["subtype"] != "X08" or r["expected_enforcing_layer"] != "none":
                    bad.append({"case_id": r["case_id"], "error": "imported benign row mislabelled"})
                continue
            info = EXTERNAL_SUBTYPES.get(r["subtype"])
            if info is None:
                bad.append({"case_id": r["case_id"], "error": f"unknown imported subtype {r['subtype']}"})
            elif info["layer"] != r["expected_enforcing_layer"]:
                bad.append({"case_id": r["case_id"],
                            "error": f"imported layer {r['expected_enforcing_layer']} != subtype {info['layer']}"})
            if r["execution_level"] != 1:
                bad.append({"case_id": r["case_id"], "error": "imported row is not a single call"})
            continue
        if r["category"] == "X":
            bad.append({"case_id": r["case_id"], "error": "authored row in the imported category"})
        if not r["is_malicious"]:
            if r["subtype"] != "BEN" and not r["case_id"].startswith("ZT-BEN"):
                bad.append({"case_id": r["case_id"], "error": "benign row carries a taxonomy subtype"})
            continue
        spec = specs.get(r["subtype"])
        if spec is None:
            bad.append({"case_id": r["case_id"], "error": f"unknown subtype {r['subtype']}"})
            continue
        if spec.category != r["category"]:
            bad.append({"case_id": r["case_id"], "error": f"subtype category {spec.category} != {r['category']}"})
        if r["execution_level"] not in spec.levels:
            bad.append({"case_id": r["case_id"], "error": f"level {r['execution_level']} not declared for {spec.code}"})
        # At level 1 the declared layer must be the one that catches the call. At
        # levels 2 and 3 a different layer may legitimately catch the composition,
        # so only require that the enforcing layer is a known layer.
        if r["execution_level"] == 1 and spec.layer != r["expected_enforcing_layer"]:
            bad.append({"case_id": r["case_id"], "error": f"layer {r['expected_enforcing_layer']} != spec {spec.layer}"})
        if r["execution_level"] != 1 and r["expected_enforcing_layer"] not in LAYERS:
            bad.append({"case_id": r["case_id"], "error": f"unknown layer {r['expected_enforcing_layer']}"})
    rep.add("category_and_subtype_assignments", not bad,
            f"{len(specs)} declared subtypes; {sum(1 for r in rows if r['is_malicious'])} malicious rows; {len(bad)} violations",
            {"violations": bad[:20]})


def check_levels(rows, rep: Report) -> None:
    levels = Counter(r["execution_level"] for r in rows)
    invalid = [r["case_id"] for r in rows if r["execution_level"] not in (1, 2, 3)]
    rep.add("execution_levels", not invalid and set(levels) == {1, 2, 3},
            f"levels present {sorted(levels)}; {len(invalid)} invalid", dict(sorted(levels.items())))


def check_label_consistency(rows, rep: Report) -> None:
    bad = []
    for r in rows:
        labels = r["labels"]
        if labels["overall"] != r["expected_decision"]:
            bad.append({"case_id": r["case_id"], "error": "labels.overall != expected_decision"})
        per = labels["per_layer"]
        if set(per) != set(LAYERS):
            bad.append({"case_id": r["case_id"], "error": f"per_layer keys {sorted(per)}"})
            continue
        if set(per.values()) - LAYER_VALUES:
            bad.append({"case_id": r["case_id"], "error": "unknown per-layer label"})
        if r["is_malicious"]:
            designated = per[r["expected_enforcing_layer"]]
            if designated != DECISION_TO_LABEL[r["expected_decision"]]:
                bad.append({"case_id": r["case_id"],
                            "error": f"designated layer label {designated} != {DECISION_TO_LABEL[r['expected_decision']]}"})
            others = [k for k in LAYERS if k != r["expected_enforcing_layer"] and per[k] != "not_required"]
            if others:
                bad.append({"case_id": r["case_id"], "error": f"additional layers required: {others}"})
        else:
            if set(per.values()) != {"must_allow"}:
                bad.append({"case_id": r["case_id"], "error": "benign row requires a layer to deny"})
    rep.add("ground_truth_labels", not bad, f"{len(rows)} rows; {len(bad)} label inconsistencies",
            {"violations": bad[:20]})


def check_outcomes(rows, rep: Report) -> None:
    bad = []
    for r in rows:
        decision = r["expected_decision"]
        executed = r["expected_state_after"]["execution"]
        if executed != EXECUTION_BY_DECISION[decision]:
            bad.append({"case_id": r["case_id"], "error": f"{decision} but execution={executed}"})
        layer = r["expected_enforcing_layer"]
        if r["is_malicious"]:
            if decision not in ("DENY", "REQUIRE_APPROVAL"):
                bad.append({"case_id": r["case_id"], "error": f"malicious row expects {decision}"})
            if layer not in LAYERS:
                bad.append({"case_id": r["case_id"], "error": f"unknown enforcing layer {layer}"})
            if decision == "REQUIRE_APPROVAL" and layer != "hitl" and not is_imported(r):
                # Authored approval cases are raised by HITL only. An imported
                # source may label a call "escalate" at another stage; its
                # label is preserved verbatim and the run reports the mismatch.
                bad.append({"case_id": r["case_id"], "error": "approval demanded by a non-HITL layer"})
            if decision == "DENY" and layer == "hitl" and not is_imported(r):
                bad.append({"case_id": r["case_id"], "error": "HITL layer hard-denies"})
            if not r["policy"]["violated"]:
                bad.append({"case_id": r["case_id"], "error": "no violated policy declared"})
            state = r["expected_state_after"]["agent_state"]
            if decision == "DENY" and not state.get("blocked"):
                bad.append({"case_id": r["case_id"], "error": "denied action not marked blocked"})
            if decision == "REQUIRE_APPROVAL" and not state.get("pending_approval"):
                bad.append({"case_id": r["case_id"], "error": "approval case not marked pending"})
        else:
            if decision != "ALLOW" or layer != "none":
                bad.append({"case_id": r["case_id"], "error": f"benign row {decision}/{layer}"})
            if r["policy"]["violated"]:
                bad.append({"case_id": r["case_id"], "error": "benign row violates a policy"})
    rep.add("expected_outcomes", not bad, f"{len(rows)} rows; {len(bad)} outcome inconsistencies",
            {"violations": bad[:20]})


def check_sequences(rows, rep: Report) -> None:
    bad = []
    for r in rows:
        seq = r["expected_sequence"]
        level = r["execution_level"]
        if level == 1 and len(seq) != 1:
            bad.append({"case_id": r["case_id"], "error": f"level 1 with {len(seq)} steps"})
        if level == 2 and len(seq) < 2:
            bad.append({"case_id": r["case_id"], "error": "compositional attack with a single step"})
        if [s["step"] for s in seq] != list(range(1, len(seq) + 1)):
            bad.append({"case_id": r["case_id"], "error": "step numbers not 1..n"})
        last = seq[-1]
        if last["tool"] != r["proposed_action"]["tool"] or last["args"] != r["proposed_action"]["args"]:
            bad.append({"case_id": r["case_id"], "error": "proposed action is not the final step"})
        if r["is_malicious"]:
            earlier = seq[:-1]
            if any(s["decision"] != "ALLOW" for s in earlier):
                bad.append({"case_id": r["case_id"], "error": "an intermediate step is denied"})
            if last["decision"] != r["expected_decision"] or last["enforcing_layer"] != r["expected_enforcing_layer"]:
                bad.append({"case_id": r["case_id"], "error": "final step decision/layer differs from the case"})
        else:
            if any(s["decision"] != "ALLOW" for s in seq):
                bad.append({"case_id": r["case_id"], "error": "benign sequence contains a denial"})
        if level == 2:
            initial = r["environment"]["initial_state"]
            for i, s in enumerate(seq):
                expected_before = initial if i == 0 else seq[i - 1]["state_after"]
                if s["state_before"] != expected_before:
                    bad.append({"case_id": r["case_id"], "error": f"state not carried into step {i + 1}"})
                    break
        if level == 3 and not r["contextual_constraint"]:
            bad.append({"case_id": r["case_id"], "error": "contextual attack without a declared constraint"})
        if level != 3 and r["contextual_constraint"]:
            bad.append({"case_id": r["case_id"], "error": "constraint declared on a non-contextual case"})
        if r["contextual_constraint"]:
            keys = {"constraint", "original_objective", "violated_aspect"}
            if not keys <= set(r["contextual_constraint"]):
                bad.append({"case_id": r["case_id"], "error": f"constraint keys {sorted(r['contextual_constraint'])}"})
    rep.add("sequence_consistency", not bad, f"{len(rows)} sequences; {len(bad)} violations",
            {"violations": bad[:20]})


def check_benign(rows, rep: Report) -> None:
    benign = [r for r in rows if not r["is_malicious"]]
    hard = [r for r in benign if r["difficulty"] in ("hard_negative", "contextual_hard")]
    tools = Counter(r["proposed_action"]["tool"] for r in benign)
    levels = Counter(r["execution_level"] for r in benign)
    ok = bool(benign) and len(tools) >= 8 and bool(hard) and set(levels) == {1, 2, 3}
    rep.add("benign_and_hard_negatives", ok,
            f"{len(benign)} benign ({len(hard)} hard negatives) across {len(tools)} tools and levels {sorted(levels)}",
            {"by_tool": dict(sorted(tools.items())), "by_level": dict(sorted(levels.items()))})


def check_distributions(rows, rep: Report) -> dict:
    malicious = [r for r in rows if r["is_malicious"]]
    dist = {
        "total": len(rows),
        "malicious": len(malicious),
        "benign": len(rows) - len(malicious),
        "by_category": dict(sorted(Counter(r["category"] for r in rows).items())),
        "by_subtype": dict(sorted(Counter(r["subtype"] for r in rows if r["is_malicious"]).items())),
        "by_level": dict(sorted(Counter(r["execution_level"] for r in rows).items())),
        "by_level_malicious": dict(sorted(Counter(r["execution_level"] for r in malicious).items())),
        "by_enforcing_layer": dict(sorted(Counter(r["expected_enforcing_layer"] for r in malicious).items())),
        "by_severity": dict(sorted(Counter(r["severity"] for r in rows).items())),
        "by_difficulty": dict(sorted(Counter(f"{'malicious' if r['is_malicious'] else 'benign'}/{r['difficulty']}" for r in rows).items())),
        "by_tool": dict(sorted(Counter(r["proposed_action"]["tool"] for r in rows).items())),
        "by_tenant": dict(sorted(Counter(r["environment"]["tenant_id"] for r in rows).items())),
    }
    sub_by_cat = defaultdict(set)
    for r in malicious:
        sub_by_cat[r["category"]].add(r["subtype"])
    # The ten-subtype rule is a property of the authored taxonomy. Imported
    # rows use one family code per source and layer, so category X is exempt.
    thin = {c: sorted(s) for c, s in sub_by_cat.items()
            if c != "X" and len(s) < 10}
    authored = {c: s for c, s in sub_by_cat.items() if c != "X"}
    rep.add("class_distributions", not thin,
            f"{len(authored)} authored categories, {len(dist['by_subtype'])} subtypes, every authored category with 10 subtypes"
            if not thin else f"categories with fewer than 10 subtypes: {sorted(thin)}",
            {"categories_below_10_subtypes": thin,
             "imported_subtypes": sorted(sub_by_cat.get("X", []))})
    return dist


def check_duplicates(rows, rep: Report) -> None:
    """Distinguish real copies from deliberate look-alikes.

    A repeated payload is only a defect when nothing else separates the cases:
    for benign rows that means the same objective *and* the same action, and for
    malicious rows the same subtype at the same level. Reusing one payload across
    different subtypes or levels is reported as informational, because the
    dataset deliberately mirrors attacks at several execution levels.
    """
    by_case = {r["case_id"]: r for r in rows}
    exact = defaultdict(list)
    for r in rows:
        key = (r["proposed_action"]["tool"], json.dumps(r["proposed_action"]["args"], sort_keys=True))
        exact[key].append(r["case_id"])
    exact_dupes, informational = [], []
    for ids in exact.values():
        if len(ids) < 2:
            continue
        for a, b in combinations(sorted(ids), 2):
            ra, rb = by_case[a], by_case[b]
            same_benign = not ra["is_malicious"] and not rb["is_malicious"] and (
                ra["user_objective"]["text"] == rb["user_objective"]["text"])
            same_malicious = ra["is_malicious"] and rb["is_malicious"] and (
                ra["subtype"] == rb["subtype"] and ra["execution_level"] == rb["execution_level"])
            entry = {"a": a, "b": b,
                     "subtypes": [ra["subtype"], rb["subtype"]],
                     "levels": [ra["execution_level"], rb["execution_level"]]}
            if is_imported(ra) or is_imported(rb):
                # An imported row is identified by its source case, not by the
                # payload: the union pairs one injected call with many distinct
                # user tasks on purpose, and the provenance keeps them apart.
                informational.append(entry)
            elif same_benign or same_malicious:
                exact_dupes.append(entry)
            else:
                informational.append(entry)

    shingles = {r["case_id"]: _shingles(r["scenario"]["description"] + " " + r["expected_reason"]) for r in rows}
    near = []
    by_subtype = defaultdict(list)
    for r in rows:
        by_subtype[(r["subtype"] if r["is_malicious"] else "BEN")].append(r["case_id"])
    for ids in by_subtype.values():
        for a, b in combinations(sorted(ids), 2):
            if is_imported(by_case[a]) or is_imported(by_case[b]):
                continue
            sa, sb = shingles[a], shingles[b]
            if not sa or not sb:
                continue
            j = len(sa & sb) / len(sa | sb)
            if j >= 0.9:
                near.append({"a": a, "b": b, "jaccard": round(j, 3)})
    ok = not exact_dupes and not near
    rep.add("duplicates", ok,
            f"{len(exact_dupes)} copy pairs, {len(near)} near-duplicate description pairs (Jaccard >= 0.9); "
            f"{len(informational)} cross-level/cross-subtype payload reuses (allowed)",
            {"exact": exact_dupes[:10], "near": near[:20], "informational_reuse": informational[:10]})


def check_reproducibility(rows, rep: Report) -> None:
    fresh = build_dataset()
    payload = serialise(fresh)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    on_disk = hashlib.sha256(DATASET.read_bytes()).hexdigest()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    ok = digest == on_disk == manifest["dataset_sha256"] and len(fresh) == len(rows)
    rep.add("reproducibility", ok,
            f"rebuild {'matches' if ok else 'differs from'} the committed dataset",
            {"rebuild_sha256": digest, "file_sha256": on_disk, "manifest_sha256": manifest["dataset_sha256"],
             "rebuild_rows": len(fresh), "file_rows": len(rows)})


def check_manifest(rows, rep: Report) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    computed = {
        "total_cases": len(rows),
        "malicious": sum(1 for r in rows if r["is_malicious"]),
        "benign": sum(1 for r in rows if not r["is_malicious"]),
        "by_level": {str(k): v for k, v in sorted(Counter(r["execution_level"] for r in rows).items())},
        "by_category": dict(sorted(Counter(r["category"] for r in rows).items())),
        "by_subtype": dict(sorted(Counter(r["subtype"] for r in rows).items())),
        "by_enforcing_layer": dict(sorted(Counter(r["expected_enforcing_layer"] for r in rows if r["is_malicious"]).items())),
        "schema_version": SCHEMA_VERSION,
        "generator_version": GENERATOR_VERSION,
    }
    drift = {k: {"manifest": manifest.get(k), "computed": v} for k, v in computed.items() if manifest.get(k) != v}
    rep.add("manifest_matches_dataset", not drift, f"{len(computed)} manifest fields compared; {len(drift)} drift",
            {"drift": drift})


def render_markdown(rep: Report, dist: dict) -> str:
    lines = [
        "# Dataset validation report",
        "",
        f"Schema `{SCHEMA_VERSION}`, generator `{GENERATOR_VERSION}`. "
        f"{dist['total']} cases, {dist['malicious']} malicious, {dist['benign']} benign.",
        "",
        "| # | Check | Result | Detail |",
        "|---|---|---|---|",
    ]
    for i, c in enumerate(rep.checks, 1):
        lines.append(f"| {i} | `{c['check']}` | {'PASS' if c['passed'] else 'FAIL'} | {c['detail'].replace('|', '/')} |")

    lines += ["", "## Distributions", "",
              "| Category | Cases |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in dist["by_category"].items()]
    lines += ["", "| Level | Malicious | Benign |", "|---|---|---|"]
    for lvl in (1, 2, 3):
        m = dist["by_level_malicious"].get(str(lvl), 0)
        lines.append(f"| {lvl} | {m} | {dist['by_level'].get(str(lvl), 0) - m} |")
    lines += ["", "| Enforcing layer | Malicious cases |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in dist["by_enforcing_layer"].items()]
    lines += ["", "| Severity | Cases |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in dist["by_severity"].items()]
    lines += ["", "| Tool | Cases |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in dist["by_tool"].items()]

    lines += ["", "## Check evidence", ""]
    for c in rep.checks:
        if c["evidence"] is not None:
            lines += [f"### {c['check']}", "", "```json",
                      json.dumps(c["evidence"], indent=2, default=str)[:3000], "```", ""]

    failures = rep.failures
    lines += ["## Verdict", "",
              "All twelve checks pass." if not failures else
              f"{len(failures)} of {len(rep.checks)} checks fail: " + ", ".join(f["check"] for f in failures) + "."]
    return "\n".join(lines) + "\n"


def main() -> int:
    rows = load()
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    rep = Report()

    check_schema(rows, schema, rep)
    check_unique_ids(rows, rep)
    check_id_encoding(rows, rep)
    check_mandatory_fields(rows, schema, rep)
    check_taxonomy(rows, rep)
    check_levels(rows, rep)
    check_label_consistency(rows, rep)
    check_outcomes(rows, rep)
    check_sequences(rows, rep)
    check_benign(rows, rep)
    dist = check_distributions(rows, rep)
    check_duplicates(rows, rep)
    check_reproducibility(rows, rep)
    check_manifest(rows, rep)

    payload = {"checks": rep.checks, "distributions": dist, "passed": not rep.failures}
    REPORT_JSON.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8", newline="\n")
    REPORT_MD.write_text(render_markdown(rep, dist), encoding="utf-8", newline="\n")

    for c in rep.checks:
        print(f"{'PASS' if c['passed'] else 'FAIL'}  {c['check']:32s} {c['detail']}")
    print(f"\nwrote {REPORT_JSON} and {REPORT_MD}")
    return 0 if not rep.failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
