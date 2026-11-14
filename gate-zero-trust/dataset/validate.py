"""Validation and reporting for the GATE Zero-Trust benchmark dataset.

Runs the structural, coverage and separation checks required by the Phase-1 completion gate and writes both a
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
        elif r["expected_decision"] == "REQUIRE_APPROVAL":
            # A benign task that policy routes to a human: HITL must hold it and
            # every other layer must let it through.
            if r["expected_enforcing_layer"] != "hitl":
                bad.append({"case_id": r["case_id"], "error": "gated benign task not raised by HITL"})
            others = [k for k in LAYERS if k != "hitl" and per[k] != "must_allow"]
            if per["hitl"] != "must_require_approval" or others:
                bad.append({"case_id": r["case_id"], "error": "gated benign row has the wrong per-layer labels"})
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
            if decision == "REQUIRE_APPROVAL":
                if layer != "hitl":
                    bad.append({"case_id": r["case_id"], "error": f"gated benign row raised by {layer}"})
                if not r["expected_state_after"]["agent_state"].get("pending_approval"):
                    bad.append({"case_id": r["case_id"], "error": "gated benign row not marked pending"})
                if r["impact"]["authorization_violation"]:
                    bad.append({"case_id": r["case_id"], "error": "gated benign row claims an authorisation violation"})
            elif decision != "ALLOW" or layer != "none":
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
            gated = r["expected_decision"] == "REQUIRE_APPROVAL"
            earlier = seq[:-1] if gated else seq
            if any(s["decision"] != "ALLOW" for s in earlier):
                bad.append({"case_id": r["case_id"], "error": "benign sequence contains a denial"})
            if gated and (last["decision"] != "REQUIRE_APPROVAL" or last["enforcing_layer"] != "hitl"):
                bad.append({"case_id": r["case_id"], "error": "gated benign final step is not held by HITL"})
            if not gated and any(s["decision"] != "ALLOW" for s in seq):
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
        "by_complexity": dict(sorted(Counter(r["attack_complexity"] for r in rows).items())),
        "approval_gated_benign": sum(
            1 for r in rows if not r["is_malicious"] and r["expected_decision"] == "REQUIRE_APPROVAL"
        ),
        "schema_version": SCHEMA_VERSION,
        "generator_version": GENERATOR_VERSION,
    }
    drift = {k: {"manifest": manifest.get(k), "computed": v} for k, v in computed.items() if manifest.get(k) != v}
    rep.add("manifest_matches_dataset", not drift, f"{len(computed)} manifest fields compared; {len(drift)} drift",
            {"drift": drift})


AUTHORED_CATEGORIES = "ABCDEFGHIJK"
COMPLEXITY_BY_LEVEL = {1: "atomic", 2: "compositional", 3: "contextual"}
COMPLEXITIES = ("atomic", "compositional", "contextual")
COVERAGE_MIN = {"atomic": 20, "compositional": 15, "contextual": 15}
MAX_SUBTYPE_SHARE = 0.4
MIN_CONTEXTUAL_SUBTYPES = 4

COVERAGE_JSON = ROOT / "out" / "coverage.json"
COVERAGE_CSV = ROOT / "out" / "coverage.csv"
COVERAGE_MD = ROOT / "out" / "coverage.md"


def _authored_malicious(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [r for r in rows if r["is_malicious"] and r["category"] in AUTHORED_CATEGORIES]


def check_coverage(rows, rep: Report) -> dict:
    """Every authored category must meet the atomic/compositional/contextual floors."""
    counts: Dict[str, Counter] = defaultdict(Counter)
    for r in _authored_malicious(rows):
        counts[r["category"]][r["attack_complexity"]] += 1
    short = []
    for cat in AUTHORED_CATEGORIES:
        for comp in COMPLEXITIES:
            have = counts[cat].get(comp, 0)
            if have < COVERAGE_MIN[comp]:
                short.append({"category": cat, "complexity": comp, "count": have,
                              "minimum": COVERAGE_MIN[comp]})
    rep.add("coverage_requirements", not short,
            f"{len(AUTHORED_CATEGORIES)} authored categories against "
            f"{COVERAGE_MIN['atomic']}/{COVERAGE_MIN['compositional']}/{COVERAGE_MIN['contextual']}; "
            f"{len(short)} below floor",
            {"below_floor": short,
             "by_category": {c: {k: counts[c].get(k, 0) for k in COMPLEXITIES}
                             for c in AUTHORED_CATEGORIES}})
    return counts


def check_spread(rows, rep: Report) -> dict:
    """No single subcategory may dominate a category at one complexity."""
    by: Dict[Tuple[str, str], Counter] = defaultdict(Counter)
    names: Dict[str, str] = {}
    for r in _authored_malicious(rows):
        by[(r["category"], r["attack_complexity"])][r["subcategory"]] += 1
        names[r["subcategory"]] = r["subcategory_name"]
    concentrated, thin = [], []
    for (cat, comp), counter in sorted(by.items()):
        total = sum(counter.values())
        top, hits = counter.most_common(1)[0]
        share = hits / total
        if share > MAX_SUBTYPE_SHARE:
            concentrated.append({"category": cat, "complexity": comp, "subcategory": top,
                                 "count": hits, "total": total, "share": round(share, 3)})
    for cat in AUTHORED_CATEGORIES:
        for comp in ("compositional", "contextual"):
            n = len(by.get((cat, comp), {}))
            if n < MIN_CONTEXTUAL_SUBTYPES:
                thin.append({"category": cat, "complexity": comp, "distinct_subtypes": n,
                             "minimum": MIN_CONTEXTUAL_SUBTYPES})
    ok = not concentrated and not thin
    rep.add("subcategory_spread", ok,
            f"max subcategory share {MAX_SUBTYPE_SHARE:.0%} per category/complexity and "
            f">= {MIN_CONTEXTUAL_SUBTYPES} distinct subcategories at levels 2-3; "
            f"{len(concentrated)} concentrated, {len(thin)} thin",
            {"concentrated": concentrated, "thin": thin,
             "matrix": {f"{c}/{k}": dict(sorted(v.items())) for (c, k), v in sorted(by.items())}})
    return by


def check_record_metadata(rows, rep: Report) -> None:
    """The derived acceptance fields must agree with the record they describe."""
    bad = []
    for r in rows:
        level = int(r["execution_level"])
        if r["attack_complexity"] != COMPLEXITY_BY_LEVEL[level]:
            bad.append({"case_id": r["case_id"], "error": "attack_complexity != execution_level"})
        if r["subcategory"] != r["subtype"]:
            bad.append({"case_id": r["case_id"], "error": "subcategory != subtype"})
        if r["subcategory_name"] != r["subtype_name"]:
            bad.append({"case_id": r["case_id"], "error": "subcategory_name != subtype_name"})
        if not r["trust_boundaries"]:
            bad.append({"case_id": r["case_id"], "error": "no trust boundary declared"})
        if r["violated_property"] != r["policy"]["violated"]:
            bad.append({"case_id": r["case_id"], "error": "violated_property != policy.violated"})
        layer = r["expected_enforcing_layer"]
        if r["defense_layers"] != ([layer] if layer != "none" else []):
            bad.append({"case_id": r["case_id"], "error": "defense_layers != enforcing layer"})
        if not r["rationale"] or r["rationale"] != r["expected_reason"]:
            bad.append({"case_id": r["case_id"], "error": "rationale missing or differs from reason"})
        if r["difficulty"] not in ("easy", "moderate", "hard_negative", "contextual_hard", "ambiguous"):
            bad.append({"case_id": r["case_id"], "error": f"unknown difficulty {r['difficulty']}"})
    rep.add("record_metadata", not bad,
            f"{len(rows)} records carry consistent complexity, boundary, property, layer and rationale fields; "
            f"{len(bad)} inconsistencies", {"violations": bad[:20]})


def check_separability(rows, rep: Report) -> None:
    """Attacks must violate something; benign rows must not. Identical calls are
    allowed only when the context that makes them different is recorded."""
    authored = [r for r in rows if r["category"] != "X"]
    bad = []
    for r in authored:
        violates = bool(r["violated_property"])
        decision = r["expected_decision"]
        if r["is_malicious"]:
            if decision == "ALLOW" or not violates:
                bad.append({"case_id": r["case_id"], "error": "attack without a non-ALLOW decision or violated property"})
        else:
            if decision == "DENY" or violates:
                bad.append({"case_id": r["case_id"], "error": "benign row denies or violates a property"})
    attack_tools = {r["proposed_action"]["tool"] for r in rows if r["is_malicious"]}
    benign_tools = {r["proposed_action"]["tool"] for r in rows if not r["is_malicious"]}
    unexercised = sorted(attack_tools - benign_tools)

    def call(r):
        return (r["proposed_action"]["tool"],
                json.dumps(r["proposed_action"]["args"], sort_keys=True))

    attacks: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)
    benign: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)
    for r in authored:
        (attacks if r["is_malicious"] else benign)[call(r)].append(r)
    shared = sorted(set(attacks) & set(benign), key=str)
    indistinguishable = []
    for key in shared:
        for a in attacks[key]:
            for b in benign[key]:
                same_objective = a["user_objective"]["text"] == b["user_objective"]["text"]
                same_state = a["environment"]["initial_state"] == b["environment"]["initial_state"]
                if same_objective and same_state:
                    indistinguishable.append({"attack": a["case_id"], "benign": b["case_id"]})
    ok = not bad and not unexercised and not indistinguishable
    rep.add("attack_benign_separation", ok,
            f"{len(authored)} authored rows; {len(bad)} label errors, "
            f"{len(unexercised)} tools with no benign exercise, "
            f"{len(shared)} shared call shapes ({len(indistinguishable)} without differing context)",
            {"label_errors": bad[:20], "unexercised_tools": unexercised,
             "shared_call_shapes": len(shared), "indistinguishable": indistinguishable[:10]})


def coverage_matrix(rows) -> Dict[str, Any]:
    """Per-category and per-subcategory counts across complexity and layer."""
    matrix: Dict[str, Any] = {}
    for r in rows:
        cat = r["category"]
        entry = matrix.setdefault(cat, {
            "category_name": r["category_name"],
            "total": 0, "malicious": 0, "benign": 0,
            "by_complexity": {k: 0 for k in COMPLEXITIES},
            "by_decision": Counter(), "by_layer": Counter(),
            "subcategories": {},
        })
        entry["total"] += 1
        if r["is_malicious"]:
            entry["malicious"] += 1
            entry["by_complexity"][r["attack_complexity"]] += 1
            entry["by_layer"][r["expected_enforcing_layer"]] += 1
        else:
            entry["benign"] += 1
        entry["by_decision"][r["expected_decision"]] += 1
        sub = entry["subcategories"].setdefault(
            r["subcategory"], {"subcategory_name": r["subcategory_name"], "malicious": 0,
                               "benign": 0, "by_complexity": {k: 0 for k in COMPLEXITIES},
                               "layers": set()})
        if r["is_malicious"]:
            sub["malicious"] += 1
            sub["by_complexity"][r["attack_complexity"]] += 1
            sub["layers"].add(r["expected_enforcing_layer"])
        else:
            sub["benign"] += 1
    out: Dict[str, Any] = {}
    for cat, entry in matrix.items():
        e = dict(entry)
        e["by_decision"] = dict(sorted(entry["by_decision"].items()))
        e["by_layer"] = dict(sorted(entry["by_layer"].items()))
        e["subcategories"] = {}
        for code, sub in sorted(entry["subcategories"].items()):
            s = dict(sub)
            s["layers"] = sorted(sub["layers"])
            e["subcategories"][code] = s
        out[cat] = e
    return out


def write_coverage(rows, rep: Report) -> Dict[str, Any]:
    matrix = coverage_matrix(rows)
    authored = {c: matrix[c] for c in AUTHORED_CATEGORIES if c in matrix}
    requirements = {
        "atomic_min": COVERAGE_MIN["atomic"],
        "compositional_min": COVERAGE_MIN["compositional"],
        "contextual_min": COVERAGE_MIN["contextual"],
        "max_subtype_share": MAX_SUBTYPE_SHARE,
        "min_distinct_contextual_subtypes": MIN_CONTEXTUAL_SUBTYPES,
    }
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generator_version": GENERATOR_VERSION,
        "requirements": requirements,
        "authored_categories": authored,
        "imported_category_X": matrix.get("X"),
        "categories": matrix,
    }
    COVERAGE_JSON.write_text(json.dumps(payload, indent=2, default=str) + "\n",
                             encoding="utf-8", newline="\n")

    csv_lines = ["category,category_name,subcategory,subcategory_name,atomic,compositional,contextual,total_malicious,benign,layers"]
    for cat, entry in matrix.items():
        for code, sub in entry["subcategories"].items():
            b = sub["by_complexity"]
            csv_lines.append(",".join([
                cat, f"\"{entry['category_name']}\"", code, f"\"{sub['subcategory_name']}\"",
                str(b["atomic"]), str(b["compositional"]), str(b["contextual"]),
                str(sub["malicious"]), str(sub["benign"]), '"' + "|".join(sub["layers"]) + '"',
            ]))
    COVERAGE_CSV.write_text("\n".join(csv_lines) + "\n", encoding="utf-8", newline="\n")

    md = ["# Coverage matrix", "",
          f"Schema `{SCHEMA_VERSION}`, generator `{GENERATOR_VERSION}`. "
          f"Floors: {COVERAGE_MIN['atomic']} atomic, {COVERAGE_MIN['compositional']} compositional, "
          f"{COVERAGE_MIN['contextual']} contextual per authored category.", "",
          "## Authored categories", "",
          "| Cat | Name | Atomic | Compositional | Contextual | Malicious | Benign | Layers |",
          "|---|---|---|---|---|---|---|---|"]
    for cat, e in authored.items():
        b = e["by_complexity"]
        md.append(f"| {cat} | {e['category_name']} | {b['atomic']} | {b['compositional']} | "
                  f"{b['contextual']} | {e['malicious']} | {e['benign']} | "
                  f"{', '.join(e['by_layer'])} |")
    imported = matrix.get("X")
    if imported:
        b = imported["by_complexity"]
        md.append(f"| X | {imported['category_name']} (imported) | {b['atomic']} | "
                  f"{b['compositional']} | {b['contextual']} | {imported['malicious']} | "
                  f"{imported['benign']} | {', '.join(imported['by_layer'])} |")
    md += ["", "## Subcategory matrix", "",
           "| Category | Subcategory | Name | Atomic | Comp | Ctx | Layers |",
           "|---|---|---|---|---|---|---|"]
    for cat, entry in matrix.items():
        for code, sub in entry["subcategories"].items():
            b = sub["by_complexity"]
            md.append(f"| {cat} | {code} | {sub['subcategory_name']} | {b['atomic']} | "
                      f"{b['compositional']} | {b['contextual']} | {', '.join(sub['layers']) or '-'} |")
    COVERAGE_MD.write_text("\n".join(md) + "\n", encoding="utf-8", newline="\n")
    return payload


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
              f"All {len(rep.checks)} checks pass." if not failures else
              f"{len(failures)} of {len(rep.checks)} checks fail: " + ", ".join(f["check"] for f in failures) + ".",
              "", f"Coverage matrix: `{COVERAGE_MD.name}`, `{COVERAGE_CSV.name}`, `{COVERAGE_JSON.name}`."]
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
    check_coverage(rows, rep)
    check_spread(rows, rep)
    check_record_metadata(rows, rep)
    check_separability(rows, rep)
    coverage = write_coverage(rows, rep)

    payload = {"checks": rep.checks, "distributions": dist, "coverage": coverage,
               "passed": not rep.failures}
    REPORT_JSON.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8", newline="\n")
    REPORT_MD.write_text(render_markdown(rep, dist), encoding="utf-8", newline="\n")

    for c in rep.checks:
        print(f"{'PASS' if c['passed'] else 'FAIL'}  {c['check']:32s} {c['detail']}")
    print(f"\nwrote {REPORT_JSON} and {REPORT_MD}")
    return 0 if not rep.failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
