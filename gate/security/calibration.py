"""Safe-centroid calibration from the shipped benign call references.

``d_safe`` is the distance from the proposed call to the centroid of benign
calls for the same tool. A store seeded with a handful of calls makes that
distance meaningless, and a store with no centroid at all makes the firewall
fall back to a constant. This module builds the per-tool centroids from the
reference corpus shipped with the package, so a deployment can calibrate
without collecting traffic first.

Calibration is explicit: pass ``semantic_calibration_path`` in the config (or
call :func:`calibrate` on a firewall). Embeddings are cached per corpus path,
so building many monitors over the same corpus pays the embedding cost once.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

DEFAULT_CALLS_PATH = Path(__file__).resolve().parents[1] / "benign_calls.jsonl"

_CENTROID_CACHE: Dict[str, Dict[str, Tuple[np.ndarray, int]]] = {}


def load_reference_calls(path: Optional[str | Path] = None) -> Dict[str, list]:
    """Read the reference corpus and group call texts by tool name."""
    target = Path(path) if path else DEFAULT_CALLS_PATH
    grouped: Dict[str, list] = {}
    for line in target.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        tool = row.get("tool")
        text = row.get("text")
        if not tool or not text:
            continue
        texts = grouped.setdefault(tool, [])
        if text not in texts:
            texts.append(text)
    return grouped


def compute_safe_centroids(
    path: Optional[str | Path] = None,
    embedder: Any = None,
    tools: Optional[Iterable[str]] = None,
) -> Dict[str, Tuple[np.ndarray, int]]:
    """Mean embedding per tool, cached by corpus path.

    ``tools`` limits the work to the agent's allowlist; the cache stores the
    full corpus so a later agent with a different allowlist reuses it.
    """
    target = str(Path(path) if path else DEFAULT_CALLS_PATH)
    if target not in _CENTROID_CACHE:
        from gate.utils.embedding import EmbeddingModel

        model = embedder or EmbeddingModel("all-MiniLM-L6-v2")
        grouped = load_reference_calls(target)
        centroids: Dict[str, Tuple[np.ndarray, int]] = {}
        for tool_name, texts in grouped.items():
            mat = np.atleast_2d(model.embed_batch(list(texts)))
            centroids[tool_name] = (mat.mean(axis=0).astype(np.float64), len(texts))
        _CENTROID_CACHE[target] = centroids
    centroids = _CENTROID_CACHE[target]
    if tools is None:
        return dict(centroids)
    wanted = set(tools)
    return {k: v for k, v in centroids.items() if k in wanted}


def calibrate(
    firewall: Any,
    path: Optional[str | Path] = None,
    only_missing: bool = True,
    embedder: Any = None,
) -> Dict[str, Any]:
    """Seed per-tool safe centroids on a semantic firewall.

    Only tools in the agent's allowlist are written, so the centroid store
    never advertises tools the agent cannot call. ``only_missing`` keeps a
    store that was calibrated offline (or seeded by a benchmark) authoritative.
    """
    profile = getattr(getattr(firewall, "config", None), "agent_profile", None)
    allowed = set(getattr(profile, "allowed_tools", []) or [])
    store = getattr(firewall, "vector_store", None)
    if store is None:
        return {"seeded": 0, "skipped": 0, "tools": []}

    targets = [
        tool for tool in allowed
        if not only_missing or store.get_safe_centroid(tool) is None
    ]
    if not targets:
        return {"seeded": 0, "skipped": len(allowed), "tools": []}

    centroids = compute_safe_centroids(path, embedder=embedder, tools=targets)
    seeded = []
    for tool_name, (centroid, n_samples) in centroids.items():
        cov_inv = np.eye(centroid.shape[0], dtype=np.float64)
        store.add_safe_centroid(tool_name, centroid, cov_inv, n_samples)
        seeded.append(tool_name)

    if seeded and hasattr(firewall, "_load_prototypes"):
        firewall._load_prototypes()
    logger.info("Calibrated safe centroids for %d tool(s)", len(seeded))
    return {"seeded": len(seeded), "skipped": len(allowed) - len(seeded), "tools": sorted(seeded)}
