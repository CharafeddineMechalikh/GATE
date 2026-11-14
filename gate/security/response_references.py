"""Benign tool-result reference index for the inbound (response-side) layers.

The outbound semantic firewall compares an action against harm prototypes and
a per-tool benign-call centroid.  The inbound layer analyses tool *results*,
which have their own vocabulary (invoices, tickets, HTTP status lines, admin
listings).  This index loads a small shipped corpus of benign results, splits
them into sentences, and exposes the nearest-sentence cosine similarity for a
candidate directive span.  That similarity is a calibration signal: business
language that asks a human to do something is routine, while injected content
that redirects the agent usually falls outside the benign reference cloud.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import numpy as np

logger = logging.getLogger(__name__)

DEFAULT_REFERENCE_PATH = Path(__file__).resolve().parents[1] / "benign_results.jsonl"
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")


class BenignResultReferenceIndex:
    """Lazy nearest-neighbour index over benign tool-result sentences."""

    def __init__(self, path: Optional[Path] = None, embedder=None) -> None:
        self.path = Path(path) if path is not None else DEFAULT_REFERENCE_PATH
        self._embedder = embedder
        self._lock = threading.Lock()
        self._by_tool: Optional[Dict[str, np.ndarray]] = None
        self._global: Optional[np.ndarray] = None
        self.status = "unavailable"

    def _embed(self, texts: Sequence[str]) -> np.ndarray:
        if self._embedder is None:
            from ..utils.embedding import EmbeddingModel

            self._embedder = EmbeddingModel("all-MiniLM-L6-v2")
        batch = getattr(self._embedder, "embed_batch", None)
        if batch is not None and len(texts) > 1:
            vectors = np.asarray(batch(list(texts)), dtype=np.float64)
        else:
            vectors = np.stack([np.asarray(self._embedder.embed(t), dtype=np.float64) for t in texts])
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        return vectors / np.maximum(norms, 1e-12)

    def _load(self) -> None:
        if self._by_tool is not None:
            return
        with self._lock:
            if self._by_tool is not None:
                return
            if not self.path.exists():
                self.status = "missing"
                self._by_tool = {}
                self._global = np.zeros((0, 384))
                return
            per_tool: Dict[str, List[str]] = {}
            everything: List[str] = []
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                tool = str(row.get("tool", "")).strip()
                for sentence in _SENTENCE_SPLIT.split(str(row.get("text", ""))):
                    sentence = sentence.strip()
                    if len(sentence) < 12:
                        continue
                    per_tool.setdefault(tool, []).append(sentence)
                    everything.append(sentence)
            if not everything:
                self.status = "empty"
                self._by_tool = {}
                self._global = np.zeros((0, 384))
                return
            self._global = self._embed(everything)
            self._by_tool = {t: self._embed(texts) for t, texts in per_tool.items()}
            self.status = "ok"
            logger.debug("benign result references loaded: %d sentences, %d tools",
                         len(everything), len(self._by_tool))

    @property
    def available(self) -> bool:
        self._load()
        return self.status == "ok"

    def similarity(self, tool: str, candidate: str) -> Optional[float]:
        """Max cosine similarity between a candidate span and benign result sentences.

        Uses the candidate's own tool when that tool has references, otherwise the
        global pool, so an unseen tool still gets a calibrated score.
        """
        if not candidate or not candidate.strip():
            return None
        values = self.similarity_batch(tool, [candidate])
        return values[0] if values else None

    def similarity_batch(self, tool: str, candidates: Sequence[str]) -> List[Optional[float]]:
        """Vectorised form of :meth:`similarity`, one embedding batch per call."""
        texts = [c.strip() for c in candidates]
        if not texts:
            return []
        self._load()
        if self._global is None or len(self._global) == 0:
            return [None] * len(texts)
        queries = self._embed(texts)
        pool = self._by_tool.get(tool) if self._by_tool else None
        if pool is None or len(pool) == 0:
            pool = self._global
        return [float(v) for v in np.max(queries @ pool.T, axis=1)]
