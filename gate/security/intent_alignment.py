"""
Intent-action alignment for the semantic firewall.

The SSS compares an action against harm prototypes, a per-tool safe centroid and
the intent anchor in embedding space. A call can sit close to a harm prototype
while still matching the user's stated goal, and a call can be far from every
prototype while pursuing a different goal than the one stated. A pretrained NLI
cross-encoder scores the pair (user intent, proposed action) directly and returns
P(contradiction); the firewall adds a weighted term to the harmful score.

The encoder is loaded once per process and predictions are cached, because the
harness builds a fresh monitor per case. If the model cannot be loaded the
aligner disables itself and the firewall falls back to the SSS thresholds, which
keeps the fallback deterministic rather than failing open.
"""

from __future__ import annotations

import logging
import threading
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "cross-encoder/nli-MiniLM2-L6-H768"

_MODEL = None
_MODEL_LOCK = threading.Lock()
_CACHE: Dict[Tuple[str, str], Tuple[float, float]] = {}
_CACHE_LIMIT = 4096


class IntentActionAligner:
    """Scores whether a proposed action contradicts the stated user intent."""

    def __init__(self, model_name: str = DEFAULT_MODEL, weight: float = 0.5) -> None:
        self.model_name = model_name
        self.weight = weight
        self._disabled = False

    @property
    def disabled(self) -> bool:
        return self._disabled

    def _load(self):
        global _MODEL
        if _MODEL is not None:
            return _MODEL
        with _MODEL_LOCK:
            if _MODEL is None:
                from sentence_transformers import CrossEncoder

                _MODEL = CrossEncoder(self.model_name)
        return _MODEL

    def score(self, intent: str, action: str) -> Optional[Tuple[float, float]]:
        """Return (P(contradiction), P(entailment)), or None if unavailable."""
        if self._disabled or not intent or not action:
            return None
        key = (intent, action)
        cached = _CACHE.get(key)
        if cached is not None:
            return cached
        try:
            probs = self._load().predict([key], apply_softmax=True)[0]
            out = (float(probs[0]), float(probs[1]))
        except Exception as exc:  # model missing, offline, or runtime failure
            self._disabled = True
            logger.warning(
                "Intent-action aligner unavailable (%s); semantic firewall falls back to SSS",
                exc,
            )
            return None
        if len(_CACHE) >= _CACHE_LIMIT:
            _CACHE.clear()
        _CACHE[key] = out
        return out
