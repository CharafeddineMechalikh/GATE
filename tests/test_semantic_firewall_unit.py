"""Unit tests for the default semantic firewall and trajectory tracker."""

import numpy as np
import pytest

from gate.core.config import AgentProfile, gateConfig
from gate.security import semantic_firewall as sf_mod
from gate.security.semantic_firewall import (
    DefaultSemanticFirewall,
    TrajectoryTracker,
)
from gate.security.circuit_breaker import CircuitState
from gate.utils.embedding import EmbeddingModel

DIM = 4
_CACHE_KEY = ("all-MiniLM-L6-v2", None, None)


class _StubEncoder:
    """Deterministic encoder: maps known prompts, defaults to unit x-axis."""

    def __init__(self):
        self.raise_error = False

    def encode(self, texts, convert_to_numpy=True, **kwargs):
        if self.raise_error:
            raise RuntimeError("embedding unavailable")
        vecs = []
        for t in texts:
            vecs.append(_VECTORS.get(t, np.array([1.0, 0.0, 0.0, 0.0])))
        return np.array(vecs, dtype="float32")


_VECTORS = {
    "harm": np.array([-1.0, 0.0, 0.0, 0.0]),
    "safe": np.array([1.0, 0.0, 0.0, 0.0]),
    "mid": np.array([0.35, np.sqrt(1 - 0.35 ** 2), 0.0, 0.0]),
}


@pytest.fixture
def firewall():
    stub = _StubEncoder()
    EmbeddingModel._MODEL_CACHE[_CACHE_KEY] = stub
    config = gateConfig(
        agent_profile=AgentProfile(
            agent_id="a1", role="r", allowed_tools={"search", "read"}
        ),
        embedding_model_name="all-MiniLM-L6-v2",
        vector_store_path=None,
    )
    fw = DefaultSemanticFirewall(config)
    yield fw, stub
    EmbeddingModel._MODEL_CACHE.pop(_CACHE_KEY, None)


class TestTrajectoryTracker:
    def test_set_initial_anchor(self):
        tt = TrajectoryTracker()
        tt.set_initial_anchor(np.array([1.0, 0.0, 0.0]))
        assert tt.get_current_anchor() is not None
        assert len(tt.trajectory) == 1

    def test_update_creates_anchor_when_empty(self):
        tt = TrajectoryTracker()
        tt.update(np.array([0.0, 1.0, 0.0]))
        assert tt.get_current_anchor() is not None

    def test_update_moves_ema(self):
        tt = TrajectoryTracker(ema_alpha=0.5)
        tt.set_initial_anchor(np.array([1.0, 0.0, 0.0]))
        tt.update(np.array([0.0, 1.0, 0.0]))
        anchor = tt.get_current_anchor()
        assert anchor[0] == pytest.approx(0.5)
        assert len(tt.trajectory) == 2

    def test_max_length_enforced(self):
        tt = TrajectoryTracker(max_trajectory_length=2)
        tt.set_initial_anchor(np.array([1.0, 0.0, 0.0]))
        for _ in range(5):
            tt.update(np.array([0.0, 1.0, 0.0]))
        assert len(tt.trajectory) <= 2

    def test_drift_no_anchor(self):
        tt = TrajectoryTracker()
        assert tt.get_drift_from_trajectory(np.array([1.0, 0.0])) == 0.5

    def test_drift_from_centroid(self):
        tt = TrajectoryTracker(ema_alpha=0.5)
        tt.set_initial_anchor(np.array([1.0, 0.0, 0.0]))
        tt.update(np.array([0.0, 1.0, 0.0]))
        drift = tt.get_drift_from_trajectory(np.array([1.0, 1.0, 0.0]))
        assert 0.0 <= drift <= 2.0

    def test_cosine_zero_norm(self):
        tt = TrajectoryTracker()
        assert tt._cosine_distance(np.zeros(3), np.array([1.0, 0.0, 0.0])) == 1.0


class TestDefaultSemanticFirewall:
    def test_load_prototypes_empty(self, firewall):
        fw, _ = firewall
        assert fw.harm_prototypes == []
        assert fw.safe_centroids == {}

    def test_set_intent_anchor(self, firewall):
        fw, _ = firewall
        fw.set_intent_anchor("do something safe")
        assert fw.trajectory_tracker.get_current_anchor() is not None

    def test_check_allow(self, firewall):
        fw, _ = firewall
        fw.harm_prototypes = [np.array([-1.0, 0.0, 0.0, 0.0], dtype="float32")]
        score = fw.check_semantic_safety("act", "search", "a1")
        assert score.decision == "ALLOW"

    def test_check_block(self, firewall):
        fw, _ = firewall
        fw.harm_prototypes = [np.array([1.0, 0.0, 0.0, 0.0], dtype="float32")]
        score = fw.check_semantic_safety("act", "search", "a1")
        assert score.decision == "BLOCK"

    def test_check_escalate(self, firewall):
        fw, _ = firewall
        fw.harm_prototypes = [_VECTORS["mid"].astype("float32")]
        score = fw.check_semantic_safety("act", "search", "a1")
        assert score.decision == "ESCALATE"

    def test_check_with_safe_centroid(self, firewall):
        fw, _ = firewall
        fw.harm_prototypes = [np.array([-1.0, 0.0, 0.0, 0.0], dtype="float32")]
        fw.safe_centroids["search"] = {
            "centroid": np.array([1.0, 0.0, 0.0, 0.0]),
            "covariance_inv": np.eye(4),
        }
        score = fw.check_semantic_safety("act", "search", "a1")
        assert score.details["has_safe_centroid"] is True
        assert score.decision == "ALLOW"

    def test_drift_to_harm_empty(self, firewall):
        fw, _ = firewall
        assert fw._compute_drift_to_harm(np.array([1.0, 0, 0, 0])) == 1.0

    def test_drift_to_safe_missing(self, firewall):
        fw, _ = firewall
        assert fw._compute_drift_to_safe_centroid(np.array([1.0, 0, 0, 0]), "ghost") == 1.0

    def test_cosine_zero_norm(self, firewall):
        fw, _ = firewall
        assert fw._cosine_distance(np.zeros(4), np.ones(4)) == 1.0

    def test_check_error_falls_back_to_block(self, firewall):
        fw, stub = firewall
        stub.raise_error = True
        score = fw.check_semantic_safety("anything", "search", "a1")
        assert score.decision == "BLOCK"
        assert "error" in score.details

    @pytest.mark.asyncio
    async def test_embed_async(self, firewall):
        fw, _ = firewall
        vec = await fw.embed("harm")
        assert vec.shape == (4,)

    @pytest.mark.asyncio
    async def test_embed_open_breaker_returns_zeros(self, firewall):
        fw, stub = firewall
        stub.raise_error = True
        fw.embedding_cb._state = CircuitState.OPEN
        vec = await fw.embed("harm")
        assert vec.shape == (384,)
        assert np.all(vec == 0.0)
