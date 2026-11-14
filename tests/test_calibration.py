"""Unit tests for reference-corpus calibration of safe centroids."""

import json

import numpy as np
import pytest

from gate.security import calibration
from gate.security.calibration import calibrate, compute_safe_centroids, load_reference_calls
from gate.utils.vector_store import VectorStore


DIM = 6


class _StubEmbedder:
    """Deterministic embeddings so centroid arithmetic is checkable."""

    def __init__(self):
        self.calls = 0

    def embed_batch(self, texts, batch_size=32):
        self.calls += 1
        out = []
        for text in texts:
            seed = int.from_bytes(text.encode("utf-8")[:2].ljust(2, b"\0"), "little")
            rng = np.random.default_rng(seed)
            out.append(rng.normal(size=DIM).astype("float32"))
        return np.array(out, dtype="float32")


class _Store:
    def __init__(self):
        self.written = {}

    def get_safe_centroid(self, tool):
        return self.written.get(tool)

    def add_safe_centroid(self, tool, centroid, cov_inv, n):
        self.written[tool] = {"centroid": centroid, "covariance_inv": cov_inv, "sample_count": n}


class _Firewall:
    def __init__(self, tools, store=None):
        self.vector_store = store or _Store()
        self.config = type("Cfg", (), {"agent_profile": type("P", (), {"allowed_tools": set(tools)})()})()
        self.reloaded = 0

    def _load_prototypes(self):
        self.reloaded += 1


@pytest.fixture
def corpus(tmp_path):
    path = tmp_path / "calls.jsonl"
    rows = [
        {"tool": "web_search", "text": "Call web_search(query=a)"},
        {"tool": "web_search", "text": "Call web_search(query=b)"},
        {"tool": "web_search", "text": "Call web_search(query=a)"},
        {"tool": "sql_query", "text": "Call sql_query(sql=select 1)"},
        {"tool": "send_email", "text": "Call send_email(to=x, body=y)"},
        {"tool": "missing_text"},
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    calibration._CENTROID_CACHE.clear()
    yield path
    calibration._CENTROID_CACHE.clear()


def test_load_groups_and_dedupes(corpus):
    grouped = load_reference_calls(corpus)
    assert set(grouped) == {"web_search", "sql_query", "send_email"}
    assert grouped["web_search"] == ["Call web_search(query=a)", "Call web_search(query=b)"]


def test_centroid_is_mean_of_tool_texts(corpus):
    stub = _StubEmbedder()
    centroids = compute_safe_centroids(corpus, embedder=stub)
    texts = load_reference_calls(corpus)["web_search"]
    expected = np.atleast_2d(stub.embed_batch(texts)).mean(axis=0)
    assert centroids["web_search"][1] == 2
    assert np.allclose(centroids["web_search"][0], expected)


def test_centroids_are_cached_per_path(corpus):
    stub = _StubEmbedder()
    compute_safe_centroids(corpus, embedder=stub)
    first = stub.calls
    assert first == 3  # one batch per tool
    compute_safe_centroids(corpus, embedder=stub)
    assert stub.calls == first


def test_tools_filter_restricts_output(corpus):
    centroids = compute_safe_centroids(corpus, embedder=_StubEmbedder(), tools=["sql_query"])
    assert list(centroids) == ["sql_query"]


def test_calibrate_writes_only_allowlisted_tools(corpus):
    fw = _Firewall({"web_search", "unknown_tool"})
    result = calibrate(fw, corpus, embedder=_StubEmbedder())
    assert result["seeded"] == 1
    assert result["tools"] == ["web_search"]
    assert set(fw.vector_store.written) == {"web_search"}
    assert fw.reloaded == 1


def test_calibrate_keeps_existing_centroid(corpus):
    store = _Store()
    store.written["web_search"] = {"centroid": np.zeros(DIM), "covariance_inv": np.eye(DIM), "sample_count": 5}
    fw = _Firewall({"web_search"}, store=store)
    result = calibrate(fw, corpus, embedder=_StubEmbedder())
    assert result["seeded"] == 0
    assert np.allclose(fw.vector_store.written["web_search"]["centroid"], np.zeros(DIM))


def test_calibrate_without_store_is_a_noop(corpus):
    fw = _Firewall({"web_search"})
    fw.vector_store = None
    assert calibrate(fw, corpus, embedder=_StubEmbedder())["seeded"] == 0


def test_shipped_corpus_covers_mediated_tools():
    grouped = load_reference_calls()
    assert len(grouped) == 9
    assert sum(len(v) for v in grouped.values()) == 152


def test_config_defaults_calibration_off():
    from gate.core.config import gateConfig, AgentProfile

    cfg = gateConfig(agent_profile=AgentProfile(agent_id="a", role="tester", allowed_tools={"web_search"}))
    assert cfg.semantic_calibration_path is None


def test_firewall_calibrates_from_config_path(corpus):
    """A config path seeds only the allowlisted tool that lacks a centroid."""
    from gate.core.config import AgentProfile, gateConfig
    from gate.security.semantic_firewall import DefaultSemanticFirewall
    from gate.utils.embedding import EmbeddingModel

    key = ("all-MiniLM-L6-v2", None, None)

    class _Encoder:
        def encode(self, texts, convert_to_numpy=True, **kwargs):
            return np.ones((len(texts), DIM), dtype="float32")

        def get_sentence_embedding_dimension(self):
            return DIM

    EmbeddingModel._MODEL_CACHE[key] = _Encoder()
    try:
        cfg = gateConfig(
            agent_profile=AgentProfile(
                agent_id="a", role="tester", allowed_tools={"web_search", "other"}
            ),
            semantic_calibration_path=str(corpus),
        )
        cfg.semantic_thresholds.alignment_weight = 0.0
        fw = DefaultSemanticFirewall(cfg)
        assert set(fw.safe_centroids) == {"web_search"}
        assert fw.safe_centroids["web_search"]["sample_count"] == 2
    finally:
        EmbeddingModel._MODEL_CACHE.pop(key, None)
