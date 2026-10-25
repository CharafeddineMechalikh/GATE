"""Unit tests for the FAISS vector-store wrapper.

The store exercises both backends: with FAISS available (the installed default)
and the numpy cosine fallback, which is reached by clearing the index. Disk
persistence uses a temporary directory; no embedding model is required because
the store operates on raw arrays.
"""

import numpy as np
import pytest

from gate.utils.vector_store import VectorStore, SafeCentroid


def _unit(v):
    v = np.asarray(v, dtype="float32")
    return v / (np.linalg.norm(v) + 1e-12)


@pytest.fixture
def store():
    return VectorStore(storage_path=None, embedding_dim=4)


def test_add_and_retrieve_harm_prototype(store):
    store.add_harm_prototype(_unit([1, 0, 0, 0]), {"label": "drop"})
    store.add_harm_prototypes_batch(
        [_unit([0, 1, 0, 0]), _unit([0, 0, 1, 0])],
        [{"label": "a"}, {"label": "b"}],
    )
    assert len(store.get_prototypes_by_category("harm")) == 3
    assert store.get_prototypes_by_category("safe") == []


def test_search_nearest_harm_ranks_by_similarity(store):
    store.add_harm_prototypes_batch(
        [_unit([1, 0, 0, 0]), _unit([0, 1, 0, 0])]
    )
    hits = store.search_nearest_harm(_unit([0.9, 0.1, 0, 0]), k=2)
    assert len(hits) == 2
    assert hits[0][0] == 0  # closest to the first prototype


def test_search_nearest_harm_empty_returns_empty(store):
    assert store.search_nearest_harm(_unit([1, 0, 0, 0])) == []


def test_numpy_fallback_when_index_absent(store):
    store._harm_index = None
    store.add_harm_prototype(_unit([1, 0, 0, 0]))
    store.add_harm_prototype(_unit([0, 1, 0, 0]))
    hits = store.search_nearest_harm(_unit([0, 0.9, 0.1, 0]), k=1)
    assert hits[0][0] == 1  # numpy path ranks correctly


def test_safe_centroid_add_get_and_mahalanobis(store):
    cov_inv = np.eye(4, dtype="float32")
    store.add_safe_centroid("search", _unit([1, 0, 0, 0]), cov_inv, 10)
    data = store.get_safe_centroid("search")
    assert data is not None
    assert data["sample_count"] == 10

    dist = store.compute_mahalanobis_distance(np.array([1, 0, 0, 0], dtype="float32"), "search")
    assert dist == pytest.approx(0.0, abs=1e-5)

    far = store.compute_mahalanobis_distance(np.array([10, 0, 0, 0], dtype="float32"), "search")
    assert far > dist


def test_missing_centroid_returns_none_and_inf(store):
    assert store.get_safe_centroid("nope") is None
    assert store.compute_mahalanobis_distance(np.zeros(4, dtype="float32"), "nope") == float("inf")


def test_clear_resets_all_state(store):
    store.add_harm_prototype(_unit([1, 0, 0, 0]))
    store.add_safe_centroid("search", _unit([1, 0, 0, 0]), np.eye(4, dtype="float32"), 1)
    store.clear()
    assert store.get_prototypes_by_category("harm") == []
    assert store.get_safe_centroid("search") is None


def test_save_and_reload_from_disk(tmp_path):
    path = tmp_path / "gate-vectors"
    store = VectorStore(storage_path=str(path), embedding_dim=4)
    store.add_harm_prototypes_batch([_unit([1, 0, 0, 0]), _unit([0, 1, 0, 0])])
    store.add_safe_centroid("search", _unit([1, 0, 0, 0]), np.eye(4, dtype="float32"), 5)
    store.save_to_disk()

    assert (path / "default_harm.npy").exists()
    assert (path / "default_centroids.npy").exists()

    reloaded = VectorStore(storage_path=str(path), embedding_dim=4)
    assert len(reloaded.get_prototypes_by_category("harm")) == 2
    assert reloaded.get_safe_centroid("search")["sample_count"] == 5


def test_load_from_missing_path_starts_fresh(tmp_path):
    store = VectorStore(storage_path=str(tmp_path / "does-not-exist"), embedding_dim=4)
    assert store.get_prototypes_by_category("harm") == []


def test_save_without_storage_path_is_noop(store):
    store.add_harm_prototype(_unit([1, 0, 0, 0]))
    store.save_to_disk()  # storage_path is None; must not raise


def test_safecentroid_dataclass_fields():
    c = SafeCentroid(centroid=np.zeros(4), covariance_inv=np.eye(4), sample_count=3, tool_name="t")
    assert c.tool_name == "t"
    assert c.sample_count == 3
