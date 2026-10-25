"""Unit tests for the embedding wrapper.

The wrapper's own logic (cache reuse, string vs list handling, batch embed,
dimension, and translation of encoder faults into ``EmbeddingModelError``) is
tested against a stub encoder injected into the model cache, so no
sentence-transformers model is downloaded. This tests GATE's behavior, not the
third-party library.
"""

import numpy as np
import pytest

from gate.core.exceptions import EmbeddingModelError
from gate.utils.embedding import EmbeddingModel


DIM = 8


class _StubEncoder:
    def encode(self, texts, **kwargs):
        if isinstance(texts, str):
            texts = [texts]
        return np.ones((len(texts), DIM), dtype="float32")

    def get_sentence_embedding_dimension(self):
        return DIM


class _FailingEncoder(_StubEncoder):
    def encode(self, texts, **kwargs):
        raise RuntimeError("encoder exploded")


@pytest.fixture
def stubbed_model():
    name = "stub-model-for-tests"
    key = (name, None, None)
    EmbeddingModel._MODEL_CACHE[key] = _StubEncoder()
    try:
        yield EmbeddingModel(model_name=name)
    finally:
        EmbeddingModel._MODEL_CACHE.pop(key, None)


def test_load_model_uses_cache_stub(stubbed_model):
    assert stubbed_model._model is not None


def test_cache_is_reused_for_same_key(stubbed_model):
    again = EmbeddingModel(model_name="stub-model-for-tests")
    assert again._model is stubbed_model._model


def test_embed_string_returns_single_vector(stubbed_model):
    vec = stubbed_model.embed("hello world")
    assert vec.shape == (DIM,)


def test_embed_list_returns_matrix(stubbed_model):
    vecs = stubbed_model.embed(["a", "b", "c"])
    assert vecs.shape == (3, DIM)


def test_embed_batch(stubbed_model):
    vecs = stubbed_model.embed_batch(["x", "y"], batch_size=1)
    assert vecs.shape == (2, DIM)


def test_dimension_property(stubbed_model):
    assert stubbed_model.dimension == DIM


def test_embed_translates_encoder_failure():
    name = "stub-failing-model"
    key = (name, None, None)
    EmbeddingModel._MODEL_CACHE[key] = _FailingEncoder()
    try:
        model = EmbeddingModel(model_name=name)
        with pytest.raises(EmbeddingModelError):
            model.embed("trigger failure")
    finally:
        EmbeddingModel._MODEL_CACHE.pop(key, None)


def test_embed_batch_translates_encoder_failure():
    name = "stub-failing-batch"
    key = (name, None, None)
    EmbeddingModel._MODEL_CACHE[key] = _FailingEncoder()
    try:
        model = EmbeddingModel(model_name=name)
        with pytest.raises(EmbeddingModelError):
            model.embed_batch(["a", "b"])
    finally:
        EmbeddingModel._MODEL_CACHE.pop(key, None)


def test_embed_without_model_raises():
    name = "stub-model-none"
    EmbeddingModel._MODEL_CACHE[key := (name, None, None)] = _StubEncoder()
    try:
        model = EmbeddingModel(model_name=name)
        model._model = None
        with pytest.raises(EmbeddingModelError):
            model.embed("no model")
        with pytest.raises(EmbeddingModelError):
            model.embed_batch(["no model"])
        with pytest.raises(EmbeddingModelError):
            _ = model.dimension
    finally:
        EmbeddingModel._MODEL_CACHE.pop(key, None)
