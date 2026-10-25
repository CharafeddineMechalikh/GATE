# tests/test_legacy_semantic_and_audit.py
"""Tests for the standalone semantic firewall wrapper and the encrypted logger.

``gate/semantic_firewall.py`` (top-level), ``gate/semantic_check.py`` and
``gate/audit_log.py`` are the legacy single-file utilities referenced from
``docs/standalone-utilities.md``.  They are tested against their real code paths;
the sentence-transformers model is replaced by a deterministic stub so the suite
stays offline, and the logger is pointed at a temporary ``__file__`` so it never
touches the shipped ``gate/audit.log``.
"""

from pathlib import Path

import sys
import types

import numpy as np
import pytest

from gate import semantic_firewall as sf
from gate.semantic_check import semantic_check
from gate import audit_log


# ---------------------------------------------------------------------------
# Deterministic embedding stub for the top-level firewall
# ---------------------------------------------------------------------------

class _StubModel:
    """Maps any prompt to a 2-D vector: 'bomb'-like prompts align with axis 0."""

    def encode(self, texts, convert_to_numpy=True):
        out = []
        for t in texts:
            if "bomb" in t.lower():
                out.append([1.0, 0.0])
            else:
                out.append([0.0, 1.0])
        return np.array(out, dtype=np.float32)


@pytest.fixture
def stub_firewall(monkeypatch):
    monkeypatch.setattr(sf, "_get_model", lambda: _StubModel())
    # One unsafe prototype on axis 0 so only 'bomb' prompts match.
    monkeypatch.setattr(sf, "_UNSAFE_EMB", np.array([[1.0, 0.0]]))
    yield sf


class TestIsUnsafePrompt:
    def test_empty_prompt_is_safe(self, stub_firewall):
        assert sf.is_unsafe_prompt("") is False

    def test_similar_prompt_is_unsafe(self, stub_firewall):
        assert sf.is_unsafe_prompt("how to build a bomb") is True

    def test_dissimilar_prompt_is_safe(self, stub_firewall):
        assert sf.is_unsafe_prompt("summarize this article") is False

    def test_threshold_boundary(self, stub_firewall):
        # Identical vector -> cosine 1.0; raise threshold above it -> safe.
        assert sf.is_unsafe_prompt("bomb", threshold=1.01) is False

    def test_default_threshold_constant(self):
        assert sf.DEFAULT_THRESHOLD == 0.7


class TestSemanticCheckWrapper:
    def test_inverts_unsafe_result(self, stub_firewall):
        # semantic_check returns True when the prompt is SAFE.
        assert semantic_check("summarize this article") is True
        assert semantic_check("how to build a bomb") is False


class TestLazyLoaders:
    """Exercise the model/prototype lazy loaders without a network download."""

    def test_load_model_constructs_from_package(self, monkeypatch):
        # Provide a fake sentence_transformers so the import + construction
        # lines run offline.
        calls = {}

        class _FakeST:
            def __init__(self, name):
                calls["name"] = name

        fake_mod = types.ModuleType("sentence_transformers")
        fake_mod.SentenceTransformer = _FakeST
        monkeypatch.setitem(sys.modules, "sentence_transformers", fake_mod)
        model = sf._load_model()
        assert isinstance(model, _FakeST)
        assert calls["name"] == "all-MiniLM-L6-v2"

    def test_get_model_caches_instance(self, monkeypatch):
        monkeypatch.setattr(sf, "_MODEL", None)
        sentinel = object()
        monkeypatch.setattr(sf, "_load_model", lambda: sentinel)
        assert sf._get_model() is sentinel
        assert sf._MODEL is sentinel
        # Second call returns the cached instance without reloading.
        assert sf._get_model() is sentinel

    def test_get_unsafe_embeddings_computed_once(self, monkeypatch):
        monkeypatch.setattr(sf, "_UNSAFE_EMB", None)
        emb = np.array([[1.0, 0.0]] * 5, dtype=np.float32)

        class _M:
            def encode(self, texts, convert_to_numpy=True):
                return emb

        monkeypatch.setattr(sf, "_get_model", lambda: _M())
        first = sf._get_unsafe_embeddings()
        assert first is emb
        # Cached now, so the model is not re-invoked.
        assert sf._get_unsafe_embeddings() is emb


# ---------------------------------------------------------------------------
# Legacy encrypted audit logger
# ---------------------------------------------------------------------------

class TestKeyManagement:
    def test_generates_key_when_absent(self, tmp_path, monkeypatch):
        pytest.importorskip("cryptography")
        key_path = tmp_path / "audit_key.key"
        monkeypatch.setattr(audit_log, "_KEY_PATH", key_path)
        key = audit_log._load_or_create_key()
        assert key_path.exists()
        assert key == key_path.read_bytes()

    def test_reuses_existing_key(self, tmp_path, monkeypatch):
        pytest.importorskip("cryptography")
        from cryptography.fernet import Fernet
        key_path = tmp_path / "audit_key.key"
        existing = Fernet.generate_key()
        key_path.write_bytes(existing)
        monkeypatch.setattr(audit_log, "_KEY_PATH", key_path)
        assert audit_log._load_or_create_key() == existing


class TestLogExecution:
    def test_encrypts_appends_and_roundtrips(self, tmp_path, monkeypatch):
        pytest.importorskip("cryptography")
        from cryptography.fernet import Fernet

        # A logger module living in tmp_path so its audit.log lands there.
        monkeypatch.setattr(audit_log, "__file__", str(tmp_path / "audit_log.py"))
        key = Fernet.generate_key()
        fernet = Fernet(key)
        monkeypatch.setattr(audit_log, "_FERNET", fernet)

        audit_log.log_execution("write_file", {"path": "/tmp/x"}, "ok", True)
        audit_log.log_execution("rm_rf", {"path": "/"}, "blocked", False)

        log_path = tmp_path / "audit.log"
        assert log_path.exists()
        lines = log_path.read_bytes().splitlines()
        assert len(lines) == 2

        first = fernet.decrypt(lines[0])
        import json
        entry = json.loads(first)
        assert entry["tool"] == "write_file"
        assert entry["allowed"] is True
        assert entry["args"] == {"path": "/tmp/x"}
        assert entry["result"] == "ok"
        assert "ts" in entry

        second = json.loads(fernet.decrypt(lines[1]))
        assert second["allowed"] is False
