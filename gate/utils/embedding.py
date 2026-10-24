"""
Embedding Model Wrapper
Enhanced with retry logic and circuit breaker integration.
"""

import logging
import os
import threading
from typing import Any, Dict, List, Optional, Union
import numpy as np

# Force the PyTorch backend for transformers/sentence-transformers before they
# are imported. Some hosts ship a broken TensorFlow/Keras stack; without this
# guard the top-level ``transformers`` import eagerly loads TF utilities and
# fails. PyTorch is the backend gate is developed and benchmarked against.
os.environ.setdefault("USE_TF", "0")
os.environ.setdefault("USE_TORCH", "1")

from ..core.exceptions import EmbeddingModelError
from .retry import with_retry, RetryConfig

logger = logging.getLogger(__name__)


class EmbeddingModel:
    """
    Wrapper around sentence-transformers with retry logic.
    """
    # Shared SentenceTransformer instances, keyed by (model_name, device,
    # cache_folder). Benchmark harnesses build one monitor per case; without
    # this cache each build pays a cold model load. Embeddings are
    # deterministic, so sharing never changes a measured number.
    _MODEL_CACHE: Dict[Any, Any] = {}
    _MODEL_CACHE_LOCK = threading.Lock()

    
    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        device: Optional[str] = None,
        cache_folder: Optional[str] = None,
        retry_config: Optional[RetryConfig] = None,
    ) -> None:
        self.model_name = model_name
        self.device = device
        self.cache_folder = cache_folder
        self.retry_config = retry_config or RetryConfig(
            max_attempts=3,
            min_wait_seconds=0.5,
            max_wait_seconds=5.0,
        )
        self._model = None
        
        self._load_model()
    
    def _load_model(self) -> None:
        """Load the embedding model (shared instance per model identity)."""
        key = (self.model_name, self.device, self.cache_folder)
        with EmbeddingModel._MODEL_CACHE_LOCK:
            if key not in EmbeddingModel._MODEL_CACHE:
                try:
                    from sentence_transformers import SentenceTransformer
                    EmbeddingModel._MODEL_CACHE[key] = SentenceTransformer(
                        self.model_name,
                        device=self.device,
                        cache_folder=self.cache_folder,
                    )
                    logger.info(f"Loaded embedding model: {self.model_name}")
                except ImportError as e:
                    raise EmbeddingModelError(
                        "sentence-transformers is required. "
                        "Install with: pip install sentence-transformers"
                    ) from e
                except Exception as e:
                    raise EmbeddingModelError(f"Failed to load model {self.model_name}: {e}") from e
            else:
                logger.debug(f"Reusing cached embedding model: {self.model_name}")
            self._model = EmbeddingModel._MODEL_CACHE[key]
    
    @with_retry(
        max_attempts=3,
        min_wait_seconds=0.5,
        max_wait_seconds=5.0,
        operation_name="embed",
    )
    def embed(self, text: Union[str, List[str]]) -> np.ndarray:
        """Embed text with retry logic."""
        if self._model is None:
            raise EmbeddingModelError("Model not loaded")
        
        try:
            if isinstance(text, str):
                embeddings = self._model.encode([text], convert_to_numpy=True)
                return embeddings[0]
            else:
                return self._model.encode(text, convert_to_numpy=True)
        except Exception as e:
            logger.error(f"Embedding failed: {e}", exc_info=True)
            raise EmbeddingModelError(f"Failed to embed text: {e}") from e
    
    @with_retry(
        max_attempts=3,
        min_wait_seconds=0.5,
        max_wait_seconds=5.0,
        operation_name="embed_batch",
    )
    def embed_batch(self, texts: List[str], batch_size: int = 32) -> np.ndarray:
        """Embed a batch of texts with retry logic."""
        if self._model is None:
            raise EmbeddingModelError("Model not loaded")
        
        try:
            return self._model.encode(
                texts,
                batch_size=batch_size,
                convert_to_numpy=True,
                show_progress_bar=False,
            )
        except Exception as e:
            logger.error(f"Batch embedding failed: {e}", exc_info=True)
            raise EmbeddingModelError(f"Failed to embed batch: {e}") from e
    
    @property
    def dimension(self) -> int:
        """Get the embedding dimension."""
        if self._model is None:
            raise EmbeddingModelError("Model not loaded")
        return self._model.get_sentence_embedding_dimension()
