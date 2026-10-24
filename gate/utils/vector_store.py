"""
Vector Store Wrapper
Wraps FAISS for efficient vector similarity search.
"""

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from ..core.exceptions import VectorStoreError

logger = logging.getLogger(__name__)


@dataclass
class SafeCentroid:
    """Safe centroid for a tool's typical usage patterns."""
    centroid: np.ndarray
    covariance_inv: np.ndarray
    sample_count: int
    tool_name: str


class VectorStore:
    """
    Wrapper around FAISS for vector similarity search.
    
    Supports:
    - Harm prototype storage and retrieval
    - Safe centroid storage per tool
    - Cosine and Mahalanobis distance queries
    """
    
    def __init__(
        self,
        storage_path: Optional[str] = None,
        namespace: str = "default",
        embedding_dim: int = 384,
    ) -> None:
        self.storage_path = Path(storage_path) if storage_path else None
        self.namespace = namespace
        self.embedding_dim = embedding_dim
        
        self._harm_index = None
        self._harm_prototypes: List[np.ndarray] = []
        self._harm_metadata: List[Dict[str, Any]] = []
        
        self._safe_centroids: Dict[str, SafeCentroid] = {}
        
        self._initialize_indexes()
        
        if self.storage_path:
            self._load_from_disk()
    
    def _initialize_indexes(self) -> None:
        """Initialize FAISS indexes."""
        try:
            import faiss
            
            self._harm_index = faiss.IndexFlatIP(self.embedding_dim)
            logger.info(f"Initialized FAISS index with dim={self.embedding_dim}")
        except ImportError as e:
            logger.warning(
                "FAISS not available. Using numpy-based fallback. "
                "Install with: pip install faiss-cpu"
            )
            self._harm_index = None
        except Exception as e:
            raise VectorStoreError(f"Failed to initialize FAISS: {e}") from e
    
    def _load_from_disk(self) -> None:
        """Load vector store from disk if available."""
        if not self.storage_path or not self.storage_path.exists():
            logger.info("No existing vector store found, starting fresh")
            return
        
        try:
            harm_path = self.storage_path / f"{self.namespace}_harm.npy"
            meta_path = self.storage_path / f"{self.namespace}_harm_meta.npy"
            centroids_path = self.storage_path / f"{self.namespace}_centroids.npy"
            
            if harm_path.exists():
                self._harm_prototypes = list(np.load(harm_path, allow_pickle=True))
                logger.info(f"Loaded {len(self._harm_prototypes)} harm prototypes")
            
            if centroids_path.exists():
                self._safe_centroids = dict(np.load(centroids_path, allow_pickle=True).item())
                logger.info(f"Loaded {len(self._safe_centroids)} safe centroids")
        
        except Exception as e:
            logger.warning(f"Failed to load vector store from disk: {e}")
    
    def save_to_disk(self) -> None:
        """Save vector store to disk."""
        if not self.storage_path:
            return
        
        try:
            self.storage_path.mkdir(parents=True, exist_ok=True)
            
            if self._harm_prototypes:
                np.save(
                    self.storage_path / f"{self.namespace}_harm.npy",
                    np.array(self._harm_prototypes),
                )
            
            if self._safe_centroids:
                np.save(
                    self.storage_path / f"{self.namespace}_centroids.npy",
                    self._safe_centroids,
                )
            
            logger.info(f"Saved vector store to {self.storage_path}")
        except Exception as e:
            logger.error(f"Failed to save vector store: {e}")
    
    def add_harm_prototype(
        self,
        embedding: np.ndarray,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a harm prototype to the store."""
        self._harm_prototypes.append(embedding)
        self._harm_metadata.append(metadata or {})
        
        if self._harm_index is not None:
            import faiss
            normalized = embedding.reshape(1, -1).astype("float32")
            faiss.normalize_L2(normalized)
            self._harm_index.add(normalized)
    
    def add_harm_prototypes_batch(
        self,
        embeddings: List[np.ndarray],
        metadata: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """Add multiple harm prototypes in batch."""
        self._harm_prototypes.extend(embeddings)
        self._harm_metadata.extend(metadata or [{}] * len(embeddings))
        
        if self._harm_index is not None:
            import faiss
            normalized = np.array(embeddings, dtype="float32")
            faiss.normalize_L2(normalized)
            self._harm_index.add(normalized)
    
    def add_safe_centroid(
        self,
        tool_name: str,
        centroid: np.ndarray,
        covariance_inv: np.ndarray,
        sample_count: int,
    ) -> None:
        """Add a safe centroid for a tool."""
        self._safe_centroids[tool_name] = SafeCentroid(
            centroid=centroid,
            covariance_inv=covariance_inv,
            sample_count=sample_count,
            tool_name=tool_name,
        )
        logger.debug(f"Added safe centroid for tool: {tool_name}")
    
    def get_prototypes_by_category(self, category: str) -> List[np.ndarray]:
        """Get all prototypes for a category."""
        if category == "harm":
            return self._harm_prototypes
        return []
    
    def get_safe_centroid(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get safe centroid data for a tool."""
        if tool_name not in self._safe_centroids:
            return None
        
        centroid = self._safe_centroids[tool_name]
        return {
            "centroid": centroid.centroid,
            "covariance_inv": centroid.covariance_inv,
            "sample_count": centroid.sample_count,
        }
    
    def search_nearest_harm(
        self, query: np.ndarray, k: int = 5
    ) -> List[Tuple[int, float]]:
        """
        Search for k nearest harm prototypes.
        
        Returns list of (index, distance) tuples.
        """
        if not self._harm_prototypes:
            return []
        
        if self._harm_index is not None:
            import faiss
            normalized = query.reshape(1, -1).astype("float32")
            faiss.normalize_L2(normalized)
            
            distances, indices = self._harm_index.search(normalized, min(k, len(self._harm_prototypes)))
            return list(zip(indices[0].tolist(), distances[0].tolist()))
        else:
            query_norm = query / (np.linalg.norm(query) + 1e-10)
            similarities = []
            for i, prototype in enumerate(self._harm_prototypes):
                proto_norm = prototype / (np.linalg.norm(prototype) + 1e-10)
                sim = float(np.dot(query_norm, proto_norm))
                similarities.append((i, sim))
            similarities.sort(key=lambda x: x[1], reverse=True)
            return similarities[:k]
    
    def compute_mahalanobis_distance(
        self, query: np.ndarray, tool_name: str
    ) -> float:
        """Compute Mahalanobis distance to a tool's safe centroid."""
        if tool_name not in self._safe_centroids:
            return float("inf")
        
        centroid = self._safe_centroids[tool_name]
        diff = query - centroid.centroid
        return float(np.sqrt(diff.T @ centroid.covariance_inv @ diff))
    
    def clear(self) -> None:
        """Clear all data from the vector store."""
        self._harm_prototypes = []
        self._harm_metadata = []
        self._safe_centroids = {}
        
        if self._harm_index is not None:
            self._initialize_indexes()
        
        logger.info("Vector store cleared")
