"""
Semantic Firewall Implementation
Enhanced with dynamic intent anchor, circuit breaker integration,
and trajectory-based drift detection.
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field
import numpy as np

from ..core.interfaces import SemanticFirewall
from ..core.config import gateConfig
from ..core.models import SemanticScore
from ..core.exceptions import EmbeddingModelError, VectorStoreError
from ..utils.embedding import EmbeddingModel
from ..utils.vector_store import VectorStore
from .circuit_breaker import CircuitBreaker, CircuitState

logger = logging.getLogger(__name__)


class TrajectoryTracker:
    """
    Tracks the semantic trajectory of an agent's actions.
    
    Uses exponential moving average to maintain a dynamic anchor
    that evolves as the agent progresses through legitimate tasks.
    """
    
    def __init__(self, ema_alpha: float = 0.3, max_trajectory_length: int = 20) -> None:
        """
        Initialize trajectory tracker.
        
        Args:
            ema_alpha: EMA smoothing factor (0 < alpha <= 1).
            max_trajectory_length: Maximum number of points to track.
        """
        self.ema_alpha = ema_alpha
        self.max_length = max_trajectory_length
        
        self.initial_anchor: Optional[np.ndarray] = None
        self.trajectory: List[np.ndarray] = []
        self.ema_anchor: Optional[np.ndarray] = None
    
    def set_initial_anchor(self, embedding: np.ndarray) -> None:
        """Set the initial anchor from user's prompt."""
        self.initial_anchor = embedding.copy()
        self.ema_anchor = embedding.copy()
        self.trajectory = [embedding.copy()]
        logger.debug("Initial anchor set")
    
    def update(self, embedding: np.ndarray) -> None:
        """
        Update the trajectory with a new action embedding.
        
        Uses EMA to smoothly track the agent's semantic direction.
        """
        if self.ema_anchor is None:
            self.set_initial_anchor(embedding)
            return
        
        self.ema_anchor = (
            self.ema_alpha * embedding +
            (1 - self.ema_alpha) * self.ema_anchor
        )
        
        self.trajectory.append(embedding.copy())
        if len(self.trajectory) > self.max_length:
            self.trajectory.pop(0)
        
        logger.debug(f"Trajectory updated, length={len(self.trajectory)}")
    
    def get_current_anchor(self) -> Optional[np.ndarray]:
        """Get the current dynamic anchor."""
        return self.ema_anchor
    
    def get_drift_from_trajectory(self, embedding: np.ndarray) -> float:
        """
        Compute drift from the trajectory (not just initial anchor).
        
        Uses both EMA anchor and trajectory centroid for robustness.
        """
        if self.ema_anchor is None:
            return 0.5
        
        drift_from_ema = self._cosine_distance(embedding, self.ema_anchor)
        
        if len(self.trajectory) > 1:
            trajectory_centroid = np.mean(self.trajectory, axis=0)
            drift_from_centroid = self._cosine_distance(embedding, trajectory_centroid)
            return 0.6 * drift_from_ema + 0.4 * drift_from_centroid
        
        return drift_from_ema
    
    def _cosine_distance(self, v1: np.ndarray, v2: np.ndarray) -> float:
        """Compute cosine distance."""
        dot_product = np.dot(v1, v2)
        norm1 = np.linalg.norm(v1)
        norm2 = np.linalg.norm(v2)
        
        if norm1 == 0 or norm2 == 0:
            return 1.0
        
        cosine_similarity = dot_product / (norm1 * norm2)
        return 1.0 - cosine_similarity


class DefaultSemanticFirewall(SemanticFirewall):
    """
    Enhanced semantic firewall with:
    - Dynamic intent anchor (trajectory-based)
    - Circuit breaker integration for graceful degradation
    - Triangulated semantic scoring
    """
    
    def __init__(
        self,
        config: gateConfig,
        embedding_circuit_breaker: Optional[CircuitBreaker] = None,
        vector_store_circuit_breaker: Optional[CircuitBreaker] = None,
        trajectory_ema_alpha: float = 0.3,
    ) -> None:
        self.config = config
        self.embedding_model = EmbeddingModel(config.embedding_model_name)
        self.vector_store = VectorStore(config.vector_store_path)
        self.thresholds = config.semantic_thresholds
        
        self.trajectory_tracker = TrajectoryTracker(ema_alpha=trajectory_ema_alpha)
        
        self.embedding_cb = embedding_circuit_breaker or CircuitBreaker(
            name="embedding_model",
            failure_threshold=3,
            recovery_timeout=30.0,
        )
        
        self.vector_store_cb = vector_store_circuit_breaker or CircuitBreaker(
            name="vector_store",
            failure_threshold=3,
            recovery_timeout=30.0,
        )
        
        self.harm_prototypes: List[np.ndarray] = []
        self.safe_centroids: Dict[str, Dict] = {}
        
        self._load_prototypes()
        
        logger.info(f"SemanticFirewall initialized with model: {config.embedding_model_name}")
    
    def _load_prototypes(self) -> None:
        """Load prototypes with circuit breaker protection."""
        try:
            self.harm_prototypes = self.vector_store.get_prototypes_by_category("harm")
            logger.info(f"Loaded {len(self.harm_prototypes)} harm prototypes")
            
            for tool_name in self.config.agent_profile.allowed_tools:
                centroid_data = self.vector_store.get_safe_centroid(tool_name)
                if centroid_data:
                    self.safe_centroids[tool_name] = centroid_data
                    logger.debug(f"Loaded safe centroid for tool: {tool_name}")
        
        except Exception as e:
            logger.error(f"Failed to load prototypes: {e}")
            raise VectorStoreError(f"Failed to load prototypes: {e}")
    
    def set_intent_anchor(self, user_prompt: str) -> None:
        """Set the user's original intent as the initial anchor."""
        try:
            embedding = self.embedding_model.embed(user_prompt)
            self.trajectory_tracker.set_initial_anchor(embedding)
            logger.debug("Intent anchor set")
        except Exception as e:
            logger.error(f"Failed to set intent anchor: {e}")
            raise EmbeddingModelError(f"Failed to embed user prompt: {e}")
    
    async def embed(self, text: str) -> np.ndarray:
        """Embed text with circuit breaker protection."""
        async def _embed_impl() -> np.ndarray:
            return self.embedding_model.embed(text)
        
        try:
            return await self.embedding_cb.call(_embed_impl)
        except Exception as e:
            logger.error(f"Embedding failed: {e}")
            if self.embedding_cb.state == CircuitState.OPEN:
                logger.warning("Embedding circuit breaker OPEN, using fallback")
                return np.zeros(384)
            raise EmbeddingModelError(f"Failed to embed text: {e}")
    
    def check_semantic_safety(
        self, action: str, tool_name: str, agent_id: str
    ) -> SemanticScore:
        """
        Check semantic safety using triangulated scoring with dynamic anchor.
        """
        try:
            e_action = self.embedding_model.embed(action)
            
            self.trajectory_tracker.update(e_action)
            
            drift_to_harm = self._compute_drift_to_harm(e_action)
            drift_to_safe = self._compute_drift_to_safe_centroid(e_action, tool_name)
            drift_to_intent = self.trajectory_tracker.get_drift_from_trajectory(e_action)
            
            epsilon = 1e-6
            sss_value = (drift_to_harm + epsilon) / (
                drift_to_safe + drift_to_intent + epsilon
            )
            
            if sss_value > self.thresholds.sss_safe_threshold:
                decision = "ALLOW"
            elif sss_value < self.thresholds.sss_block_threshold:
                decision = "BLOCK"
            else:
                decision = "ESCALATE"
            
            score = SemanticScore(
                sss_value=sss_value,
                drift_to_intent=drift_to_intent,
                drift_to_harm=drift_to_harm,
                drift_to_safe=drift_to_safe,
                decision=decision,
                details={
                    "action_embedding_norm": float(np.linalg.norm(e_action)),
                    "num_harm_prototypes": len(self.harm_prototypes),
                    "has_safe_centroid": tool_name in self.safe_centroids,
                    "trajectory_length": len(self.trajectory_tracker.trajectory),
                    "embedding_cb_state": self.embedding_cb.state.value,
                },
            )
            
            logger.debug(
                f"Semantic check for {tool_name}: SSS={sss_value:.3f}, "
                f"decision={decision}, drift_to_harm={drift_to_harm:.3f}, "
                f"drift_to_safe={drift_to_safe:.3f}, drift_to_intent={drift_to_intent:.3f}"
            )
            
            return score
            
        except Exception as e:
            logger.error(f"Semantic safety check failed: {e}", exc_info=True)
            return SemanticScore(
                sss_value=0.0,
                drift_to_intent=0.0,
                drift_to_harm=1.0,
                drift_to_safe=1.0,
                decision="BLOCK",
                details={"error": str(e)},
            )
    
    def _compute_drift_to_harm(self, e_action: np.ndarray) -> float:
        """Compute minimum distance to any harm prototype."""
        if not self.harm_prototypes:
            return 1.0
        
        min_distance = float("inf")
        for prototype in self.harm_prototypes:
            distance = self._cosine_distance(e_action, prototype)
            min_distance = min(min_distance, distance)
        
        return min_distance
    
    def _compute_drift_to_safe_centroid(
        self, e_action: np.ndarray, tool_name: str
    ) -> float:
        """Compute Mahalanobis distance to tool's safe centroid."""
        if tool_name not in self.safe_centroids:
            return 1.0
        
        centroid_data = self.safe_centroids[tool_name]
        centroid = centroid_data["centroid"]
        cov_inv = centroid_data["covariance_inv"]
        
        diff = e_action - centroid
        mahal_dist = np.sqrt(diff.T @ cov_inv @ diff)
        
        return float(mahal_dist)
    
    def _cosine_distance(self, v1: np.ndarray, v2: np.ndarray) -> float:
        """Compute cosine distance."""
        dot_product = np.dot(v1, v2)
        norm1 = np.linalg.norm(v1)
        norm2 = np.linalg.norm(v2)
        
        if norm1 == 0 or norm2 == 0:
            return 1.0
        
        cosine_similarity = dot_product / (norm1 * norm2)
        return 1.0 - cosine_similarity
