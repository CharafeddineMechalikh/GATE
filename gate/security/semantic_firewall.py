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
from .intent_alignment import IntentActionAligner

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
        aligner: Optional[IntentActionAligner] = None,
    ) -> None:
        self.config = config
        self.embedding_model = EmbeddingModel(config.embedding_model_name)
        self.vector_store = VectorStore(config.vector_store_path)
        self.thresholds = config.semantic_thresholds
        
        self.trajectory_tracker = TrajectoryTracker(ema_alpha=trajectory_ema_alpha)
        self.intent_text: Optional[str] = None
        self.aligner = aligner
        if self.aligner is None and self.thresholds.alignment_weight > 0:
            self.aligner = IntentActionAligner(
                self.thresholds.alignment_model_name,
                self.thresholds.alignment_weight,
            )
        
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
        if getattr(config, "semantic_calibration_path", None):
            from gate.security.calibration import calibrate
            calibrate(self, config.semantic_calibration_path)
        
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
            self.intent_text = user_prompt
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
    
    @staticmethod
    def _compute_provenance(provenance=None, **kwargs):
        """Deterministic provenance/taint features (v1+3C-H). Higher taint = more untrusted/external influence.
        METADATA ONLY: never affects SSS/thresholds/decisions (decision computed before this in check_semantic_safety).
        Consumes richer segment schema when present; backward-compatible with sources-only."""
        prov = provenance or kwargs.get('context_provenance') or {}
        sources = prov.get('sources') or prov.get('taint_sources') or []
        if isinstance(sources, str):
            sources = [sources]
        sources_l = [str(s).lower() for s in sources]
        # 3C-H: derive source flags from known segments (origin metadata), without inference/labels
        segments = prov.get('segments') or []
        if isinstance(segments, list):
            for seg in segments:
                if not isinstance(seg, dict):
                    continue
                if not seg.get('known', False) and seg.get('origin') != 'user_instruction':
                    # explicit unknown segments do not create trusted/untrusted flags
                    pass
                org = str(seg.get('origin', '')).lower()
                if seg.get('known'):
                    if org == 'user_instruction' and 'user' not in sources_l:
                        sources_l.append('user')
                    elif org == 'external_document' and 'external_content' not in sources_l:
                        sources_l.append('external_content')
                    elif org == 'tool_result' and 'tool_result' not in sources_l:
                        sources_l.append('tool_result')
                    elif org == 'system_developer_context' and 'system' not in sources_l:
                        sources_l.append('system')
        flags = {
            'prov_user': 1.0 if any('user' in s for s in sources_l) else 0.0,
            'prov_external': 1.0 if any(x in s for s in sources_l for x in ('external', 'web', 'email', 'retriev', 'document', 'injection')) else 0.0,
            'prov_tool_result': 1.0 if any('tool' in s or 'result' in s for s in sources_l) else 0.0,
            'prov_system': 1.0 if any('system' in s for s in sources_l) else 0.0,
        }
        known = 1.0 if (sources_l or any(isinstance(s, dict) and s.get('known') for s in segments if isinstance(s, dict))) else 0.0
        # taint: external/tool_result contribute; user/system reduce relative trust uncertainty (metadata only)
        taint = 0.0
        if known:
            taint = min(1.0, 0.75*flags['prov_external'] + 0.45*flags['prov_tool_result'] - 0.1*flags['prov_user'])
            taint = max(0.0, taint)
        return {'known': known, 'taint_score': taint if known else None, 'sources': sources_l, **flags}

    def check_semantic_safety(
        self, action: str, tool_name: str, agent_id: str, provenance=None, **kwargs
    ) -> SemanticScore:
        """
        Check semantic safety using triangulated scoring with dynamic anchor.
        Optional provenance/taint context (backward-compatible): provenance={'sources':[...]}.
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

            # An anchor the agent supplies as a copy of its own action carries no
            # evidence: both consistency signals collapse and the ratio's
            # denominator loses the intent term. Below every benign separation,
            # decide on the intent-free evidence and never allow.
            degenerate_anchor = (
                self.intent_text is not None
                and drift_to_intent < self.thresholds.degenerate_intent_threshold
            )

            if degenerate_anchor:
                decision = "BLOCK" if drift_to_harm < drift_to_safe else "ESCALATE"
            elif sss_value > self.thresholds.sss_safe_threshold:
                decision = "ALLOW"
            elif sss_value < self.thresholds.sss_block_threshold:
                decision = "BLOCK"
            else:
                decision = "ESCALATE"

            contradiction = None
            entailment = None
            fused_harm = None
            if (
                not degenerate_anchor
                and self.aligner is not None
                and self.thresholds.alignment_weight != 0
                and self.intent_text
            ):
                alignment = self.aligner.score(self.intent_text, action)
                if alignment is not None:
                    contradiction, entailment = alignment
                    fused_harm = (
                        -np.log(max(sss_value, 1e-9))
                        + self.thresholds.alignment_weight * contradiction
                    )
                    # One-sided: alignment may add refusal, never grant it.
                    if (
                        fused_harm > self.thresholds.fused_block_threshold
                        and decision != "ALLOW"
                    ):
                        decision = "BLOCK"

            prov = self._compute_provenance(provenance=provenance, **kwargs)
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
                    "anchor_degenerate": bool(degenerate_anchor),
                    "embedding_cb_state": self.embedding_cb.state.value,
                    "alignment_contradiction": contradiction,
                    "alignment_entailment": entailment,
                    "fused_harm": fused_harm,
                    "provenance_known": prov['known'],
                    "provenance_taint_score": prov['taint_score'],
                    "prov_external": prov['prov_external'],
                    "prov_tool_result": prov['prov_tool_result'],
                    "prov_user": prov['prov_user'],
                },
                alignment_contradiction=contradiction,
                fused_harm=fused_harm,
                provenance={'sources': prov['sources'], 'known': prov['known']} if prov['known'] else None,
                taint_score=prov['taint_score'],
            )
            
            logger.debug(
                f"Semantic check for {tool_name}: SSS={sss_value:.3f}, "
                f"decision={decision}, drift_to_harm={drift_to_harm:.3f}, "
                f"drift_to_safe={drift_to_safe:.3f}, drift_to_intent={drift_to_intent:.3f}, "
                f"contradiction={contradiction}, fused_harm={fused_harm}"
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
