from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict

import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler


@dataclass
class ClusterModelState:
    scaler: StandardScaler
    model: KMeans
    sample_count: int
    trained_at: datetime
    distance_threshold: float


class ClusterDriftDetector:
    def __init__(self, min_samples: int = 10, retrain_step: int = 5):
        self.min_samples = min_samples
        self.retrain_step = retrain_step
        self._states: Dict[int, ClusterModelState] = {}

    def score(self, user_id: int, current_vector: np.ndarray, training_matrix: np.ndarray) -> Dict[str, float]:
        sample_count = int(training_matrix.shape[0]) if training_matrix.size else 0
        if sample_count < self.min_samples:
            return {
                "score": 0.0,
                "ready": False,
                "sample_count": sample_count,
            }

        state = self._states.get(user_id)
        if self._needs_retrain(state, sample_count):
            state = self._train_model(training_matrix)
            self._states[user_id] = state

        current_scaled = state.scaler.transform(current_vector.reshape(1, -1))
        current_distance = self._distance_to_cluster_center(state.model, current_scaled)[0]
        distance_ratio = current_distance / max(state.distance_threshold, 1e-6)
        score = float(np.clip((distance_ratio - 0.6) * 70.0, 0.0, 100.0))
        return {
            "score": score,
            "ready": True,
            "sample_count": sample_count,
        }

    def _needs_retrain(self, state: ClusterModelState | None, sample_count: int) -> bool:
        if state is None:
            return True
        return sample_count - state.sample_count >= self.retrain_step

    def _train_model(self, training_matrix: np.ndarray) -> ClusterModelState:
        scaler = StandardScaler()
        training_scaled = scaler.fit_transform(training_matrix)
        cluster_count = min(4, max(2, int(round(np.sqrt(training_scaled.shape[0] / 2.0)))))
        model = KMeans(
            n_clusters=cluster_count,
            n_init=10,
            random_state=42,
        )
        model.fit(training_scaled)
        distances = self._distance_to_cluster_center(model, training_scaled)
        distance_threshold = float(np.percentile(distances, 90))
        return ClusterModelState(
            scaler=scaler,
            model=model,
            sample_count=int(training_matrix.shape[0]),
            trained_at=datetime.now(timezone.utc),
            distance_threshold=max(distance_threshold, 1e-6),
        )

    @staticmethod
    def _distance_to_cluster_center(model: KMeans, data: np.ndarray) -> np.ndarray:
        centers = model.cluster_centers_[model.predict(data)]
        return np.linalg.norm(data - centers, axis=1)
