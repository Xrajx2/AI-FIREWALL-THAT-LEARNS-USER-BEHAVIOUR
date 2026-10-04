from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


@dataclass
class IsolationForestState:
    scaler: StandardScaler
    model: IsolationForest
    sample_count: int
    trained_at: datetime
    lower_bound: float
    upper_bound: float


class PointAnomalyDetector:
    def __init__(self, min_samples: int = 12, retrain_step: int = 5):
        self.min_samples = min_samples
        self.retrain_step = retrain_step
        self._states: Dict[int, IsolationForestState] = {}

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
        raw_score = float(state.model.decision_function(current_scaled)[0])
        anomaly_score = self._map_decision_to_score(raw_score, state.lower_bound, state.upper_bound)
        return {
            "score": anomaly_score,
            "ready": True,
            "sample_count": sample_count,
        }

    def _needs_retrain(self, state: IsolationForestState | None, sample_count: int) -> bool:
        if state is None:
            return True
        return sample_count - state.sample_count >= self.retrain_step

    def _train_model(self, training_matrix: np.ndarray) -> IsolationForestState:
        scaler = StandardScaler()
        training_scaled = scaler.fit_transform(training_matrix)
        model = IsolationForest(
            contamination=0.1,
            n_estimators=200,
            random_state=42,
        )
        model.fit(training_scaled)
        training_scores = model.decision_function(training_scaled)
        lower_bound = float(np.percentile(training_scores, 5))
        upper_bound = float(np.percentile(training_scores, 95))
        return IsolationForestState(
            scaler=scaler,
            model=model,
            sample_count=int(training_matrix.shape[0]),
            trained_at=datetime.now(timezone.utc),
            lower_bound=lower_bound,
            upper_bound=upper_bound,
        )

    @staticmethod
    def _map_decision_to_score(raw_score: float, lower_bound: float, upper_bound: float) -> float:
        spread = max(upper_bound - lower_bound, 1e-6)
        normalized = (upper_bound - raw_score) / spread
        return float(np.clip(normalized * 100.0, 0.0, 100.0))
