from __future__ import annotations

from typing import Any, Dict, List, Sequence

import numpy as np

from .clustering import ClusterDriftDetector
from .features import ActivityFeatureEncoder, normalize_activity
from .isolation_forest import PointAnomalyDetector
from .markov_model import SequenceAnalyzer
from ..risk import clamp_risk_score, score_to_recommended_action, score_to_risk_level


class ScoringEngine:
    def __init__(self):
        self.encoder = ActivityFeatureEncoder()
        self.sequence_model = SequenceAnalyzer()
        self.point_model = PointAnomalyDetector()
        self.cluster_model = ClusterDriftDetector()

    def evaluate_threat(
        self,
        user_id: int,
        current_activity: Any,
        recent_activities: Sequence[Any],
    ) -> Dict[str, Any]:
        normalized_history = [normalize_activity(item) for item in recent_activities]
        normalized_current = normalize_activity(current_activity)

        if normalized_history:
            historical_rows = normalized_history[:-1]
        else:
            historical_rows = []

        action_sequence = [item["action_type"] for item in normalized_history[-5:]] or [normalized_current["action_type"]]
        historical_actions = [item["action_type"] for item in historical_rows]

        current_vector = self.encoder.vectorize(normalized_current, historical_rows)
        training_matrix = self.encoder.build_training_matrix(historical_rows[-240:])
        context = self.encoder.summarize_context(normalized_current, historical_rows)

        isolation = self.point_model.score(user_id, current_vector, training_matrix)
        cluster = self.cluster_model.score(user_id, current_vector, training_matrix)
        sequence_score = self.sequence_model.predict_sequence_anomaly(action_sequence, historical_actions)
        heuristic = self._heuristic_score(normalized_current, historical_rows, context)

        component_scores = {
            "isolation_forest": isolation["score"],
            "cluster_drift": cluster["score"],
            "sequence_behavior": sequence_score,
            "heuristics": heuristic["score"],
        }

        if isolation["ready"] and cluster["ready"]:
            final_score = (
                component_scores["isolation_forest"] * 0.4
                + component_scores["cluster_drift"] * 0.25
                + component_scores["sequence_behavior"] * 0.2
                + component_scores["heuristics"] * 0.15
            )
        elif isolation["ready"]:
            final_score = (
                component_scores["isolation_forest"] * 0.55
                + component_scores["sequence_behavior"] * 0.2
                + component_scores["heuristics"] * 0.25
            )
        else:
            final_score = (
                component_scores["sequence_behavior"] * 0.4
                + component_scores["heuristics"] * 0.6
            )

        reasons = heuristic["reasons"]
        final_score = self._apply_overrides(normalized_current, final_score, reasons)
        final_score = float(np.clip(final_score, 0.0, 100.0))

        if final_score >= 70 and isolation["ready"]:
            reasons.append("Isolation Forest marked this event as an outlier versus learned user history.")
        if final_score >= 60 and cluster["ready"]:
            reasons.append("Clustering placed this event far away from the user's normal activity groups.")
        if sequence_score >= 35:
            reasons.append("The action sequence was rare or out-of-order compared with prior behavior.")

        reasons = self._dedupe_reasons(reasons)[:4]
        summary = self._build_summary(normalized_current, reasons, isolation, cluster)
        risk_level = score_to_risk_level(final_score)
        recommended_action = score_to_recommended_action(final_score)

        training_samples = int(training_matrix.shape[0]) if training_matrix.size else 0
        learning_mode = training_samples < 10

        return {
            "score": round(final_score, 2),
            "level": risk_level,
            "risk_level": risk_level,
            "learning_mode": learning_mode,
            "recommended_action": recommended_action,
            "summary": summary,
            "reasons": reasons,
            "component_scores": {key: round(value, 2) for key, value in component_scores.items()},
            "learning_state": {
                "user_id": user_id,
                "training_samples": training_samples,
                "learning_mode": learning_mode,
                "isolation_forest_ready": isolation["ready"],
                "cluster_model_ready": cluster["ready"],
                "continuous_learning": True,
            },
        }

    def _heuristic_score(
        self,
        current_activity: Dict[str, Any],
        historical_rows: Sequence[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        score = 5.0
        reasons: List[str] = []
        current_hour = int(context["current_hour"])
        current_network = float(context["current_network_activity"])
        current_action = context["current_action"]

        if current_action == "network_connection_suspicious":
            score += 34.0
            reasons.append("An unusual outgoing connection was detected and flagged for review.")

        if current_action == "network_connection_blocked":
            score = max(score, 82.0)
            reasons.append("A risky outgoing connection was blocked automatically by the network policy.")

        if historical_rows:
            activity_hours = [item["timestamp"].hour for item in historical_rows]
            mean_hour = float(np.mean(activity_hours))
            std_hour = float(np.std(activity_hours)) if len(activity_hours) > 1 else 0.0
            if std_hour > 0 and abs(current_hour - mean_hour) > max(2.5 * std_hour, 4):
                score += 28.0
                reasons.append(f"Access happened at an unusual time ({current_hour:02d}:00) for this user.")
            elif current_hour < 6 or current_hour > 21:
                score += 16.0
                reasons.append(f"Access happened during off-hours ({current_hour:02d}:00).")

            avg_network = float(context["avg_network_activity"])
            std_network = float(context["std_network_activity"])
            if std_network > 0 and current_network > 0:
                network_zscore = abs((current_network - avg_network) / std_network)
                if network_zscore > 3:
                    score += 35.0
                    reasons.append("Network transfer volume is well outside the learned normal range.")
                elif network_zscore > 2:
                    score += 18.0
                    reasons.append("Network transfer volume is trending above the learned normal range.")
            elif avg_network > 0 and current_network > avg_network * 4:
                score += 24.0
                reasons.append("Network transfer volume is a large spike over the user's baseline.")

            if context["known_action_count"] == 0:
                score += 18.0
                reasons.append(f"The action '{current_action}' has not been seen before for this user.")
            if current_activity["device"] and context["known_device_count"] == 0:
                score += 14.0
                reasons.append("The event came from a new or rarely seen device.")
        else:
            if current_hour < 6 or current_hour > 21:
                score += 18.0
                reasons.append(f"Access happened during off-hours ({current_hour:02d}:00).")
            if current_network > 1000:
                score += 25.0
                reasons.append("Large transfer volume was observed before the model had baseline data.")

        details = current_activity["details"].lower()
        suspicious_terms = [
            "blocked",
            "dangerous",
            "exfiltration",
            "firewall",
            "macro",
            "malicious",
            "outgoing",
            "public",
            "quarantine",
            "remote",
            "threat",
            "unknown",
            "usb",
        ]
        matched_terms = [term for term in suspicious_terms if term in details]
        if matched_terms:
            score += min(30.0, 8.0 * len(matched_terms))
            reasons.append("Alert details contain high-risk indicators: " + ", ".join(sorted(set(matched_terms))) + ".")

        if current_action == "usb_scan_complete" and ("dangerous" in details or "malicious" in details):
            score += 40.0
            reasons.append("USB scan reported dangerous or malicious files.")

        return {
            "score": float(np.clip(score, 0.0, 100.0)),
            "reasons": reasons,
        }

    def _apply_overrides(self, current_activity: Dict[str, Any], current_score: float, reasons: List[str]) -> float:
        action = current_activity["action_type"]
        details = current_activity["details"].lower()
        network_activity = float(current_activity["network_activity"])
        score = current_score

        if action == "usb_insertion" and score < 35:
            score = 35.0
        if action == "usb_scan_complete" and any(term in details for term in ("dangerous", "malicious", "severe")):
            score = max(score, 95.0)
            reasons.append("USB scan matched dangerous threat indicators.")
        if network_activity > 5000:
            score = max(score, 94.0)
            reasons.append("Massive data transfer volume triggered a hard anomaly override.")
        if action == "file_transfer" and network_activity > 1500:
            score = max(score, 82.0)
        if action == "network_connection_suspicious" and any(term in details for term in ("unknown", "outgoing", "remote", "public")):
            score = max(score, 58.0)
        if action == "network_connection_blocked":
            score = max(score, 88.0)

        return clamp_risk_score(score)

    @staticmethod
    def _dedupe_reasons(reasons: Sequence[str]) -> List[str]:
        seen = set()
        ordered: List[str] = []
        for reason in reasons:
            cleaned = str(reason or "").strip()
            if not cleaned:
                continue
            if cleaned in seen:
                continue
            seen.add(cleaned)
            ordered.append(cleaned)
        return ordered

    @staticmethod
    def _build_summary(
        current_activity: Dict[str, Any],
        reasons: Sequence[str],
        isolation: Dict[str, Any],
        cluster: Dict[str, Any],
    ) -> str:
        action_name = current_activity["action_type"].replace("_", " ")
        if reasons:
            return f"Adaptive anomaly detection flagged {action_name} because {reasons[0].lower()}"

        if isolation["ready"] or cluster["ready"]:
            return f"Adaptive anomaly detection flagged {action_name} as an outlier against learned behavior."

        return f"Behavior analysis evaluated {action_name} with fallback baseline heuristics while the model is still learning."


engine = ScoringEngine()
