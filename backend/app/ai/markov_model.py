from __future__ import annotations

from collections import Counter
from typing import List, Sequence

"""
Markov sequence model for detecting anomalous sequences of user and process actions.
Computes first-order and second-order transition probabilities against learned historical transitions.
"""


class SequenceAnalyzer:
    """Markov sequence model for action sequence anomaly detection."""

    def predict_sequence_anomaly(
        self, sequence: Sequence[str], historical_actions: Sequence[str] | None = None
    ) -> float:
        normalized_sequence = [
            str(item or "").strip().lower() for item in sequence if str(item or "").strip()
        ]
        history = [
            str(item or "").strip().lower()
            for item in (historical_actions or [])
            if str(item or "").strip()
        ]

        if not normalized_sequence:
            return 0.0

        current_action = normalized_sequence[-1]
        previous_action = (
            normalized_sequence[-2]
            if len(normalized_sequence) >= 2
            else (history[-1] if history else None)
        )
        score = 8.0

        routine_actions = {"process_start", "web_browsing", "file_access", "app_launch", "system_event", "login"}
        is_learning = len(history) < 10

        if len(history) < 4:
            if current_action in {"usb_insertion", "network_spike", "network_connection_suspicious"}:
                score += 25.0
            if current_action == "file_transfer":
                score += 18.0
            return min(score, 100.0)

        action_counts = Counter(history)
        if current_action not in action_counts:
            # During early learning mode, do not penalize routine desktop actions as anomalous
            if not (is_learning and current_action in routine_actions):
                score += 35.0
        elif action_counts[current_action] <= 2:
            if not (is_learning and current_action in routine_actions):
                score += 10.0

        if previous_action:
            transition_counts = Counter(zip(history[:-1], history[1:]))
            outgoing_total = sum(
                count for (source, _), count in transition_counts.items() if source == previous_action
            )
            if outgoing_total == 0:
                if not (is_learning and current_action in routine_actions):
                    score += 12.0
            else:
                transition_probability = (
                    transition_counts.get((previous_action, current_action), 0) / outgoing_total
                )
                if transition_probability == 0:
                    if not (is_learning and current_action in routine_actions):
                        score += 30.0
                elif transition_probability < 0.1:
                    if not (is_learning and current_action in routine_actions):
                        score += 16.0

        last_three = normalized_sequence[-3:]
        if last_three[-2:] == ["usb_insertion", "file_transfer"]:
            score += 30.0
        if last_three[-2:] == ["login", "usb_insertion"]:
            score += 12.0
        if last_three == ["usb_insertion", "file_access", "file_transfer"]:
            score += 20.0

        return min(score, 100.0)
