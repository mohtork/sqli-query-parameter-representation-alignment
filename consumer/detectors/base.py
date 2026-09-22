"""Common scoring interface for the SQLi detector."""

import json
from abc import ABC, abstractmethod
from pathlib import Path

import joblib
import numpy as np

TIER_ATTACK = "ATTACK"
TIER_SUSPICIOUS = "SUSPICIOUS"
TIER_BENIGN = "BENIGN"
TIER_NO_QS = "NO_QS"
VALID_TIERS = (TIER_ATTACK, TIER_SUSPICIOUS, TIER_BENIGN, TIER_NO_QS)


class BaseDetector(ABC):
    """Load model artefacts and implement max-score tiering."""

    name: str = "base"

    def __init__(self, config_path):
        config_path = Path(config_path)
        with config_path.open(encoding="utf-8") as handle:
            cfg = json.load(handle)

        self.t_low = float(cfg["t_low"])
        self.t_high = float(cfg["t_high"])
        self.model_ver = cfg.get("model_version", "unknown")

        base = config_path.parent
        self.vectorizer = joblib.load(base / cfg["vectorizer_path"])
        self.classifier = joblib.load(base / cfg["classifier_path"])
        self._cfg = cfg

    def _classify_tier(self, score: float) -> str:
        if score >= self.t_high:
            return TIER_ATTACK
        if score >= self.t_low:
            return TIER_SUSPICIOUS
        return TIER_BENIGN

    @abstractmethod
    def _extract_targets(self, request_target: str) -> list[str]:
        """Return the query-parameter values that should be scored."""
        raise NotImplementedError

    @abstractmethod
    def _score_targets(self, targets: list[str]) -> np.ndarray:
        """Return malicious-class probabilities for extracted values."""
        raise NotImplementedError

    def score(self, request_target: str) -> dict:
        """QPRA extraction -> per-value scoring -> max aggregation -> tier."""
        targets = self._extract_targets(request_target)
        if not targets:
            return {
                "detector": self.name,
                "tier": TIER_NO_QS,
                "max_score": None,
                "param_scores": [],
                "t_low": self.t_low,
                "t_high": self.t_high,
                "model_version": self.model_ver,
            }

        probs = self._score_targets(targets)
        max_score = float(probs.max())
        return {
            "detector": self.name,
            "tier": self._classify_tier(max_score),
            "max_score": round(max_score, 6),
            "param_scores": [
                {"param_value": target, "score": round(float(prob), 6)}
                for target, prob in zip(targets, probs)
            ],
            "t_low": self.t_low,
            "t_high": self.t_high,
            "model_version": self.model_ver,
        }
