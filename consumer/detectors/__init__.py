"""SQL injection detector package."""

from .base import (
    BaseDetector,
    TIER_ATTACK,
    TIER_SUSPICIOUS,
    TIER_BENIGN,
    TIER_NO_QS,
    VALID_TIERS,
)
from .sqli import SQLiDetector

__all__ = [
    "BaseDetector",
    "SQLiDetector",
    "TIER_ATTACK",
    "TIER_SUSPICIOUS",
    "TIER_BENIGN",
    "TIER_NO_QS",
    "VALID_TIERS",
]
