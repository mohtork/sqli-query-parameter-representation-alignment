"""SQLi-only inference pipeline.

Loads the NB27 Random Forest SQL injection detector once at startup and
provides a small process() API for the Kafka/OpenSearch consumer.
"""

import logging
import os
from pathlib import Path

from detectors import SQLiDetector

logger = logging.getLogger(__name__)
MODELS_DIR = Path(os.getenv("MODELS_DIR", "/app/models"))
_detector: SQLiDetector | None = None


def load_detector() -> None:
    """Load the SQLi detector and its model artefacts once."""
    global _detector
    cfg = MODELS_DIR / "sqli_detector_config.json"
    if not cfg.exists():
        raise FileNotFoundError(f"SQLi detector config not found: {cfg}")
    _detector = SQLiDetector(cfg)
    logger.info(
        "SQLi detector loaded (model=%s, T_LOW=%s, T_HIGH=%s)",
        _detector.model_ver,
        _detector.t_low,
        _detector.t_high,
    )


def get_detector() -> SQLiDetector:
    if _detector is None:
        raise RuntimeError("SQLi detector is not initialised; call load_detector() first")
    return _detector


def process(url: str) -> dict:
    """Score one request URL and return the SQLi detector result."""
    return get_detector().score(url)
