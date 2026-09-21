"""Small smoke tests for the packaged SQLi detector."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "consumer"))

from detectors import SQLiDetector  # noqa: E402


def detector():
    return SQLiDetector(ROOT / "models" / "sqli_detector_config.json")


def test_no_query_string():
    result = detector().score("/index.html")
    assert result["tier"] == "NO_QS"
    assert result["max_score"] is None


def test_query_values_are_scored_individually():
    result = detector().score("/product?id=1%20AND%20SLEEP(5)--&category=shoes")
    values = [item["param_value"] for item in result["param_scores"]]
    assert "1 AND SLEEP(5)--" in values
    assert "shoes" in values
    assert result["max_score"] == max(item["score"] for item in result["param_scores"])
