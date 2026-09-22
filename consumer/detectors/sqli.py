"""
detectors/sqli.py
─────────────────
SQLi detector — character n-grams + 17 symbol-frequency structural features.
Calibrated thresholds: T_High=0.81, T_Low=0.65 (from NB27/NB28 production work).
"""

import urllib.parse
import numpy as np
import scipy.sparse as sp
from collections import Counter

from .base import BaseDetector


# Default symbol list — overridden by config file if present
DEFAULT_SQLI_SYMBOLS = [
    "'", '"', ";", "--", "#", "/*", "*/", "*", "+",
    "|", "(", ")", ">", "<", "\\", "/", "=",
]


class SQLiDetector(BaseDetector):
    name = "sqli"

    def __init__(self, config_path):
        super().__init__(config_path)
        self.symbols = self._cfg.get("structural_features", DEFAULT_SQLI_SYMBOLS)

    # ── Feature engineering ─────────────────────────────────────────────────
    def _build_symbol_matrix(self, texts: list[str]) -> sp.csr_matrix:
        """17 symbol-frequency features per text (matches NB27 training)."""
        rows = [[t.count(sym) for sym in self.symbols] for t in texts]
        return sp.csr_matrix(np.array(rows, dtype=np.float32))

    def _build_feature_matrix(self, texts: list[str]) -> sp.csr_matrix:
        ngrams = self.vectorizer.transform(texts)
        syms   = self._build_symbol_matrix(texts)
        return sp.hstack([ngrams, syms])

    # ── Target extraction (Way 3) ───────────────────────────────────────────
    def _extract_targets(self, query_string: str) -> list[str]:
        """
        Way 3 extractor — isolate individual query parameter VALUES.
        Discards URL path to prevent path-trigram false alarms
        (e.g. '/api/v2/users' contains 'use', 'ser' that the model
        would weight as suspicious tokens).
        Each value is URL-decoded once (POST body wouldn't be in access logs).
        """
        parsed = urllib.parse.urlparse(query_string)
        # Note: urlparse handles both full URLs and bare query strings safely
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
        values = []
        for vlist in params.values():
            for v in vlist:
                decoded = urllib.parse.unquote(v).strip()
                if decoded:
                    values.append(decoded)
        return values

    def _score_targets(self, targets: list[str]) -> np.ndarray:
        X = self._build_feature_matrix(targets)
        return self.classifier.predict_proba(X)[:, 1]
