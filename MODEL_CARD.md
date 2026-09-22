# NB27 SQLi Model Card

## Purpose

This model is the Random Forest SQL injection detector used by the QPRA deployment pipeline described in the DASC 2026 paper.

## Input representation

The detector scores **URL-decoded query-parameter values**, not complete URLs. For a multi-parameter request, each value is scored independently and the request score is the maximum probability.

## Feature pipeline

- `CountVectorizer(analyzer="char", ngram_range=(1, 3), min_df=3)`
- 8,805 character n-gram vocabulary features
- 17 SQL-oriented symbol-count features
- total RF feature count: 8,822

## Classifier

- Random Forest
- `n_estimators=100`
- `class_weight=None`
- `random_state=42`
- `max_depth=None`
- `min_samples_split=2`

## Operational thresholds

- `T_LOW = 0.65`
- `T_HIGH = 0.81`

Tiers:

- `ATTACK`: score >= 0.81
- `SUSPICIOUS`: 0.65 <= score < 0.81
- `BENIGN`: score < 0.65
- `NO_QS`: no query-parameter value is available to score

## Runtime compatibility

The joblib artefacts were serialized with **scikit-learn 1.6.0**. The repository pins that version to avoid cross-version model-persistence issues.

## SHA-256

```text
f77290afc2a7acec5062df59d14c8f500ab3838dfd4b0097da08815de61e1247  models/27_rf_raw.joblib
e3cde0e73d3dee3bc212c7a61e7e754044346ac3571e268d1be4cd4666f185ab  models/27_vectorizer.joblib
```

## Data

The initial training corpus is the Sajid576 SQL Injection Dataset:
https://www.kaggle.com/datasets/sajid576/sql-injection-dataset

The repository does not redistribute the real production Nginx log used for deployment evaluation.
