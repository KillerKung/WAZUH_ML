#!/usr/bin/env python3
"""Train and evaluate a leakage-safe XGBoost classifier for Wazuh alerts."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from pandas.api.types import is_numeric_dtype
from sklearn.compose import ColumnTransformer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier


LABEL_TO_ID = {"Safe": 0, "Suspicious": 1, "Dangerous": 2}
ID_TO_LABEL = {value: key for key, value in LABEL_TO_ID.items()}
NEVER_FEATURES = {
    "event_id", "operation_id", "timestamp", "class_3", "binary_label",
    "provenance", "lab_session_id", "source_ip", "source_ip_internal",
    "username", "username_internal", "full_log", "raw_log",
}


def split_by_operation(frame: pd.DataFrame, test_size: float, seed: int):
    if frame["operation_id"].nunique() < 2:
        raise ValueError("at least 2 distinct operation_id values are required")
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train_idx, test_idx = next(splitter.split(frame, groups=frame["operation_id"]))
    return frame.iloc[train_idx].copy(), frame.iloc[test_idx].copy()


def train(args: argparse.Namespace) -> dict:
    frame = pd.read_csv(args.dataset)
    required = {"operation_id", "class_3"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"dataset is missing columns: {sorted(missing)}")
    frame = frame.dropna(subset=["class_3"]).copy()
    unknown = set(frame["class_3"]) - set(LABEL_TO_ID)
    if unknown:
        raise ValueError(f"unknown labels: {sorted(unknown)}")
    if frame.empty:
        raise ValueError("dataset has no labeled rows")

    train_frame, test_frame = split_by_operation(frame, args.test_size, args.seed)
    present_train = set(train_frame["class_3"])
    missing_train = set(LABEL_TO_ID) - present_train
    if missing_train:
        raise ValueError(
            f"training split lacks classes {sorted(missing_train)}; collect more operations "
            "or change --test-size/--seed"
        )

    feature_columns = [column for column in frame.columns if column not in NEVER_FEATURES]
    leaked = [name for name in feature_columns if any(token in name.lower() for token in ("provenance", "marker", "session_id"))]
    if leaked:
        raise ValueError(f"possible leakage columns detected: {leaked}")

    X_train = train_frame[feature_columns]
    X_test = test_frame[feature_columns]
    y_train = train_frame["class_3"].map(LABEL_TO_ID)
    y_test = test_frame["class_3"].map(LABEL_TO_ID)

    # Pandas 3 uses a dedicated string dtype instead of object by default.
    # Treat every non-numeric feature as categorical so both Pandas 2 and 3 work.
    categorical = [column for column in feature_columns if not is_numeric_dtype(X_train[column])]
    numeric = [column for column in feature_columns if column not in categorical]
    preprocessor = ColumnTransformer(
        transformers=[
            ("categorical", OneHotEncoder(handle_unknown="ignore"), categorical),
            ("numeric", "passthrough", numeric),
        ],
        remainder="drop",
    )
    classifier = XGBClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        learning_rate=args.learning_rate,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="multi:softprob",
        num_class=3,
        eval_metric="mlogloss",
        tree_method="hist",
        random_state=args.seed,
        n_jobs=args.jobs,
    )
    pipeline = Pipeline([("preprocess", preprocessor), ("model", classifier)])
    sample_weights = compute_sample_weight(class_weight="balanced", y=y_train)
    pipeline.fit(X_train, y_train, model__sample_weight=sample_weights)

    predictions = pipeline.predict(X_test)
    probabilities = pipeline.predict_proba(X_test)
    labels = [0, 1, 2]
    report = classification_report(
        y_test,
        predictions,
        labels=labels,
        target_names=[ID_TO_LABEL[item] for item in labels],
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(y_test, predictions, labels=labels)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.output_dir / "wazuh_xgboost.joblib"
    report_path = args.output_dir / "metrics.json"
    matrix_path = args.output_dir / "confusion_matrix.csv"
    predictions_path = args.output_dir / "test_predictions.csv"

    bundle = {
        "pipeline": pipeline,
        "feature_columns": feature_columns,
        "label_to_id": LABEL_TO_ID,
        "id_to_label": ID_TO_LABEL,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(bundle, model_path)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    pd.DataFrame(
        matrix,
        index=[f"actual_{ID_TO_LABEL[item]}" for item in labels],
        columns=[f"predicted_{ID_TO_LABEL[item]}" for item in labels],
    ).to_csv(matrix_path)

    result = test_frame[["event_id", "operation_id", "class_3"]].copy()
    result["predicted_class"] = [ID_TO_LABEL[int(item)] for item in predictions]
    for class_id, class_name in ID_TO_LABEL.items():
        result[f"probability_{class_name}"] = probabilities[:, class_id]
    result.to_csv(predictions_path, index=False)

    return {
        "train_rows": len(train_frame),
        "test_rows": len(test_frame),
        "train_operations": sorted(train_frame["operation_id"].astype(str).unique().tolist()),
        "test_operations": sorted(test_frame["operation_id"].astype(str).unique().tolist()),
        "accuracy": report["accuracy"],
        "macro_f1": report["macro avg"]["f1-score"],
        "dangerous_recall": report["Dangerous"]["recall"],
        "model": str(model_path.resolve()),
        "metrics": str(report_path.resolve()),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n-estimators", type=int, default=300)
    parser.add_argument("--max-depth", type=int, default=5)
    parser.add_argument("--learning-rate", type=float, default=0.05)
    parser.add_argument("--jobs", type=int, default=-1)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not 0 < args.test_size < 1:
        print("error: --test-size must be between 0 and 1", file=sys.stderr)
        return 1
    try:
        summary = train(args)
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
