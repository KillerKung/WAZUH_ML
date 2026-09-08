#!/usr/bin/env python3
"""Merge manual Ground Truth, validate it, and train XGBoost."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from xgboost import XGBClassifier


LABEL_TO_ID = {"Safe": 0, "Suspicious": 1, "Dangerous": 2}

CATEGORICAL_FEATURES = [
    "rule_id",
    "rule_groups",
    "decoder_name",
    "mitre_id",
]

NUMERIC_FEATURES = [
    "rule_level",
    "source_port",
    "destination_port",
    "source_is_private",
    "destination_is_private",
    "network_bytes",
    "network_packets",
    "has_network_evidence",
    "has_audit_evidence",
    "has_process_evidence",
    "has_file_evidence",
    "has_auth_evidence",
    "has_privilege_evidence",
    "host_events_previous_5m",
    "same_rule_previous_5m",
    "unique_rules_previous_10m",
    "high_level_events_previous_10m",
    "auth_events_previous_10m",
    "file_events_previous_10m",
    "privilege_events_previous_30m",
    "mitre_events_previous_30m",
    "rule_level_max_previous_10m",
    "hour",
    "day_of_week",
    "is_after_hours",
    "rule_count",
]

FEATURES = CATEGORICAL_FEATURES + NUMERIC_FEATURES


def load_approved_ground_truth(path):
    """รับเฉพาะ Label ที่มนุษย์ยืนยันเป็น approved แล้ว"""
    labels = pd.read_csv(path, dtype={"event_id": str, "incident_id": str})
    required = {
        "event_id", "manual_label", "incident_id", "confidence",
        "label_reason", "reviewer", "review_status",
    }
    missing = sorted(required - set(labels.columns))
    if missing:
        raise ValueError(f"Ground Truth ขาดคอลัมน์: {missing}")
    if labels["event_id"].duplicated().any():
        raise ValueError("Ground Truth มี event_id ซ้ำ")

    labels = labels[labels["review_status"].astype(str).str.lower() == "approved"].copy()
    if labels.empty:
        raise ValueError("ยังไม่มี Label ที่ review_status=approved")

    if labels["manual_label"].isna().any() or (labels["manual_label"].astype(str).str.strip() == "").any():
        raise ValueError("Label ที่ approved ต้องมี manual_label ทุกแถว")
    labels["manual_label"] = labels["manual_label"].astype(str).str.strip()
    unknown = sorted(set(labels["manual_label"]) - set(LABEL_TO_ID))
    if unknown:
        raise ValueError(f"manual_label ต้องเป็น Safe/Suspicious/Dangerous เท่านั้น: {unknown}")
    if labels["incident_id"].isna().any() or (labels["incident_id"].str.strip() == "").any():
        raise ValueError("ทุก Label ต้องมี incident_id เพื่อแบ่ง Train/Test โดยไม่รั่ว")
    labels["incident_id"] = labels["incident_id"].str.strip()

    incident_label_counts = labels.groupby("incident_id")["manual_label"].nunique()
    mixed = incident_label_counts[incident_label_counts > 1].index.tolist()
    if mixed:
        examples = ", ".join(mixed[:5])
        raise ValueError(f"incident_id เดียวกันมีหลาย Label ซึ่งแบ่งข้อมูลอย่างปลอดภัยไม่ได้: {examples}")
    return labels


def merge_labels(candidates, labels):
    candidates = candidates.copy()
    candidates["event_id"] = candidates["event_id"].astype(str)
    merged = candidates.merge(
        labels[["event_id", "manual_label", "incident_id", "confidence", "reviewer"]],
        on="event_id", how="inner", validate="one_to_one",
    )
    if merged.empty:
        raise ValueError("ไม่มี event_id ที่ตรงกันระหว่าง ML Candidates และ Ground Truth")
    return merged


def build_pipeline(seed):
    preprocess = ColumnTransformer([
        ("categorical", Pipeline([
            ("impute", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ]), CATEGORICAL_FEATURES),
        ("numeric", Pipeline([
            ("impute", SimpleImputer(strategy="median")),
        ]), NUMERIC_FEATURES),
    ])

    classifier = XGBClassifier(
        n_estimators=300,
        max_depth=5,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="multi:softprob",
        num_class=3,
        eval_metric="mlogloss",
        tree_method="hist",
        random_state=seed,
        n_jobs=-1,
    )
    return Pipeline([("preprocess", preprocess), ("model", classifier)])


def incident_balanced_weights(frame):
    """ให้แต่ละคลาสและแต่ละ incident มีน้ำหนักรวมใกล้เคียงกัน"""
    rows_per_incident = frame.groupby("incident_id")["event_id"].transform("size")
    incidents_per_class = frame.groupby("manual_label")["incident_id"].transform("nunique")
    weights = 1.0 / (rows_per_incident * incidents_per_class)
    return (weights * (len(weights) / weights.sum())).to_numpy()


def dataset_diagnostics(frame):
    incident_labels = frame[["incident_id", "manual_label"]].drop_duplicates()
    rows_by_label = frame["manual_label"].value_counts().reindex(LABEL_TO_ID, fill_value=0)
    incidents_by_label = incident_labels["manual_label"].value_counts().reindex(LABEL_TO_ID, fill_value=0)
    largest_incidents = (
        frame.groupby(["incident_id", "manual_label"]).size()
        .sort_values(ascending=False).head(10)
    )
    warnings = []
    for label, count in incidents_by_label.items():
        if count < 5:
            warnings.append(f"{label} มีเพียง {int(count)} incidents; ควรมีอย่างน้อย 5 และแนะนำ 10–20")
    if len(frame) and largest_incidents.iloc[0] / len(frame) > 0.20:
        warnings.append("incident ที่ใหญ่ที่สุดมีมากกว่า 20% ของข้อมูลทั้งหมด")
    return {
        "incident_count": int(frame["incident_id"].nunique()),
        "rows_by_label": {k: int(v) for k, v in rows_by_label.items()},
        "incidents_by_label": {k: int(v) for k, v in incidents_by_label.items()},
        "largest_incidents": [
            {"incident_id": incident, "label": label, "rows": int(count)}
            for (incident, label), count in largest_incidents.items()
        ],
        "warnings": warnings,
    }


def evaluate_group_cv(frame, X, y, requested_folds, seed, min_incidents_per_class):
    incidents_by_label = (
        frame[["incident_id", "manual_label"]].drop_duplicates()["manual_label"]
        .value_counts().reindex(LABEL_TO_ID, fill_value=0)
    )
    smallest_class = int(incidents_by_label.min())
    if smallest_class < min_incidents_per_class:
        raise ValueError(
            f"Incident ต่อคลาสไม่พอ: {incidents_by_label.to_dict()} "
            f"(กำหนดขั้นต่ำ {min_incidents_per_class})"
        )
    if smallest_class < 2:
        raise ValueError("แต่ละ Label ต้องมีอย่างน้อย 2 incident_id เพื่อทำ Group Cross-validation")

    folds_used = min(requested_folds, smallest_class)
    splitter = StratifiedGroupKFold(n_splits=folds_used, shuffle=True, random_state=seed)
    predicted = np.full(len(frame), -1, dtype=int)
    fold_metrics = []

    for fold_number, (train_index, test_index) in enumerate(
        splitter.split(X, y, groups=frame["incident_id"]), start=1
    ):
        train_frame = frame.iloc[train_index]
        model = clone(build_pipeline(seed + fold_number))
        model.fit(
            X.iloc[train_index], y.iloc[train_index],
            model__sample_weight=incident_balanced_weights(train_frame),
        )
        fold_predicted = model.predict(X.iloc[test_index]).astype(int)
        predicted[test_index] = fold_predicted
        fold_report = classification_report(
            y.iloc[test_index], fold_predicted, labels=[0, 1, 2],
            target_names=list(LABEL_TO_ID), output_dict=True, zero_division=0,
        )
        fold_metrics.append({
            "fold": fold_number,
            "train_rows": int(len(train_index)),
            "test_rows": int(len(test_index)),
            "train_incidents": int(train_frame["incident_id"].nunique()),
            "test_incidents": int(frame.iloc[test_index]["incident_id"].nunique()),
            "macro_f1": float(fold_report["macro avg"]["f1-score"]),
            "dangerous_recall": float(fold_report["Dangerous"]["recall"]),
        })

    if (predicted < 0).any():
        raise RuntimeError("Cross-validation ไม่ได้สร้าง prediction ครบทุกแถว")

    report = classification_report(
        y, predicted, labels=[0, 1, 2], target_names=list(LABEL_TO_ID),
        output_dict=True, zero_division=0,
    )
    matrix = confusion_matrix(y, predicted, labels=[0, 1, 2])
    return {
        "cv_folds_requested": int(requested_folds),
        "cv_folds_used": int(folds_used),
        "folds": fold_metrics,
        "macro_f1": float(report["macro avg"]["f1-score"]),
        "dangerous_recall": float(report["Dangerous"]["recall"]),
        "dangerous_as_safe": int(((y.to_numpy() == 2) & (predicted == 0)).sum()),
        "confusion_matrix": matrix.tolist(),
        "classification_report": report,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path("routed/ml_candidates.csv"))
    parser.add_argument("--ground-truth", type=Path, default=Path("ground_truth_manual.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("model"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument("--min-incidents-per-class", type=int, default=2)
    parser.add_argument("--min-macro-f1", type=float, default=0.60)
    parser.add_argument("--min-dangerous-recall", type=float, default=0.70)
    parser.add_argument(
        "--allow-low-quality", action="store_true",
        help="บันทึก candidate model แม้ไม่ผ่าน quality gate",
    )
    args = parser.parse_args()

    candidates = pd.read_csv(args.input, dtype={"event_id": str, "rule_id": str})
    labels = load_approved_ground_truth(args.ground_truth)
    frame = merge_labels(candidates, labels)

    missing_features = sorted(set(FEATURES) - set(frame.columns))
    if missing_features:
        raise ValueError(f"ML Candidates ขาด Feature: {missing_features}")

    X = frame[FEATURES].copy()
    y = frame["manual_label"].map(LABEL_TO_ID).astype(int)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    diagnostics = dataset_diagnostics(frame)
    evaluation = evaluate_group_cv(
        frame, X, y, args.cv_folds, args.seed, args.min_incidents_per_class,
    )
    quality_reasons = []
    if evaluation["macro_f1"] < args.min_macro_f1:
        quality_reasons.append(
            f"macro_f1 {evaluation['macro_f1']:.3f} ต่ำกว่า {args.min_macro_f1:.3f}"
        )
    if evaluation["dangerous_recall"] < args.min_dangerous_recall:
        quality_reasons.append(
            f"dangerous_recall {evaluation['dangerous_recall']:.3f} ต่ำกว่า {args.min_dangerous_recall:.3f}"
        )
    quality_gate_passed = not quality_reasons

    metrics = {
        "feature_count": len(FEATURES),
        "approved_labeled_rows": len(frame),
        "split_seed": args.seed,
        "dataset": diagnostics,
        **evaluation,
        "quality_gate": {
            "passed": quality_gate_passed,
            "min_macro_f1": args.min_macro_f1,
            "min_dangerous_recall": args.min_dangerous_recall,
            "reasons": quality_reasons,
        },
        "model_saved": bool(quality_gate_passed or args.allow_low_quality),
    }
    metrics_path = args.output_dir / "metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    if not quality_gate_passed and not args.allow_low_quality:
        print(json.dumps({"model": None, **metrics}, indent=2))
        print(
            "ไม่บันทึกโมเดล: ไม่ผ่าน quality gate; เพิ่ม independent incidents แล้ว Train ใหม่ "
            "หรือใช้ --allow-low-quality เฉพาะการทดลอง",
            file=sys.stderr,
        )
        return 2

    pipeline = build_pipeline(args.seed)
    pipeline.fit(X, y, model__sample_weight=incident_balanced_weights(frame))
    model_path = args.output_dir / "wazuh_xgboost.joblib"
    joblib.dump({
        "pipeline": pipeline,
        "features": FEATURES,
        "label_to_id": LABEL_TO_ID,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "evaluation": evaluation,
        "quality_gate_passed": quality_gate_passed,
    }, model_path)
    print(json.dumps({"model": str(model_path), **metrics}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
