#!/usr/bin/env python3
"""Predict Safe/Suspicious/Dangerous classes from a prepared Wazuh CSV."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import pandas as pd


def priority(probability: float, rule_level: float, asset_importance: float, chain_length: float) -> int:
    severity = min(max(float(rule_level), 0.0) / 16.0, 1.0)
    asset = min(max(float(asset_importance), 1.0) / 10.0, 1.0)
    chain = min(max(float(chain_length), 0.0) / 7.0, 1.0)
    return round(100 * (0.50 * probability + 0.20 * severity + 0.20 * asset + 0.10 * chain))


def level(score: int) -> str:
    if score >= 81:
        return "Critical"
    if score >= 61:
        return "High"
    if score >= 31:
        return "Medium"
    return "Low"


def predict(args: argparse.Namespace) -> dict:
    bundle = joblib.load(args.model)
    frame = pd.read_csv(args.dataset)
    missing = set(bundle["feature_columns"]) - set(frame.columns)
    if missing:
        raise ValueError(f"input dataset is missing model features: {sorted(missing)}")

    X = frame[bundle["feature_columns"]]
    predicted_ids = bundle["pipeline"].predict(X)
    probabilities = bundle["pipeline"].predict_proba(X)
    id_to_label = {int(key): value for key, value in bundle["id_to_label"].items()}

    result = frame[[column for column in ("event_id", "operation_id", "timestamp", "agent_name", "rule_id", "rule_level", "event_action") if column in frame]].copy()
    result["predicted_class"] = [id_to_label[int(item)] for item in predicted_ids]
    for class_id, class_name in id_to_label.items():
        result[f"probability_{class_name}"] = probabilities[:, class_id]

    dangerous_id = next(key for key, value in id_to_label.items() if value == "Dangerous")
    dangerous_probability = probabilities[:, dangerous_id]
    rule_levels = frame.get("rule_level", pd.Series(0, index=frame.index))
    asset_scores = frame.get("asset_importance", pd.Series(5, index=frame.index))
    chains = frame.get("chain_length_previous_30m", pd.Series(0, index=frame.index))
    result["priority_score"] = [
        priority(prob, rule, asset, chain)
        for prob, rule, asset, chain in zip(dangerous_probability, rule_levels, asset_scores, chains)
    ]
    result["priority"] = result["priority_score"].map(level)
    result = result.sort_values("priority_score", ascending=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(args.output, index=False)
    return {
        "rows": len(result),
        "critical": int((result["priority"] == "Critical").sum()),
        "high": int((result["priority"] == "High").sum()),
        "output": str(args.output.resolve()),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("predictions/prioritized_alerts.csv"))
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        summary = predict(args)
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
