#!/usr/bin/env python3
"""Rule-based using rule_id/rule_level/rule_groups/repetition only."""

import argparse
import json
from collections import deque
from pathlib import Path

import pandas as pd


# ใส่เฉพาะ Rule ID ที่ผ่านการตรวจและอนุมัติแล้วเท่านั้น
CRITICAL_RULE_IDS = {
    # Authentication attacks
    "5551",   # PAM: Login ล้มเหลวหลายครั้งในช่วงเวลาสั้น
    "5712",   # SSH brute-force ด้วย User ที่ไม่มีอยู่
    "5720",   # SSH authentication failure หลายครั้ง

    # Web attacks
    "31106",  # Web attack pattern และ Server ตอบ HTTP 200
    "31152",  # SQL Injection หลายครั้งจาก Source IP เดียว
    "31153",  # Common Web Attack หลายครั้งจาก Source IP เดียว
    "31154",  # XSS หลายครั้งจาก Source IP เดียว
}
KNOWN_NOISE_RULE_IDS = {
    # Login lifecycle
    "5502",   # PAM: Login session closed

    # Security Configuration Assessment
    "19001",  # รายงานสรุปผล SCA
    "19008",  # SCA check ผ่าน
    "19009",  # SCA check ไม่เกี่ยวข้องกับเครื่องนี้
    "19010",  # SCA เปลี่ยนจาก failed เป็น passed
    "19015",  # SCA เปลี่ยนจาก not applicable เป็น passed
}

CRITICAL_MIN_LEVEL = 12
KNOWN_NOISE_MAX_LEVEL = 5
AGGREGATE_MAX_LEVEL = 7
AGGREGATE_MIN_COUNT = 10
AGGREGATE_WINDOW_MINUTES = 5

CRITICAL_GROUPS = {"privilege_escalation", "rootcheck", "malware"}


def tokens(value):
    return {
        item.strip().lower()
        for item in str(value or "").replace(",", "|").split("|")
        if item.strip()
    }


def add_rule_count(frame):
    """นับ Rule ID เดียวกันบน Agent เดียวกันย้อนหลัง 5 นาที"""
    result = frame.copy()
    result["timestamp"] = pd.to_datetime(
        result["timestamp"], utc=True, errors="coerce", format="mixed"
    )
    if result["timestamp"].isna().any():
        raise ValueError("พบ timestamp ผิดรูปแบบ")

    counts = pd.Series(0, index=result.index, dtype="int64")
    window = pd.Timedelta(minutes=AGGREGATE_WINDOW_MINUTES)

    for _, group in result.groupby(["agent_name", "rule_id"], dropna=False):
        history = deque()
        for index in group.sort_values(["timestamp", "event_id"]).index:
            now = result.at[index, "timestamp"]
            cutoff = now - window
            while history and history[0] < cutoff:
                history.popleft()
            history.append(now)
            counts.at[index] = len(history)

    result["rule_count"] = counts
    return result


def route(frame):
    routed = add_rule_count(frame)
    decisions = []
    reasons = []

    for row in routed.itertuples(index=False):
        rule_id = str(row.rule_id)
        level = int(row.rule_level)
        groups = tokens(row.rule_groups)

        if rule_id in CRITICAL_RULE_IDS or level >= CRITICAL_MIN_LEVEL or groups & CRITICAL_GROUPS:
            decision = "critical"
            reason = "critical rule id/group or high rule level"
        elif rule_id in KNOWN_NOISE_RULE_IDS and level <= KNOWN_NOISE_MAX_LEVEL:
            decision = "known_noise"
            reason = "approved noise rule id"
        elif (
            rule_id != "unknown"
            and row.rule_count >= AGGREGATE_MIN_COUNT
            and level <= AGGREGATE_MAX_LEVEL
        ):
            decision = "aggregate"
            reason = "same rule repeated >= 10 times in 5 minutes"
        else:
            decision = "ml_candidate"
            reason = "rule is not deterministic enough"

        decisions.append(decision)
        reasons.append(reason)

    routed["rule_decision"] = decisions
    routed["rule_reason"] = reasons
    routed["timestamp"] = routed["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return routed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path("normalized.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("routed"))
    args = parser.parse_args()

    frame = pd.read_csv(args.input, dtype={"event_id": str, "rule_id": str})
    required = {"event_id", "timestamp", "agent_name", "rule_id", "rule_level", "rule_groups"}
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"normalized.csv ขาดคอลัมน์: {missing}")

    routed = route(frame)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    routed.to_csv(args.output_dir / "all_routed.csv", index=False)

    for filename, decision in {
        "critical.csv": "critical",
        "known_noise.csv": "known_noise",
        "aggregated.csv": "aggregate",
        "ml_candidates.csv": "ml_candidate",
    }.items():
        routed[routed["rule_decision"] == decision].to_csv(args.output_dir / filename, index=False)

    report = {
        "input_alerts": len(routed),
        "decision_counts": routed["rule_decision"].value_counts().to_dict(),
        "rule_reduction_rate": float(1 - (routed["rule_decision"] == "ml_candidate").mean()),
    }
    (args.output_dir / "rule_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
