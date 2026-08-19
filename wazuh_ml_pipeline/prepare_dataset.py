#!/usr/bin/env python3
"""Normalize Wazuh alerts and build leakage-safe behavioral ML features."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path
from typing import Any, Iterable

import pandas as pd


LABEL_ORDER = {"Safe": 0, "Suspicious": 1, "Dangerous": 2}
STAGE_WEIGHTS = {
    "network_scan": 1,
    "service_scan": 2,
    "wordpress_scan": 2,
    "ssh_login_failed": 3,
    "ssh_login_success": 4,
    "suspicious_php_created": 5,
    "web_process_spawned_shell": 6,
    "sudo_group_change": 7,
}
FAILED_ACTIONS = {"ssh_login_failed", "login_failed", "authentication_failed"}
SCAN_ACTIONS = {"network_scan", "service_scan", "wordpress_scan", "port_scan"}
DEFAULT_ASSET_IMPORTANCE = {
    "intranet_server": 9,
    "web_server": 9,
    "database_server": 10,
    "domain_controller": 10,
    "mail_server": 7,
    "mail": 7,
}


def nested(obj: Any, path: str, default: Any = None) -> Any:
    current = obj
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def first(*values: Any, default: Any = None) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return default


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"{path}:{line_number}: each JSON line must be an object")
            yield item


def parse_full_log(alert: dict[str, Any]) -> dict[str, Any]:
    raw = alert.get("full_log")
    if not isinstance(raw, str):
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def normalize_groups(value: Any) -> str:
    if isinstance(value, list):
        return "|".join(sorted(str(item) for item in value))
    return str(value or "unknown")


def normalize_mitre_id(alert: dict[str, Any], payload: dict[str, Any]) -> str:
    value = first(nested(alert, "rule.mitre.id"), nested(payload, "mitre.id"), default=[])
    if isinstance(value, list):
        return "|".join(sorted(str(item) for item in value)) or "none"
    return str(value or "none")


def is_private_ip(value: str) -> int:
    try:
        return int(ipaddress.ip_address(value).is_private)
    except ValueError:
        return 0


def load_asset_map(path: Path | None) -> dict[str, int]:
    result = dict(DEFAULT_ASSET_IMPORTANCE)
    if path is None:
        return result
    with path.open("r", encoding="utf-8") as stream:
        custom = json.load(stream)
    if not isinstance(custom, dict):
        raise ValueError("asset map must be a JSON object: {agent_name: importance}")
    for key, value in custom.items():
        score = int(value)
        if not 1 <= score <= 10:
            raise ValueError(f"asset importance for {key!r} must be between 1 and 10")
        result[str(key)] = score
    return result


def extract_row(alert: dict[str, Any], asset_map: dict[str, int], row_number: int) -> dict[str, Any]:
    payload = parse_full_log(alert)
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}

    event_id = str(first(
        alert.get("event_id"), data.get("event_id"), payload.get("event_id"),
        default=f"unmatched-{row_number}",
    ))
    operation_id = str(first(
        alert.get("operation_id"), data.get("operation_id"), payload.get("operation_id"),
        default="unknown-operation",
    ))
    timestamp = first(alert.get("timestamp"), payload.get("timestamp"))
    agent_name = str(first(nested(alert, "agent.name"), nested(payload, "agent.name"), default="unknown"))
    action = str(first(
        nested(data, "event.action"), nested(alert, "event.action"), nested(payload, "event.action"),
        data.get("action"), default="unknown",
    ))
    category = str(first(
        nested(data, "event.category"), nested(alert, "event.category"), nested(payload, "event.category"),
        data.get("category"), default="unknown",
    ))
    status = str(first(
        nested(data, "event.status"), nested(alert, "event.status"), nested(payload, "event.status"),
        data.get("status"), default="unknown",
    ))
    source_ip = str(first(
        data.get("srcip"), data.get("source_ip"), alert.get("source_ip"), payload.get("source_ip"),
        nested(payload, "source.ip"), default="",
    ))
    username = str(first(
        data.get("srcuser"), nested(data, "user.name"), nested(alert, "user.name"),
        nested(payload, "user.name"), default="",
    ))
    groups = first(nested(alert, "rule.groups"), nested(payload, "rule.groups"), default=[])
    rule_level = int(first(
        nested(alert, "rule.level"), nested(payload, "rule_hint.level"), nested(payload, "rule.level"), default=0,
    ))
    rule_id = str(first(nested(alert, "rule.id"), nested(payload, "rule.id"), default="unknown"))

    return {
        "event_id": event_id,
        "operation_id": operation_id,
        "timestamp": timestamp,
        "agent_name": agent_name,
        "rule_level": rule_level,
        "rule_id": rule_id,
        "rule_groups": normalize_groups(groups),
        "decoder_name": str(first(nested(alert, "decoder.name"), default="unknown")),
        "location": str(alert.get("location", "unknown")),
        "event_category": category,
        "event_action": action,
        "event_status": status,
        "mitre_id": normalize_mitre_id(alert, payload),
        "source_ip_internal": source_ip,
        "username_internal": username,
        "source_is_private": is_private_ip(source_ip),
        "user_present": int(bool(username)),
        "is_privileged_user": int(username.lower() in {"root", "administrator", "admin"}),
        "asset_importance": int(asset_map.get(agent_name, 5)),
        "stage_weight": STAGE_WEIGHTS.get(action, 0),
    }


def trim(queue: deque, cutoff: pd.Timestamp) -> None:
    while queue and queue[0] < cutoff:
        queue.popleft()


def add_behavioral_features(frame: pd.DataFrame) -> pd.DataFrame:
    frame = frame.copy()
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    if frame["timestamp"].isna().any():
        bad = int(frame["timestamp"].isna().sum())
        raise ValueError(f"{bad} alert(s) have missing or invalid timestamps")
    frame = frame.sort_values(["timestamp", "event_id"]).reset_index(drop=True)

    source_events: dict[str, deque] = defaultdict(deque)
    source_failed: dict[str, deque] = defaultdict(deque)
    source_scans: dict[str, deque] = defaultdict(deque)
    host_events: dict[str, deque] = defaultdict(deque)
    action_events: dict[tuple[str, str], deque] = defaultdict(deque)
    host_actions: dict[str, deque] = defaultdict(deque)
    host_stages: dict[str, deque] = defaultdict(deque)

    features: list[dict[str, int]] = []
    for row in frame.itertuples(index=False):
        now = row.timestamp
        source_key = row.source_ip_internal or f"missing:{row.agent_name}:{row.event_id}"
        host_key = row.agent_name
        action_key = (host_key, row.event_action)

        trim(source_events[source_key], now - timedelta(minutes=5))
        trim(source_failed[source_key], now - timedelta(minutes=10))
        trim(source_scans[source_key], now - timedelta(minutes=5))
        trim(host_events[host_key], now - timedelta(minutes=5))
        trim(action_events[action_key], now - timedelta(minutes=5))
        while host_actions[host_key] and host_actions[host_key][0][0] < now - timedelta(minutes=10):
            host_actions[host_key].popleft()
        while host_stages[host_key] and host_stages[host_key][0][0] < now - timedelta(minutes=30):
            host_stages[host_key].popleft()

        previous_stages = [stage for _, stage in host_stages[host_key]]
        features.append({
            "source_events_previous_5m": len(source_events[source_key]),
            "failed_logins_previous_10m": len(source_failed[source_key]),
            "scans_previous_5m": len(source_scans[source_key]),
            "host_events_previous_5m": len(host_events[host_key]),
            "same_action_previous_5m": len(action_events[action_key]),
            "unique_actions_previous_10m": len({action for _, action in host_actions[host_key]}),
            "previous_stage_max_30m": max(previous_stages, default=0),
            "chain_length_previous_30m": len(previous_stages),
        })

        source_events[source_key].append(now)
        host_events[host_key].append(now)
        action_events[action_key].append(now)
        host_actions[host_key].append((now, row.event_action))
        if row.event_action in FAILED_ACTIONS:
            source_failed[source_key].append(now)
        if row.event_action in SCAN_ACTIONS:
            source_scans[source_key].append(now)
        if row.stage_weight:
            host_stages[host_key].append((now, int(row.stage_weight)))

    feature_frame = pd.DataFrame(features)
    frame = pd.concat([frame, feature_frame], axis=1)
    frame["hour"] = frame["timestamp"].dt.hour
    frame["day_of_week"] = frame["timestamp"].dt.dayofweek
    frame["is_after_hours"] = ((frame["hour"] < 8) | (frame["hour"] >= 18)).astype(int)
    return frame


def load_labels(path: Path) -> pd.DataFrame:
    labels = pd.DataFrame(read_jsonl(path))
    required = {"event_id", "class_3"}
    missing = required - set(labels.columns)
    if missing:
        raise ValueError(f"labels file is missing columns: {sorted(missing)}")
    unknown = set(labels["class_3"].dropna()) - set(LABEL_ORDER)
    if unknown:
        raise ValueError(f"unknown labels: {sorted(unknown)}")
    if labels["event_id"].duplicated().any():
        raise ValueError("labels file contains duplicate event_id values")
    return labels[["event_id", "class_3"]]


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    asset_map = load_asset_map(args.asset_map)
    alerts = [extract_row(item, asset_map, index) for index, item in enumerate(read_jsonl(args.alerts), 1)]
    if not alerts:
        raise ValueError("alerts file contains no JSON objects")
    frame = add_behavioral_features(pd.DataFrame(alerts))

    if args.labels:
        labels = load_labels(args.labels)
        frame = frame.merge(labels, on="event_id", how="left", validate="one_to_one")
        unmatched = int(frame["class_3"].isna().sum())
        if unmatched and not args.allow_unlabeled:
            raise ValueError(
                f"{unmatched} alert(s) could not be matched to labels by event_id; "
                "use --allow-unlabeled only for inference data"
            )
    else:
        frame["class_3"] = pd.NA
        unmatched = len(frame)

    # Raw marker-bearing identifiers are used only to calculate behavior and are never exported.
    frame = frame.drop(columns=["source_ip_internal", "username_internal"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(args.output, index=False)

    return {
        "alerts_read": len(alerts),
        "rows_written": len(frame),
        "unlabeled_rows": unmatched,
        "operations": int(frame["operation_id"].nunique()),
        "output": str(args.output.resolve()),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alerts", type=Path, required=True, help="Wazuh alerts.json JSONL file")
    parser.add_argument("--labels", type=Path, help="Ground-truth labels.jsonl from the lab")
    parser.add_argument("--output", type=Path, default=Path("data/dataset.csv"))
    parser.add_argument("--asset-map", type=Path, help="Optional JSON mapping agent names to 1-10 importance")
    parser.add_argument("--allow-unlabeled", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        summary = prepare(args)
    except (OSError, ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
