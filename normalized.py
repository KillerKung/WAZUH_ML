#!/usr/bin/env python3
"""Normalize Raw Wazuh JSONL without event_action/source_system/operation_id/labels."""

import argparse
import hashlib
import ipaddress
import json
from collections import defaultdict, deque
from pathlib import Path

import pandas as pd


def nested(item, path, default=None):
    value = item
    for key in path.split("."):
        if not isinstance(value, dict) or key not in value:
            return default
        value = value[key]
    return value


def first(*values, default=None):
    return next((value for value in values if value not in (None, "")), default)


def integer(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def private_ip(value):
    try:
        return int(ipaddress.ip_address(str(value)).is_private)
    except ValueError:
        return 0


def read_jsonl(path):
    with Path(path).open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"JSON ผิดรูปแบบที่บรรทัด {line_number}") from error
            if not isinstance(item, dict):
                raise ValueError(f"บรรทัด {line_number} ต้องเป็น JSON object")
            yield item


def parse_full_log(alert):
    """Wazuh บางรายการเก็บ JSON ต้นทางไว้ใน full_log"""
    raw = alert.get("full_log")
    if not isinstance(raw, str):
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def group_text(value):
    if isinstance(value, list):
        return "|".join(sorted(str(item).lower() for item in value)) or "unknown"
    return str(value or "unknown").replace(",", "|").lower()


def mitre_text(value):
    if isinstance(value, list):
        return "|".join(sorted(str(item) for item in value)) or "none"
    return str(value or "none")


def stable_event_id(alert, row_number):
    """สร้าง String ID ที่เชื่อมกับ Ground Truth ได้โดยไม่ใช้เลข float"""
    existing = first(alert.get("event_id"), alert.get("id"))
    if existing not in (None, ""):
        return f"wazuh-{existing}"

    raw = json.dumps(alert, ensure_ascii=False, sort_keys=True)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
    return f"wazuh-{digest}-{row_number}"


def extract(alert, row_number):
    """ดึงเฉพาะข้อมูลที่สังเกตได้จริงจาก Alert ไม่อ่าน Ground Truth"""
    payload = parse_full_log(alert)
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}

    groups = group_text(first(nested(alert, "rule.groups"), nested(payload, "rule.groups"), default=[]))
    mitre = mitre_text(first(nested(alert, "rule.mitre.id"), nested(payload, "rule.mitre.id"), default=[]))

    src_ip = str(first(
        data.get("srcip"), data.get("src_ip"),
        nested(data, "srcip"), nested(payload, "network.src_ip"),
        nested(alert, "network.src_ip"), default="",
    ))
    dst_ip = str(first(
        data.get("dstip"), data.get("dest_ip"),
        nested(payload, "network.dest_ip"), nested(alert, "network.dest_ip"), default="",
    ))
    src_port = integer(first(
        data.get("srcport"), data.get("src_port"),
        nested(payload, "network.src_port"), nested(alert, "network.src_port"), default=0,
    ))
    dst_port = integer(first(
        data.get("dstport"), data.get("dest_port"),
        nested(payload, "network.dest_port"), nested(alert, "network.dest_port"), default=0,
    ))

    decoder = str(first(nested(alert, "decoder.name"), nested(payload, "decoder.name"), default="unknown"))
    location = str(alert.get("location", "unknown"))
    lower_context = f"{groups}|{decoder}|{location}".lower()

    process_value = first(
        nested(data, "audit.exe"), nested(data, "audit.command"),
        nested(payload, "audit.process"), nested(alert, "audit.process"), default="",
    )

    return {
        # Identifier ใช้เชื่อม Ground Truth เท่านั้น ห้ามเป็น ML Feature
        "event_id": stable_event_id(alert, row_number),
        "timestamp": first(alert.get("timestamp"), payload.get("timestamp")),
        "agent_name": str(first(nested(alert, "agent.name"), nested(payload, "agent.name"), default="unknown")),

        # ข้อมูล Rule ที่มีอยู่จริงใน Wazuh
        "rule_id": str(first(nested(alert, "rule.id"), nested(payload, "rule.id"), default="unknown")),
        "rule_level": integer(first(nested(alert, "rule.level"), nested(payload, "rule.level"), default=0)),
        "rule_groups": groups,
        "decoder_name": decoder,
        "mitre_id": mitre,
        "location": location,

        # Network fields ถ้า Alert ไม่มีข้อมูลจะเป็น 0 อย่างชัดเจน
        "source_port": src_port,
        "destination_port": dst_port,
        "source_is_private": private_ip(src_ip),
        "destination_is_private": private_ip(dst_ip),
        "network_bytes": integer(first(data.get("bytes"), nested(payload, "network.bytes"), default=0)),
        "network_packets": integer(first(data.get("packets"), nested(payload, "network.packets"), default=0)),

        # Flags สร้างจาก Field/Group ที่สังเกตได้ ไม่ได้เดาว่าเป็นคลาสอะไร
        "has_network_evidence": int(bool(src_ip or dst_ip or src_port or dst_port or "suricata" in lower_context or "ids" in groups)),
        "has_audit_evidence": int("audit" in lower_context or isinstance(data.get("audit"), dict)),
        "has_process_evidence": int(bool(process_value) or "audit_command" in groups),
        "has_file_evidence": int("syscheck" in groups or "file" in groups),
        "has_auth_evidence": int("authentication" in groups or "pam" in groups or "sshd" in lower_context),
        "has_privilege_evidence": int("privilege" in groups or "sudo" in groups or "T1548" in mitre),
    }


def trim(queue, cutoff):
    while queue and queue[0] < cutoff:
        queue.popleft()


def add_behavior(frame):
    """สร้างพฤติกรรมย้อนหลังจาก agent_name + rule_id โดยไม่ใช้สามคอลัมน์ที่ตัดออก"""
    frame = frame.copy()
    frame["timestamp"] = pd.to_datetime(
        frame["timestamp"], utc=True, errors="coerce", format="mixed"
    )
    if frame["timestamp"].isna().any():
        raise ValueError(f"พบ timestamp ผิดรูปแบบ {int(frame['timestamp'].isna().sum())} แถว")

    frame = frame.sort_values(["timestamp", "event_id"]).reset_index(drop=True)

    host_events = defaultdict(deque)
    same_rule_events = defaultdict(deque)
    recent_rules = defaultdict(deque)
    high_level_events = defaultdict(deque)
    auth_events = defaultdict(deque)
    file_events = defaultdict(deque)
    privilege_events = defaultdict(deque)
    mitre_events = defaultdict(deque)
    previous_levels = defaultdict(deque)
    features = []

    for row in frame.itertuples(index=False):
        now = row.timestamp
        host = row.agent_name
        rule_key = f"{host}:{row.rule_id}"

        for queue, minutes in (
            (host_events[host], 5),
            (same_rule_events[rule_key], 5),
            (high_level_events[host], 10),
            (auth_events[host], 10),
            (file_events[host], 10),
            (privilege_events[host], 30),
            (mitre_events[host], 30),
        ):
            trim(queue, now - pd.Timedelta(minutes=minutes))

        while recent_rules[host] and recent_rules[host][0][0] < now - pd.Timedelta(minutes=10):
            recent_rules[host].popleft()
        while previous_levels[host] and previous_levels[host][0][0] < now - pd.Timedelta(minutes=10):
            previous_levels[host].popleft()

        levels = [level for _, level in previous_levels[host]]
        features.append({
            "host_events_previous_5m": len(host_events[host]),
            "same_rule_previous_5m": len(same_rule_events[rule_key]),
            "unique_rules_previous_10m": len({rule for _, rule in recent_rules[host]}),
            "high_level_events_previous_10m": len(high_level_events[host]),
            "auth_events_previous_10m": len(auth_events[host]),
            "file_events_previous_10m": len(file_events[host]),
            "privilege_events_previous_30m": len(privilege_events[host]),
            "mitre_events_previous_30m": len(mitre_events[host]),
            "rule_level_max_previous_10m": max(levels, default=0),
        })

        # เพิ่มเหตุการณ์ปัจจุบันหลังคำนวณ เพื่อให้ Feature มองเฉพาะอดีต
        host_events[host].append(now)
        same_rule_events[rule_key].append(now)
        recent_rules[host].append((now, row.rule_id))
        previous_levels[host].append((now, row.rule_level))
        if row.rule_level >= 8:
            high_level_events[host].append(now)
        if row.has_auth_evidence:
            auth_events[host].append(now)
        if row.has_file_evidence:
            file_events[host].append(now)
        if row.has_privilege_evidence:
            privilege_events[host].append(now)
        if row.mitre_id != "none":
            mitre_events[host].append(now)

    frame = pd.concat([frame, pd.DataFrame(features)], axis=1)
    frame["hour"] = frame["timestamp"].dt.hour
    frame["day_of_week"] = frame["timestamp"].dt.dayofweek
    frame["is_after_hours"] = ((frame["hour"] < 8) | (frame["hour"] >= 18)).astype(int)

    # บันทึก Timestamp เป็นรูปแบบเดียวกันทุกแถว
    frame["timestamp"] = frame["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return frame


def create_ground_truth_template(frame, path):
    """สร้างตารางให้มนุษย์กรอกคำตอบเอง โดยไม่ใส่ Label อัตโนมัติ"""
    template = frame[[
        "event_id", "timestamp", "agent_name", "rule_id", "rule_level",
        "rule_groups", "mitre_id",
    ]].copy()

    # ช่องด้านล่างเป็นช่องที่ผู้ตรวจต้องกรอกเอง
    template["manual_label"] = ""            # Safe / Suspicious / Dangerous
    template["incident_id"] = ""             # เหตุการณ์เดียวกันใช้ ID เดียวกัน
    template["attack_type"] = ""             # เช่น Brute_Force หรือ Privilege_Escalation
    template["confidence"] = ""              # low / medium / high
    template["label_reason"] = ""            # เหตุผลหรือหลักฐานที่ใช้ตัดสิน
    template["reviewer"] = ""                # ชื่อผู้ตรวจ
    template["review_status"] = "pending"    # เปลี่ยนเป็น approved เมื่อยืนยันแล้ว

    path.parent.mkdir(parents=True, exist_ok=True)
    template.to_csv(path, index=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True, help="Raw Wazuh JSONL")
    parser.add_argument("--output", type=Path, default=Path("normalized.csv"))
    parser.add_argument("--ground-truth", type=Path, default=Path("ground_truth_manual.csv"))
    args = parser.parse_args()

    rows = [extract(alert, number) for number, alert in enumerate(read_jsonl(args.input), 1)]
    if not rows:
        raise ValueError("ไฟล์ Input ไม่มี Alert")

    frame = add_behavior(pd.DataFrame(rows))
    if frame["event_id"].duplicated().any():
        raise ValueError("event_id ซ้ำ กรุณาตรวจ Raw alerts")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(args.output, index=False)
    create_ground_truth_template(frame, args.ground_truth)

    print(f"normalized: {args.output} ({len(frame)} แถว)")
    print(f"กรอก Ground Truth ที่: {args.ground_truth}")


if __name__ == "__main__":
    main()

