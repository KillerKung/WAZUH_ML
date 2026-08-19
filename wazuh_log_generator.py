#!/usr/bin/env python3
"""Generate safe, synthetic JSON logs for a Wazuh lab.

This program simulates the Wazuh project scope without scanning hosts,
guessing passwords, opening shells, or changing privileges.  It writes:

1. events.jsonl - events that a Wazuh agent can monitor.
2. labels.jsonl - ground truth/provenance kept separate to prevent ML leakage.

Each JSON object is written on one line so Wazuh's JSON log collector can read
it with <log_format>json</log_format>.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, TextIO


DEFAULT_ATTACKER_IP = "10.99.99.10"
DEFAULT_NORMAL_IP = "10.0.0.55"
DEFAULT_TARGET = "intranet_server"


@dataclass(frozen=True)
class ScenarioEvent:
    category: str
    action: str
    message: str
    severity: int
    mitre_id: str | None = None
    mitre_tactic: str | None = None
    username: str | None = None
    source_ip: str | None = None
    process_name: str | None = None
    file_path: str | None = None
    status: str = "observed"


NOISE_EVENTS = (
    ScenarioEvent("update", "signature_update", "ClamAV signature database updated", 3),
    ScenarioEvent("package", "package_install", "apt installed approved package", 3),
    ScenarioEvent("cron", "session_open", "cron opened a root session", 3, username="root"),
    ScenarioEvent("backup", "backup_complete", "Scheduled backup completed", 2),
    ScenarioEvent("service", "service_restart", "Approved service restart completed", 3),
    ScenarioEvent(
        "authentication",
        "ssh_login_success",
        "SSH successful login for normal user",
        5,
        mitre_id="T1078",
        mitre_tactic="Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        username="alice",
        source_ip=DEFAULT_NORMAL_IP,
    ),
    ScenarioEvent(
        "privilege",
        "sudo_group_change",
        "Administrator added an approved user to sudo group",
        12,
        mitre_id="T1098",
        mitre_tactic="Persistence, Privilege Escalation",
        username="bob",
    ),
)


ATTACK_CHAIN = (
    ScenarioEvent(
        "network",
        "network_scan",
        "Synthetic network discovery activity",
        5,
        "T1046",
        "Discovery",
        source_ip=DEFAULT_ATTACKER_IP,
    ),
    ScenarioEvent(
        "web",
        "wordpress_scan",
        "Synthetic repeated WordPress path discovery",
        5,
        "T1595.003",
        "Reconnaissance",
        source_ip=DEFAULT_ATTACKER_IP,
    ),
    ScenarioEvent(
        "authentication",
        "ssh_login_failed",
        "Synthetic SSH authentication failure",
        5,
        "T1110",
        "Credential Access",
        username="atk_admin",
        source_ip=DEFAULT_ATTACKER_IP,
        status="failed",
    ),
    ScenarioEvent(
        "authentication",
        "ssh_login_success",
        "Synthetic SSH login after repeated failures",
        5,
        "T1110",
        "Credential Access",
        username="atk_admin",
        source_ip=DEFAULT_ATTACKER_IP,
        status="success",
    ),
    ScenarioEvent(
        "file_integrity",
        "suspicious_php_created",
        "Synthetic suspicious PHP file created in web root",
        6,
        "T1505.003",
        "Persistence",
        source_ip=DEFAULT_ATTACKER_IP,
        file_path="/var/www/html/atk_demo.php",
    ),
    ScenarioEvent(
        "process",
        "web_process_spawned_shell",
        "Synthetic web process spawned a command interpreter",
        8,
        "T1059.004",
        "Execution",
        process_name="bash",
    ),
    ScenarioEvent(
        "privilege",
        "sudo_group_change",
        "Synthetic attack user added to sudo group",
        12,
        "T1548",
        "Privilege Escalation",
        username="atk_admin",
    ),
)


def iso_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_event(
    spec: ScenarioEvent,
    timestamp: datetime,
    operation_id: str,
    agent_name: str,
    session_id: str,
    sequence: int,
) -> tuple[dict, dict]:
    event_id = str(uuid.uuid4())
    event = {
        "timestamp": iso_timestamp(timestamp),
        "event_id": event_id,
        "operation_id": operation_id,
        "source": "wazuh_project_synthetic_generator",
        "agent": {"name": agent_name},
        "event": {
            "category": spec.category,
            "action": spec.action,
            "status": spec.status,
            "sequence": sequence,
        },
        "rule_hint": {
            "level": spec.severity,
            "description": spec.message,
        },
        "message": spec.message,
    }

    if spec.source_ip:
        event["source_ip"] = spec.source_ip
    if spec.username:
        event["user"] = {"name": spec.username}
    if spec.process_name:
        event["process"] = {"name": spec.process_name, "session_id": session_id}
    if spec.file_path:
        event["file"] = {"path": spec.file_path}
    if spec.mitre_id:
        event["mitre"] = {"id": [spec.mitre_id], "tactic": [spec.mitre_tactic]}

    is_attack = spec in ATTACK_CHAIN
    provenance: list[str] = []
    if is_attack:
        if spec.source_ip == DEFAULT_ATTACKER_IP:
            provenance.append("controlled_lab_source")
        if spec.username and spec.username.startswith("atk_"):
            provenance.append("controlled_lab_user")
        if spec.file_path and "atk_" in spec.file_path:
            provenance.append("controlled_lab_file_marker")
        if spec.action in {"web_process_spawned_shell", "sudo_group_change"}:
            provenance.append("controlled_lab_session")

    label = {
        "event_id": event_id,
        "operation_id": operation_id,
        "binary_label": "attack" if is_attack else "noise",
        "class_3": (
            "Dangerous"
            if is_attack and spec.severity >= 8
            else "Suspicious"
            if is_attack
            else "Safe"
        ),
        "provenance": provenance,
        "lab_session_id": session_id if is_attack else None,
    }
    return event, label


def scenario_specs(
    profile: str,
    noise_count: int,
    scan_count: int,
    web_scan_count: int,
    failed_login_count: int,
) -> list[ScenarioEvent]:
    noise = [random.choice(NOISE_EVENTS) for _ in range(noise_count)]
    attack = (
        [ATTACK_CHAIN[0]] * scan_count
        + [ATTACK_CHAIN[1]] * web_scan_count
        + [ATTACK_CHAIN[2]] * failed_login_count
        + list(ATTACK_CHAIN[3:])
    )
    if profile == "baseline":
        return noise
    if profile == "attack":
        return attack

    # Mixed keeps a realistic baseline around the ordered attack chain.
    split = len(noise) // 2
    return noise[:split] + attack + noise[split:]


def write_json_line(stream: TextIO, payload: dict) -> None:
    stream.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
    stream.flush()


def generate(args: argparse.Namespace) -> dict[str, int | str]:
    random.seed(args.seed)
    operation_id = args.operation_id or f"op-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"
    session_id = f"lab-{uuid.uuid4().hex[:10]}"
    start = args.start_time or datetime.now(timezone.utc)
    specs = scenario_specs(
        args.profile,
        args.noise_count,
        args.scan_count,
        args.web_scan_count,
        args.failed_login_count,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.labels.parent.mkdir(parents=True, exist_ok=True)

    mode = "a" if args.append else "w"
    counts = {"Safe": 0, "Suspicious": 0, "Dangerous": 0}
    with args.output.open(mode, encoding="utf-8") as event_stream, args.labels.open(
        mode, encoding="utf-8"
    ) as label_stream:
        current = start
        for sequence, spec in enumerate(specs, start=1):
            event, label = build_event(
                spec,
                current,
                operation_id,
                args.agent_name,
                session_id,
                sequence,
            )
            write_json_line(event_stream, event)
            write_json_line(label_stream, label)
            counts[label["class_3"]] += 1
            current += timedelta(seconds=args.step_seconds)
            if args.realtime_delay:
                time.sleep(args.realtime_delay)

    return {
        "operation_id": operation_id,
        "profile": args.profile,
        "events_written": len(specs),
        **counts,
        "events_file": str(args.output.resolve()),
        "labels_file": str(args.labels.resolve()),
    }


def parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Use an ISO-8601 time, e.g. 2026-08-18T11:00:00Z") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def positive_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("value must be zero or greater")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create safe synthetic JSONL logs for the Wazuh prioritization lab."
    )
    parser.add_argument("--profile", choices=("baseline", "attack", "mixed"), default="mixed")
    parser.add_argument("--output", type=Path, default=Path("generated/events.jsonl"))
    parser.add_argument("--labels", type=Path, default=Path("generated/labels.jsonl"))
    parser.add_argument("--noise-count", type=positive_int, default=30)
    parser.add_argument("--scan-count", type=positive_int, default=20)
    parser.add_argument("--web-scan-count", type=positive_int, default=20)
    parser.add_argument("--failed-login-count", type=positive_int, default=15)
    parser.add_argument("--agent-name", default=DEFAULT_TARGET)
    parser.add_argument("--operation-id")
    parser.add_argument("--start-time", type=parse_time)
    parser.add_argument("--step-seconds", type=positive_int, default=5)
    parser.add_argument("--realtime-delay", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--append", action="store_true")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.realtime_delay < 0:
        parser.error("--realtime-delay must be zero or greater")
    if args.output.resolve() == args.labels.resolve():
        parser.error("--output and --labels must be different files")

    try:
        summary = generate(args)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
