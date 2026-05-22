"""Append-only JSONL audit storage with SHA256 chaining.

The hash chain persists across process restarts: on first write, the module
reads the last event from today's (or the most recent) audit file and seeds
the in-memory _last_hash from it.
"""
import json
import os
import time
import threading
from datetime import datetime
from audit.chain import hash_event


AUDIT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "audit")
_last_hash = ""
_hash_lock = threading.Lock()
_seeded = False


def _daily_path(for_date: str = "") -> str:
    if not for_date:
        for_date = datetime.now().strftime("%Y-%m-%d")
    return os.path.join(AUDIT_DIR, f"{for_date}.jsonl")


def _seed_from_disk():
    global _last_hash, _seeded
    if _seeded:
        return
    _seeded = True
    if not os.path.isdir(AUDIT_DIR):
        return
    # Scan all JSONL files, pick the last event by timestamp
    files = sorted([f for f in os.listdir(AUDIT_DIR) if f.endswith(".jsonl")],
                   reverse=True)
    for fname in files:
        path = os.path.join(AUDIT_DIR, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                last_line = None
                for line in f:
                    if line.strip():
                        last_line = line
                if last_line:
                    event = json.loads(last_line)
                    _last_hash = event.get("event_hash", "")
                    return
        except (OSError, json.JSONDecodeError):
            continue


def write_event(event_type: str, payload: dict, user_id: str = "default"):
    global _last_hash
    os.makedirs(AUDIT_DIR, exist_ok=True)
    _seed_from_disk()

    event = {
        "event_id": f"evt_{int(time.time() * 1_000_000)}",
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "actor": f"user:{user_id}",
        **payload,
    }

    with _hash_lock:
        prev = _last_hash
        event["prev_hash"] = prev
        event["event_hash"] = hash_event(event, prev)
        _last_hash = event["event_hash"]

    path = _daily_path()
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

    return event


def read_recent(limit: int = 50) -> list:
    path = _daily_path()
    if not os.path.exists(path):
        return []
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                events.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue
    return events[-limit:]


def read_range(from_date: str, to_date: str) -> list:
    events = []
    for fname in sorted(os.listdir(AUDIT_DIR)):
        if not fname.endswith(".jsonl"):
            continue
        date_str = fname[:10]
        if from_date <= date_str <= to_date:
            with open(os.path.join(AUDIT_DIR, fname), "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        events.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
    return events
