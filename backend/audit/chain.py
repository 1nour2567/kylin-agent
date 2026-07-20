"""SHA256 hash chain for tamper-evident audit trail."""
import hashlib
import json


def hash_event(event: dict, prev_hash: str = "") -> str:
    payload = json.dumps(event, sort_keys=True, ensure_ascii=False)
    combined = payload + prev_hash
    return hashlib.sha256(combined.encode()).hexdigest()


def verify_chain(events: list) -> tuple:
    if not events:
        return True, 0

    # Seed from first event's prev_hash — chain may span multiple days
    prev_hash = events[0].get("prev_hash", "")
    for i, event in enumerate(events):
        stored_hash = event.get("event_hash", "")
        computed = hash_event({k: v for k, v in event.items() if k != "event_hash"}, prev_hash)
        if stored_hash and stored_hash != computed:
            return False, i
        prev_hash = stored_hash or computed

    return True, len(events)
