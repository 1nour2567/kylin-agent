"""FOIA endpoints — transparency without exploitability."""
from audit.store import read_recent, read_range
from audit.chain import verify_chain


def query_trail(from_date: str, to_date: str, limit: int = 100) -> dict:
    events = read_range(from_date, to_date)
    events = events[-limit:]
    valid, mismatch_at = verify_chain(events)
    return {
        "events": events,
        "count": len(events),
        "chain_valid": valid,
        "mismatch_at": mismatch_at if not valid else None,
    }


def get_event(event_id: str) -> dict:
    events = read_recent(200)
    for e in events:
        if e.get("event_id") == event_id:
            return e
    return {"error": "Event not found"}


def verify_day(date: str) -> dict:
    events = read_range(date, date)
    valid, mismatch_at = verify_chain(events)
    return {
        "date": date,
        "event_count": len(events),
        "chain_valid": valid,
        "first_mismatch": mismatch_at if not valid else None,
    }
