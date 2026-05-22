import datetime as dt
from perception.os_sensors import MockOSSensor, RealOSSensor
from config import settings


class Perception:
    def __init__(self):
        self.sensor = RealOSSensor() if settings.agent_mode != "mock" else MockOSSensor()

    def build(self, user_input: str, user_id: str = "default",
              role: str = "viewer", key_id: str = "",
              conversation_history: list = None) -> dict:
        now = dt.datetime.now()
        ctx = {
            "user_input": user_input,
            "user_id": user_id,
            "operator": {
                "user_id": user_id,
                "role": role,
                "key_id": key_id,
            },
            "time": {
                "iso": now.isoformat(),
                "hour": now.hour,
                "time_of_day": _time_of_day(now.hour),
            },
            "system": self.sensor.snapshot(),
            "audit_recent": _load_recent_audit(limit=10),
            "conversation_history": conversation_history or [],
        }
        return ctx


def _load_recent_audit(limit: int = 10) -> list:
    try:
        from audit.store import read_recent
        events = read_recent(limit)
        return [
            {
                "type": e.get("event_type", ""),
                "actor": e.get("actor", ""),
                "timestamp": e.get("timestamp", ""),
                "command": e.get("command", ""),
                "exit_code": e.get("exit_code"),
                "input_text": (e.get("input_text") or "")[:120],
            }
            for e in events
            if e.get("event_type") in ("receive", "execute", "chain_close")
        ]
    except Exception:
        return []


def _time_of_day(hour: int) -> str:
    if 5 <= hour < 12:
        return "morning"
    elif 12 <= hour < 18:
        return "afternoon"
    elif 18 <= hour < 22:
        return "evening"
    return "night"
