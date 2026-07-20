"""System behavior baseline learner — daily profiles + anomaly detection.

Analogue of Malio L3 (user profiling) adapted to operations: learns what
"normal" looks like from audit trail, then detects statistical deviations.

Daily profile (computed once per day at 01:00):
  - Command counts by hour
  - Read vs write vs blocked op breakdown
  - Top N most-used commands
  - Unique actors

Anomaly check: compare today-so-far against rolling 30-day baseline.
  Flags any metric exceeding 3 standard deviations from the mean.
"""
import json
import os
import statistics
import threading
from datetime import datetime, timedelta

from audit.store import read_range

BASELINE_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "baseline"
)
MAX_PROFILES = 30


def _today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _yesterday_str() -> str:
    return (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")


def _hour_from_iso(ts: str) -> int:
    try:
        return int(ts[11:13])
    except (ValueError, IndexError):
        return 0


def _parse_date(ts: str) -> str:
    return ts[:10]


class BaselineLearner:
    def __init__(self):
        self._lock = threading.Lock()
        self._profiles: list = []
        self._load()

    # ── Daily profile computation ──

    def learn_daily(self, date_str: str = "") -> dict:
        """Compute a daily profile from the given date's audit JSONL.

        Returns the profile dict.  Automatically persists to disk.
        Called once per day by the lifespan loop.
        """
        target = date_str or _yesterday_str()
        events = read_range(target, target)
        if not events:
            return {"date": target, "total_commands": 0}

        profile = self._compute_profile(target, events)
        self._append(profile)
        return profile

    def _compute_profile(self, date_str: str, events: list) -> dict:
        total = len(events)
        by_hour = [0] * 24
        command_counts: dict = {}
        actors: set = set()
        read_ops = write_ops = blocked_ops = 0

        for e in events:
            hour = _hour_from_iso(e.get("timestamp", ""))
            if 0 <= hour < 24:
                by_hour[hour] += 1

            etype = e.get("event_type", "")
            if etype == "execute":
                cmd = e.get("command", "").split()[0] if e.get("command") else "?"
                command_counts[cmd] = command_counts.get(cmd, 0) + 1
                read_ops += 1
            elif etype == "chain_close":
                ct = e.get("close_type", "")
                if ct == "completed":
                    write_ops += 1
                elif ct in ("vetoed", "rejected"):
                    blocked_ops += 1

            actor = e.get("actor", "")
            if actor:
                actors.add(actor)

        top_cmds = sorted(command_counts.items(), key=lambda x: -x[1])[:5]

        return {
            "date": date_str,
            "total_commands": total,
            "read_ops": read_ops,
            "write_ops": write_ops,
            "blocked_ops": blocked_ops,
            "unique_actors": len(actors),
            "peak_hour": int(max(range(24), key=lambda h: by_hour[h])),
            "hourly_breakdown": by_hour,
            "top_commands": [{"cmd": c, "count": n} for c, n in top_cmds],
        }

    # ── Anomaly detection ──

    def check_anomaly(self, today: dict | None = None) -> dict:
        """Compare today-so-far metrics against the rolling baseline.

        Args:
            today: dict with keys matching profile fields (total_commands,
                   read_ops, write_ops, blocked_ops). If None, computes
                   from today's audit so far.

        Returns: {"anomalies": [...], "baseline_days": N}
        """
        if today is None:
            today = self._today_so_far()

        if len(self._profiles) < 3:
            return {"anomalies": [], "baseline_days": len(self._profiles),
                    "message": "Insufficient baseline data (need >= 3 days)"}

        baseline = self._compute_baseline()
        anomalies = []

        for metric in ("total_commands", "read_ops", "write_ops", "blocked_ops"):
            b = baseline.get(metric)
            if b is None or b["std"] == 0:
                continue
            value = today.get(metric, 0)
            mean = b["mean"]
            sd = b["std"]
            if abs(value - mean) > 3 * sd:
                anomalies.append({
                    "metric": metric,
                    "current": value,
                    "baseline_mean": round(mean, 1),
                    "baseline_std": round(sd, 1),
                    "sigma": round((value - mean) / sd, 2),
                })

        return {
            "anomalies": anomalies,
            "baseline_days": len(self._profiles),
            "today_date": _today_str(),
            "today_summary": today,
        }

    def _compute_baseline(self) -> dict:
        """Compute mean/std for each numeric metric from stored profiles."""
        metrics = ("total_commands", "read_ops", "write_ops", "blocked_ops")
        result = {}
        for m in metrics:
            values = [p.get(m, 0) for p in self._profiles]
            if len(values) < 3:
                result[m] = {"mean": 0, "std": 0}
            else:
                result[m] = {
                    "mean": statistics.mean(values),
                    "std": statistics.stdev(values) if len(values) >= 2 else 0,
                }
        return result

    def _today_so_far(self) -> dict:
        """Compute a snapshot of today's metrics from the audit log."""
        today = _today_str()
        events = read_range(today, today)
        if not events:
            return {"total_commands": 0, "read_ops": 0, "write_ops": 0, "blocked_ops": 0}
        profile = self._compute_profile(today, events)
        return {
            "total_commands": profile["total_commands"],
            "read_ops": profile["read_ops"],
            "write_ops": profile["write_ops"],
            "blocked_ops": profile["blocked_ops"],
        }

    # ── Persistence ──

    def _append(self, profile: dict):
        with self._lock:
            self._profiles.append(profile)
            # Keep only last N profiles
            if len(self._profiles) > MAX_PROFILES:
                self._profiles = self._profiles[-MAX_PROFILES:]
            self._save()

    def _save(self):
        os.makedirs(BASELINE_DIR, exist_ok=True)
        path = os.path.join(BASELINE_DIR, "profiles.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._profiles, f, ensure_ascii=False, indent=2)

    def _load(self):
        path = os.path.join(BASELINE_DIR, "profiles.json")
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._profiles = json.load(f)[-MAX_PROFILES:]
        except (json.JSONDecodeError, OSError):
            pass

    def profile_count(self) -> int:
        return len(self._profiles)
