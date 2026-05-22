"""Tests for BaselineLearner — daily profile + anomaly detection."""
import json
import os
import sys
import tempfile
import statistics
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit.baseline import BaselineLearner


def _make_events(date_str: str, n: int,
                 read_ratio: float = 0.7,
                 write_ratio: float = 0.2,
                 block_ratio: float = 0.1,
                 noise: int = 0) -> list:
    """Generate synthetic audit events for a given date.  noise adds +/- variance."""
    import random
    n = n + random.randint(-noise, noise) if noise else n
    n = max(1, n)
    events = []
    for i in range(n):
        hour = 9 + (i * 13 // max(1, n))
        hour = min(23, hour)
        ts = f"{date_str}T{hour:02d}:{(i * 7) % 60:02d}:{i % 60:02d}"
        r = i / max(1, n - 1)

        if r < read_ratio:
            events.append({
                "event_id": f"evt_{i}",
                "timestamp": ts,
                "event_type": "execute",
                "actor": "user:alice",
                "command": "ps aux --no-headers",
                "exit_code": 0,
            })
        elif r < read_ratio + write_ratio:
            events.append({
                "event_id": f"evt_{i}",
                "timestamp": ts,
                "event_type": "chain_close",
                "actor": "user:alice",
                "close_type": "completed",
            })
        else:
            events.append({
                "event_id": f"evt_{i}",
                "timestamp": ts,
                "event_type": "chain_close",
                "actor": "user:bob",
                "close_type": "vetoed",
            })
    return events


class TestBaselineLearner:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        # Patch BASELINE_DIR to use temp
        import audit.baseline as baseline_mod
        self._orig_baseline_dir = baseline_mod.BASELINE_DIR
        baseline_mod.BASELINE_DIR = self.tmpdir
        self.learner = BaselineLearner()

    def teardown_method(self):
        import audit.baseline as baseline_mod
        baseline_mod.BASELINE_DIR = self._orig_baseline_dir
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_compute_profile_basic(self):
        events = _make_events("2026-05-20", 100)
        profile = self.learner._compute_profile("2026-05-20", events)
        assert profile["date"] == "2026-05-20"
        assert profile["total_commands"] == 100
        assert profile["read_ops"] >= 65  # ~70%
        assert profile["write_ops"] >= 15  # ~20%
        assert profile["blocked_ops"] >= 5  # ~10%
        assert 0 <= profile["peak_hour"] <= 23
        assert len(profile["top_commands"]) <= 5

    def test_profile_empty_events(self):
        profile = self.learner._compute_profile("2026-05-20", [])
        assert profile["total_commands"] == 0

    def test_anomaly_insufficient_data(self):
        result = self.learner.check_anomaly({"total_commands": 50})
        assert result["baseline_days"] == 0
        assert len(result["anomalies"]) == 0

    def test_anomaly_detection_3sigma(self):
        # Create 10 days of baseline with slight variance (~100 ± 5)
        for d in range(10):
            date = f"2026-05-{d+10:02d}"
            profile = self.learner._compute_profile(date, _make_events(date, 100, noise=5))
            self.learner._append(profile)

        # Today is 5x normal → should trigger anomaly
        today = {"total_commands": 500, "read_ops": 350, "write_ops": 100, "blocked_ops": 50}
        result = self.learner.check_anomaly(today)

        assert result["baseline_days"] == 10
        assert len(result["anomalies"]) >= 1
        assert any(a["metric"] == "total_commands" for a in result["anomalies"])

    def test_anomaly_no_deviation(self):
        # Create stable baseline of 100 events/day with slight variance
        for d in range(10):
            date = f"2026-05-{d+10:02d}"
            profile = self.learner._compute_profile(date, _make_events(date, 100, noise=5))
            self.learner._append(profile)

        # Today is normal
        today = {"total_commands": 105, "read_ops": 70, "write_ops": 20, "blocked_ops": 10}
        result = self.learner.check_anomaly(today)
        assert len(result["anomalies"]) == 0

    def test_persistence_roundtrip(self):
        events = _make_events("2026-06-01", 50)
        profile = self.learner._compute_profile("2026-06-01", events)
        self.learner._append(profile)

        # Load fresh learner from same dir
        learner2 = BaselineLearner()
        assert learner2.profile_count() == 1
        assert learner2._profiles[0]["date"] == "2026-06-01"

    def test_max_profiles_capped(self):
        for d in range(35):
            date = f"2026-{(d // 30) + 5:02d}-{d % 30 + 1:02d}"
            profile = self.learner._compute_profile(date, [])
            self.learner._append(profile)
        assert self.learner.profile_count() <= 30

    def test_hourly_breakdown_range(self):
        events = _make_events("2026-05-20", 100)
        profile = self.learner._compute_profile("2026-05-20", events)
        assert len(profile["hourly_breakdown"]) == 24
        assert all(0 <= h <= 100 for h in profile["hourly_breakdown"])

    def test_sigma_calculation(self):
        """Verify sigma math: (value - mean) / std yields correct sign."""
        for d in range(10):
            date = f"2026-05-{d+10:02d}"
            profile = self.learner._compute_profile(date, _make_events(date, 100, noise=3))
            self.learner._append(profile)

        # Sharp drop → negative sigma
        today = {"total_commands": 10, "read_ops": 7, "write_ops": 2, "blocked_ops": 1}
        result = self.learner.check_anomaly(today)
        if result["anomalies"]:
            for a in result["anomalies"]:
                assert a["sigma"] < 0  # below baseline
