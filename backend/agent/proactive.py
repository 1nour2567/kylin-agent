"""Proactive system inspector — scheduled health checks.

Transforms the agent from passive (wait for user input) to active
(autonomously detect issues before users report them).

Runs every INSPECT_INTERVAL seconds (default 300 = 5 min).
Stores last MAX_INSPECT_HISTORY results in a rotating buffer.
"""
import json
import os
import threading
import time
from collections import deque
from datetime import datetime

from perception.os_sensors import RealOSSensor, MockOSSensor
from config import settings

INSPECT_INTERVAL = int(os.getenv("INSPECT_INTERVAL", "300"))
MAX_INSPECT_HISTORY = 100

# Thresholds
DISK_WARN_PCT = 85
DISK_CRIT_PCT = 95
MEM_WARN_PCT = 85
MEM_CRIT_PCT = 95
CRITICAL_SERVICES = ["sshd", "crond", "firewalld"]


class ProactiveInspector:
    def __init__(self):
        self.sensor = RealOSSensor() if settings.agent_mode != "mock" else MockOSSensor()
        self._lock = threading.Lock()
        self._history = deque(maxlen=MAX_INSPECT_HISTORY)
        self._alerts: list = []

    def inspect(self) -> dict:
        """Run a full inspection cycle. Returns a result dict."""
        t0 = time.time()
        snapshot = self.sensor.snapshot()
        findings = []

        # ── Disk ──
        disk = snapshot.get("disk", {})
        disk_pct_str = disk.get("use_pct", "0%")
        try:
            disk_pct = int(disk_pct_str.rstrip("%"))
        except ValueError:
            disk_pct = 0

        if disk_pct >= DISK_CRIT_PCT:
            findings.append({"severity": "critical", "category": "disk",
                             "message": f"磁盘使用率达到 {disk_pct}%，已超过严重阈值 {DISK_CRIT_PCT}%",
                             "detail": disk})
        elif disk_pct >= DISK_WARN_PCT:
            findings.append({"severity": "warning", "category": "disk",
                             "message": f"磁盘使用率达到 {disk_pct}%，超过告警阈值 {DISK_WARN_PCT}%",
                             "detail": disk})

        # ── Memory ──
        mem = snapshot.get("memory", {})
        mem_used = mem.get("used", "0")
        mem_total = mem.get("total", "0")
        try:
            mem_pct = int(round(_parse_size(mem_used) / max(1, _parse_size(mem_total)) * 100))
        except (ValueError, ZeroDivisionError):
            mem_pct = 0

        if mem_pct >= MEM_CRIT_PCT:
            findings.append({"severity": "critical", "category": "memory",
                             "message": f"内存使用率达到 {mem_pct}%，超过严重阈值 {MEM_CRIT_PCT}%",
                             "detail": mem})
        elif mem_pct >= MEM_WARN_PCT:
            findings.append({"severity": "warning", "category": "memory",
                             "message": f"内存使用率达到 {mem_pct}%，超过告警阈值 {MEM_WARN_PCT}%",
                             "detail": mem})

        # ── Critical services ──
        services = {s.get("unit", ""): s for s in snapshot.get("services", [])}
        for svc in CRITICAL_SERVICES:
            found = any(svc in unit for unit in services)
            if not found:
                findings.append({"severity": "critical", "category": "service",
                                 "message": f"关键服务 {svc} 未运行",
                                 "detail": {"service": svc, "state": "not_found"}})

        # ── Build result ──
        critical = [f for f in findings if f["severity"] == "critical"]
        warnings = [f for f in findings if f["severity"] == "warning"]
        healthy = len(findings) == 0

        result = {
            "ts": datetime.now().isoformat(),
            "healthy": healthy,
            "elapsed_ms": round((time.time() - t0) * 1000),
            "critical_count": len(critical),
            "warning_count": len(warnings),
            "disk_pct": disk_pct,
            "mem_pct": mem_pct,
            "findings": findings,
        }

        with self._lock:
            self._history.append(result)
            # Keep alerts for the latest cycle
            self._alerts = [f for f in findings if f["severity"] in ("critical", "warning")]

        return result

    def latest(self) -> dict:
        """Return the most recent inspection result."""
        with self._lock:
            if self._history:
                return self._history[-1]
            return {"healthy": True, "findings": [], "message": "no inspections yet"}

    def recent(self, n: int = 10) -> list:
        with self._lock:
            return list(self._history)[-n:]

    def active_alerts(self) -> list:
        with self._lock:
            return list(self._alerts)

    def has_critical(self) -> bool:
        with self._lock:
            if not self._history:
                return False
            return self._history[-1].get("critical_count", 0) > 0

    def check_anomaly_tie_in(self, baseline_learner) -> list:
        """Combine proactive findings with baseline anomaly detection.

        Called by the API endpoint to give a unified health picture.
        """
        anomalies = baseline_learner.check_anomaly()
        combined = []
        for a in anomalies.get("anomalies", []):
            if abs(a.get("sigma", 0)) > 3:
                combined.append({
                    "severity": "warning",
                    "category": "baseline_anomaly",
                    "message": f"指标 {a['metric']} 偏离基线 {a['sigma']}σ (当前 {a['current']}, 基线均值 {a['baseline_mean']})",
                    "detail": a,
                })
        return combined


def _parse_size(s: str) -> float:
    """Parse a size string like '1.2G' or '350M' to a float in GB."""
    s = s.strip().upper()
    if s.endswith("G"):
        return float(s[:-1])
    if s.endswith("M"):
        return float(s[:-1]) / 1024
    if s.endswith("K"):
        return float(s[:-1]) / (1024 * 1024)
    try:
        return float(s)
    except ValueError:
        return 0
