"""
Industrial-grade perception engine — wraps raw sensors, applies schema,
runs anomaly detection, queries knowledge base.

This is the single entry point for perception data. All downstream consumers
(reasoner, constraint layer, audit) receive PerceptionContext.
"""
from __future__ import annotations
import platform
import socket
from datetime import datetime
from typing import Optional

from perception.schema import (
    PerceptionContext,
    ProcessSnapshot, ServiceSnapshot, DiskSnapshot,
    MemorySnapshot, NetworkSnapshot, LogSnapshot,
    FileInventorySnapshot,
    ProcessInfo, ServiceInfo, DiskInfo, MemoryInfo,
    NetworkConnection, FileInfo, LogEntry,
    Severity, ServiceState,
)
from perception.anomaly_detector import AnomalyDetector
from perception.knowledge_base import OpsKnowledgeBase


class PerceptionEngine:
    """Builds PerceptionContext from raw sensor data + enrichment."""

    def __init__(self):
        self._anomaly_detector = AnomalyDetector()
        self._knowledge_base = OpsKnowledgeBase.instance()

    def build(self, mode: str = "status", user_id: str = "") -> PerceptionContext:
        """Build a full perception snapshot.

        Args:
            mode: 'status' (lightweight) or 'full' (all sensors)
            user_id: for audit trail
        """
        ctx = PerceptionContext(
            timestamp=datetime.now().isoformat(),
            hostname=socket.gethostname(),
            arch=platform.machine(),
        )

        try:
            from perception.os_sensors import RealOSSensor
            sensor = RealOSSensor()

            # ── Processes ──
            if mode in ("status", "full"):
                procs = sensor.get_processes()
                ctx.processes.total_count = len(procs)
                ctx.processes.zombie_count = sum(
                    1 for p in procs if p.get("state", "") == "Z"
                )
                ctx.processes.top_by_cpu = [
                    ProcessInfo(
                        pid=int(p.get("pid", 0)),
                        name=p.get("command", "")[:30],
                        cpu_percent=float(p.get("cpu", 0)),
                        memory_mb=float(p.get("mem", 0)) * 0.01,  # approximate
                        state=p.get("state", "S"),
                        uptime_seconds=0,
                        user=p.get("user", "root"),
                        is_zombie=(p.get("state", "") == "Z"),
                    )
                    for p in procs[:10]
                ]

            # ── Services ──
            if mode in ("status", "full"):
                svcs = sensor.get_services()
                ctx.services.total_count = len(svcs)
                svc_list = []
                for s in svcs:
                    state_str = s.get("state", "unknown")
                    state = ServiceState.ACTIVE if state_str in ("active", "running") else \
                            ServiceState.FAILED if state_str == "failed" else \
                            ServiceState.INACTIVE if state_str == "inactive" else \
                            ServiceState.UNKNOWN
                    svc_list.append(ServiceInfo(
                        name=s.get("unit", s.get("name", "unknown")),
                        state=state,
                        enabled=s.get("enabled", False),
                    ))
                ctx.services.services = svc_list
                ctx.services.active_count = sum(
                    1 for s in svc_list if s.state == ServiceState.ACTIVE
                )
                ctx.services.failed_count = sum(
                    1 for s in svc_list if s.state == ServiceState.FAILED
                )

            # ── Disks ──
            if mode in ("status", "full"):
                disks = sensor.get_disk()
                vol_list = []
                for d in disks:
                    use_pct = float(d.get("use_pct", d.get("use_percent", 0)))
                    sev = Severity.CRITICAL if use_pct > 90 else \
                          Severity.WARN if use_pct > 80 else Severity.OK
                    vol_list.append(DiskInfo(
                        mount_point=d.get("mount", d.get("mount_point", "/")),
                        total_gb=float(d.get("total_gb", d.get("total", 0))),
                        used_gb=float(d.get("used_gb", d.get("used", 0))),
                        available_gb=float(d.get("avail_gb", d.get("available", 0))),
                        use_percent=use_pct,
                        filesystem=d.get("fs", d.get("filesystem", "")),
                        severity=sev,
                    ))
                ctx.disks.volumes = vol_list
                ctx.disks.critical_volumes = [
                    v for v in vol_list if v.severity == Severity.CRITICAL
                ]

            # ── Memory ──
            if mode in ("status", "full"):
                mem = sensor.get_memory()
                if mem:
                    use_pct = float(mem.get("use_pct", mem.get("use_percent", 0)))
                    sev = Severity.CRITICAL if use_pct > 95 else \
                          Severity.WARN if use_pct > 85 else Severity.OK
                    ctx.memory.memory = MemoryInfo(
                        total_gb=float(mem.get("total_gb", mem.get("total", 0))),
                        used_gb=float(mem.get("used_gb", mem.get("used", 0))),
                        available_gb=float(mem.get("avail_gb", mem.get("available", 0))),
                        use_percent=use_pct,
                        swap_total_gb=float(mem.get("swap_total_gb", mem.get("swap_total", 0))),
                        swap_used_gb=float(mem.get("swap_used_gb", mem.get("swap_used", 0))),
                        severity=sev,
                    )

            # ── Network ──
            if mode == "full":
                conns = sensor.get_connections()
                ctx.network.total_connections = len(conns)
                ctx.network.established_count = sum(
                    1 for c in conns if c.get("state", "") == "ESTABLISHED"
                )
                ctx.network.time_wait_count = sum(
                    1 for c in conns if c.get("state", "") == "TIME_WAIT"
                )
                listening = set()
                for c in conns:
                    local = c.get("local", c.get("local_address", ""))
                    if "LISTEN" in c.get("state", ""):
                        try:
                            port = int(local.split(":")[-1])
                            listening.add(port)
                        except ValueError:
                            pass
                ctx.network.listening_ports = sorted(listening)

            # ── Logs ──
            if mode == "full":
                logs = sensor.get_logs()
                ctx.logs.entries = [
                    LogEntry(
                        timestamp=l.get("timestamp", ""),
                        unit=l.get("unit", ""),
                        message=l.get("message", ""),
                        priority=l.get("priority", "info"),
                    )
                    for l in logs[:50]
                ]
                ctx.logs.error_count = sum(
                    1 for l in logs if l.get("priority", "") in ("err", "error", "crit")
                )
                ctx.logs.warning_count = sum(
                    1 for l in logs if l.get("priority", "") == "warning"
                )

        except Exception as e:
            ctx.all_anomalies.append(f"[WARN] 感知层采集异常: {e}")

        # ── Enrichment ──
        try:
            self._anomaly_detector.enrich_perception(ctx)
        except Exception:
            pass

        try:
            self._knowledge_base.enrich_perception(ctx)
        except Exception:
            pass

        return ctx
