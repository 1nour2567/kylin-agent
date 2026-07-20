"""
Industrial-grade unified perception data schema.
All perception data flows through these typed models before reaching the reasoner.
Compatible with OpenTelemetry and Prometheus export.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    OK = "ok"
    WARN = "warn"
    CRITICAL = "critical"


class ServiceState(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    FAILED = "failed"
    UNKNOWN = "unknown"


# ── Individual metric types ──

@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str
    cpu_percent: float
    memory_mb: float
    state: str
    uptime_seconds: int
    user: str = "root"
    is_zombie: bool = False


@dataclass(frozen=True)
class ServiceInfo:
    name: str
    state: ServiceState
    enabled: bool
    active_since: str = ""
    memory_mb: float = 0.0


@dataclass(frozen=True)
class DiskInfo:
    mount_point: str
    total_gb: float
    used_gb: float
    available_gb: float
    use_percent: float
    filesystem: str
    severity: Severity = Severity.OK


@dataclass(frozen=True)
class MemoryInfo:
    total_gb: float
    used_gb: float
    available_gb: float
    use_percent: float
    swap_total_gb: float = 0.0
    swap_used_gb: float = 0.0
    severity: Severity = Severity.OK


@dataclass(frozen=True)
class NetworkConnection:
    protocol: str
    local_address: str
    remote_address: str
    state: str
    pid: Optional[int] = None
    process_name: str = ""


@dataclass(frozen=True)
class OpenFile:
    pid: int
    process_name: str
    fd: int
    file_type: str
    path: str
    size_bytes: int = 0


@dataclass(frozen=True)
class LogEntry:
    timestamp: str
    unit: str
    message: str
    priority: str = "info"
    pid: Optional[int] = None


@dataclass(frozen=True)
class FileInfo:
    path: str
    size_bytes: int
    owner: str
    group: str
    permissions: str
    modified_at: str
    accessed_at: str
    is_directory: bool = False


# ── Aggregated snapshots ──

@dataclass
class ProcessSnapshot:
    """Structured process table."""
    total_count: int
    zombie_count: int
    top_by_cpu: list[ProcessInfo] = field(default_factory=list)
    top_by_memory: list[ProcessInfo] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)  # e.g. "僵尸进程堆积"


@dataclass
class ServiceSnapshot:
    """Structured service status."""
    total_count: int
    active_count: int
    failed_count: int
    services: list[ServiceInfo] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)


@dataclass
class DiskSnapshot:
    """Structured disk usage."""
    volumes: list[DiskInfo] = field(default_factory=list)
    critical_volumes: list[DiskInfo] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)


@dataclass
class MemorySnapshot:
    """Structured memory state."""
    memory: Optional[MemoryInfo] = None
    anomalies: list[str] = field(default_factory=list)


@dataclass
class NetworkSnapshot:
    """Structured network state."""
    total_connections: int
    listening_ports: list[int] = field(default_factory=list)
    established_count: int = 0
    time_wait_count: int = 0
    anomalies: list[str] = field(default_factory=list)


@dataclass
class LogSnapshot:
    """Recent system logs."""
    entries: list[LogEntry] = field(default_factory=list)
    error_count: int = 0
    warning_count: int = 0


@dataclass
class FileInventorySnapshot:
    """File system inventory for cleanup analysis."""
    large_files: list[FileInfo] = field(default_factory=list)  # > 100MB
    temp_files: list[FileInfo] = field(default_factory=list)
    log_files: list[FileInfo] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)


# ── Top-level perception context ──

@dataclass
class PerceptionContext:
    """The unified perception snapshot consumed by the reasoner and constraint layers."""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    hostname: str = ""
    arch: str = ""  # e.g. "loongarch64", "x86_64"

    # Sub-snapshots
    processes: ProcessSnapshot = field(default_factory=ProcessSnapshot)
    services: ServiceSnapshot = field(default_factory=ServiceSnapshot)
    disks: DiskSnapshot = field(default_factory=DiskSnapshot)
    memory: MemorySnapshot = field(default_factory=MemorySnapshot)
    network: NetworkSnapshot = field(default_factory=NetworkSnapshot)
    logs: LogSnapshot = field(default_factory=LogSnapshot)
    files: FileInventorySnapshot = field(default_factory=FileInventorySnapshot)

    # Knowledge associations (filled by KnowledgeBase)
    knowledge_hits: list[dict] = field(default_factory=list)

    # Overall anomaly summary
    all_anomalies: list[str] = field(default_factory=list)

    def summary(self) -> str:
        """Compact text summary for LLM prompt."""
        parts = []
        parts.append(f"主机: {self.hostname} ({self.arch})")
        parts.append(f"时间: {self.timestamp}")

        if self.memory.memory:
            m = self.memory.memory
            parts.append(f"内存: {m.used_gb:.1f}/{m.total_gb:.1f}GB ({m.use_percent:.0f}%) [{m.severity.value}]")

        for v in self.disks.volumes[:5]:
            parts.append(f"磁盘 {v.mount_point}: {v.use_percent:.0f}% ({v.available_gb:.1f}GB可用) [{v.severity.value}]")

        parts.append(f"进程: {self.processes.total_count}个 (僵死:{self.processes.zombie_count})")
        parts.append(f"服务: {self.services.active_count}/{self.services.total_count}活跃, {self.services.failed_count}失败")
        parts.append(f"网络: {self.network.total_connections}连接 (ESTABLISHED:{self.network.established_count}, TIME_WAIT:{self.network.time_wait_count})")

        if self.logs.error_count:
            parts.append(f"日志: {self.logs.error_count}条错误, {self.logs.warning_count}条警告")
        if self.files.large_files:
            parts.append(f"大文件: {len(self.files.large_files)}个 (>100MB)")

        if self.knowledge_hits:
            parts.append(f"知识关联: {len(self.knowledge_hits)}条匹配")

        return "\n".join(parts)

    def summary_json(self) -> dict:
        """Machine-readable summary for MCP/API export."""
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "arch": self.arch,
            "memory": {
                "used_gb": round(self.memory.memory.used_gb, 1) if self.memory.memory else 0,
                "total_gb": round(self.memory.memory.total_gb, 1) if self.memory.memory else 0,
                "use_percent": round(self.memory.memory.use_percent, 0) if self.memory.memory else 0,
            } if self.memory.memory else None,
            "disks": [{"mount": d.mount_point, "use_pct": d.use_percent, "severity": d.severity.value}
                      for d in self.disks.volumes],
            "processes": {"total": self.processes.total_count, "zombie": self.processes.zombie_count},
            "services": {"total": self.services.total_count, "active": self.services.active_count,
                         "failed": self.services.failed_count, "anomalies": self.services.anomalies},
            "network": {"connections": self.network.total_connections,
                        "established": self.network.established_count},
            "logs": {"errors": self.logs.error_count, "warnings": self.logs.warning_count},
            "anomalies": self.all_anomalies,
            "knowledge_hits": len(self.knowledge_hits),
        }
