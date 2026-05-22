from abc import ABC, abstractmethod
from typing import Dict, Any, List
import os


class OSSensor(ABC):
    @abstractmethod
    def snapshot(self) -> dict:
        pass


class RealOSSensor(OSSensor):
    def _run(self, cmd: list) -> str:
        import subprocess
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return (r.stdout or r.stderr or "").strip()
        except Exception:
            return ""

    def get_processes(self) -> list:
        out = self._run(["ps", "aux", "--sort=-%mem"])
        procs = []
        for line in out.split("\n")[1:11]:
            parts = line.split()
            if len(parts) >= 11:
                procs.append({
                    "user": parts[0], "pid": parts[1],
                    "cpu": parts[2], "mem": parts[3],
                    "command": " ".join(parts[10:]),
                })
        return procs

    def get_services(self) -> list:
        out = self._run(["systemctl", "list-units", "--type=service",
                         "--state=running", "--no-legend"])
        services = []
        for line in out.split("\n")[:20]:
            parts = line.split()
            if parts:
                services.append({"unit": parts[0], "state": "running"})
        return services or self._fallback_services()

    def _fallback_services(self) -> list:
        """If systemctl unavailable (container / non-systemd), scan /proc."""
        svcs = []
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                try:
                    with open(f"/proc/{pid}/comm") as f:
                        name = f.read().strip()
                    if name not in {s["unit"] for s in svcs}:
                        svcs.append({"unit": f"{name}.service", "state": "running"})
                except Exception:
                    continue
        except Exception:
            return [{"unit": "unknown.service", "state": "unknown"}]
        return svcs[:20]

    def get_disk(self) -> dict:
        out = self._run(["df", "-h", "/"])
        if not out:
            return {"filesystem": "unknown", "size": "?", "used": "?",
                    "available": "?", "use_pct": "?", "mounted": "/"}
        # Parse "df -h /" output: header line + data line
        lines = out.split("\n")
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 6:
                return {"filesystem": parts[0], "size": parts[1],
                        "used": parts[2], "available": parts[3],
                        "use_pct": parts[4], "mounted": parts[5]}
        return {"filesystem": "?", "size": "?", "used": "?",
                "available": "?", "use_pct": "?", "mounted": "/", "raw": out}

    def get_memory(self) -> dict:
        out = self._run(["free", "-b"])  # bytes for parsing, then convert
        if not out:
            return {"total": "?", "used": "?", "free": "?", "available": "?"}
        lines = out.split("\n")
        # Parse "free -b" output: Mem: total used free ... available
        for line in lines:
            if line.startswith("Mem:"):
                parts = line.split()
                if len(parts) >= 7:
                    return {
                        "total": _human_size(int(parts[1])),
                        "used": _human_size(int(parts[2])),
                        "free": _human_size(int(parts[3])),
                        "available": _human_size(int(parts[6])),
                    }
        # Fallback: try "free -h" and return raw
        out_h = self._run(["free", "-h"])
        return {"total": "?", "used": "?", "free": "?", "available": "?", "raw": out_h}

    def get_connections(self) -> list:
        out = self._run(["ss", "-tlnp"])
        conns = []
        for line in out.split("\n")[1:11]:
            parts = line.split()
            if len(parts) >= 4:
                conns.append({"proto": "tcp", "local": parts[3],
                              "process": parts[-1] if len(parts) > 4 else ""})
        return conns or self._fallback_connections()

    def _fallback_connections(self) -> list:
        """If ss unavailable, try netstat."""
        out = self._run(["netstat", "-tlnp"])
        conns = []
        for line in out.split("\n")[2:12]:
            parts = line.split()
            if len(parts) >= 4:
                conns.append({"proto": parts[0], "local": parts[3],
                              "process": parts[-1] if len(parts) > 6 else ""})
        return conns

    # ── Individual tool-level sensors (used by MCP tools directly) ──

    def get_systemctl_status(self, service: str) -> dict:
        out = self._run(["systemctl", "status", service, "--no-pager", "-n", "0"])
        if not out:
            return {"service": service, "status": "unknown",
                    "detail": "systemctl unavailable"}
        active = "unknown"
        for line in out.split("\n"):
            line_stripped = line.strip()
            if line_stripped.startswith("Active:"):
                active = line_stripped.replace("Active:", "").strip()
                break
        return {"service": service, "status": active.split()[0] if active != "unknown" else active,
                "detail": active, "raw": out[:500]}

    def get_journalctl_logs(self, unit: str = "", lines: int = 50) -> dict:
        cmd = ["journalctl", "--no-pager", "-n", str(lines)]
        if unit:
            cmd += ["-u", unit]
        out = self._run(cmd)
        if not out:
            return {"unit": unit or "all", "entries": [],
                    "note": "journalctl unavailable or no logs"}
        entries = []
        for line in out.split("\n")[:lines]:
            if line.strip():
                entries.append(line[:300])
        return {"unit": unit or "all", "entries": entries, "count": len(entries)}

    def get_lsof_files(self) -> dict:
        """List open files for common service processes."""
        procs = self._run(["ps", "-eo", "pid,comm", "--no-headers"])
        target_pids = []
        for line in procs.split("\n"):
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1] in ("sshd", "nginx", "mysqld",
                                                  "mariadbd", "crond", "firewalld"):
                target_pids.append(parts[0])
        if not target_pids:
            # Fallback: list any network listeners
            out = self._run(["lsof", "-nP", "-i"])
            return {"open_files": out[:2000] if out else "(lsof unavailable)",
                    "count": len(out.split("\n")) - 1 if out else 0}
        out = self._run(["lsof", "-nP", "-p", ",".join(target_pids[:10])])
        return {"open_files": out[:2000] if out else "(no open files or lsof unavailable)",
                "count": len(out.split("\n")) - 1 if out else 0}

    def get_rpm_verify(self, package: str = "") -> dict:
        if package:
            out = self._run(["rpm", "-V", package])
            if not out:
                q = self._run(["rpm", "-q", "--info", package])
                return {"package": package, "verified": not bool(out),
                        "detail": "No verification issues" if not out else out[:500],
                        "info": q[:500]}
            return {"package": package, "verified": False,
                    "detail": out[:1000]}
        # List all packages with issues
        out = self._run(["rpm", "-Va"])
        issues = [l for l in out.split("\n") if l.strip()][:30] if out else []
        return {"package": "(all)", "verified": len(issues) == 0,
                "issues": issues, "count": len(issues)}

    def snapshot(self) -> dict:
        return {
            "processes": self.get_processes(),
            "services": self.get_services(),
            "disk": self.get_disk(),
            "memory": self.get_memory(),
            "connections": self.get_connections(),
        }


def _human_size(bytes_val: int) -> str:
    if bytes_val >= 1073741824:
        return f"{bytes_val / 1073741824:.1f}G"
    if bytes_val >= 1048576:
        return f"{bytes_val / 1048576:.1f}M"
    if bytes_val >= 1024:
        return f"{bytes_val / 1024:.1f}K"
    return f"{bytes_val}B"


class MockOSSensor(OSSensor):
    """Returns realistic fake data for development on non-LoongArch/x86."""

    def get_systemctl_status(self, service: str) -> dict:
        return {"service": service, "status": "running" if "sshd" in service or "firewalld" in service else "inactive",
                "detail": f"Mock: {service} would be checked on real OS"}

    def get_journalctl_logs(self, unit: str = "", lines: int = 50) -> dict:
        entries = [
            "May 19 22:15:01 kylin CROND[1201]: (root) CMD (/usr/libexec/sa/sa1)",
            "May 19 22:10:01 kylin sshd[891]: Accepted publickey for admin from 10.11.0.10 port 58432",
            "May 19 22:05:33 kylin firewalld[562]: WARNING: INVALID_HELPER: 'nf_conntrack_sip' is not available",
        ]
        return {"unit": unit or "all", "entries": entries[:lines], "count": len(entries[:lines])}

    def get_lsof_files(self) -> dict:
        return {"open_files": (
            "sshd    891 root  3u  IPv4  12345  0t0  TCP *:22 (LISTEN)\n"
            "nginx   892 root  6u  IPv4  12346  0t0  TCP *:80 (LISTEN)\n"
            "mariadb 1023 mysql 10u IPv4  12347  0t0  TCP *:3306 (LISTEN)"
        ), "count": 3}

    def get_rpm_verify(self, package: str = "") -> dict:
        if package:
            return {"package": package, "verified": True,
                    "detail": f"Mock: {package} verification passed", "info": ""}
        return {"package": "(all)", "verified": True, "issues": [], "count": 0}

    def snapshot(self) -> dict:
        return {
            "processes": [
                {"user": "root", "pid": "1", "cpu": "0.0", "mem": "0.1", "command": "/usr/lib/systemd/systemd"},
                {"user": "root", "pid": "342", "cpu": "0.0", "mem": "0.3", "command": "/usr/sbin/sshd -D"},
                {"user": "nginx", "pid": "891", "cpu": "0.2", "mem": "1.2", "command": "nginx: worker process"},
                {"user": "mysql", "pid": "1023", "cpu": "0.5", "mem": "8.7", "command": "/usr/sbin/mariadbd"},
                {"user": "root", "pid": "1201", "cpu": "0.1", "mem": "0.4", "command": "/usr/sbin/crond -n"},
            ],
            "services": [
                {"unit": "sshd.service", "state": "running"},
                {"unit": "nginx.service", "state": "stopped"},
                {"unit": "mariadb.service", "state": "running"},
                {"unit": "crond.service", "state": "running"},
                {"unit": "firewalld.service", "state": "running"},
            ],
            "disk": {"filesystem": "/dev/sda1", "size": "50G", "used": "32G", "available": "15G", "use_pct": "68%", "mounted": "/"},
            "memory": {"total": "8.0G", "used": "3.2G", "free": "1.8G", "available": "4.5G"},
            "connections": [
                {"proto": "tcp", "local": "0.0.0.0:22", "process": "sshd"},
                {"proto": "tcp", "local": "0.0.0.0:3306", "process": "mariadbd"},
                {"proto": "tcp", "local": "127.0.0.1:8080", "process": ""},
            ],
        }
