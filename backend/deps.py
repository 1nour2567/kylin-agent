"""Shared service instances and state for all routers."""
import json
import os
import time
import logging
import threading
from logging.handlers import TimedRotatingFileHandler
from typing import List, Optional

from fastapi import Request

from slowapi import Limiter
from slowapi.util import get_remote_address

from config import settings
from agent.perception import Perception
from agent.router import Router
from agent.reasoner import Reasoner
from agent.classifier import Classifier
from agent.providers import DeepSeekProvider, MockProvider, ProviderRegistry
from agent.risk_posture import RiskPostureEngine
from agent.tools_manifest import MANIFEST
from agent.session_store import SessionStore
from agent.proactive import ProactiveInspector
from audit.baseline import BaselineLearner
from mcp.server import MCPServer
from security.guardrail import Guardrail

class _JSONFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def _setup_logging():
    root = logging.getLogger("kylin-agent")
    root.setLevel(logging.INFO)
    root.handlers.clear()

    # Console: human-readable
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%dT%H:%M:%S"))
    root.addHandler(console)

    # File: structured JSON with daily rotation
    log_dir = os.path.join(os.path.dirname(__file__), "..", "data", "logs")
    os.makedirs(log_dir, exist_ok=True)
    file_handler = TimedRotatingFileHandler(
        os.path.join(log_dir, "agent.log"), when="midnight", backupCount=14,
        encoding="utf-8")
    file_handler.setFormatter(_JSONFormatter())
    root.addHandler(file_handler)


_setup_logging()
logger = logging.getLogger("kylin-agent")
limiter = Limiter(key_func=get_remote_address)

# ── Provider registry ──
provider_registry = ProviderRegistry()
if settings.agent_mode in ("mock", "live"):
    # mock = fake sensors + fake LLM (dev); live = real sensors + fake LLM (VM demo)
    provider_registry.register(MockProvider())
else:
    provider_registry.register(DeepSeekProvider(
        settings.deepseek_api_key, settings.deepseek_base_url, settings.deepseek_model))

# ── Pipeline services ──
perception = Perception()
router = Router()
classifier = Classifier(provider_registry, settings.agent_mode)
reasoner = Reasoner(provider_registry)
session_store = SessionStore()
posture_engine = RiskPostureEngine()
guardrail = Guardrail()
baseline_learner = BaselineLearner()
proactive_inspector = ProactiveInspector()
mcp_server = MCPServer()

# ── WebSocket state ──
_ws_clients: List = []

# ── Pending confirmation store ──
PENDING_TTL = 300
PENDING_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "pending.json")


class PendingStore:
    """Thread-safe pending confirmation store with JSON persistence.

    Survives process restarts: loads from disk on init, saves on every mutation.
    """

    def __init__(self, path: str = PENDING_FILE):
        self.path = path
        self._lock = threading.RLock()
        self._items: dict = {}
        self._load()

    def __contains__(self, event_id: str) -> bool:
        with self._lock:
            return event_id in self._items

    def get(self, event_id: str):
        with self._lock:
            return self._items.get(event_id)

    def add(self, event_id: str, entry: dict):
        with self._lock:
            self._items[event_id] = entry
            self._save()

    def pop(self, event_id: str):
        with self._lock:
            item = self._items.pop(event_id, None)
            if item is not None:
                self._save()
            return item

    def items_for_user(self, user_id: str) -> list:
        with self._lock:
            return [
                {"event_id": eid, "command": p["command"],
                 "risk_label": p["risk_label"], "created_at": p["created_at"]}
                for eid, p in self._items.items()
                if p["user_id"] == user_id
            ]

    def cleanup_expired(self):
        now = time.time()
        with self._lock:
            expired = [eid for eid, p in self._items.items()
                       if now - p.get("created_at", 0) > PENDING_TTL]
            if expired:
                for eid in expired:
                    del self._items[eid]
                self._save()

    def _load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self._items = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass

    def _save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._items, f, ensure_ascii=False)


_pending_confirmations = PendingStore()
_pending_lock = _pending_confirmations._lock  # for backward compat


def cleanup_pending():
    _pending_confirmations.cleanup_expired()


def _file_op(op: str, path: str, content: str) -> dict:
    import os as _os
    if not path:
        return {"status": "error", "reason": "path required"}
    path = _os.path.abspath(_os.path.expanduser(path))
    blocked = {"/etc", "/boot", "/sys", "/proc"}
    if any(path.startswith(d) for d in blocked):
        return {"status": "vetoed", "reason": f"Path {path} is in blocked prefix set"}
    try:
        _os.makedirs(_os.path.dirname(path), exist_ok=True)
        mode = "a" if op == "append" else "w"
        with open(path, mode) as f:
            f.write(content)
        return {"status": "written", "path": path, "bytes": len(content)}
    except Exception as e:
        return {"status": "error", "reason": str(e)[:200]}


def _exec_script(path: str) -> dict:
    import os as _os, subprocess as _sp
    if not path:
        return {"status": "error", "reason": "path required"}
    path = _os.path.abspath(_os.path.expanduser(path))
    allowed_dir = "/tmp/kylin-agent"
    if not path.startswith(allowed_dir + "/") and path != allowed_dir:
        return {"status": "vetoed", "reason": f"Script must be under {allowed_dir}"}
    if not _os.path.isfile(path):
        return {"status": "error", "reason": f"Not a file: {path}"}
    try:
        with open(path) as f:
            first_line = f.readline().strip()
        if first_line.startswith("#!"):
            if any(p in first_line for p in ("python", "perl", "ruby")):
                return {"status": "vetoed", "reason": f"Shebang rejected: {first_line}"}
    except Exception as e:
        return {"status": "error", "reason": str(e)[:200]}
    try:
        r = _sp.run(["bash", path], capture_output=True, text=True, timeout=15)
        return {"status": "executed", "exit_code": r.returncode,
                "stdout": r.stdout[:500], "stderr": r.stderr[:200]}
    except Exception as e:
        return {"status": "error", "reason": str(e)[:200]}


def register_mcp_tools():
    from perception.os_sensors import MockOSSensor, RealOSSensor
    sensor = RealOSSensor() if settings.agent_mode != "mock" else MockOSSensor()

    impls = {
        "get_processes": lambda limit=10: sensor.snapshot()["processes"][:limit],
        "get_services": lambda: sensor.snapshot()["services"],
        "get_disk": lambda: sensor.snapshot()["disk"],
        "get_memory": lambda: sensor.snapshot()["memory"],
        "get_connections": lambda: sensor.snapshot()["connections"],
        "systemctl_status": lambda service: sensor.get_systemctl_status(service),
        "journalctl_logs": lambda unit="", lines=50: sensor.get_journalctl_logs(unit, lines),
        "lsof_files": lambda: sensor.get_lsof_files(),
        "rpm_verify": lambda package="": sensor.get_rpm_verify(package),
        "systemctl_restart": lambda service: {"action": "restart", "service": service,
                                               "status": "pending_confirmation"},
        "journalctl_clean": lambda days="7": {"action": "vacuum", "days": days,
                                               "status": "pending_confirmation"},
        "kill_process": lambda pid: {"action": "kill", "pid": pid, "signal": "SIGTERM",
                                      "status": "pending_confirmation"},
        "truncate_log": lambda file: {"action": "truncate", "file": file,
                                       "status": "pending_confirmation"},
        "create_file": lambda path="", content="": _file_op("create", path, content),
        "append_file": lambda path="", content="": _file_op("append", path, content),
        "execute_script": lambda path="": _exec_script(path),
    }

    for entry in MANIFEST:
        mcp_name = entry["mcp_name"]
        if mcp_name in impls:
            params = {k: v for k, v in entry.get("params", {}).items()}
            mcp_server.register_tool(mcp_name, entry["description"], params, impls[mcp_name])


# ══════════════════════════════════════════════════════════════
# TokenStore interface — pluggable auth backend
# ══════════════════════════════════════════════════════════════

class TokenStore:
    """Pluggable token validation backend.

    Current: reads API_KEY from .env (single token).
    Future: swap implementation to validate JWTs / DB tokens.
    """

    @staticmethod
    def validate(token: str) -> Optional[str]:
        api_key = settings.api_key
        if not api_key:
            return "anonymous"
        import hmac
        if hmac.compare_digest(token, api_key):
            return "authenticated"
        return None


async def get_current_user(request: Request) -> str:
    """FastAPI dependency — extracts user_id from request state (set by middleware)."""
    return getattr(request.state, "user_id", "anonymous")

