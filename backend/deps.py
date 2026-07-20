"""Shared service instances and state for all routers."""
import json
import os
import time
import logging
import threading
import secrets
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
from security.redaction import redact_text
from security.tool_gateway import ToolSecurityGateway
from security.capability_token import CapabilityReplayStore, CapabilityTokenService
from security.indirect_injection import ToolOutputGuard
from security.execution_gateway import ExecutionGateway
from agent.tool_runtime import ToolRuntime

class _JSONFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact_text(record.getMessage()),
        }
        if record.exc_info and record.exc_info[1]:
            entry["exc"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(entry, ensure_ascii=False)


class _RedactingFormatter(logging.Formatter):
    def format(self, record):
        return redact_text(super().format(record))


def _setup_logging():
    root = logging.getLogger("kylin-agent")
    root.setLevel(logging.INFO)
    root.handlers.clear()

    # Console: human-readable
    console = logging.StreamHandler()
    console.setFormatter(_RedactingFormatter(
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

# ── Startup manifest validation (#13) ──
from agent.tools_manifest import validate_manifest
_manifest_warnings = validate_manifest()
for w in _manifest_warnings:
    logger.warning("Manifest: %s", w)

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
# Perception has been enhanced with all PerceptionEngine features
# (anomaly detection, large file scan, io stats, config drift, loadavg, knowledge base).
# The separate PerceptionEngine class in perception/engine.py exists as a typed-dataclass
# alternative for advanced use cases but is not used by the main chat pipeline.
posture_engine = RiskPostureEngine()

_data_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "data"))
_replay_path = settings.capability_replay_store or os.path.join(
    _data_dir, "capability_replay.json"
)
_capability_secret = settings.capability_token_secret
if not _capability_secret:
    if settings.environment == "production":
        raise RuntimeError(
            "CAPABILITY_TOKEN_SECRET is required in production; write operations are disabled"
        )
    _capability_secret = secrets.token_urlsafe(48)
    logger.warning(
        "SECURITY WARNING: CAPABILITY_TOKEN_SECRET is unset; using a process-local "
        "development key. Tokens will not survive restart."
    )

capability_replay_store = CapabilityReplayStore(_replay_path)
capability_token_service = CapabilityTokenService(
    capability_replay_store,
    _capability_secret,
    ttl_seconds=settings.capability_token_ttl_seconds,
)


def _output_security_audit(event_type: str, payload: dict) -> None:
    from audit.trail import AuditTrail
    AuditTrail("system:output-guard", role="admin").security_event(event_type, payload)


tool_output_guard = ToolOutputGuard(
    mode=settings.ipi_output_mode,
    max_scan_chars=settings.ipi_max_scan_chars,
    max_decode_depth=settings.ipi_max_decode_depth,
    audit_hook=_output_security_audit,
    on_block=posture_engine.on_veto,
)
guardrail = Guardrail(capability_token_service)
tool_runtime = ToolRuntime()
execution_gateway = ExecutionGateway(
    capability_token_service,
    tool_output_guard,
    tool_runtime,
)
perception = Perception(tool_output_guard)
router = Router()
classifier = Classifier(provider_registry, settings.agent_mode)
reasoner = Reasoner(provider_registry)
session_store = SessionStore()
baseline_learner = BaselineLearner()
proactive_inspector = ProactiveInspector()
mcp_server = MCPServer(output_guard=tool_output_guard)

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

    def compare_and_pop(self, event_id: str, expected_user: str) -> bool:
        """Atomically pop only if owner matches (#07). Returns True on success."""
        with self._lock:
            entry = self._items.get(event_id)
            if entry is None:
                return False
            if entry.get("user_id") != expected_user:
                return False
            del self._items[event_id]
            self._save()
            return True

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
tool_gateway = ToolSecurityGateway(
    guardrail=guardrail,
    posture_engine=posture_engine,
    pending_store=_pending_confirmations,
    logger=logger,
    capability_token_service=capability_token_service,
    execution_gateway=execution_gateway,
    output_guard=tool_output_guard,
)


def cleanup_pending():
    _pending_confirmations.cleanup_expired()


def register_mcp_tools():
    from perception.os_sensors import MockOSSensor, RealOSSensor
    sensor = RealOSSensor() if settings.agent_mode != "mock" else MockOSSensor()
    mcp_server.registry.security_gate = tool_gateway.authorize_mcp
    mcp_server.registry.audit_hook = tool_gateway.record_mcp_execution
    mcp_server.registry.output_guard = tool_output_guard

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
        "systemctl_restart": lambda **_: {"status": "security_gateway_required"},
        "journalctl_clean": lambda **_: {"status": "security_gateway_required"},
        "kill_process": lambda **_: {"status": "security_gateway_required"},
        "truncate_log": lambda **_: {"status": "security_gateway_required"},
        "create_file": lambda **_: {"status": "security_gateway_required"},
        "append_file": lambda **_: {"status": "security_gateway_required"},
        "execute_script": lambda **_: {"status": "security_gateway_required"},
    }

    # Optional params per tool (all others required) (#04)
    _optional_params = {
        "get_processes": ["limit"],
        "journalctl_logs": ["unit", "lines"],
        "rpm_verify": ["package"],
        "journalctl_clean": ["days"],
        "create_file": ["content"],
        "append_file": ["content"],
        "kill_process": ["signal"],
    }
    for entry in MANIFEST:
        mcp_name = entry["mcp_name"]
        if mcp_name in impls:
            params = {k: v for k, v in entry.get("params", {}).items()}
            mcp_server.register_tool(mcp_name, entry["description"], params, impls[mcp_name],
                                     optional_params=_optional_params.get(mcp_name))


# ══════════════════════════════════════════════════════════════
# TokenStore interface — pluggable auth backend
# ══════════════════════════════════════════════════════════════

class TokenStore:
    """Pluggable token validation backend.

    Current: reads API_KEY from .env (single token).
    Future: swap implementation to validate JWTs / DB tokens.

    Note: This is an ALTERNATIVE implementation. The middleware uses KeyStore
    from auth.key_store by default. TokenStore exists as a reference for
    future pluggable auth backends. Both MUST return Optional[dict] with
    keys: user_id, role, key_id.
    """

    @staticmethod
    def validate(token: str) -> Optional[dict]:
        api_key = settings.api_key
        if not api_key:
            return None  # No auth configured → no valid identity
        import hmac
        if hmac.compare_digest(token, api_key):
            return {"user_id": "admin", "role": "admin", "key_id": "key_env"}
        return None


async def get_current_user(request: Request) -> str:
    """FastAPI dependency — extracts user_id from request state (set by middleware)."""
    return getattr(request.state, "user_id", "anonymous")
