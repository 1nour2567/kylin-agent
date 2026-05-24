"""Agent OS — production-grade abstract skeleton.

Seven subsystems. Domain-agnostic. Independently validated in two reference
implementations spanning security operations and embodied AI.

  Shell      ← user entry point
  Identity   ← who are you, what can you do
  Scheduler  ← when does what run
  Memory     ← what just happened, what usually happens
  Protocol   ← how the agent talks to tools and peers
  Constraint ← what must never happen
  Tools      ← what the agent can do (domain-specific handlers)

Read order:
  1. This file                         (interfaces + data flow)
  2. CONSTRAINT.md / CONSTRAINT_EN.md   (design rationale + principles)
  3. Kylin-Agent: backend/security/    (concrete — security ops)
  4. Malio:       malio/agent/         (concrete — embodied AI)

Important — this file defines LAYERS, not a pipeline.
  Kylin-Agent wires them one way (commands → validate → execute).
  Malio wires them differently (response → persona filter → core_action push).
  The ABCs are the shared contract. The wiring is domain-specific.

Copyright (c) 2026 1nour2567. MIT License.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Protocol,
    Tuple,
)

__version__ = "1.5.0"
__all__ = [
    # Data
    "ValidationResult",
    "ExecutionResult",
    "AuditEvent",
    "PipelineContext",
    "StateEvent",
    "UserIntent",
    "ScheduleTrigger",
    "LoopTurn",
    "AuthorizationResult",
    "Identity",
    "ToolDefinition",
    "Tier",
    "EventType",
    "MemoryLevel",
    # Shell (interaction layer)
    "AgentShell",
    "Shell",
    "ToolResult",
    # Identity (authentication & authorization)
    "AgentIdentity",
    "IdentityProvider",
    # Scheduler (when tasks run)
    "AgentScheduler",
    "SchedulerProvider",
    # Memory (what the agent remembers)
    "AgentMemory",
    "MemoryProvider",
    # Protocol (Agent-to-system communication)
    "AgentProtocol",
    "AgentWire",
    # Tools (what the agent can do)
    "AgentTools",
    "ToolProvider",
    # Layer ABCs (async — LLM calls are never sync)
    "ReasoningLayer",
    "ConstraintEngine",
    "ExecutionProxy",
    "AuditTrail",
    # Protocols (duck-typing)
    "Reasoner",
    "ConstraintValidator",
    "Executor",
    "Auditor",
    # Exceptions
    "ConstraintError",
    "VetoError",
    "ExecutionRefusedError",
    "AuditIntegrityError",
]


# ═══════════════════════════════════════════════════════════════════
# Enumerations
# ═══════════════════════════════════════════════════════════════════

class Tier(str, Enum):
    """Execution tier.

    Why three tiers — not two (allow / deny):
      A binary gate forces safe-but-suspicious-looking commands into
      either silent auto-execute or hard block — both are wrong. Three
      tiers give a middle path: "this looks risky — ask the human."
    """
    AUTO = "auto"          # Read-only diagnostics.  Execute immediately.
    CONFIRM = "confirm"    # Write operations.  Validate → queue → confirm → execute.
    VETO = "veto"          # Destruction.  Never executable through this proxy.


class EventType(str, Enum):
    """Audit event lifecycle — one event per pipeline stage."""
    RECEIVE = "receive"
    PERCEIVE = "perceive"
    ROUTE = "route"
    REASON = "reason"
    VALIDATE = "validate"
    EXECUTE = "execute"
    CONFIRM = "confirm"
    CHAIN_CLOSE = "chain_close"


class MemoryLevel(str, Enum):
    """Memory tier.  Each level has its own read/write/expire semantics."""
    SHORT_TERM = "short_term"    # Recent events, bounded window, auto-expire
    LONG_TERM = "long_term"      # Distilled preferences, semantic retrieval
    BASELINE = "baseline"        # Statistical norms, anomaly detection


# ═══════════════════════════════════════════════════════════════════
# Custom exceptions
# ═══════════════════════════════════════════════════════════════════

class ConstraintError(Exception):
    """Base exception for all constraint-layer failures."""

class VetoError(ConstraintError):
    """Layer 2 hard-blocked an action.  Must NOT execute.

    Attributes:
        reason:      Human-readable explanation.
        alternative: Safer action to suggest, if one exists.
        ref:         Traceable rejection reference (e.g. 'REF-00001-ROLESWITCH').
    """
    def __init__(self, reason: str, alternative: str = "", ref: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.alternative = alternative
        self.ref = ref

class ExecutionRefusedError(ConstraintError):
    """Layer 3 refused — command not in allowlist, or tier mismatch."""

class AuditIntegrityError(ConstraintError):
    """Layer 4 detected a broken hash chain."""


# ═══════════════════════════════════════════════════════════════════
# Shared data classes — the lingua franca between layers
# ═══════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ValidationResult:
    """Immutable output of ConstraintEngine.validate().

    Frozen so no downstream code can silently flip a veto into a pass.
    """
    allowed: bool
    requires_confirmation: bool = False
    reason: str = ""
    alternative: str = ""
    risk_score: int = 0

    def __post_init__(self):
        # Kylin-Agent operates on a 1-9 risk scale (5 = balanced confirm threshold).
        # 0 is reserved for "not scored".  Hard-cap at 9 so downstream code
        # can't inflate the scale arbitrarily.
        if not (0 <= self.risk_score <= 9):
            raise ValueError(
                f"risk_score must be 0-9 (Kylin confirm threshold range), "
                f"got {self.risk_score}"
            )


@dataclass(frozen=True)
class ExecutionResult:
    """Immutable output of ExecutionProxy.execute()."""
    exit_code: int
    stdout: str
    stderr: str
    tier: Tier = Tier.AUTO


@dataclass(frozen=True)
class AuditEvent:
    """One event in the immutable audit chain.

    event_hash = SHA256(prev_hash + serialized event data).
    prev_hash is REQUIRED — the caller MUST provide the hash of the
    immediately preceding event ("" for the genesis event).  Making
    prev_hash positional prevents accidentally omitting it.

    event_hash is computed by AuditTrail.record(), not by this class.
    The skeleton does not enforce SHA256 correctness here — that
    enforcement belongs to the concrete AuditTrail implementation.
    """
    prev_hash: str                              # REQUIRED — "" for genesis, otherwise prior event's hash
    event_type: EventType
    actor: str
    timestamp: str
    data: Dict[str, Any] = field(default_factory=dict)
    event_hash: str = ""                        # set by AuditTrail.record() after construction

    def __post_init__(self):
        # prev_hash must be a non-None string (empty string = genesis, explicit)
        if not isinstance(self.prev_hash, str):
            raise ValueError(
                f"prev_hash must be str (empty for genesis), "
                f"got {type(self.prev_hash).__name__}"
            )


@dataclass
class PipelineContext:
    """Typed context passed to the reasoning layer.

    Every field except user_input is optional.  Layers 2-4 consume
    the *structured output* of layer 1 — not this context directly.

    audit_recent is present so the reasoning layer can implement
    Intent Profile: the LLM inspects recent events, flags suspicious
    patterns (e.g. "viewer was denied 2 min ago, now operator key"),
    and emits an intent_profile signal that layer 2 consumes.
    """
    user_input: str
    user_id: str = "anonymous"
    role: str = "viewer"                            # admin / operator / viewer
    posture: str = "balanced"                       # restrictive / balanced / permissive
    session_id: str = ""
    conversation_history: List[Dict[str, str]] = field(default_factory=list)
    system_snapshot: Dict[str, Any] = field(default_factory=dict)
    time_of_day: str = ""                           # morning / afternoon / evening / night
    hour: Optional[int] = None                  # 0-23.  None = unknown.  hour and time_of_day MUST be consistent — the caller is responsible for keeping them in sync
    audit_recent: List[Dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class StateEvent:
    """One tick of the Agent's continuous state stream.

    Not a one-shot response — the Agent's body unfolding in time.
    Malio: 60fps particle params (speed, color, density).
    Kylin: system status panel updates (disk%, mem%, service states).

    Discrete respond() tells the user what happened.
    stream_state() shows the user what's happening *right now*.
    """
    timestamp: str
    target: str                       # "particles" | "core" | "atmosphere" | "panel"
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UserIntent:
    """Normalized user input — output of a channel adapter, input to AgentShell.

    Channel adapters (chat box, gesture recognizer, voice transcriber) produce
    this.  AgentShell.receive() consumes it.  The shell doesn't know or care
    whether the original input was typed, spoken, or gestured.

    content:  Normalized text — typed words, transcribed speech,
              or semantic label of a gesture (e.g. "swipe_right_skip").
    source:   Which channel produced this intent.
    raw:      Original channel data (gesture coordinates, audio chunk, etc.).
              Layer 1 MAY inspect this; Layer 2+ should not.
    """
    content: str
    source: str = "text_chat"         # "text_chat" | "gesture" | "voice" | ...
    raw: Any = None                   # Channel-specific data — Layer 1 only


@dataclass(frozen=True)
class ScheduleTrigger:
    """When a scheduled task should fire.

    Kylin:  Interval(300) → active inspection every 5 min.
            Cron("0 1 * * *") → baseline learn at 01:00 daily.
    Malio:  Interval(180) → proactive heartbeat at 3 min (high energy).
            Interval(1200) → deep-night slow pulse.
    """
    type: str                          # "interval" | "cron"
    value: int | str                   # seconds (interval) or cron expression (cron)

    def __post_init__(self):
        if self.type not in ("interval", "cron"):
            raise ValueError(f"ScheduleTrigger.type must be 'interval' or 'cron', got {self.type!r}")
        if self.type == "interval" and not isinstance(self.value, int):
            raise ValueError(f"interval value must be int, got {type(self.value).__name__}")
        if self.type == "cron" and not isinstance(self.value, str):
            raise ValueError(f"cron value must be str, got {type(self.value).__name__}")


@dataclass(frozen=True)
class LoopTurn:
    """One turn of a multi-step reasoning loop.

    The caller feeds turn.context back into the next iteration.
    max_turns caps the loop; the reasoner may also signal "done"
    via turn.done to stop early.
    """
    turn: int
    result: Dict[str, Any] = field(default_factory=dict)
    context: PipelineContext | None = None
    done: bool = False


@dataclass(frozen=True)
class AuthorizationResult:
    """Output of AgentIdentity.authorize().

    Kylin:  allowed + tier (auto/confirm/veto) + risk_score.
    Malio:  allowed + constraints dict (e.g. blocked_actions, energy cap).
    """
    allowed: bool
    tier: Tier = Tier.AUTO
    constraints: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""


@dataclass(frozen=True)
class Identity:
    """Authenticated identity — returned by AgentIdentity.authenticate().

    role:       admin / operator / viewer (Kylin) or "single_user" (Malio).
    attributes: Domain-specific metadata.  Kylin carries groups + mfa flag.
                Malio carries persona energy/warmth/playfulness.
    """
    identity_id: str
    role: str = "viewer"
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolDefinition:
    """What one tool looks like — the LLM sees this, the sandbox enforces it.

    mode: "call" = invoked by LLM via call_tool (Kylin: ps, systemctl restart).
          "continuous" = runs autonomously every frame/tick (Malio: DSL rules).
          Continuous tools are NOT invoked via call_tool; they're scheduled
          by the Scheduler and evaluated by the rule engine.  Full ABC support
          for continuous tools is deferred to a future version.

    Kylin:  ToolDefinition(name="ps_processes", description="List processes",
             parameters={"limit":"int"}, tier=Tier.AUTO)
    Malio:  ToolDefinition(name="search_music", description="Search NetEase",
             parameters={"query":"str"}, tier=Tier.AUTO)
    """
    name: str
    description: str
    parameters: Dict[str, str] = field(default_factory=dict)  # param_name → type
    tier: Tier = Tier.AUTO
    mode: str = "call"              # "call" | "continuous" (future)


# ═══════════════════════════════════════════════════════════════════
# Shell — User & Developer Interface
# ═══════════════════════════════════════════════════════════════════

# ToolProvider is defined in the Tools section at the end of this file.
# With "from __future__ import annotations", forward references are
# stringified — safe to use before the class body is parsed.


class AgentShell(ABC):
    """How users and developers face the Agent.

    Design rationale
    ----------------
    The shell is the boundary between the outside world and the agent's
    internal pipeline.  It translates raw input into PipelineContext
    (receive), dispatches results to the right channel (respond), and
    maintains a continuous state stream for "living" agent bodies
    (stream_state).

    What the shell does NOT do
    --------------------------
    - It does not validate.  That's Layer 2.
    - It does not execute.  That's Layer 3.
    - It does not register tools.  That's the Tools layer — the shell
      merely exposes a reference to the tool registry via .tools.

    Two response modes — why
    -------------------------
    respond()      — discrete.  One-shot.  "Here's the diagnosis."
                     Called once per pipeline turn.
    stream_state() — continuous.  The Agent's body in time.
                     60fps particles (Malio) or live system panel (Kylin).
                     This is not a function call — it's an async iterator
                     that yields forever.

    Reference implementations
    -------------------------
    Kylin-Agent:  routers/chat.py, routers/stream.py, routers/ws.py
    Malio:        agent/feedback.py, frontend/src/ws-client.js
    """

    @abstractmethod
    async def receive(self, intent: UserIntent) -> PipelineContext:
        """Normalized input → typed context for the constraint pipeline.

        The shell does not know whether the original input was typed,
        spoken, or gestured.  A channel adapter (chat box, gesture
        recognizer, voice transcriber) normalizes it to UserIntent first.
        The shell translates UserIntent → PipelineContext for Layer 1.
        """
        ...

    @abstractmethod
    async def respond(self, result: dict) -> None:
        """One-shot response — message, alert, confirmation popup.

        Called once per pipeline turn.  The result dict carries the
        pipeline's output (diagnosis, executed commands, risk labels).
        The shell routes it to the correct output channel.
        """
        ...

    @abstractmethod
    async def stream_state(self) -> AsyncIterator[StateEvent]:
        """Continuous state stream — the Agent's body unfolding in time.

        Yields forever (or until the session ends).  Each tick carries
        a snapshot of the Agent's visual/physical state — particle params,
        panel data, atmosphere variables.  The frontend interpolates
        between ticks.

        Malio:  60fps particle engine consuming StateEvent stream.
        Kylin:  Live system-status panel refreshed every 5s.
        """
        ...

    @property
    @abstractmethod
    def tools(self) -> ToolProvider:
        """The tool registry.  Developers register new tools via
        shell.tools.register(...), not shell.register_tool(...).
        The shell doesn't own tool logic — it exposes access to the
        layer that does.
        """
        ...


class Shell(Protocol):
    """Duck-typing version of AgentShell."""
    async def receive(self, intent: UserIntent) -> PipelineContext: ...
    async def respond(self, result: dict) -> None: ...
    async def stream_state(self) -> AsyncIterator[StateEvent]: ...
    @property
    def tools(self) -> ToolProvider: ...


# ═══════════════════════════════════════════════════════════════════
# Identity — Authentication & Authorization
# ═══════════════════════════════════════════════════════════════════

class AgentIdentity(ABC):
    """Who you are. What you can do. Revocable at any time.

    Design rationale
    ----------------
    The identity layer answers three questions:
      1. Are you who you say you are?          (authenticate)
      2. Are you allowed to do this?           (authorize)
      3. Can that permission be taken away
         without waiting for a TTL?            (revoke — yes, immediately)

    Identity is NOT the LLM's responsibility.  The LLM cannot grant
    itself a higher role, cannot extend its own session, and cannot
    override a revoke.  These decisions are code-level.

    Kylin:  admin/operator/viewer roles with risk-score thresholds.
    Malio:  single-user, but PersonaEngine enforces structural
            constraints — the agent CANNOT emit light_burst when
            energy < 0.3, which is an authorization decision.

    Reference implementations
    -------------------------
    Kylin-Agent:  middleware/auth.py, security/key_store.py
    Malio:        agent/persona.py  (constraint-based identity via persona bounds)
    """

    @abstractmethod
    async def authenticate(self, credential: str) -> Identity:
        """Verify a credential — token, key, password → Identity.

        Returns Identity on success.  Raises on failure (implementations
        choose the exception — ValueError, PermissionError, etc.).
        The caller MUST NOT proceed without a valid Identity.
        """
        ...

    @abstractmethod
    async def authorize(self, identity: Identity, action: str) -> AuthorizationResult:
        """Can this identity perform this action?

        Returns AuthorizationResult — not just a bool.  The result
        carries tier (auto/confirm/veto), constraints, and a human-
        readable reason.  The caller checks result.allowed first,
        then inspects result.tier for execution-level routing.
        """
        ...

    @abstractmethod
    async def revoke(self, identity_id: str) -> None:
        """Immediately invalidate this identity — no TTL grace period.

        After revoke returns, the next authenticate() with this
        credential MUST fail.  Kylin-Agent uses KeyStore mtime;
        every authorization check re-reads the store from disk.
        """
        ...


class IdentityProvider(Protocol):
    """Duck-typing version of AgentIdentity."""
    async def authenticate(self, credential: str) -> Identity: ...
    async def authorize(self, identity: Identity, action: str) -> AuthorizationResult: ...
    async def revoke(self, identity_id: str) -> None: ...


# ═══════════════════════════════════════════════════════════════════
# Scheduler — When Tasks Run
# ═══════════════════════════════════════════════════════════════════

class AgentScheduler(ABC):
    """When does what run.  Four modes covering two reference implementations.

    Design rationale
    ----------------
    Every agent has code that runs "when X happens" — user input arrives,
    a timer fires, one round of reasoning wasn't enough, a feedback
    stream needs continuous attention.  These four modes cover all
    scheduling patterns in Kylin and Malio.

    Modes
    -----
    run_now     Event-driven.  User spoke.  Run the pipeline now.
    schedule    Clock-driven.  Register a task to fire on an interval
                or cron schedule.  Returns a task_id for later cancel().
    loop        Multi-turn reasoning.  Round 1 → observe → Round 2 → ...
                Each iteration yields a LoopTurn; the caller feeds
                turn.context back into the next round.
    ooda_loop   Feedback-driven closed loop.  The scheduler iterates
                a feedback stream forever, calling handler(item) each
                tick.  One error does not stop the loop — it logs,
                yields {"error": ...}, and continues.  The caller
                cancels the task to stop.

    Reference implementations
    -------------------------
    Kylin-Agent:  main.py (Agentic Loop, _atmosphere_loop, _persist_loop)
    Malio:        agent/llm_autonomous.py (Proactive Heartbeat, _react)
    """

    @abstractmethod
    async def run_now(self, trigger: str, context: PipelineContext) -> dict:
        """Event-driven — user input arrived.  Run one full pipeline turn."""
        ...

    @abstractmethod
    def schedule(self, trigger: ScheduleTrigger,
                 task: Callable[[], Awaitable[None]]) -> str:
        """Register a clock-driven task.  Returns task_id for cancel()."""
        ...

    def cancel(self, task_id: str) -> bool:
        """Cancel a scheduled task by id.  Returns True if found and cancelled.

        Default raises NotImplementedError — implementations that support
        cancellation must override.  This is not abstract so existing
        implementations that don't support cancellation can keep working,
        but callers get a clear signal rather than a silent False.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.cancel is not implemented"
        )

    @abstractmethod
    async def loop(self, context: PipelineContext,
                   max_turns: int = 3) -> AsyncIterator[LoopTurn]:
        """Multi-turn reasoning.  Yields one LoopTurn per iteration.

        The caller inspects turn.done to decide whether to stop early.
        The caller feeds turn.context back into the next round's input
        via a new call to loop() — or by mutating context in-place if
        the implementation supports it.
        """
        ...

    @abstractmethod
    async def ooda_loop(
        self,
        feedback: AsyncIterator[dict],
        handler: Callable[[dict], Awaitable[dict]],
    ) -> AsyncIterator[dict]:
        """Feedback-driven closed loop.  Never self-terminates.

        The scheduler iterates feedback, calls handler(item) each tick,
        and yields the handler's output.  Errors in one tick are caught,
        logged, and yielded as {"error": ...} — the loop continues.

        Malio:  OODA rule-health feedback → agent adjusts rules.
        Kylin:  time-based posture regulation → posture engine adapts.
        """
        ...


class SchedulerProvider(Protocol):
    """Duck-typing version of AgentScheduler."""
    async def run_now(self, trigger: str, context: PipelineContext) -> dict: ...
    def schedule(self, trigger: ScheduleTrigger,
                 task: Callable[[], Awaitable[None]]) -> str: ...
    def cancel(self, task_id: str) -> bool: ...
    async def loop(self, context: PipelineContext,
                   max_turns: int = 3) -> AsyncIterator[LoopTurn]: ...
    async def ooda_loop(
        self, feedback: AsyncIterator[dict],
        handler: Callable[[dict], Awaitable[dict]],
    ) -> AsyncIterator[dict]: ...


# ═══════════════════════════════════════════════════════════════════
# Memory — What the Agent Remembers
# ═══════════════════════════════════════════════════════════════════

class AgentMemory(ABC):
    """What just happened, what usually happens, what the user prefers.

    Design rationale
    ----------------
    Three tiers, not two.  Short-term memory captures what's happening
    right now (bounded window, auto-expire).  Long-term memory distills
    patterns from short-term (preferences, habits).  Baseline memory
    defines "normal" — the statistical backdrop that makes anomalies
    visible.

    write/read operate on a level; each level defines its own query
    structure.  expire clears stale entries from bounded windows.
    distill moves patterns from one level to another (L2→L3, or
    session→baseline).  clear empties a level — for tests and GDPR.

    What this does NOT cover
    -------------------------
    Context assembly — combining memory levels into the LLM's prompt
    is the pipeline's responsibility, not the memory layer's.  Memory
    stores and retrieves; the pipeline decides what to show the LLM.

    Reference implementations
    -------------------------
    Kylin-Agent:  memory/session_store.py (short-term), baseline_learner.py
    Malio:        memory/short_term.py (L2), memory/user_profile.py (L3),
                  memory/history.py (L4 append-only log)
    """

    @abstractmethod
    async def write(self, level: MemoryLevel, event: dict) -> None:
        """Store one event at the given memory level."""
        ...

    @abstractmethod
    async def read(self, level: MemoryLevel, query: dict) -> list[dict]:
        """Retrieve events from the given level.

        query shape is level-specific — short-term may take {"limit": 10},
        long-term may take {"embedding": [...], "top_k": 5}.  The ABC
        does not mandate query structure.
        """
        ...

    @abstractmethod
    async def expire(self, level: MemoryLevel) -> int:
        """Remove stale entries from a bounded-window level.

        Returns the number of entries removed.  No-op for levels
        that don't auto-expire (long-term, baseline).
        """
        ...

    @abstractmethod
    async def distill(self, from_level: MemoryLevel,
                      to_level: MemoryLevel) -> dict:
        """Extract patterns from one level into another.

        Typical:  short_term → long_term (L2→L3, hourly).
                  short_term → baseline (session→baseline, daily).
        Returns a summary dict: {"extracted": N, "merged": M}.
        """
        ...

    @abstractmethod
    async def clear(self, level: MemoryLevel) -> int:
        """Delete all entries from a level.  Returns count removed."""
        ...


class MemoryProvider(Protocol):
    """Duck-typing version of AgentMemory."""
    async def write(self, level: MemoryLevel, event: dict) -> None: ...
    async def read(self, level: MemoryLevel, query: dict) -> list[dict]: ...
    async def expire(self, level: MemoryLevel) -> int: ...
    async def distill(self, from_level: MemoryLevel,
                      to_level: MemoryLevel) -> dict: ...
    async def clear(self, level: MemoryLevel) -> int: ...


# ═══════════════════════════════════════════════════════════════════
# Protocol — Agent-to-System Communication
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class ToolResult:
    """Standardized result of a tool call via the protocol layer.

    The protocol layer does not interpret the result — it passes it
    back to the caller (Layer 1 or the scheduling loop) as-is.
    success=False + error string is sufficient for now; a unified
    error-code enum can be added once more implementations surface
    recurring error patterns.
    """
    tool_name: str
    success: bool = True
    data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    latency_ms: float = 0.0


class AgentProtocol(ABC):
    """How an Agent communicates with external systems and tools.

    Design rationale
    ----------------
    This layer is a semantic pipe — unlike a network stack that moves
    opaque bytes, the Agent protocol moves structured semantic messages.
    Both sides agree on what a "tool call" or a "state push" means.

    What the protocol layer does NOT do
    -----------------------------------
    - It does not validate.  That's Layer 2.
    - It does not execute.  That's Layer 3.
    - It does not aggregate rules.  That's the Federation subsystem
      (application logic).  The protocol layer provides send_to_peer()
      as a transport primitive; federation logic calls it.

    Why call_tool + push_state + stream are all here
    -------------------------------------------------
    They are three directions of the same thing — structured messages
    flowing between Agent and outside world:
      call_tool:     Agent → Tool → Agent   (request/response)
      push_state:    Agent → Consumer        (one-way push)
      stream:        Agent → Consumer        (continuous stream)
      send_to_peer:   Agent ↔ Agent           (peer-to-peer request/response)
      stream_to_peer: Agent → Agent            (peer-to-peer continuous stream)

    Reference implementations
    -------------------------
    Kylin-Agent:  mcp/protocol.py, mcp/handlers.py, routers/stream.py
    Malio:        agent/feedback.py (WebSocket push), routers (export/import)
    """

    @abstractmethod
    async def call_tool(self, tool_name: str, params: Dict[str, Any]) -> ToolResult:
        """Standardized tool call — MCP JSON-RPC or equivalent.

        The protocol layer serializes the request, sends it to the tool
        executor, and returns the structured result.  It does not interpret
        the result — that's the caller's job.

        Kylin:  MCP JSON-RPC → tools/call → subprocess
        Malio:  ToolRegistry → search_music / get_weather / etc.
        """
        ...

    @abstractmethod
    async def push_state(self, event: StateEvent) -> None:
        """Push a discrete state snapshot to external consumers.

        One-way.  No response expected.  The consumer could be a frontend
        particle engine (Malio) or a monitoring dashboard (Kylin).

        Kylin:  WebSocket → context push (state_snapshot)
        Malio:  WebSocket → state_snapshot + atmosphere
        """
        ...

    @abstractmethod
    async def stream(self, event_type: str, payload: Dict[str, Any]) -> AsyncIterator[Dict[str, Any]]:
        """Continuous event stream — SSE, WebSocket, or gRPC stream.

        The caller yields dicts; the protocol serializes them for the
        transport.  SSE converts dict→"data: {json}\n\n".  WebSocket
        sends dict as JSON frame.  The interface stays the same.

        Kylin:  SSE /api/chat/stream (token-by-token LLM output)
        Malio:  (not implemented — continuous state via push_state instead)
        """
        ...

    @abstractmethod
    async def send_to_peer(self, peer: str, message: Dict[str, Any]) -> Dict[str, Any]:
        """Send a structured message to another Agent instance.

        Transport primitive.  Federation logic (rule aggregation,
        scoring, merge) is application-layer — this method only
        delivers the message and returns the peer's response.

        Malio:  GET /api/rules/export on peer → receive rule list
        Kylin:  (not implemented — single-instance deployment)
        """
        ...

    async def stream_to_peer(
        self, peer: str, event_type: str, payload: Dict[str, Any]
    ) -> AsyncIterator[Dict[str, Any]]:
        """Continuous event stream pushed to a peer Agent.

        The peer-to-peer counterpart of stream().  Not yet needed by
        either reference implementation (federation syncs are pull-based,
        not real-time pushes), but this completes the communication
        matrix.  Default raises NotImplementedError so existing
        implementations don't break.

        Future use: real-time cross-instance state sync, live rule
        propagation, multi-agent observation sharing.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.stream_to_peer is not implemented"
        )

    @property
    @abstractmethod
    def tool_registry(self) -> ToolProvider:
        """The same ToolProvider that AgentShell.tools exposes.
        Both Shell and Protocol reference the same registry — Shell for
        developer ergonomics, Protocol for tool-call resolution.
        """
        ...


class AgentWire(Protocol):
    """Duck-typing version of AgentProtocol."""
    async def call_tool(self, tool_name: str, params: Dict[str, Any]) -> ToolResult: ...
    async def push_state(self, event: StateEvent) -> None: ...
    async def stream(self, event_type: str, payload: Dict[str, Any]) -> AsyncIterator[Dict[str, Any]]: ...
    async def send_to_peer(self, peer: str, message: Dict[str, Any]) -> Dict[str, Any]: ...
    async def stream_to_peer(self, peer: str, event_type: str, payload: Dict[str, Any]) -> AsyncIterator[Dict[str, Any]]: ...
    @property
    def tool_registry(self) -> ToolProvider: ...


# ═══════════════════════════════════════════════════════════════════
# Layer 1 — Reasoning (LLM)
# ═══════════════════════════════════════════════════════════════════

class ReasoningLayer(ABC):
    """LLM reasons freely. Output is information — not permission to act.

    Design rationale
    ----------------
    This layer has the most freedom and the least authority. The LLM can
    propose anything — creative diagnoses, unconventional commands, novel
    analyses.  It cannot *authorize* anything.  That separation is the
    core of Constraint Architecture: the thinker does not decide what
    is safe.

    Security property: layer-1 output is untrusted input to layer 2.
    Even if an attacker controls the LLM's entire output string, layers
    2-3-4 do not trust it.

    All LLM calls are inherently async (API round-trips, WebSocket
    streaming, asyncio event loops in FastAPI).  This interface is async.

    Reference implementations
    -------------------------
    Kylin-Agent:  agent/reasoner.py       — Reasoner.reason() [async]
    Malio:        agent/reasoner.py       — Reasoner.reason() [async]
    """

    @abstractmethod
    async def reason(self, context: PipelineContext) -> Dict[str, Any]:
        """Accept typed context. Return structured instructions.

        The return value is a free-form dict whose *keys* are the
        contract between layer 1 and layer 2 of a specific pipeline.
        Kylin uses {"commands": [...]}.  Malio uses {"response": ...,
        "core_actions": [...], "atmosphere": {...}}.  The skeleton does
        not mandate a key — only that layers 1 and 2 agree on one.

        Raises:
            RuntimeError: LLM provider unreachable after retries.
        """
        ...


class Reasoner(Protocol):
    """Duck-typing version of ReasoningLayer."""
    async def reason(self, context: PipelineContext) -> Dict[str, Any]: ...


# ═══════════════════════════════════════════════════════════════════
# Layer 2 — Constraints (Deterministic)
# ═══════════════════════════════════════════════════════════════════

class ConstraintEngine(ABC):
    """Deterministic validation. Code never defers to the LLM.

    Design rationale
    ----------------
    This is where "LLM reasons, code decides" lives.  Role, posture, and
    intent_profile all feed into the decision — but the decision itself
    is code, never the LLM.

    Hard guarantee: Layer 2 rejection > Layer 1 preference. Always.
    Even permissive mode + admin role.  The baseline constraints are
    additive-only — new contexts can tighten them, never loosen them.

    Dual-path validation
    --------------------
    LLM output for the same intended action can arrive in two forms:
      structured:  {"tool": "kill_process", "params": {"pid": "1234"}}
      raw string:  "kill -9 1234"
    A single validation path can be bypassed by switching formats.
    Two independent paths — one checking structured tool + params,
    one checking raw regex — close this gap.  Both must pass.

    Reference implementations
    -------------------------
    Kylin-Agent:  security/constraints.py  — 24 regex patterns +
                   destructured tool-name / param-value / path-prefix checks
    Malio:        agent/persona.py         — 3D persona-boundary enforcement:
                   energy<0.3 blocks light_burst; warmth<0.3 truncates messages
    """

    @abstractmethod
    async def validate(
        self,
        llm_output: Dict[str, Any],
        *,
        role: str = "operator",
        posture: str = "balanced",
        intent_profile: Optional[Dict[str, Any]] = None,
    ) -> List[ValidationResult]:
        """Validate every action the LLM proposed.

        Returns one ValidationResult per action.  The caller pairs
        results[i] with the corresponding action — the mapping is the
        caller's responsibility, not the engine's.

        Args:
            llm_output:     Layer-1 output. The engine inspects whatever
                            keys its domain expects (e.g. "commands" for
                            Kylin, "core_actions" for Malio).
            role:           admin / operator / viewer. Drives threshold offset.
            posture:        restrictive / balanced / permissive. Drives base
                            confirm threshold.
            intent_profile: Behavioral signal from the LLM (optional).
                            The LLM provides an *observation*; this engine
                            provides the *decision*.  The LLM says "this
                            looks like a privilege-retry."  The engine
                            reads that hint and adjusts thresholds — but the
                            LLM cannot set the threshold itself.

        Returns:
            One ValidationResult per action. allowed=False = hard veto.
            requires_confirmation=True = confirm-tier — human must approve.

        Raises:
            KeyError: A key this domain's implementation expects in
            llm_output is missing.  The specific key is part of the
            layer-1-to-layer-2 contract for that domain.
        """
        ...


class ConstraintValidator(Protocol):
    """Duck-typing version of ConstraintEngine."""
    async def validate(
        self,
        llm_output: Dict[str, Any],
        *,
        role: str = "operator",
        posture: str = "balanced",
        intent_profile: Optional[Dict[str, Any]] = None,
    ) -> List[ValidationResult]: ...


# ═══════════════════════════════════════════════════════════════════
# Layer 3 — Execution (Sandbox)
# ═══════════════════════════════════════════════════════════════════

class ExecutionProxy(ABC):
    """Tiered execution with whitelist enforcement.

    Design rationale
    ----------------
    auto    — Read-only operations on safe paths. Execute immediately.
              Kylin: ps, df, free, ss, journalctl, systemctl status.
              Malio: atmosphere derivation, color blending.

    confirm — Write operations.  Must survive Layer 2 validation AND
              receive explicit human confirmation before execution.
              Kylin: systemctl restart, kill, truncate.
              Malio: core_action push after persona filtering.

    veto    — Destruction. Never executable through this proxy.
              Kylin: rm, chmod, mkfs, dd.
              Malio: light_burst when energy < 0.3.

    Security property: the executor holds I/O lockouts *outside* of
    any locks — subprocess calls must not keep critical sections open.

    Reference implementations
    -------------------------
    Kylin-Agent:  security/sandbox.py    — subprocess.run with sudo -n
    Malio:        agent/visual_agent.py  — DSL rule evaluation → feedback push
    """

    @abstractmethod
    async def execute(self, command: str, *, tier: Tier = Tier.AUTO) -> ExecutionResult:
        """Execute a command at the given tier.

        The caller MUST have passed this command through Layer 2 and,
        for confirm-tier, obtained human confirmation.

        Args:
            command:  Resolved shell command or action identifier.
            tier:     auto / confirm / veto.

        Returns:
            ExecutionResult.

        Raises:
            ExecutionRefusedError: command not in whitelist, or tier
            mismatch (e.g. attempting to execute a veto-tier command).
        """
        ...

    @abstractmethod
    def resolve_command(self, llm_tool_call: Dict[str, Any]) -> Tuple[str, Tier]:
        """Translate one LLM tool call → (executable_string, tier).

        Pure function — same input always produces the same output.
        No side effects.

        Example:  {"tool": "ps_processes", "params": {"limit": "10"}}
               → ("ps aux --no-headers | head -10", Tier.AUTO)
        """
        ...


class Executor(Protocol):
    """Duck-typing version of ExecutionProxy."""
    async def execute(self, command: str, *, tier: Tier = Tier.AUTO) -> ExecutionResult: ...
    def resolve_command(self, llm_tool_call: Dict[str, Any]) -> Tuple[str, Tier]: ...


# ═══════════════════════════════════════════════════════════════════
# Layer 4 — Audit (Immutable Record)
# ═══════════════════════════════════════════════════════════════════

class AuditTrail(ABC):
    """Every action recorded. Tampering detectable.

    Design rationale
    ----------------
    "The system executed X" ≠ "the system can PROVE it executed X, and
    no one has tampered with the log."  The first is a log.  The second
    is an audit trail with non-repudiation.

    The chain: event_N.hash = SHA256(event_N-1.hash + event_N.data).
    Inserting, deleting, or modifying any event breaks all subsequent
    hashes. verify_chain() pinpoints the break.

    Restart recovery
    ----------------
    _seed_from_disk() reads the last event_hash from the most recent
    persisted log on startup.  Without it, an in-memory _last_hash resets
    to "" on process restart — and the chain silently breaks.  This was
    discovered during live deployment on Kylin V11, not during whiteboard
    design.

    Lightweight form
    ----------------
    Not every domain needs cryptographic non-repudiation.  Malio uses a
    rule-health feedback loop (OODA): the frontend reports back which
    rules fired / were suppressed; the agent uses that signal to correct
    future rule generation.  This is "audit" in the sense of "keeping
    constraints continuously valid at runtime."

    Reference implementations
    -------------------------
    Kylin-Agent:  audit/trail.py          — SHA256 chain + _seed_from_disk
    Malio:        agent/visual_agent.py   — OODA rule-health feedback
    """

    @abstractmethod
    async def record(
        self,
        event_type: EventType,
        data: Dict[str, Any],
        *,
        actor: str = "",
    ) -> AuditEvent:
        """Record one pipeline event into the immutable chain.

        Args:
            event_type:  Pipeline stage identifier.
            data:        Arbitrary event payload.
            actor:       user_id or agent module name.

        Returns:
            The recorded AuditEvent with computed event_hash.

        Raises:
            OSError: Unable to write to the underlying log file.

        Thread safety: implementations MUST protect the append with a
        lock. Kylin-Agent uses threading.Lock around open().write() +
        flush, keeping the critical section as short as possible.
        """
        ...

    @abstractmethod
    def verify_chain(self) -> Dict[str, Any]:
        """Recompute every event_hash; compare against stored values.

        Returns:
            {'valid': True, 'events_checked': <int>}
            {'valid': False, 'broken_at': '<event_id>',
             'expected_hash': '<hex>', 'actual_hash': '<hex>'}
        """
        ...


class Auditor(Protocol):
    """Duck-typing version of AuditTrail."""
    async def record(
        self,
        event_type: EventType,
        data: Dict[str, Any],
        *,
        actor: str = "",
    ) -> AuditEvent: ...
    def verify_chain(self) -> Dict[str, Any]: ...


# ═══════════════════════════════════════════════════════════════════
# Tools — What the Agent Can Do
# ═══════════════════════════════════════════════════════════════════

class AgentTools(ABC):
    """What the agent can do.  The only layer that changes completely
    between implementations.

    Design rationale
    ----------------
    Every other layer defines *how* the agent operates — how it receives
    input, remembers, schedules, communicates, constrains itself.  Tools
    define *what* it operates on.  Kylin has 16 OS-diagnostic tools.
    Malio has 11 music tools + a DSL rule engine.  They share nothing
    at the handler level — but they share the concept of "a named,
    described, tiered capability that the LLM can invoke and the sandbox
    enforces."

    Tool modes
    ----------
    call       — LLM invokes via Protocol.call_tool → Tools.invoke.
                 Kylin: ps, systemctl, journalctl.
                 Malio: search_music, get_weather, tts_speak.
    continuous — Runs autonomously (frame loop, tick, heartbeat).
                 NOT invoked by LLM.  Scheduled by the Scheduler.
                 Malio: DSL rule engine (when/then/endWhen, 60fps).
                 Full ABC support deferred to a future version —
                 registered as ToolDefinition(mode="continuous") for now.

    Reference implementations
    -------------------------
    Kylin-Agent:  agent/tools_manifest.py  — 16 tools, MANIFEST list
    Malio:        agent/tools.py           — 11 tools, ToolRegistry
    """

    @abstractmethod
    def register(self, tool: ToolDefinition,
                 handler: Callable[..., Awaitable[Any]]) -> None:
        """Register a tool with its implementation handler.

        The handler signature is tool-specific.  For ps_processes it's
        async def handler(limit: int) -> dict.  The ABC does not
        constrain the handler signature beyond "callable awaitable."
        """
        ...

    @abstractmethod
    def unregister(self, tool_name: str) -> bool:
        """Remove a tool.  Returns True if it existed and was removed."""
        ...

    @abstractmethod
    def list_tools(self) -> List[ToolDefinition]:
        """Return all registered tools for programmatic discovery.

        Distinct from describe_for_llm() — that generates prompt text.
        This returns structured data for API endpoints (e.g. GET /api/mcp/tools).
        """
        ...

    @abstractmethod
    def describe_for_llm(self) -> str:
        """Generate the tool-list text injected into the LLM's system prompt.

        Kylin returns a JSON Schema block.  Malio returns a Chinese
        text list.  The format is domain-specific; what matters is that
        the LLM receives enough information to decide when to call
        each tool.
        """
        ...

    @abstractmethod
    async def invoke(self, tool_name: str, params: dict) -> ToolResult:
        """Execute a registered tool by name.  Protocol.call_tool delegates here.

        The caller (Protocol layer) has already verified the tool exists
        and the params are well-formed.  This method executes and returns
        the result.
        """
        ...


class ToolProvider(Protocol):
    """Duck-typing version of AgentTools."""
    def register(self, tool: ToolDefinition,
                 handler: Callable[..., Awaitable[Any]]) -> None: ...
    def unregister(self, tool_name: str) -> bool: ...
    def list_tools(self) -> List[ToolDefinition]: ...
    def describe_for_llm(self) -> str: ...
    async def invoke(self, tool_name: str, params: dict) -> ToolResult: ...


# ═══════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════
# Self-check — validates this skeleton is internally consistent
# ═══════════════════════════════════════════════════════════════════

def _self_check() -> None:
    """Verify: ABCs are abstract, data classes are correct, exceptions
    carry documented attributes, and enums have expected cardinalities.
    No domain-specific wiring — this is a pure interface check."""
    import sys

    ok = 0
    fail = 0

    def check(name: str, condition: bool, detail: str = ""):
        nonlocal ok, fail
        if condition:
            ok += 1
        else:
            fail += 1
            print(f"  FAIL [{name}]: {detail}", file=sys.stderr)

    # ── ABCs cannot be instantiated ──
    for cls, label in [
        (AgentShell, "AgentShell"),
        (AgentIdentity, "AgentIdentity"),
        (AgentScheduler, "AgentScheduler"),
        (AgentMemory, "AgentMemory"),
        (AgentProtocol, "AgentProtocol"),
        (AgentTools, "AgentTools"),
        (ReasoningLayer, "ReasoningLayer"),
        (ConstraintEngine, "ConstraintEngine"),
        (ExecutionProxy, "ExecutionProxy"),
        (AuditTrail, "AuditTrail"),
    ]:
        try:
            cls()
            check(f"{label} instantiable", False, "ABC was instantiated — missing @abstractmethod?")
        except TypeError:
            check(f"{label} is abstract", True)

    # ── Frozen dataclass immutability ──
    vr = ValidationResult(allowed=True, risk_score=5)
    try:
        vr.allowed = False  # type: ignore[misc]
        check("ValidationResult frozen", False, "Should be frozen")
    except Exception:
        check("ValidationResult frozen", True)

    # ── risk_score 0-9 bounds ──
    for bad in (-1, 10):
        try:
            ValidationResult(allowed=True, risk_score=bad)
            check(f"risk_score={bad} rejected", False, f"Accepted out-of-range value")
        except ValueError:
            check(f"risk_score={bad} rejected", True)

    # ── ScheduleTrigger bounds ──
    for bad_type in ("daily", "once", ""):
        try:
            ScheduleTrigger(type=bad_type, value=0)
            check(f"ScheduleTrigger type={bad_type!r} rejected", False,
                  f"Accepted invalid type {bad_type!r}")
        except ValueError:
            check(f"ScheduleTrigger type={bad_type!r} rejected", True)

    # ── Identity is frozen ──
    ident = Identity(identity_id="test", role="operator")
    try:
        ident.role = "viewer"  # type: ignore[misc]
        check("Identity frozen", False, "Should be frozen")
    except Exception:
        check("Identity frozen", True)

    # ── AuthorizationResult is frozen ──
    ar = AuthorizationResult(allowed=True, tier=Tier.CONFIRM)
    try:
        ar.allowed = False  # type: ignore[misc]
        check("AuthorizationResult frozen", False, "Should be frozen")
    except Exception:
        check("AuthorizationResult frozen", True)

    # ── ToolDefinition is frozen ──
    td = ToolDefinition(name="test_tool", description="A test tool")
    try:
        td.name = "other"  # type: ignore[misc]
        check("ToolDefinition frozen", False, "Should be frozen")
    except Exception:
        check("ToolDefinition frozen", True)

    # ── AuditEvent prev_hash is required (no default) ──
    try:
        AuditEvent(event_type=EventType.REASON, actor="t", timestamp="2026-01-01T00:00:00")
        check("AuditEvent prev_hash required", False, "Accepted without prev_hash")
    except TypeError:
        check("AuditEvent prev_hash required", True)

    # ── MemoryLevel has 3 values ──
    check("MemoryLevel count = 3", len(MemoryLevel) == 3)

    # ── Exceptions carry attributes ──
    ve = VetoError("blocked", alternative="use ps", ref="REF-00001")
    check("VetoError.reason", ve.reason == "blocked")
    check("VetoError.alternative", ve.alternative == "use ps")
    check("VetoError.ref", ve.ref == "REF-00001")

    # ── Tier has 3 values ──
    check("Tier count = 3", len(Tier) == 3)

    # ── Summary ──
    total = ok + fail
    print(f"Agent OS skeleton v{__version__}")
    print(f"  {total} checks: {ok} passed, {fail} failed")
    print(f"  Shell:     1 ABC + 1 Protocol")
    print(f"  Identity:  1 ABC + 1 Protocol")
    print(f"  Scheduler: 1 ABC + 1 Protocol")
    print(f"  Memory:    1 ABC + 1 Protocol")
    print(f"  Protocol:  1 ABC + 1 Protocol")
    print(f"  Tools:     1 ABC + 1 Protocol")
    print(f"  Constraint: {4} ABCs + {4} Protocols")
    print(f"  Data:      {12} (10 frozen + 2 mutable)")
    print(f"  Ref implementations:")
    print(f"    Kylin-Agent — github.com/1nour2567/kylin-agent")
    print(f"    Malio       — github.com/1nour2567/Malio")

    if fail > 0:
        sys.exit(1)


if __name__ == "__main__":
    _self_check()
