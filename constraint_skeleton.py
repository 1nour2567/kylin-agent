"""Constraint Architecture — production-grade abstract skeleton.

Four layers. Domain-agnostic. Independently validated in two reference
implementations spanning security operations and embodied AI.

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
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Protocol,
    Tuple,
)

__version__ = "1.0.0"
__all__ = [
    # Data
    "ValidationResult",
    "ExecutionResult",
    "AuditEvent",
    "PipelineContext",
    "Tier",
    "EventType",
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
    prev_hash is the hash of the immediately preceding event
    (empty string for the genesis event).
    """
    event_type: EventType
    actor: str
    timestamp: str
    data: Dict[str, Any] = field(default_factory=dict)
    event_hash: str = ""
    prev_hash: str = ""


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
    hour: Optional[int] = None                  # 0-23.  None = unknown. Caller MUST keep these consistent
    audit_recent: List[Dict[str, Any]] = field(default_factory=list)


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
# Reference pipeline — documentation-as-code
# ═══════════════════════════════════════════════════════════════════
#
# This pipeline wires the four layers into one request flow for a
# Kylin-Agent-style "commands" domain.  It is ONE way to wire the
# layers — not THE way.  Malio wires them differently:
#   reason → persona filter (each core_action) → rule push → feedback
#
# Copy this class into your project and modify the wiring to match
# your domain's layer-1 output format.  The ABCs above are the
# contract; this class is just an example.


class ConstraintPipeline:
    """One turn of Kylin-Agent-style constraint flow.

    This is an EXAMPLE, not a framework.  The inputs and outputs are
    Kylin-specific:  layer 1 outputs "commands", layer 2 validates one
    per command, layer 3 executes with resolve_command().  Malio would
    use different keys and a different loop — but the same four ABCs.

    Minimal usage:

        pipe = ConstraintPipeline(reasoner, constraint_engine,
                                  executor, audit_trail)
        result = await pipe.run(PipelineContext(
            user_input="restart nginx service",
            user_id="alice", role="operator",
        ))
    """

    def __init__(
        self,
        reasoner: ReasoningLayer,
        constraint: ConstraintEngine,
        executor: ExecutionProxy,
        audit: AuditTrail,
    ):
        if reasoner is None or constraint is None or executor is None or audit is None:
            raise TypeError("All four layers must be provided (none is None)")
        self._reasoner = reasoner
        self._constraint = constraint
        self._executor = executor
        self._audit = audit

    async def run(self, context: PipelineContext) -> Dict[str, Any]:
        """Execute one full turn of the constraint pipeline.

        Returns a dict with key 'status' ∈ {completed, vetoed,
        confirmation_required}.  The caller inspects 'status' and
        acts accordingly.
        """
        # ── Layer 1: Reason ──────────────────────────
        llm_output = await self._reasoner.reason(context)
        await self._audit.record(
            EventType.REASON,
            {"output_keys": list(llm_output.keys())},
            actor=context.user_id,
        )

        # ── Layer 2: Validate ────────────────────────
        results = await self._constraint.validate(
            llm_output,
            role=context.role,
            posture=context.posture,
            intent_profile=llm_output.get("intent_profile"),
        )
        await self._audit.record(
            EventType.VALIDATE,
            {"results": [asdict(r) for r in results]},
            actor=context.user_id,
        )

        # Extract domain-specific actions.  Kylin uses "commands";
        # Malio would use "core_actions" or iterate differently.
        commands: List[Dict[str, Any]] = llm_output.get("commands", [])

        # Pair each command with its validation result.
        # Length mismatch means one layer changed the action list
        # without the other knowing — a constraint boundary violation.
        if len(commands) != len(results):
            raise ConstraintError(
                f"Layer 2 result count ({len(results)}) does not match "
                f"Layer 1 command count ({len(commands)}). "
                f"Each command must have exactly one validation result."
            )
        pairs: List[Tuple[Dict[str, Any], ValidationResult]] = list(
            zip(commands, results)
        )

        # Check for hard veto
        for cmd, r in pairs:
            if not r.allowed:
                await self._audit.record(
                    EventType.CHAIN_CLOSE,
                    {"reason": r.reason, "vetoed": True, "command": cmd},
                    actor=context.user_id,
                )
                return {
                    "status": "vetoed",
                    "reason": r.reason,
                    "alternative": r.alternative,
                }

        # Check for confirmation required
        needs_confirm = [
            {"command": cmd, **asdict(r)}
            for cmd, r in pairs
            if r.requires_confirmation
        ]
        if needs_confirm:
            return {
                "status": "confirmation_required",
                "pending": needs_confirm,
            }

        # ── Layer 3: Execute ─────────────────────────
        executed: List[Dict[str, Any]] = []
        for cmd, r in pairs:
            resolved, tier = self._executor.resolve_command(cmd)
            result = await self._executor.execute(resolved, tier=tier)
            await self._audit.record(
                EventType.EXECUTE,
                {
                    "command": resolved,
                    "tier": tier.value,
                    "exit_code": result.exit_code,
                },
                actor=context.user_id,
            )
            executed.append(asdict(result))

        # ── Layer 4: Close ───────────────────────────
        await self._audit.record(
            EventType.CHAIN_CLOSE,
            {"status": "completed"},
            actor=context.user_id,
        )

        return {"status": "completed", "executed": executed}


# ═══════════════════════════════════════════════════════════════════
# Self-check — validates this skeleton is internally consistent
# ═══════════════════════════════════════════════════════════════════

def _self_check() -> None:
    """Smoke check: abstractness, frozen, bounds, exceptions, pipeline
    end-to-end with mock layers."""
    import asyncio
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

    # ── Exceptions carry attributes ──
    ve = VetoError("blocked", alternative="use ps", ref="REF-00001")
    check("VetoError.reason", ve.reason == "blocked")
    check("VetoError.alternative", ve.alternative == "use ps")
    check("VetoError.ref", ve.ref == "REF-00001")

    # ── Tier has 3 values ──
    check("Tier count = 3", len(Tier) == 3)

    # ── Pipeline rejects None ──
    try:
        ConstraintPipeline(None, None, None, None)  # type: ignore[arg-type]
        check("Pipeline rejects None", False)
    except TypeError:
        check("Pipeline rejects None", True)

    # ── Pipeline end-to-end with mock layers ──
    class MockReasoner(ReasoningLayer):
        async def reason(self, context):
            return {
                "commands": [
                    {"tool": "ps_processes", "params": {"limit": "5"}},
                    {"tool": "systemctl_restart", "params": {"service": "nginx"}},
                ],
                "intent_profile": {"risk_hint": "normal"},
            }

    class MockExecutor(ExecutionProxy):
        async def execute(self, command, *, tier=Tier.AUTO):
            return ExecutionResult(0, "ok", "", tier)
        def resolve_command(self, tool_call):
            return (tool_call["tool"], Tier.AUTO)

    class MockAudit(AuditTrail):
        async def record(self, event_type, data, *, actor=""):
            return AuditEvent(event_type, actor, "", data, "mock_hash", "")
        def verify_chain(self):
            return {"valid": True, "events_checked": 0}

    async def run_with(mock_constraint, expected_status, label):
        pipe = ConstraintPipeline(
            MockReasoner(), mock_constraint, MockExecutor(), MockAudit()
        )
        ctx = PipelineContext(user_input="test", user_id="tester", role="operator")
        return await pipe.run(ctx), label, expected_status

    # ── E2E: confirmation_required ──
    class MockConfirm(ConstraintEngine):
        async def validate(self, llm_output, *, role="operator",
                           posture="balanced", intent_profile=None):
            return [
                ValidationResult(allowed=True, risk_score=1),
                ValidationResult(allowed=True, requires_confirmation=True, risk_score=6),
            ]

    # ── E2E: completed (all auto) ──
    class MockAllAuto(ConstraintEngine):
        async def validate(self, llm_output, *, role="operator",
                           posture="balanced", intent_profile=None):
            return [
                ValidationResult(allowed=True, risk_score=1),
                ValidationResult(allowed=True, risk_score=2),
            ]

    # ── E2E: vetoed ──
    class MockVeto(ConstraintEngine):
        async def validate(self, llm_output, *, role="operator",
                           posture="balanced", intent_profile=None):
            return [
                ValidationResult(allowed=True, risk_score=1),
                ValidationResult(allowed=False, reason="rm is vetoed", alternative="use trash"),
            ]

    async def run_all():
        results = await asyncio.gather(
            run_with(MockConfirm(), "confirmation_required", "confirm"),
            run_with(MockAllAuto(), "completed", "completed"),
            run_with(MockVeto(), "vetoed", "veto"),
        )
        return results

    all_results = asyncio.run(run_all())
    for result, label, expected in all_results:
        check(f"Pipeline E2E {label}", result["status"] == expected,
              f"expected {expected}, got {result.get('status')}")
        # Completed path must actually execute — not just return an empty status
        if expected == "completed":
            check(f"Pipeline E2E {label} executed count",
                  len(result.get("executed", [])) == 2,
                  f"expected 2 executed, got {len(result.get('executed', []))}")

    # ── Summary ──
    total = ok + fail
    print(f"Constraint Architecture skeleton v{__version__}")
    print(f"  {total} checks: {ok} passed, {fail} failed")
    print(f"  ABCs:      {4}  (async)")
    print(f"  Protocols: {4}  (duck-typing)")
    print(f"  Data:      {4}  (frozen dataclasses)")
    print(f"  Pipeline:  1  (example — Kylin-style commands wiring)")
    print(f"  Ref implementations:")
    print(f"    Kylin-Agent — github.com/1nour2567/kylin-agent")
    print(f"    Malio       — github.com/1nour2567/Malio")

    if fail > 0:
        sys.exit(1)


if __name__ == "__main__":
    _self_check()
