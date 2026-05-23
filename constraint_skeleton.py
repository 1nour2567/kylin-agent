"""Constraint Architecture — production-grade abstract skeleton.

Four layers. Domain-agnostic. Independently validated in two reference
implementations spanning security operations and embodied AI.

Read order:
  1. This file                    (interfaces + data flow)
  2. CONSTRAINT.md / CONSTRAINT_EN.md  (design rationale + principles)
  3. Kylin-Agent: backend/security/   (concrete implementation — security)
  4. Malio:       malio/agent/        (concrete implementation — embodied AI)

Copyright (c) 2026 1nour2567. MIT License.
"""

from __future__ import annotations

import hashlib
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple, Union

__version__ = "0.1.0"
__all__ = [
    # Data
    "ValidationResult",
    "ExecutionResult",
    "AuditEvent",
    "PipelineContext",
    "Tier",
    "EventType",
    # Layer ABCs
    "ReasoningLayer",
    "ConstraintEngine",
    "ExecutionProxy",
    "AuditTrail",
    # Protocols (duck-typing)
    "Reasoner",
    "ConstraintValidator",
    "Executor",
    "Auditor",
    # Pipeline
    "ConstraintPipeline",
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

    Why three tiers, not two (allow / deny):
      A binary gate forces false positives (safe commands that need
      confirmation) to become either silently auto-executed or hard-blocked.
      Three tiers give the system a middle path — "this looks risky, ask the
      human."  Kylin-Agent's auto / confirm / veto maps directly to these
      three states. Malio uses the same pattern for persona-filtered actions.
    """
    AUTO = "auto"          # Read-only diagnostics. Execute immediately.
    CONFIRM = "confirm"    # Write operations. Validate → queue → human → execute.
    VETO = "veto"          # Destruction commands. Never executable.


class EventType(str, Enum):
    """Audit event lifecycle — one event type per pipeline stage.

    Every stage listed. Lightweight implementations may skip non-critical
    stages; the interface requires only that RECEIVE + CHAIN_CLOSE exist
    so every chain has a beginning and an end.
    """
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
    """Layer 2 hard-blocked an action. The action must not execute.

    Attributes:
        reason: Human-readable explanation of why the action was vetoed.
        alternative: A safer action to suggest, if one exists.
        ref: Traceable rejection reference (e.g. 'REF-00001-ROLESWITCH').
    """
    def __init__(self, reason: str, alternative: str = "", ref: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.alternative = alternative
        self.ref = ref

class ExecutionRefusedError(ConstraintError):
    """Layer 3 refused to execute — command not in allowlist or tier mismatch."""

class AuditIntegrityError(ConstraintError):
    """Layer 4 detected a broken chain. Events have been tampered with."""


# ═══════════════════════════════════════════════════════════════════
# Shared data classes — the lingua franca between layers
# ═══════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ValidationResult:
    """Immutable output of ConstraintEngine.validate().

    Frozen so that no downstream code can mutate a veto into a pass.
    """
    allowed: bool
    requires_confirmation: bool = False
    reason: str = ""
    alternative: str = ""
    risk_score: int = 0

    def __post_init__(self):
        if self.risk_score < 0 or self.risk_score > 10:
            raise ValueError(f"risk_score must be 0-10, got {self.risk_score}")


@dataclass(frozen=True)
class ExecutionResult:
    """Immutable output of ExecutionProxy.execute()."""
    exit_code: int
    stdout: str
    stderr: str
    tier: Tier = Tier.AUTO


@dataclass(frozen=True)
class AuditEvent:
    """One immutable event in the audit chain.

    event_hash = SHA256(prev_hash + serialized_event_data).
    prev_hash is the hash of the immediately preceding event ("" for the first).
    """
    event_type: EventType
    actor: str
    timestamp: str
    data: Dict[str, Any] = field(default_factory=dict)
    event_hash: str = ""
    prev_hash: str = ""


@dataclass
class PipelineContext:
    """Typed context passed to layer 1 — what the agent knows at inference time.

    This is the contract between the caller (API handler) and the
    reasoning layer. Every field is optional except user_input; layers
    2-4 consume the structured output, not this context directly.
    """
    user_input: str
    user_id: str = "anonymous"
    role: str = "viewer"                      # admin / operator / viewer
    posture: str = "balanced"                 # restrictive / balanced / permissive
    session_id: str = ""
    conversation_history: List[Dict[str, str]] = field(default_factory=list)
    system_snapshot: Dict[str, Any] = field(default_factory=dict)
    time_of_day: str = ""                     # morning / afternoon / evening / night
    hour: int = 12
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
    analyses.  It cannot authorize anything.  That separation is the core
    of Constraint Architecture:  the thinker does not decide what is safe.

    Security property:  layer-1 output is treated as untrusted input by
    layer 2.  Even if an attacker fully controls the LLM's output string,
    layers 2-3-4 do not trust it.

    Reference implementations
    -------------------------
    Kylin-Agent:  agent/reasoner.py       — Reasoner.reason()
    Malio:        agent/reasoner.py       — Reasoner.reason()
    """

    @abstractmethod
    def reason(self, context: PipelineContext) -> Dict[str, Any]:
        """Accept typed context, return structured instructions.

        The return value MUST contain a 'commands' key (list of tool-call
        dicts).  May optionally contain 'intent_profile' for layer-2
        behavioral analysis.  The caller passes this dict directly to
        layer 2 without interpreting it.

        Thread safety: implementations MUST be callable from multiple
        threads (the LLM provider client is typically thread-safe already).

        Raises:
            RuntimeError: LLM provider unreachable after retries.
        """
        ...


# ── Protocol (duck-typing) ─────────────────────────────────────

class Reasoner(Protocol):
    """Duck-typing version of ReasoningLayer. Implement any object with
    this signature — no need to inherit from the ABC."""

    def reason(self, context: PipelineContext) -> Dict[str, Any]: ...


# ═══════════════════════════════════════════════════════════════════
# Layer 2 — Constraints (Deterministic)
# ═══════════════════════════════════════════════════════════════════

class ConstraintEngine(ABC):
    """Deterministic validation. Code-level constraints.

    Design rationale
    ----------------
    This is where "LLM reasons, code decides" lives. The LLM's structured
    output passes through here. Role, posture, and intent_profile all
    feed into the decision — but the decision itself is code, never LLM.

    Hard guarantee:  Layer 2 rejection overrides Layer 1 preference.
    Always.  Even permissive mode + admin role.  The baseline constraints
    (no rm -rf /, no /etc/shadow writes, etc.) are never removed — new
    contexts only add tighter constraints.

    Why dual-path validation?
      LLM output may arrive in two forms for the same intended command:
        structured:  {"tool": "kill_process", "params": {"pid": "1234"}}
        raw string:  "kill -9 1234"
      A single validation path can be bypassed by switching formats.
      Two independent paths — one for structured params, one for raw
      regex — close this gap.

    Reference implementations
    -------------------------
    Kylin-Agent:  security/constraints.py — 24 regex patterns + destructured tool-param checks
    Malio:        agent/persona.py        — 3D continuous persona boundary enforcement
    """

    @abstractmethod
    def validate(
        self,
        llm_output: Dict[str, Any],
        *,
        role: str = "operator",
        posture: str = "balanced",
        intent_profile: Optional[Dict[str, Any]] = None,
    ) -> List[ValidationResult]:
        """Validate every action the LLM proposed.

        Called once per pipeline turn. Returns one result per command;
        allowed=False means hard veto — the command must not execute.

        Args:
            llm_output:     Layer-1 output dict. MUST contain key 'commands'.
            role:           admin / operator / viewer. Drives threshold offset.
            posture:        restrictive / balanced / permissive. Drives base threshold.
            intent_profile: Behavioral signal from the LLM (optional).
                            The LLM provides an observation (e.g. "the user is
                            retrying a denied operation with a different key").
                            This layer consumes that observation as an input
                            to its threshold calculation — but the decision is
                            still deterministic code, not the LLM.

        Returns:
            One ValidationResult per command, in order. The caller checks
            `allowed` first, then `requires_confirmation`.

        Raises:
            KeyError: llm_output is missing the 'commands' key.
        """
        ...


class ConstraintValidator(Protocol):
    """Duck-typing version of ConstraintEngine."""

    def validate(
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
    Three tiers, not two. A binary allow/deny gate forces false positives
    (safe commands that happen to look suspicious) into either silent
    auto-execution or hard block — both are wrong.  Three tiers give the
    system a middle path:  "this looks risky.  Queue it.  Let a human decide."

    Tier definitions
    ----------------
    auto    — Read-only operations on safe paths.  Execute immediately.
              Kylin:  ps, df, free, ss, journalctl, systemctl status.
              Malio:  atmosphere derivation, color blending.

    confirm — Write operations.  Must pass Layer 2 validation AND receive
              explicit human confirmation before execution.
              Kylin:  systemctl restart, kill, truncate, journalctl --vacuum.
              Malio:  core_action push after persona filtering.

    veto    — Destruction.  Never executable through this proxy, full stop.
              Kylin:  rm, chmod, mkfs, dd.
              Malio:  light_burst when energy < 0.3 (PersonaEngine block).

    Reference implementations
    -------------------------
    Kylin-Agent:  security/sandbox.py    — subprocess.run with sudo -n
    Malio:        agent/visual_agent.py  — DSL rule evaluation loop
    """

    @abstractmethod
    def execute(self, command: str, *, tier: Tier = Tier.AUTO) -> ExecutionResult:
        """Execute a command at the given tier.

        The caller MUST have validated the command through Layer 2 and,
        for confirm-tier, obtained human confirmation before calling this.

        Args:
            command:  Resolved shell command or action identifier.
            tier:     auto / confirm / veto. Veto-tier returns immediately
                      with exit_code=-1 and an explanatory stderr message.

        Returns:
            ExecutionResult with exit_code, stdout, stderr.

        Raises:
            ExecutionRefusedError:  command not in whitelist, or tier mismatch
                                    (e.g. attempting to execute a veto-tier command).

        Thread safety: implementations that shell out MUST NOT hold locks
        across subprocess calls.  Kylin-Agent's sandbox acquires the
        pending-store lock, pops the event, releases the lock, THEN
        calls subprocess.run — the I/O is outside the critical section.
        """
        ...

    @abstractmethod
    def resolve_command(self, llm_tool_call: Dict[str, Any]) -> Tuple[str, Tier]:
        """Translate an LLM tool-call dict into (executable_string, tier).

        Example:  {'tool': 'ps_processes', 'params': {'limit': '10'}}
               -> ('ps aux --no-headers | head -10', Tier.AUTO)

        The resolution step is a pure function — same input always
        produces the same output.  No side effects.
        """
        ...


class Executor(Protocol):
    """Duck-typing version of ExecutionProxy."""

    def execute(self, command: str, *, tier: Tier = Tier.AUTO) -> ExecutionResult: ...

    def resolve_command(self, llm_tool_call: Dict[str, Any]) -> Tuple[str, Tier]: ...


# ═══════════════════════════════════════════════════════════════════
# Layer 4 — Audit (Immutable Record)
# ═══════════════════════════════════════════════════════════════════

class AuditTrail(ABC):
    """Every action recorded. Tampering detectable.

    Design rationale
    ----------------
    "The system executed command X" is not the same as "the system can
    PROVE it executed command X, and no one has tampered with the log."
    The first is a log.  The second is an audit trail with non-repudiation.

    The chain is:  event_N.hash = SHA256(event_N-1.hash + event_N.data).
    Inserting, deleting, or modifying any event breaks all subsequent
    hashes.  verify_chain() detects where the break occurred.

    Restart recovery
    ----------------
    _seed_from_disk() reads the last event_hash from the most recent
    persisted log file on startup.  Without it, an in-memory _last_hash
    resets to "" on process restart — the chain silently breaks.  This
    was discovered during live deployment on Kylin V11, not during
    whiteboard design.

    Lightweight form
    ----------------
    Not every domain needs cryptographic non-repudiation.  Malio uses
    a rule-health feedback loop (OODA):  the frontend reports back which
    rules fired and which were suppressed; the agent uses that signal
    to correct future rule generation.  This is "audit" in the sense of
    "keeping constraints continuously valid at runtime."

    Reference implementations
    -------------------------
    Kylin-Agent:  audit/trail.py         — SHA256 chain + _seed_from_disk
    Malio:        agent/visual_agent.py  — OODA rule-health feedback
    """

    @abstractmethod
    def record(
        self,
        event_type: EventType,
        data: Dict[str, Any],
        *,
        actor: str = "",
    ) -> AuditEvent:
        """Record one pipeline event into the immutable chain.

        Args:
            event_type:  Pipeline stage identifier.
            data:        Arbitrary event payload (command, exit_code, etc.).
            actor:       user_id or agent module name.

        Returns:
            The recorded AuditEvent with computed event_hash.

        Raises:
            OSError:  Unable to write to the underlying log file.

        Thread safety: implementations MUST protect the append with a lock.
        Kylin-Agent uses threading.Lock around open().write() + flush.
        """
        ...

    @abstractmethod
    def verify_chain(self) -> Dict[str, Any]:
        """Recompute every event_hash and compare against stored values.

        Returns:
            {'valid': True, 'events_checked': <int>}
            {'valid': False, 'broken_at': '<event_id>',
             'expected_hash': '<hex>', 'actual_hash': '<hex>'}
        """
        ...


class Auditor(Protocol):
    """Duck-typing version of AuditTrail."""

    def record(
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

class ConstraintPipeline:
    """Orchestrator that wires four layers into one request flow.

    This is NOT a framework.  It is documentation-as-code — a single-file
    demonstration of how the four layers connect.  Copy it into your
    project.  Replace each layer with your domain's implementation.
    The contract is the ABCs above, not this class.

    Example minimal usage:

        pipe = ConstraintPipeline(
            reasoner=MyReasoner(llm_client),
            constraint=MyConstraintEngine(allowed_commands, dangerous_params),
            executor=MyExecutionProxy(allowed_commands),
            audit=MyAuditTrail("/var/log/myagent/audit.jsonl"),
        )
        result = pipe.run(PipelineContext(
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

    # ── Public API ─────────────────────────────────────────────

    def run(self, context: PipelineContext) -> Dict[str, Any]:
        """Execute one full turn of the constraint pipeline.

        Returns a dict with key 'status' ∈ {completed, vetoed, confirmation_required}.
        The caller should inspect 'status' and act accordingly.
        """
        # ── Layer 1: Reason ──────────────────────────
        llm_output = self._reasoner.reason(context)
        self._audit.record(
            EventType.REASON,
            {"commands": llm_output.get("commands", [])},
            actor=context.user_id,
        )

        # ── Layer 2: Validate ────────────────────────
        results = self._constraint.validate(
            llm_output,
            role=context.role,
            posture=context.posture,
            intent_profile=llm_output.get("intent_profile"),
        )
        self._audit.record(
            EventType.VALIDATE,
            {"results": [asdict(r) for r in results]},
            actor=context.user_id,
        )

        # Check for hard veto
        for r in results:
            if not r.allowed:
                self._audit.record(
                    EventType.CHAIN_CLOSE,
                    {"reason": r.reason, "vetoed": True},
                    actor=context.user_id,
                )
                return {
                    "status": "vetoed",
                    "reason": r.reason,
                    "alternative": r.alternative,
                }

        # Check for confirmation required
        needs_confirm = [r for r in results if r.requires_confirmation]
        if needs_confirm:
            return {
                "status": "confirmation_required",
                "pending": [asdict(r) for r in needs_confirm],
            }

        # ── Layer 3: Execute ─────────────────────────
        executed: List[Dict[str, Any]] = []
        for cmd in llm_output.get("commands", []):
            resolved, tier = self._executor.resolve_command(cmd)
            result = self._executor.execute(resolved, tier=tier)
            self._audit.record(
                EventType.EXECUTE,
                {"command": resolved, "tier": tier.value,
                 "exit_code": result.exit_code},
                actor=context.user_id,
            )
            executed.append(asdict(result))

        # ── Layer 4: Close ───────────────────────────
        self._audit.record(
            EventType.CHAIN_CLOSE,
            {"status": "completed"},
            actor=context.user_id,
        )

        return {"status": "completed", "executed": executed}


# ═══════════════════════════════════════════════════════════════════
# Self-check — validate this skeleton is internally consistent
# ═══════════════════════════════════════════════════════════════════

def _self_check() -> None:
    """Verify that ABCs are correctly abstract, frozen dataclasses work,
    and exceptions carry the right information. Not a test suite — a
    smoke check that catches import-time regressions."""
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

    # ABCs cannot be instantiated
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

    # Frozen dataclasses are immutable
    vr = ValidationResult(allowed=True, risk_score=5)
    try:
        vr.allowed = False
        check("ValidationResult frozen", False, "Should be frozen but allowed mutation")
    except Exception:
        check("ValidationResult frozen", True)

    # risk_score clamping
    try:
        ValidationResult(allowed=True, risk_score=11)
        check("ValidationResult risk_score upper bound", False, "Accepted risk_score=11")
    except ValueError:
        check("ValidationResult risk_score upper bound", True)
    try:
        ValidationResult(allowed=True, risk_score=-1)
        check("ValidationResult risk_score lower bound", False, "Accepted risk_score=-1")
    except ValueError:
        check("ValidationResult risk_score lower bound", True)

    # Exceptions carry attributes
    ve = VetoError("blocked", alternative="use ps instead", ref="REF-00001")
    check("VetoError.reason", ve.reason == "blocked")
    check("VetoError.alternative", ve.alternative == "use ps instead")
    check("VetoError.ref", ve.ref == "REF-00001")

    # Enum values
    check("Tier has 3 values", len(Tier) == 3)

    # Pipeline rejects None layers
    try:
        ConstraintPipeline(None, None, None, None)  # type: ignore[arg-type]
        check("Pipeline rejects None", False)
    except TypeError:
        check("Pipeline rejects None", True)

    # Summary
    total = ok + fail
    print(f"Constraint Architecture skeleton v{__version__}")
    print(f"  {total} checks: {ok} passed, {fail} failed")
    print(f"  ABCs:     {4} layers")
    print(f"  Protocols: {4} duck-typing interfaces")
    print(f"  Data:     {4} typed dataclasses")
    print(f"  Pipeline: {1} reference orchestrator")
    print(f"  Ref implementations:")
    print(f"    Kylin-Agent — github.com/1nour2567/kylin-agent")
    print(f"    Malio       — github.com/1nour2567/Malio")

    if fail > 0:
        sys.exit(1)


if __name__ == "__main__":
    _self_check()
