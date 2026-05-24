"""Example: Kylin-Agent-style constraint pipeline.

This is ONE way to wire the four constraint layers — not THE way.
Malio wires them differently:
  reason → persona filter (each core_action) → rule push → feedback

Copy this class into your project and modify the wiring to match
your domain's layer-1 output format.  The ABCs in the parent directory
are the contract; this class is just an example.

Usage:
  pipe = ConstraintPipeline(reasoner, constraint_engine, executor, audit_trail)
  result = await pipe.run(PipelineContext(
      user_input="restart nginx service",
      user_id="alice", role="operator",
  ))
"""

from __future__ import annotations

import asyncio
import sys
from dataclasses import asdict
from typing import Any, Dict, List, Tuple

# Assume constraint_skeleton.py is on sys.path or in the parent directory
from constraint_skeleton import (
    AuditEvent,
    AuditTrail,
    ConstraintEngine,
    ConstraintError,
    ConstraintPipeline,
    EventType,
    ExecutionProxy,
    ExecutionResult,
    PipelineContext,
    ReasoningLayer,
    Tier,
    ValidationResult,
)


class ConstraintPipeline:
    """One turn of Kylin-Agent-style constraint flow.

    This is an EXAMPLE, not a framework — wiring the four layers into a
    Kylin-specific pipeline.  Malio uses different keys and a different
    loop, but the same four ABCs.

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
# Self-check — end-to-end with mock layers
# ═══════════════════════════════════════════════════════════════════

def _self_check() -> None:
    """Pipeline end-to-end test: confirm, completed, veto paths."""
    ok = 0
    fail = 0

    def check(name, condition, detail=""):
        nonlocal ok, fail
        if condition:
            ok += 1
        else:
            fail += 1
            print(f"  FAIL [{name}]: {detail}", file=sys.stderr)

    # ── Pipeline rejects None ──
    try:
        ConstraintPipeline(None, None, None, None)  # type: ignore[arg-type]
        check("Pipeline rejects None", False)
    except TypeError:
        check("Pipeline rejects None", True)

    # ── Mock layers ──
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
            return AuditEvent("mock_prev", event_type, actor, "", data, "mock_hash")
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
        if expected == "completed":
            check(f"Pipeline E2E {label} executed count",
                  len(result.get("executed", [])) == 2,
                  f"expected 2 executed, got {len(result.get('executed', []))}")
        if expected == "confirm":
            check(f"Pipeline E2E {label} pending count",
                  len(result.get("pending", [])) == 1,
                  f"expected 1 pending, got {len(result.get('pending', []))}")
        if expected == "veto":
            check(f"Pipeline E2E {label} reason",
                  "rm is vetoed" in result.get("reason", ""),
                  f"veto reason missing: {result.get('reason', '')}")

    total = ok + fail
    print(f"Kylin Pipeline self-check: {total} checks, {ok} passed, {fail} failed")
    if fail > 0:
        sys.exit(1)


if __name__ == "__main__":
    _self_check()
