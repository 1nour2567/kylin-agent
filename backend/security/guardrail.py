"""Security guardrail orchestrator: T0-U -> T1 -> T2 scope construction."""
from __future__ import annotations

import os
import secrets
import tempfile
from typing import Dict, List, Optional

from agent.tools_manifest import lookup_by_llm_name
from security.anti_injection import sanitize
from security.capability_token import (
    CapabilityReplayStore,
    CapabilityTokenService,
    canonicalize_params,
    stable_json,
)
from security.constraints import ConstraintEngine, ValidationResult
from security.risk_model import assess, risk_label


class GuardrailResult:
    def __init__(self):
        self.passed = True
        self.blocked_at: Optional[str] = None
        self.rejection_ref: str = ""
        self.command_results: List[Dict] = []


class Guardrail:
    def __init__(self, capability_token_service: CapabilityTokenService | None = None):
        self.constraints = ConstraintEngine()
        self.posture = "balanced"
        # Standalone unit users still need the unified scope constructor.  The
        # application always injects the shared service from deps.py.
        if capability_token_service is None:
            replay_path = os.path.join(
                tempfile.gettempdir(), f"kylin-capbac-standalone-{os.getpid()}.json"
            )
            capability_token_service = CapabilityTokenService(
                CapabilityReplayStore(replay_path), secrets.token_bytes(32), ttl_seconds=60
            )
        self.capability_token_service = capability_token_service

    def validate_input(self, user_input: str) -> tuple:
        blocked, cleaned, ref = sanitize(user_input)
        if blocked:
            return False, cleaned, ref
        return True, cleaned, ""

    def validate_commands(
        self,
        commands: List[dict],
        posture: str | None = None,
        role: str = "operator",
        intent_profile: dict | None = None,
        actor_context: dict | None = None,
        trace_id: str = "",
    ) -> GuardrailResult:
        result = GuardrailResult()
        posture = posture or self.posture
        intent_profile = intent_profile or {}
        actor_context = dict(actor_context or {})
        actor_context.setdefault("user_id", "anonymous")
        actor_context.setdefault("role", role)
        trace_id = trace_id or str(actor_context.get("trace_id") or f"tr_{secrets.token_hex(12)}")

        for index, cmd in enumerate(commands):
            raw_tool = str(cmd.get("tool") or cmd.get("command") or "").strip()
            raw_params = cmd.get("params") or {}
            event_id = str(cmd.get("event_id") or f"evt_{secrets.token_hex(12)}")
            operation_id = str(cmd.get("operation_id") or f"op_{secrets.token_hex(12)}")

            try:
                canonical_tool, canonical_params = canonicalize_params(raw_tool, raw_params)
                entry = lookup_by_llm_name(canonical_tool)
                if entry is None or entry.get("exec_tier") not in {"auto", "confirm", "veto"}:
                    raise ValueError("unknown manifest execution tier")
            except Exception as exc:
                result.passed = False
                result.blocked_at = f"T2: {exc}"
                result.command_results.append({
                    "command": raw_tool,
                    "display_command": raw_tool,
                    "canonical_tool": "",
                    "canonical_params": {},
                    "params": {},
                    "risk_score": 10,
                    "risk_label": "Critical",
                    "allowed": False,
                    "requires_confirmation": False,
                    "capability_required": False,
                    "capability_scope": None,
                    "can_execute": False,
                    "reason": str(exc),
                    "alternative": "Use a registered tool with valid manifest parameters",
                    "vetoed": True,
                })
                break

            display_params = stable_json(canonical_params)
            command_for_risk = f"{canonical_tool} {display_params}"
            risk = assess(command_for_risk)
            validation: ValidationResult = self.constraints.validate(
                canonical_tool,
                posture,
                params=canonical_params,
                role=role,
                intent_profile=intent_profile,
            )

            # Keep legacy raw patterns as defense in depth, without trusting any
            # LLM-supplied risk or confirmation fields.
            if validation.allowed:
                raw_validation = self.constraints._validate_raw(command_for_risk, posture)
                if not raw_validation.allowed:
                    validation = raw_validation

            tier = entry.get("exec_tier")
            capability_required = entry.get("risk") != "readonly" or tier == "confirm"
            if tier == "veto":
                validation = ValidationResult(
                    allowed=False,
                    reason=f"Tool '{canonical_tool}' is vetoed by manifest",
                    alternative="Use a read-only diagnostic tool",
                    risk_score=10,
                )
            if capability_required and role == "viewer" and validation.allowed:
                validation = ValidationResult(
                    allowed=False,
                    reason="Viewer role cannot execute write operations",
                    alternative="Request an operator or admin",
                    risk_score=10,
                )

            requires_confirmation = bool(
                validation.allowed
                and capability_required
                and (tier == "confirm" or validation.requires_confirmation)
            )
            scope = None
            if validation.allowed and capability_required:
                try:
                    scope = self.capability_token_service.build_scope(
                        canonical_tool,
                        canonical_params,
                        actor_context,
                        trace_id=trace_id,
                        operation_id=operation_id,
                        event_id=event_id,
                    )
                except Exception as exc:
                    validation = ValidationResult(
                        allowed=False,
                        reason=f"Capability scope construction failed: {exc}",
                        alternative="Retry with complete authenticated task context",
                        risk_score=10,
                    )

            cmd_result = {
                "tool": canonical_tool,
                "command": canonical_tool,
                "display_command": f"{canonical_tool} {display_params}",
                "canonical_tool": canonical_tool,
                "canonical_params": canonical_params,
                "params": canonical_params,
                "risk_score": max(risk, validation.risk_score),
                "risk_label": risk_label(max(risk, validation.risk_score)),
                "allowed": validation.allowed,
                "requires_confirmation": requires_confirmation,
                "capability_required": capability_required,
                "capability_scope": scope.to_dict() if scope else None,
                "event_id": event_id,
                "operation_id": operation_id,
                "trace_id": trace_id,
                "can_execute": validation.allowed and tier in {"auto", "confirm"},
                "reason": validation.reason,
                "alternative": validation.alternative,
            }

            if not validation.allowed:
                result.passed = False
                result.blocked_at = f"T2: {validation.reason}"
                cmd_result["vetoed"] = True
                result.command_results.append(cmd_result)
                break
            result.command_results.append(cmd_result)

        return result

