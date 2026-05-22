"""Security guardrail orchestrator — T0 → T1 → T2 → T3 pipeline."""
from typing import Dict, List, Any, Optional
from security.anti_injection import sanitize
from security.risk_model import assess, risk_label
from security.constraints import ConstraintEngine, ValidationResult
from security.sandbox import can_execute_as_agent, resolve_cmd
from agent.tools_manifest import exec_tier_for_resolved_cmd


class GuardrailResult:
    def __init__(self):
        self.passed = True
        self.blocked_at: Optional[str] = None
        self.rejection_ref: str = ""
        self.command_results: List[Dict] = []


class Guardrail:
    def __init__(self):
        self.constraints = ConstraintEngine()
        self.posture = "balanced"

    def validate_input(self, user_input: str) -> tuple:
        blocked, cleaned, ref = sanitize(user_input)
        if blocked:
            return False, cleaned, ref
        return True, cleaned, ""

    def validate_commands(self, commands: List[dict], posture: str = None,
                          role: str = "operator",
                          intent_profile: dict = None) -> GuardrailResult:
        result = GuardrailResult()
        posture = posture or self.posture
        intent_profile = intent_profile or {}

        for cmd in commands:
            cmd_str = cmd.get("command", cmd.get("tool", ""))
            params = cmd.get("params", {})
            display_cmd = f"{cmd_str} {' '.join(f'{k}={v}' for k, v in params.items())}"
            sandbox_cmd = resolve_cmd(display_cmd)
            base_cmd = sandbox_cmd.strip().split()[0] if sandbox_cmd.strip() else ""

            risk = assess(sandbox_cmd)
            # T2: structural validation on tool_name + params (not regex on concat string)
            validation: ValidationResult = self.constraints.validate(
                base_cmd, posture, params=params, role=role,
                intent_profile=intent_profile,
            )
            # Also run raw regex as defense-in-depth for escaped or unusual formats
            if validation.allowed and params:
                raw = self.constraints._validate_raw(sandbox_cmd, posture)
                if not raw.allowed:
                    validation = raw
            # Escalate to confirmation if the resolved command implies a write
            tier = exec_tier_for_resolved_cmd(sandbox_cmd)
            # Viewer role: any confirm-tier (write) command → veto
            if tier == "confirm" and role == "viewer" and validation.allowed:
                validation.allowed = False
                validation.reason = "Viewer role cannot execute write operations"
                validation.alternative = "Request an operator or admin to perform this action"
            if tier == "confirm" and validation.allowed:
                # Defense-in-depth: ALL confirm-tier tools require explicit user
                # confirmation regardless of posture/role threshold. The threshold
                # math in constraints.py determines WHETHER a command needs confirm;
                # this guardrail ensures confirm-tier commands ALWAYS need it.
                validation.requires_confirmation = True

            cmd_result = {
                "command": sandbox_cmd,
                "display_command": display_cmd,
                "risk_score": risk,
                "risk_label": risk_label(risk),
                "allowed": validation.allowed,
                "requires_confirmation": validation.requires_confirmation,
                "can_execute": can_execute_as_agent(cmd_str),
                "reason": validation.reason,
                "alternative": validation.alternative,
            }

            if not validation.allowed:
                result.passed = False
                result.blocked_at = f"T2: {validation.reason}"
                cmd_result["vetoed"] = True
                result.command_results.append(cmd_result)
                break

            if not can_execute_as_agent(cmd_str):
                result.passed = False
                result.blocked_at = "T3: Command not in agent allowlist"
                cmd_result["vetoed"] = True
                result.command_results.append(cmd_result)
                break

            result.command_results.append(cmd_result)

        return result
