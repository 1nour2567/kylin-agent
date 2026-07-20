import asyncio
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.risk_posture import RiskPostureEngine
from agent.loop import run_agentic_loop
from agent.tool_runtime import RuntimeResult
from mcp.registry import ToolRegistry
from security.capability_token import CapabilityReplayStore, CapabilityTokenService
from security.execution_gateway import ExecutionGateway
from security.guardrail import Guardrail
from security.indirect_injection import ToolOutputGuard
from security.pending import build_pending_entry
from security.tool_gateway import ToolSecurityGateway


class FakeRuntime:
    def __init__(self):
        self.calls = []

    def execute(self, tool_name, params, timeout=30):
        self.calls.append((tool_name, dict(params)))
        return RuntimeResult(0, "executed safely", "", f"{tool_name} target")


class Pending:
    def __init__(self):
        self.items = {}

    def add(self, event_id, value):
        self.items[event_id] = value


class Logger:
    def warning(self, *args, **kwargs):
        pass


def services(tmp_path):
    cap = CapabilityTokenService(
        CapabilityReplayStore(str(tmp_path / "replay.json")),
        "integration-capability-secret",
    )
    runtime = FakeRuntime()
    output = ToolOutputGuard()
    gateway = ExecutionGateway(cap, output, runtime)
    return cap, runtime, output, gateway


def test_t2_constructs_exact_scope_and_auto_write_still_requires_capability(tmp_path):
    cap, _, _, _ = services(tmp_path)
    result = Guardrail(cap).validate_commands(
        [{"tool": "create_file", "params": {"path": "/tmp/cap-auto.tmp", "content": "hello"}}],
        role="operator",
        actor_context={"user_id": "ops", "role": "operator"},
        trace_id="trace-auto",
    )
    command = result.command_results[0]
    assert result.passed
    assert command["capability_required"] is True
    assert command["requires_confirmation"] is False
    assert command["capability_scope"]["subject"] == "ops"
    assert command["capability_scope"]["trace_id"] == "trace-auto"
    assert command["capability_scope"]["tool_name"] == "create_file"


def test_unknown_tool_fails_closed_at_t2(tmp_path):
    cap, _, _, _ = services(tmp_path)
    result = Guardrail(cap).validate_commands(
        [{"tool": "unknown_write", "params": {}}],
        role="admin",
        actor_context={"user_id": "admin", "role": "admin"},
        trace_id="trace-unknown",
    )
    assert not result.passed
    assert result.command_results[0]["vetoed"]


def test_mcp_write_cannot_invoke_handler_and_preserves_canonical_pending(tmp_path):
    cap, runtime, output, execution = services(tmp_path)
    pending = Pending()
    security = ToolSecurityGateway(
        Guardrail(cap), RiskPostureEngine(), pending, Logger(),
        capability_token_service=cap,
        execution_gateway=execution,
        output_guard=output,
    )
    registry = ToolRegistry(output_guard=output)
    called = {"value": False}

    def handler(**kwargs):
        called["value"] = True
        return "bypassed"

    registry.register("systemctl_restart", "restart", {"service": "string"}, handler)
    registry.security_gate = security.authorize_mcp
    response = registry.call(
        "systemctl_restart", {"service": "nginx"},
        {"user_id": "ops", "role": "operator", "trace_id": "trace-mcp"},
    )
    assert response["requires_confirmation"]
    assert not called["value"]
    entry = next(iter(pending.items.values()))
    assert entry["params"] == {"service": "nginx"}
    assert entry["capability_scope"]["tool_name"] == "systemctl_restart"
    assert entry["trace_id"] == "trace-mcp"


def test_mcp_readonly_uses_execution_gateway(tmp_path):
    cap, runtime, output, execution = services(tmp_path)
    security = ToolSecurityGateway(
        Guardrail(cap), RiskPostureEngine(), Pending(), Logger(),
        capability_token_service=cap,
        execution_gateway=execution,
        output_guard=output,
    )
    decision = security.authorize_mcp(
        "get_processes", {"limit": 5},
        {"user_id": "view", "role": "viewer", "trace_id": "trace-read"},
    )
    assert decision["allowed"]
    assert decision["execution_result"]["exit_code"] == 0
    assert runtime.calls[0][0] == "ps_processes"


def test_stream_pending_record_contains_full_capability_context(tmp_path):
    cap, _, _, _ = services(tmp_path)
    result = Guardrail(cap).validate_commands(
        [{"tool": "systemctl_restart", "params": {"service": "nginx"}}],
        role="operator",
        actor_context={"user_id": "ops", "role": "operator"},
        trace_id="trace-stream",
    ).command_results[0]
    event_id, pending = build_pending_entry(
        result, "ops", "operator", "balanced", source="stream"
    )
    assert pending["source"] == "stream"
    assert pending["tool_name"] == "systemctl_restart"
    assert pending["params"] == {"service": "nginx"}
    assert pending["trace_id"] == "trace-stream"
    assert pending["operation_id"]
    assert pending["capability_scope"]["event_id"] == event_id


def test_auto_low_risk_write_uses_single_use_internal_token(tmp_path):
    cap, runtime, _, execution = services(tmp_path)
    validated = Guardrail(cap).validate_commands(
        [{"tool": "create_file", "params": {"path": "/tmp/auto-write.tmp", "content": "ok"}}],
        role="operator",
        actor_context={"user_id": "ops", "role": "operator"},
        trace_id="trace-auto-write",
    ).command_results[0]
    assert validated["requires_confirmation"] is False
    from security.capability_token import CapabilityScope
    scope = CapabilityScope.from_dict(validated["capability_scope"])
    token = cap.issue(scope)
    first = execution.execute_tool(
        validated["canonical_tool"], validated["canonical_params"],
        {"user_id": "ops", "role": "operator"}, token, scope,
    )
    second = execution.execute_tool(
        validated["canonical_tool"], validated["canonical_params"],
        {"user_id": "ops", "role": "operator"}, token, scope,
    )
    assert first.capability_verification["reason"] == "consumed"
    assert second.capability_verification["reason"] == "replay_blocked"
    assert len(runtime.calls) == 1


def test_agentic_loop_write_cannot_bypass_capability(tmp_path):
    cap, runtime, _, execution = services(tmp_path)

    class Reasoner:
        calls = 0

        def reason(self, ctx):
            self.calls += 1
            if self.calls == 1:
                return {
                    "commands": [{"tool": "create_file", "params": {"path": "/tmp/loop-write.tmp", "content": "ok"}}],
                    "diagnosis": "write temp", "explanation": "writing", "done": False,
                }
            return {"commands": [], "diagnosis": "done", "explanation": "done", "done": True}

    class Session:
        def get_history(self, sid):
            return []

        def add_turn(self, *args):
            pass

    class Trail:
        def reason(self, *args):
            pass

        def validate(self, *args):
            pass

        def execute(self, *args):
            pass

        def chain_close(self, *args):
            pass

    result = run_agentic_loop(
        Reasoner(), Guardrail(cap), RiskPostureEngine(), Session(),
        "sid", "ops", "operator", Trail(),
        {"user_input": "create temp", "operator": {"user_id": "ops", "role": "operator"}, "time": {"hour": 12}, "system": {}},
        None, execution, cap, "trace-loop-write",
    )
    assert result["executed"][0]["capability_verification"]["reason"] == "consumed"
    assert runtime.calls[0][0] == "create_file"
    assert "token" not in str(result).lower()


def test_confirm_path_issues_verifies_and_consumes_without_returning_token(monkeypatch):
    import deps
    import routers.confirm as confirm_router

    original_runtime = deps.execution_gateway.runtime
    fake_runtime = FakeRuntime()
    monkeypatch.setattr(deps.execution_gateway, "runtime", fake_runtime)
    try:
        trace_id = "trace-confirm-integration"
        validated = deps.guardrail.validate_commands(
            [{"tool": "systemctl_restart", "params": {"service": "nginx"}}],
            role="operator",
            actor_context={"user_id": "ops-confirm", "role": "operator"},
            trace_id=trace_id,
        ).command_results[0]
        event_id, pending = build_pending_entry(
            validated, "ops-confirm", "operator", "balanced", source="chat"
        )
        deps._pending_confirmations.add(event_id, pending)
        request = SimpleNamespace(state=SimpleNamespace(user_id="ops-confirm", role="operator"))
        response = asyncio.run(confirm_router.confirm(
            request,
            confirm_router.ConfirmRequest(event_id=event_id, confirmed=True),
        ))
        assert response["status"] == "executed"
        assert response["capability_verification"]["reason"] == "consumed"
        assert "capability" not in response or "token" not in str(response).lower()
        assert fake_runtime.calls == [("systemctl_restart", {"service": "nginx"})]
        again = asyncio.run(confirm_router.confirm(
            request,
            confirm_router.ConfirmRequest(event_id=event_id, confirmed=True),
        ))
        assert again["status"] in {"not_found", "already_consumed"}
    finally:
        deps.execution_gateway.runtime = original_runtime
