import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.tool_runtime import RuntimeResult
from security.capability_token import (
    CapabilityReplayStore,
    CapabilityTokenService,
    normalized_params_hash,
)
from security.execution_gateway import ExecutionGateway
from security.guardrail import Guardrail
from security.indirect_injection import ToolOutputGuard


class Clock:
    def __init__(self, value=1000.0):
        self.value = value

    def __call__(self):
        return self.value


class FakeRuntime:
    def __init__(self, stdout="ok"):
        self.stdout = stdout
        self.calls = []

    def execute(self, tool_name, params, timeout=30):
        self.calls.append((tool_name, params, timeout))
        return RuntimeResult(0, self.stdout, "", f"{tool_name} safe-display")


@pytest.fixture
def cap(tmp_path):
    clock = Clock()
    store = CapabilityReplayStore(str(tmp_path / "replay.json"), clock=clock)
    service = CapabilityTokenService(store, "unit-test-capability-secret", 60, clock=clock)
    return service, clock


def scope_for(service, tool="systemctl_restart", params=None, **overrides):
    return service.build_scope(
        tool,
        params or {"service": "nginx"},
        {"user_id": overrides.get("user_id", "ops"), "role": overrides.get("role", "operator")},
        trace_id=overrides.get("trace_id", "trace-1"),
        operation_id=overrides.get("operation_id", "op-1"),
        event_id=overrides.get("event_id", "evt-1"),
    )


def test_legal_token_executes_matching_write(cap):
    service, _ = cap
    runtime = FakeRuntime()
    gateway = ExecutionGateway(service, ToolOutputGuard(), runtime)
    scope = scope_for(service)
    result = gateway.execute_tool(
        "systemctl_restart", {"service": "nginx"},
        {"user_id": "ops", "role": "operator", "trace_id": "trace-1"},
        capability_token=service.issue(scope), expected_scope=scope,
    )
    assert result.exit_code == 0
    assert result.capability_verification["reason"] == "consumed"
    assert runtime.calls


def test_write_without_token_is_denied(cap):
    service, _ = cap
    runtime = FakeRuntime()
    result = ExecutionGateway(service, ToolOutputGuard(), runtime).execute_tool(
        "systemctl_restart", {"service": "nginx"}, {"user_id": "ops", "role": "operator"}
    )
    assert result.exit_code == -1
    assert result.capability_verification["reason"] == "capability_required"
    assert not runtime.calls


def test_expired_token_is_denied(cap):
    service, clock = cap
    scope = scope_for(service)
    token = service.issue(scope)
    clock.value += 61
    result = service.verify_and_consume(token, scope)
    assert not result.valid
    assert result.reason == "expired"


def test_modified_signature_is_denied(cap):
    service, _ = cap
    scope = scope_for(service)
    token = service.issue(scope)
    token = token[:-1] + ("A" if token[-1] != "A" else "B")
    assert service.verify(token, scope).reason == "invalid_signature"


def test_tool_and_service_substitution_are_denied(cap):
    service, _ = cap
    original = scope_for(service)
    token = service.issue(original)
    other_tool = scope_for(
        service, "create_file", {"path": "/tmp/cap-test", "content": "x"}
    )
    assert service.verify(token, other_tool).reason == "scope_mismatch"
    other_service = scope_for(service, params={"service": "sshd"})
    assert service.verify(token, other_service).reason == "scope_mismatch"


def test_kill_signal_change_is_rejected_before_execution(cap):
    service, _ = cap
    runtime = FakeRuntime()
    scope = scope_for(
        service, "kill_process", {"pid": 1234, "signal": 15},
        event_id="evt-kill", operation_id="op-kill",
    )
    result = ExecutionGateway(service, ToolOutputGuard(), runtime).execute_tool(
        "kill_process", {"pid": 1234, "signal": 9},
        {"user_id": "ops", "role": "operator", "trace_id": "trace-1"},
        capability_token=service.issue(scope), expected_scope=scope,
    )
    assert result.exit_code == -1
    assert "Only SIGTERM" in result.sanitized_stderr
    assert not runtime.calls


@pytest.mark.parametrize("changed", ["user", "trace", "operation"])
def test_identity_trace_and_operation_mismatch(cap, changed):
    service, _ = cap
    original = scope_for(service)
    token = service.issue(original)
    kwargs = {}
    if changed == "user":
        kwargs["user_id"] = "other"
    if changed == "trace":
        kwargs["trace_id"] = "trace-other"
    if changed == "operation":
        kwargs["operation_id"] = "op-other"
    expected = scope_for(service, **kwargs)
    assert service.verify(token, expected).reason == "scope_mismatch"


def test_parameter_order_is_stable_and_content_change_is_not():
    _, _, first = normalized_params_hash(
        "create_file", {"content": "hello", "path": "/tmp/cap-order"}
    )
    _, _, reordered = normalized_params_hash(
        "create_file", {"path": "/tmp/cap-order", "content": "hello"}
    )
    _, _, changed = normalized_params_hash(
        "create_file", {"path": "/tmp/cap-order", "content": "changed"}
    )
    assert first == reordered
    assert first != changed


def test_token_is_single_use(cap):
    service, _ = cap
    scope = scope_for(service)
    token = service.issue(scope)
    assert service.verify_and_consume(token, scope).valid
    replay = service.verify_and_consume(token, scope)
    assert not replay.valid
    assert replay.reason == "replay_blocked"


def test_viewer_cannot_receive_write_scope(cap):
    service, _ = cap
    result = Guardrail(service).validate_commands(
        [{"tool": "systemctl_restart", "params": {"service": "nginx"}}],
        role="viewer",
        actor_context={"user_id": "view", "role": "viewer"},
        trace_id="trace-view",
    )
    assert not result.passed
    assert result.command_results[0]["capability_scope"] is None


def test_token_never_appears_in_execution_result(cap):
    service, _ = cap
    runtime = FakeRuntime()
    scope = scope_for(service)
    token = service.issue(scope)
    result = ExecutionGateway(service, ToolOutputGuard(), runtime).execute_tool(
        "systemctl_restart", {"service": "nginx"},
        {"user_id": "ops", "role": "operator"}, token, scope,
    )
    assert token not in str(result.to_dict())

