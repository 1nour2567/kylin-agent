import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import audit.store as audit_store
from agent.risk_posture import RiskPostureEngine
from mcp.registry import ToolRegistry
from security.guardrail import Guardrail
from security.redaction import redact_obj, redact_text
from security.sandbox import can_execute_as_agent
from security.tool_gateway import ToolSecurityGateway


class DummyPending:
    def __init__(self):
        self.items = {}

    def add(self, event_id, entry):
        self.items[event_id] = entry


class DummyLogger:
    def warning(self, *args, **kwargs):
        pass


class SecurityHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        audit_store.AUDIT_DIR = self.tmp.name
        audit_store._last_hash = ""
        audit_store._seeded = False

    def tearDown(self):
        self.tmp.cleanup()

    def _gateway(self, pending):
        return ToolSecurityGateway(
            guardrail=Guardrail(),
            posture_engine=RiskPostureEngine(),
            pending_store=pending,
            logger=DummyLogger(),
            clock=lambda: 123.456,
        )

    def test_redaction_masks_common_secret_shapes(self):
        text = "Authorization: Bearer kylin_abcdef1234567890 and DEEPSEEK_API_KEY=sk-secret123456"
        redacted = redact_text(text)
        self.assertNotIn("kylin_abcdef1234567890", redacted)
        self.assertNotIn("sk-secret123456", redacted)
        self.assertIn("REDACTED", redacted)

        payload = redact_obj({"token": "kylin_abcdef1234567890", "nested": ["password=abcdef123"]})
        self.assertIn("REDACTED", str(payload))
        self.assertNotIn("abcdef1234567890", str(payload))

    def test_unknown_commands_are_not_agent_executable(self):
        self.assertFalse(can_execute_as_agent("totally_unknown_command"))
        self.assertTrue(can_execute_as_agent("ps_processes"))

    def test_registry_security_gate_blocks_handler_invocation(self):
        registry = ToolRegistry()
        called = {"value": False}

        def handler():
            called["value"] = True
            return "executed"

        registry.register("danger", "danger", {}, handler)
        registry.security_gate = lambda name, args, ctx: {
            "allowed": False,
            "mcp_result": {"content": [{"type": "text", "text": "blocked"}], "isError": True},
        }

        result = registry.call("danger", {}, {"role": "admin"})
        self.assertTrue(result["isError"])
        self.assertFalse(called["value"])

    def test_mcp_write_tool_requires_confirmation_for_operator(self):
        pending = DummyPending()
        gateway = self._gateway(pending)
        decision = gateway.authorize_mcp(
            "systemctl_restart",
            {"service": "nginx"},
            {"user_id": "ops", "role": "operator"},
        )

        self.assertFalse(decision["allowed"])
        self.assertTrue(decision["mcp_result"]["requires_confirmation"])
        self.assertEqual(len(pending.items), 1)

    def test_mcp_write_tool_denied_for_viewer(self):
        pending = DummyPending()
        gateway = self._gateway(pending)
        decision = gateway.authorize_mcp(
            "systemctl_restart",
            {"service": "nginx"},
            {"user_id": "view", "role": "viewer"},
        )

        self.assertFalse(decision["allowed"])
        self.assertTrue(decision["mcp_result"]["isError"])
        self.assertEqual(len(pending.items), 0)

    def test_mcp_readonly_tool_allowed_for_viewer(self):
        pending = DummyPending()
        gateway = self._gateway(pending)
        decision = gateway.authorize_mcp(
            "get_processes",
            {"limit": 5},
            {"user_id": "view", "role": "viewer"},
        )

        self.assertTrue(decision["allowed"])
        self.assertEqual(len(pending.items), 0)


if __name__ == "__main__":
    unittest.main()
