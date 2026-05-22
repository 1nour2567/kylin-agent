"""Tests for KeyStore + role-based access control."""
import sys, os, json, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from auth.key_store import KeyStore, KeyEntry, generate_key, hash_key, ROLES

os.environ["AGENT_MODE"] = "mock"


class TestKeyStore:
    @pytest.fixture
    def store(self):
        fd, tmp = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        store = KeyStore(path=tmp)
        yield store
        try:
            os.unlink(tmp)
        except OSError:
            pass

    def test_generate_key_format(self):
        key = generate_key()
        assert key.startswith("kylin_")
        assert len(key) == 6 + 32  # "kylin_" + 32 hex chars

    def test_hash_key_deterministic(self):
        key = "kylin_test"
        assert hash_key(key) == hash_key(key)

    def test_create_key_returns_plain_key(self, store):
        plain = store.create_key("alice", "admin")
        assert plain.startswith("kylin_")
        assert len(plain) == 38

    def test_create_key_invalid_role_raises(self, store):
        with pytest.raises(ValueError):
            store.create_key("bob", "superuser")

    def test_validate_correct_key(self, store):
        plain = store.create_key("alice", "admin")
        info = store.validate(plain)
        assert info is not None
        assert info["user_id"] == "alice"
        assert info["role"] == "admin"
        assert info["key_id"].startswith("key_")

    def test_validate_wrong_key(self, store):
        store.create_key("alice", "admin")
        info = store.validate("wrong_key_abcdef")
        assert info is None

    def test_validate_empty_key(self, store):
        assert store.validate("") is None

    def test_revoke_existing_key(self, store):
        plain = store.create_key("alice", "admin")
        entries = store.list_entries()
        key_id = entries[0]["key_id"]

        assert store.revoke(key_id) is True
        assert store.validate(plain) is None

    def test_revoke_nonexistent_key(self, store):
        assert store.revoke("key_nonexistent") is False

    def test_list_entries(self, store):
        store.create_key("alice", "admin")
        store.create_key("bob", "operator")
        entries = store.list_entries()
        assert len(entries) == 2

        roles = {e["role"] for e in entries}
        users = {e["user_id"] for e in entries}
        assert "admin" in roles
        assert "operator" in roles
        assert "alice" in users
        assert "bob" in users

    def test_list_does_not_expose_key_hash(self, store):
        store.create_key("alice", "admin")
        entries = store.list_entries()
        assert "key_hash" not in entries[0]

    def test_persistence_survives_reload(self, store):
        plain = store.create_key("alice", "admin")
        store2 = KeyStore(path=store.path)
        info = store2.validate(plain)
        assert info is not None
        assert info["user_id"] == "alice"

    def test_multiple_keys_independent(self, store):
        key_a = store.create_key("alice", "admin")
        key_b = store.create_key("bob", "viewer")

        info_a = store.validate(key_a)
        info_b = store.validate(key_b)

        assert info_a["role"] == "admin"
        assert info_b["role"] == "viewer"
        assert info_a["user_id"] != info_b["user_id"]


class TestRoleThresholds:
    """Verify role threshold math is correct."""

    def _setup(self):
        from security.constraints import ConstraintEngine
        return ConstraintEngine()

    def test_effective_threshold_admin(self):
        engine = self._setup()
        # admin: base 5 + offset 2 = 7
        assert engine._effective_threshold("balanced", "admin") == 7
        assert engine._effective_threshold("restrictive", "admin") == 2
        assert engine._effective_threshold("permissive", "admin") == 9

    def test_effective_threshold_operator(self):
        engine = self._setup()
        # operator: base + 0
        assert engine._effective_threshold("balanced", "operator") == 5
        assert engine._effective_threshold("restrictive", "operator") == 0
        assert engine._effective_threshold("permissive", "operator") == 7

    def test_effective_threshold_viewer(self):
        engine = self._setup()
        # viewer: base - 999 (clamped to 0)
        assert engine._effective_threshold("balanced", "viewer") == 0
        assert engine._effective_threshold("permissive", "viewer") == 0

    def test_viewer_veto_on_write_tool(self):
        engine = self._setup()
        from security.constraints import ValidationResult
        result = engine.validate(
            "systemctl_restart", "balanced",
            params={"service": "nginx"}, role="viewer",
        )
        assert result.allowed is False
        assert "viewer" in result.reason.lower()

    def test_viewer_allow_readonly_tool(self):
        engine = self._setup()
        result = engine.validate(
            "systemctl", "balanced",
            params={"service": "nginx"}, role="viewer",
        )
        # ps is a read-only sandbox tool — viewer can use it
        assert result.allowed is True

    def test_admin_skip_confirm_low_risk(self):
        engine = self._setup()
        result = engine.validate(
            "systemctl", "balanced",
            params={"action": "restart", "service": "nginx"}, role="admin",
        )
        # risk=7, admin threshold=7 → 7 >= 7 → needs confirm
        assert result.requires_confirmation is True


class TestROLES:
    def test_roles_tuple(self):
        assert ROLES == ("admin", "operator", "viewer")

    def test_roles_order(self):
        # Most privileged first
        assert ROLES.index("admin") < ROLES.index("viewer")
