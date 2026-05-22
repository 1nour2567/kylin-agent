"""API tests: confirm flow + audit endpoints.  Uses FastAPI TestClient."""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ["API_KEY"] = "test-key-api-2026"
os.environ.setdefault("AGENT_MODE", "mock")

from fastapi.testclient import TestClient
from main import app
from deps import _pending_confirmations

client = TestClient(app)
AUTH = {"Authorization": "Bearer test-key-api-2026"}

# ── Helpers ──

def _seed_pending(event_id="evt_test_001", command="systemctl restart nginx"):
    _pending_confirmations.add(event_id, {
        "command": command,
        "display_command": command,
        "risk_label": "high",
        "user_id": "default",
        "created_at": __import__("time").time(),
        "posture": "balanced",
    })

def _clear_pending():
    _pending_confirmations._items.clear()

# ── Confirm: deny ──

def test_confirm_deny_removes_pending():
    _seed_pending("evt_deny_01")
    resp = client.post("/api/confirm", json={
        "user_id": "default", "event_id": "evt_deny_01", "confirmed": False,
    }, headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "denied"
    assert "evt_deny_01" not in _pending_confirmations


# ── Confirm: not found ──

def test_confirm_not_found():
    resp = client.post("/api/confirm", json={
        "user_id": "default", "event_id": "nonexistent_99999", "confirmed": True,
    }, headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "not_found"


# ── Confirm: approve executes ──

def test_confirm_approve_executes():
    _seed_pending("evt_approve_01", "ps aux --no-headers")
    resp = client.post("/api/confirm", json={
        "user_id": "default", "event_id": "evt_approve_01", "confirmed": True,
    }, headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "executed"
    assert "exit_code" in data
    assert "evt_approve_01" not in _pending_confirmations


# ── Pending list ──

def test_pending_list_filters_by_user():
    _clear_pending()
    _pending_confirmations.add("evt_a", {
        "command": "cmd_a", "risk_label": "low",
        "user_id": "user_a", "created_at": __import__("time").time(),
    })
    _pending_confirmations.add("evt_b", {
        "command": "cmd_b", "risk_label": "medium",
        "user_id": "user_b", "created_at": __import__("time").time(),
    })

    resp_a = client.get("/api/pending?user_id=user_a", headers=AUTH)
    assert resp_a.status_code == 200
    data = resp_a.json()
    assert data["count"] == 1
    assert data["pending"][0]["event_id"] == "evt_a"

    _clear_pending()


# ── Pending list respects TTL expiration ──

def test_pending_list_expires_old_entries():
    _clear_pending()
    old_ts = __import__("time").time() - 400  # beyond TTL=300
    _pending_confirmations.add("evt_old", {
        "command": "old_cmd", "risk_label": "low",
        "user_id": "default", "created_at": old_ts,
    })
    _pending_confirmations.add("evt_new", {
        "command": "new_cmd", "risk_label": "low",
        "user_id": "default", "created_at": __import__("time").time(),
    })

    resp = client.get("/api/pending?user_id=default", headers=AUTH)
    data = resp.json()
    assert data["count"] == 1  # only new
    ids = [p["event_id"] for p in data["pending"]]
    assert "evt_new" in ids
    assert "evt_old" not in ids

    _clear_pending()


# ── Audit: trail query ──

def test_audit_trail_returns_events():
    resp = client.get("/api/audit/trail?limit=5", headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data
    assert "count" in data
    assert "chain_valid" in data
    assert isinstance(data["events"], list)
    assert data["count"] <= 5


# ── Audit: event not found ──

def test_audit_event_not_found():
    resp = client.get("/api/audit/event/nonexistent_event_xyz", headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert "error" in data


# ── Audit: verify day ──

def test_audit_verify_today():
    resp = client.get("/api/audit/verify", headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert "date" in data
    assert "event_count" in data
    assert "chain_valid" in data
    assert data["chain_valid"] is True or data["chain_valid"] is False


# ── Audit: verify specific date ──

def test_audit_verify_specific_date():
    resp = client.get("/api/audit/verify?date=2099-01-01", headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_count"] == 0


if __name__ == "__main__":
    tests = [
        test_confirm_deny_removes_pending,
        test_confirm_not_found,
        test_confirm_approve_executes,
        test_pending_list_filters_by_user,
        test_pending_list_expires_old_entries,
        test_audit_trail_returns_events,
        test_audit_event_not_found,
        test_audit_verify_today,
        test_audit_verify_specific_date,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
            print(f"[PASS] {t.__name__}")
        except AssertionError as e:
            print(f"[FAIL] {t.__name__}: {e}")
        except Exception as e:
            print(f"[ERROR] {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
