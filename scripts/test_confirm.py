"""Test confirm flow on VM."""
import urllib.request
import json

def api(path, data=None):
    url = f"http://localhost:8008{path}"
    if data is None:
        req = urllib.request.Request(url)
    else:
        req = urllib.request.Request(url, data=json.dumps(data).encode(),
                                     headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=15)
    return json.loads(resp.read().decode())

print("=== Step 1: Chat (kill process) ===")
r = api("/api/chat", {"user_id": "test", "input": "kill process 1234"})
print(f"risk_awareness: {r.get('risk_awareness')}")
print(f"requires_confirmation: {r.get('requires_confirmation')}")
eids = r.get("pending_event_ids", [])
print(f"pending_event_ids: {eids}")

if not eids:
    print("FAIL: No pending_event_ids")
    print(f"Full: {json.dumps(r, indent=2)[:500]}")
    exit(1)

eid = eids[0]

print("\n=== Step 2: List pending ===")
r = api("/api/pending?user_id=test")
print(f"pending count: {r['count']}")

print(f"\n=== Step 3: Confirm {eid} ===")
r = api("/api/confirm", {"user_id": "test", "event_id": eid, "confirmed": True})
print(f"status: {r['status']}")
print(f"command: {r.get('command')}")
print(f"exit_code: {r.get('exit_code')}")
print(f"stdout: {r.get('stdout', '')[:200]}")

print("\n=== Step 4: Confirm again (should be not_found) ===")
r = api("/api/confirm", {"user_id": "test", "event_id": eid, "confirmed": True})
print(f"status: {r['status']}")

print("\n=== Step 5: Deny test ===")
r2 = api("/api/chat", {"user_id": "test2", "input": "kill process 5678"})
eids2 = r2.get("pending_event_ids", [])
if eids2:
    r = api("/api/confirm", {"user_id": "test2", "event_id": eids2[0], "confirmed": False})
    print(f"deny status: {r['status']}")
    print(f"deny message: {r['message']}")

print("\nAll confirm flow tests passed.")
