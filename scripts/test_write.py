"""End-to-end write operation test: diagnose → confirm → execute as kylin-agent."""
import urllib.request
import json

def api(path, data=None):
    url = f"http://localhost:8008{path}"
    if data is None:
        req = urllib.request.Request(url)
    else:
        req = urllib.request.Request(url, data=json.dumps(data).encode(),
                                     headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=60)
    return json.loads(resp.read().decode())

print("=== Step 1: Request log cleanup ===")
r = api("/api/chat", {"user_id": "write_test", "input": "帮我清理旧的系统日志，只保留最近7天"})
print(f"Risk: {r.get('risk_awareness')}")
print(f"Response: {r.get('response', '')[:300]}")
eids = r.get("pending_event_ids", [])
print(f"Pending IDs: {eids}")

if not eids:
    print("FAIL: No confirmation requested — check if LLM generated write commands")
    commands = r.get("commands", [])
    for c in commands:
        print(f"  cmd: {c.get('command')} tier-allowed: {c.get('allowed')} confirm: {c.get('requires_confirmation')}")
    exit(1)

print("\n=== Step 2: Confirm the operation ===")
eid = eids[0]
r = api("/api/confirm", {"user_id": "write_test", "event_id": eid, "confirmed": True})
print(f"Status: {r['status']}")
print(f"Command: {r.get('command')}")
print(f"Exit code: {r.get('exit_code')}")
print(f"Stdout: {r.get('stdout', '')[:300]}")
print(f"Stderr: {r.get('stderr', '')[:300]}")

print("\n=== Step 3: Test truncate (clean a temp log) ===")
r = api("/api/chat", {"user_id": "write_test", "input": "清空 /tmp/test.log 文件"})
print(f"Risk: {r.get('risk_awareness')}")
eids = r.get("pending_event_ids", [])
if eids:
    r = api("/api/confirm", {"user_id": "write_test", "event_id": eids[0], "confirmed": True})
    print(f"Truncate result: status={r['status']} exit={r.get('exit_code')}")
else:
    print("Truncate: no confirmation needed or rejected")
    cmds = r.get("commands", [])
    for c in cmds:
        print(f"  {c.get('command')}: allowed={c.get('allowed')} confirm={c.get('requires_confirmation')}")

print("\n=== Step 4: Verify restricted user execution ===")
# Check audit trail for kylin-agent executions
r = api("/api/audit/trail", None)
events = r.get("events", [])
exec_events = [e for e in events if e.get("event_type") == "execute"]
print(f"Execution events in audit: {len(exec_events)}")
for e in exec_events[-3:]:
    print(f"  {e.get('command', '')[:80]}")

print("\nAll write-operation tests complete.")
