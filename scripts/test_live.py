"""Test full pipeline in live mode: DeepSeek LLM + RealOSSensor."""
import urllib.request
import json, time

def api(path, data=None):
    url = f"http://localhost:8008{path}"
    if data is None:
        req = urllib.request.Request(url)
    else:
        req = urllib.request.Request(url, data=json.dumps(data).encode(),
                                     headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=60)
    return json.loads(resp.read().decode())

# Test 1: System diagnostics
print("=== Test 1: System diagnostics ===")
r = api("/api/chat", {"user_id": "live_test", "input": "帮我看看系统有什么问题"})
print(f"Diagnosis: {r.get('diagnosis', '')[:200]}")
print(f"Response: {r.get('response', '')[:300]}")
print(f"Risk: {r.get('risk_awareness', '')}")
print(f"Posture: {r.get('posture', '')}")
if r.get("executed"):
    for e in r["executed"]:
        print(f"  executed: {e['command']} -> exit {e['exit_code']}")
        if e.get('stdout'):
            print(f"  stdout: {e['stdout'][:200]}")
print()

# Test 2: Service check
print("=== Test 2: Service check ===")
r = api("/api/chat", {"user_id": "live_test", "input": "检查 sshd 服务状态"})
print(f"Diagnosis: {r.get('diagnosis', '')[:200]}")
print(f"Risk: {r.get('risk_awareness', '')}")
if r.get("executed"):
    for e in r["executed"]:
        print(f"  executed: {e['command']} -> exit {e['exit_code']}")
print()

# Test 3: Resource check
print("=== Test 3: Resource check ===")
r = api("/api/chat", {"user_id": "live_test", "input": "查看磁盘和内存使用"})
print(f"Diagnosis: {r.get('diagnosis', '')[:200]}")
print(f"Risk: {r.get('risk_awareness', '')}")
if r.get("executed"):
    for e in r["executed"]:
        print(f"  executed: {e['command']} -> exit {e['exit_code']}")
        if e.get('stdout'):
            print(f"  stdout: {e['stdout'][:200]}")

print("\nAll live tests complete.")
