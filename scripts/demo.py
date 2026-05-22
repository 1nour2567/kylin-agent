"""Run end-to-end demo tests against Kylin VM agent."""
import os
import sys
import json
import time

import paramiko

host = os.environ.get("KYLIN_VM_HOST")
user = os.environ.get("KYLIN_VM_USER")
password = os.environ.get("KYLIN_VM_PASS")

for var, name in [(host, "KYLIN_VM_HOST"), (user, "KYLIN_VM_USER"), (password, "KYLIN_VM_PASS")]:
    if not var:
        print(f"Error: {name} environment variable must be set", file=sys.stderr)
        sys.exit(1)

def run_cmd(ssh, cmd, timeout=60):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    return out, err

print("=== Kylin Agent E2E Demo ===\n")

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(host, username=user, password=password, timeout=10)

# 1. Health check
print("1. Health check")
out, _ = run_cmd(client, "curl -s http://localhost:8008/health")
print(f"   {out}\n")

# 2. Context (real OS data)
print("2. System context (RealOSSensor)")
out, _ = run_cmd(client, "curl -s http://localhost:8008/api/context")
data = json.loads(out)
sys = data["system"]
mem = sys["memory"]
disk = sys["disk"]
svcs = sys["services"][:3]
procs = sys["processes"][:3]
print(f"   Memory: {mem}")
print(f"   Disk:   {disk}")
print(f"   Services (top 3): {svcs}")
print(f"   Processes (top 3): {procs}\n")

# 3. LLM diagnosis
print("3. DeepSeek LLM: system diagnosis")
out, _ = run_cmd(client,
    """curl -s -X POST http://localhost:8008/api/chat -H "Content-Type: application/json" -d '{"input":"系统有什么异常吗"}'""",
    timeout=90)
data = json.loads(out)
print(f"   Diagnosis:  {data.get('diagnosis', '?')}")
print(f"   Response:   {data.get('response', '?')[:200]}")
print(f"   Risk:       {data.get('risk_awareness', '?')}")
print(f"   Posture:    {data.get('posture', '?')}")
cmds = data.get("commands", [])
if cmds:
    for c in cmds[:3]:
        print(f"   Command:    {c.get('command','?')[:80]}")
print()

# 4. Service check
print("4. DeepSeek LLM: service check")
out, _ = run_cmd(client,
    """curl -s -X POST http://localhost:8008/api/chat -H "Content-Type: application/json" -d '{"input":"检查sshd和防火墙状态"}'""",
    timeout=90)
data = json.loads(out)
print(f"   Diagnosis:  {data.get('diagnosis', '?')}")
print(f"   Risk:       {data.get('risk_awareness', '?')}")
print(f"   Executed:   {len(data.get('executed', []))} commands\n")

# 5. Confirmation loop test
print("5. Confirmation loop (kill test)")
out, _ = run_cmd(client,
    """curl -s -X POST http://localhost:8008/api/chat -H "Content-Type: application/json" -d '{"input":"kill nginx"}'""",
    timeout=90)
data = json.loads(out)
ra = data.get("risk_awareness", "?")
print(f"   Risk awareness: {ra}")
if ra == "CONFIRMATION_REQUIRED":
    pending = data.get("pending_event_ids", [])
    print(f"   Pending events: {pending}")
    if pending:
        # Deny it
        out2, _ = run_cmd(client,
            f"""curl -s -X POST http://localhost:8008/api/confirm -H "Content-Type: application/json" -d '{{"event_id":"{pending[0]}","confirmed":false}}'""")
        print(f"   Denied: {out2[:100]}")
print()

# 6. Audit trail
print("6. Audit trail (last 3 events)")
out, _ = run_cmd(client, "curl -s 'http://localhost:8008/api/audit/trail?limit=3'")
events = json.loads(out)
if isinstance(events, list) and len(events) > 0:
    for e in events[-3:]:
        print(f"   [{e.get('event_type','?')}] {e.get('event_id','?')[:24]}... at {e.get('timestamp','?')}")
else:
    print(f"   {out[:200]}")
print()

# 7. Posture
print("7. Risk posture")
out, _ = run_cmd(client, "curl -s http://localhost:8008/api/posture")
data = json.loads(out)
print(f"   Posture:    {data.get('posture', '?')}")
print(f"   Threshold:  {data.get('threshold', {})}")
print(f"   Veto count: {data.get('veto_count', '?')}\n")

client.close()
print("=== Demo complete ===")
