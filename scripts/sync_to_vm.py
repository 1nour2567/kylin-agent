"""Sync manifest changes to VM and restart agent."""
import os
import sys
import time

import paramiko

host = os.environ.get("KYLIN_VM_HOST")
user = os.environ.get("KYLIN_VM_USER")
password = os.environ.get("KYLIN_VM_PASS")

for var, name in [(host, "KYLIN_VM_HOST"), (user, "KYLIN_VM_USER"), (password, "KYLIN_VM_PASS")]:
    if not var:
        print(f"Error: {name} environment variable must be set", file=sys.stderr)
        sys.exit(1)

files = [
    ("backend/agent/tools_manifest.py",   "/opt/kylin-agent/backend/agent/tools_manifest.py"),
    ("backend/agent/reasoner.py",         "/opt/kylin-agent/backend/agent/reasoner.py"),
    ("backend/agent/risk_posture.py",     "/opt/kylin-agent/backend/agent/risk_posture.py"),
    ("backend/agent/providers.py",        "/opt/kylin-agent/backend/agent/providers.py"),
    ("backend/perception/os_sensors.py",  "/opt/kylin-agent/backend/perception/os_sensors.py"),
    ("backend/security/sandbox.py",       "/opt/kylin-agent/backend/security/sandbox.py"),
    ("backend/security/risk_model.py",    "/opt/kylin-agent/backend/security/risk_model.py"),
    ("backend/security/constraints.py",   "/opt/kylin-agent/backend/security/constraints.py"),
    ("backend/security/guardrail.py",     "/opt/kylin-agent/backend/security/guardrail.py"),
    ("backend/config.py",                 "/opt/kylin-agent/backend/config.py"),
    ("backend/agent/perception.py",       "/opt/kylin-agent/backend/agent/perception.py"),
    ("backend/security/anti_injection.py","/opt/kylin-agent/backend/security/anti_injection.py"),
    ("backend/security/patterns.py",      "/opt/kylin-agent/backend/security/patterns.py"),
    ("backend/middleware/__init__.py",    "/opt/kylin-agent/backend/middleware/__init__.py"),
    ("backend/middleware/auth.py",        "/opt/kylin-agent/backend/middleware/auth.py"),
    ("backend/audit/store.py",            "/opt/kylin-agent/backend/audit/store.py"),
    ("backend/deps.py",                   "/opt/kylin-agent/backend/deps.py"),
    ("backend/main.py",                   "/opt/kylin-agent/backend/main.py"),
    ("backend/routers/__init__.py",       "/opt/kylin-agent/backend/routers/__init__.py"),
    ("backend/routers/chat.py",           "/opt/kylin-agent/backend/routers/chat.py"),
    ("backend/routers/confirm.py",        "/opt/kylin-agent/backend/routers/confirm.py"),
    ("backend/routers/audit.py",          "/opt/kylin-agent/backend/routers/audit.py"),
    ("backend/routers/mcp.py",            "/opt/kylin-agent/backend/routers/mcp.py"),
    ("backend/routers/system.py",         "/opt/kylin-agent/backend/routers/system.py"),
    ("backend/routers/ws.py",             "/opt/kylin-agent/backend/routers/ws.py"),
    ("frontend/src/app.js",               "/opt/kylin-agent/frontend/src/app.js"),
    ("frontend/index.html",               "/opt/kylin-agent/frontend/index.html"),
]

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(host, username=user, password=password, timeout=10)
sftp = client.open_sftp()

print("=== Syncing files ===")
for local_rel, remote in files:
    local = f"C:/Users/m1916/Desktop/kylin-agent/{local_rel}"
    try:
        sftp.put(local, remote)
        print(f"  OK: {local_rel}")
    except Exception as e:
        print(f"  FAIL: {local_rel} - {e}")

sftp.close()

print("\n=== Restarting agent ===")
client.exec_command("pkill -f 'python3 main.py' 2>/dev/null")
time.sleep(2)

stdin, stdout, stderr = client.exec_command(
    "cd /opt/kylin-agent/backend && nohup python3 main.py > /tmp/agent.log 2>&1 &"
)
time.sleep(4)

stdin, stdout, stderr = client.exec_command("ss -tlnp | grep 8008")
port = stdout.read().decode().strip()
print(f"Port 8008: {'LISTENING' if port else 'NOT LISTENING'}")

stdin, stdout, stderr = client.exec_command("curl -s http://localhost:8008/health")
print(f"Health: {stdout.read().decode().strip()}")

# Test MCP tools list
stdin, stdout, stderr = client.exec_command("curl -s http://localhost:8008/api/mcp/tools")
print(f"MCP tools: {stdout.read().decode().strip()}")

client.close()
print("\nDone.")
