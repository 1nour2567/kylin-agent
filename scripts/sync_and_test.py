"""Sync all code + tests to VM and run full 62-test suite."""
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

# All source files + test files
files = [
    # Agent
    ("backend/agent/tools_manifest.py", "/opt/kylin-agent/backend/agent/tools_manifest.py"),
    ("backend/agent/reasoner.py",       "/opt/kylin-agent/backend/agent/reasoner.py"),
    ("backend/agent/risk_posture.py",   "/opt/kylin-agent/backend/agent/risk_posture.py"),
    ("backend/agent/providers.py",      "/opt/kylin-agent/backend/agent/providers.py"),
    ("backend/agent/router.py",         "/opt/kylin-agent/backend/agent/router.py"),
    ("backend/agent/perception.py",     "/opt/kylin-agent/backend/agent/perception.py"),
    # Perception
    ("backend/perception/os_sensors.py","/opt/kylin-agent/backend/perception/os_sensors.py"),
    # Security
    ("backend/security/sandbox.py",     "/opt/kylin-agent/backend/security/sandbox.py"),
    ("backend/security/risk_model.py",  "/opt/kylin-agent/backend/security/risk_model.py"),
    ("backend/security/constraints.py", "/opt/kylin-agent/backend/security/constraints.py"),
    ("backend/security/guardrail.py",   "/opt/kylin-agent/backend/security/guardrail.py"),
    ("backend/security/anti_injection.py","/opt/kylin-agent/backend/security/anti_injection.py"),
    # Audit
    ("backend/audit/store.py",          "/opt/kylin-agent/backend/audit/store.py"),
    ("backend/audit/chain.py",          "/opt/kylin-agent/backend/audit/chain.py"),
    ("backend/audit/trail.py",          "/opt/kylin-agent/backend/audit/trail.py"),
    ("backend/audit/foia.py",           "/opt/kylin-agent/backend/audit/foia.py"),
    # MCP
    ("backend/mcp/server.py",           "/opt/kylin-agent/backend/mcp/server.py"),
    ("backend/mcp/handlers.py",         "/opt/kylin-agent/backend/mcp/handlers.py"),
    ("backend/mcp/protocol.py",         "/opt/kylin-agent/backend/mcp/protocol.py"),
    ("backend/mcp/registry.py",         "/opt/kylin-agent/backend/mcp/registry.py"),
    # Config + main
    ("backend/config.py",               "/opt/kylin-agent/backend/config.py"),
    ("backend/main.py",                 "/opt/kylin-agent/backend/main.py"),
    # Tests
    ("backend/tests/test_guardrail.py",       "/opt/kylin-agent/backend/tests/test_guardrail.py"),
    ("backend/tests/test_jailbreak.py",       "/opt/kylin-agent/backend/tests/test_jailbreak.py"),
    ("backend/tests/test_pipeline.py",        "/opt/kylin-agent/backend/tests/test_pipeline.py"),
    ("backend/tests/test_risk_posture.py",    "/opt/kylin-agent/backend/tests/test_risk_posture.py"),
    # Frontend
    ("frontend/src/app.js",             "/opt/kylin-agent/frontend/src/app.js"),
    ("frontend/index.html",             "/opt/kylin-agent/frontend/index.html"),
]

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(host, username=user, password=password, timeout=10)
sftp = client.open_sftp()

print("=== Syncing files ===")
ok = fail = 0
for local_rel, remote in files:
    local = f"C:/Users/m1916/Desktop/kylin-agent/{local_rel}"
    try:
        sftp.put(local, remote)
        ok += 1
    except Exception as e:
        fail += 1
        print(f"  FAIL: {local_rel} - {e}")
print(f"  {ok} OK, {fail} failed")

sftp.close()

print("\n=== Running test suite ===")
test_files = [
    "test_guardrail.py", "test_jailbreak.py",
    "test_pipeline.py", "test_risk_posture.py",
]

total_pass = 0
total_tests = 0
for tf in test_files:
    stdin, stdout, stderr = client.exec_command(
        f"cd /opt/kylin-agent/backend/tests && python3 {tf}",
        timeout=30
    )
    output = stdout.read().decode()
    err = stderr.read().decode()
    if err:
        print(f"  [{tf}] stderr: {err[:200]}")
    lines = output.strip().split("\n")
    # Last line is "N/M passed" or "N passed"
    last_line = [l for l in lines if "passed" in l.lower()]
    if last_line:
        print(f"  {tf}: {last_line[-1]}")
    else:
        print(f"  {tf}: {lines[-1] if lines else 'no output'}")
    # Count passes
    for l in lines:
        if "[PASS]" in l:
            total_pass += 1
        if l.strip().startswith("[PASS]") or l.strip().startswith("[FAIL]") or l.strip().startswith("[ERROR]"):
            total_tests += 1

print(f"\nTotal: {total_pass}/{total_tests} passed")

print("\n=== Agent health ===")
stdin, stdout, stderr = client.exec_command("curl -s http://localhost:8008/health")
health = stdout.read().decode().strip()
print(f"  {health}")

client.close()
print("\nDone.")
