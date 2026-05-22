"""T1: Deterministic risk scoring matrix — no LLM involvement."""
from typing import Dict

from agent.tools_manifest import readonly_command_set, lookup_by_llm_name

READ_ONLY_COMMANDS = sorted(readonly_command_set() | {
    # Supplementary safe commands not yet in manifest
    "ls", "cat", "head", "tail", "less", "grep", "find",
    "stat", "file", "du", "uptime", "who", "w",
    "netstat", "ip addr", "ip route", "ping", "traceroute",
    "systemctl status", "rpm -q", "rpm -V",
    "ausearch", "aureport", "getenforce", "getsebool",
})

DESTRUCTIVE_COMMANDS = {
    "rm -rf /": 10,
    "mkfs": 10,
    "fdisk": 10,
    "dd if=": 10,
    "> /dev/sd": 10,
    "chmod 777 /": 9,
    "userdel -r root": 10,
    "passwd root": 8,
}

WRITE_COMMANDS = {
    "systemctl stop": 6, "systemctl restart": 5, "systemctl disable": 7,
    "kill -9": 6, "kill": 4,
    "chown -R": 7, "chmod": 5,
    "rm -rf": 8, "rm": 5,
    "iptables": 8, "firewall-cmd": 6,
}


def assess(command: str, tools: list = None) -> int:
    cmd_lower = command.lower()

    for pattern, score in DESTRUCTIVE_COMMANDS.items():
        if pattern.lower() in cmd_lower:
            return score

    for pattern, score in WRITE_COMMANDS.items():
        if pattern.lower() in cmd_lower:
            return score

    for ro_cmd in READ_ONLY_COMMANDS:
        if cmd_lower.startswith(ro_cmd):
            return 1

    cmd_tool = _extract_tool_name(command)
    # Translate llm_name to real command name via manifest
    entry = lookup_by_llm_name(cmd_tool)
    sandbox_name = entry["name"] if entry else cmd_tool
    for ro_cmd in READ_ONLY_COMMANDS:
        if sandbox_name == ro_cmd.split()[0]:
            return 1

    return 3


def _extract_tool_name(command: str) -> str:
    return command.strip().split()[0] if command.strip() else ""


def risk_label(score: int) -> str:
    if score >= 8:
        return "CRITICAL"
    elif score >= 6:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    return "LOW"
