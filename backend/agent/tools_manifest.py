"""Single source of truth for all tool names, parameters, risk levels, and execution tiers.

Every other module that references tool names (system prompt, MCP registry,
sandbox allowlist, risk model) MUST derive its list from this manifest.

exec_tier semantics:
  "auto"    — auto-execute, no confirmation needed (read-only diagnostics)
  "confirm" — requires T2 validation + user confirmation, then execute as restricted user
  "veto"    — always blocked, never executable through the agent
"""

MANIFEST = [
    # ═══ Read-only: auto tier ═══
    {
        "name": "ps",
        "mcp_name": "get_processes",
        "llm_name": "ps_processes",
        "description": "查看进程列表",
        "params": {"limit": "int"},
        "param_flags": {"limit": ""},
        "default_args": ["aux", "--no-headers"],
        "risk": "readonly",
        "requires_confirm": False,
        "exec_tier": "auto",
    },
    {
        "name": "systemctl",
        "mcp_name": "systemctl_status",
        "llm_name": "systemctl_status",
        "description": "查看服务状态",
        "params": {"service": "string"},
        "param_flags": {"service": None},
        "default_args": ["status"],
        "risk": "readonly",
        "requires_confirm": False,
        "exec_tier": "auto",
    },
    {
        "name": "journalctl",
        "mcp_name": "journalctl_logs",
        "llm_name": "journalctl_logs",
        "description": "查看系统日志",
        "params": {"unit": "string", "lines": "int"},
        "param_flags": {"unit": "-u", "lines": "-n"},
        "default_args": ["--no-pager"],
        "risk": "readonly",
        "requires_confirm": False,
        "exec_tier": "auto",
    },
    {
        "name": "ss",
        "mcp_name": "get_connections",
        "llm_name": "netstat_connections",
        "description": "查看网络连接",
        "params": {},
        "param_flags": {},
        "default_args": ["-tlnp"],
        "risk": "readonly",
        "requires_confirm": False,
        "exec_tier": "auto",
    },
    {
        "name": "df",
        "mcp_name": "get_disk",
        "llm_name": "df_disk",
        "description": "查看磁盘使用",
        "params": {},
        "param_flags": {},
        "default_args": ["-h", "/"],
        "risk": "readonly",
        "requires_confirm": False,
        "exec_tier": "auto",
    },
    {
        "name": "free",
        "mcp_name": "get_memory",
        "llm_name": "free_memory",
        "description": "查看内存使用",
        "params": {},
        "param_flags": {},
        "default_args": ["-h"],
        "risk": "readonly",
        "requires_confirm": False,
        "exec_tier": "auto",
    },
    {
        "name": "systemctl",
        "mcp_name": "get_services",
        "llm_name": "get_services",
        "description": "查看系统服务列表",
        "params": {},
        "param_flags": {},
        "default_args": ["list-units", "--type=service", "--state=running", "--no-legend"],
        "risk": "readonly",
        "requires_confirm": False,
        "exec_tier": "auto",
    },
    {
        "name": "lsof",
        "mcp_name": "lsof_files",
        "llm_name": "lsof_files",
        "description": "查看打开的文件",
        "params": {},
        "param_flags": {},
        "default_args": ["-nP", "-i"],
        "risk": "readonly",
        "requires_confirm": False,
        "exec_tier": "auto",
    },
    {
        "name": "rpm",
        "mcp_name": "rpm_verify",
        "llm_name": "rpm_verify",
        "description": "验证已安装包完整性",
        "params": {"package": "string"},
        "param_flags": {"package": None},
        "default_args": ["-V"],
        "risk": "readonly",
        "requires_confirm": False,
        "exec_tier": "auto",
    },
    # ═══ Low-risk write: confirm tier ═══
    {
        "name": "systemctl",
        "mcp_name": "systemctl_restart",
        "llm_name": "systemctl_restart",
        "description": "重启系统服务（需确认）",
        "params": {"service": "string"},
        "param_flags": {"service": None},
        "default_args": ["restart"],
        "risk": "write",
        "requires_confirm": True,
        "exec_tier": "confirm",
    },
    {
        "name": "journalctl",
        "mcp_name": "journalctl_clean",
        "llm_name": "journalctl_clean",
        "description": "清理旧系统日志（需确认）",
        "params": {"days": "string"},
        "param_flags": {"days": "--vacuum-time"},
        "default_args": ["--no-pager"],
        "risk": "write",
        "requires_confirm": True,
        "exec_tier": "confirm",
    },
    {
        "name": "kill",
        "mcp_name": "kill_process",
        "llm_name": "kill_process",
        "description": "终止指定进程，优先 SIGTERM（需确认）",
        "params": {"pid": "string"},
        "param_flags": {"pid": None},
        "default_args": ["-15"],
        "risk": "write",
        "requires_confirm": True,
        "exec_tier": "confirm",
    },
    {
        "name": "truncate",
        "mcp_name": "truncate_log",
        "llm_name": "truncate_log",
        "description": "清空指定日志文件（需确认）",
        "params": {"file": "string"},
        "param_flags": {"file": None},
        "default_args": ["-s", "0"],
        "risk": "write",
        "requires_confirm": True,
        "exec_tier": "confirm",
    },
    # ═══ File operations (handled by MCP, not sandbox) ═══
    {
        "name": "create_file",
        "mcp_name": "create_file",
        "llm_name": "create_file",
        "description": "创建文件（/tmp下自动，系统路径需确认，禁止/etc/boot/sys/proc）",
        "params": {"path": "string", "content": "string"},
        "param_flags": {"path": None, "content": None},
        "default_args": [],
        "risk": "write",
        "requires_confirm": False,
        "exec_tier": "auto",
    },
    {
        "name": "append_file",
        "mcp_name": "append_file",
        "llm_name": "append_file",
        "description": "追加内容到文件（仅追加不覆盖，系统路径需确认，禁止/etc/boot/sys/proc）",
        "params": {"path": "string", "content": "string"},
        "param_flags": {"path": None, "content": None},
        "default_args": [],
        "risk": "write",
        "requires_confirm": False,
        "exec_tier": "auto",
    },
    {
        "name": "execute_script",
        "mcp_name": "execute_script",
        "llm_name": "execute_script",
        "description": "在/tmp/kylin-agent/下执行脚本（需确认，禁止python/perl/ruby shebang）",
        "params": {"path": "string"},
        "param_flags": {"path": None},
        "default_args": [],
        "risk": "write",
        "requires_confirm": True,
        "exec_tier": "confirm",
    },

    # ═══ Prohibited: veto tier (listed for T2 completeness) ═══
    {
        "name": "rm",
        "mcp_name": None,
        "llm_name": None,
        "description": None,
        "params": {},
        "param_flags": {},
        "default_args": [],
        "risk": "destructive",
        "requires_confirm": False,
        "exec_tier": "veto",
    },
    {
        "name": "chmod",
        "mcp_name": None,
        "llm_name": None,
        "description": None,
        "params": {},
        "param_flags": {},
        "default_args": [],
        "risk": "destructive",
        "requires_confirm": False,
        "exec_tier": "veto",
    },
]


def lookup_by_llm_name(llm_name: str) -> dict | None:
    """Find manifest entry by the name the LLM sees and outputs."""
    for t in MANIFEST:
        if t["llm_name"] == llm_name:
            return t
    return None


def lookup_by_mcp_name(mcp_name: str) -> dict | None:
    """Find manifest entry by MCP registry name."""
    for t in MANIFEST:
        if t["mcp_name"] == mcp_name:
            return t
    return None


def sandbox_allowlist() -> list[str]:
    """All base command names allowed in the T3 execution sandbox (auto + confirm tiers)."""
    return sorted(set(t["name"] for t in MANIFEST
                      if t.get("exec_tier") in ("auto", "confirm")))


def readonly_command_set() -> set[str]:
    """Set of real OS command names considered safe for read-only execution."""
    return {t["name"] for t in MANIFEST if t["risk"] == "readonly"}


def llm_tool_names() -> list[str]:
    """Names the LLM is taught to use (for system prompt generation)."""
    return [t["llm_name"] for t in MANIFEST if t.get("llm_name") is not None]


def exec_tier_for(tool_or_llm_name: str) -> str:
    """Get exec_tier for a tool by name or llm_name. Defaults to 'auto'."""
    for t in MANIFEST:
        if t["name"] == tool_or_llm_name or t.get("llm_name") == tool_or_llm_name:
            return t.get("exec_tier", "auto")
    return "auto"


WRITE_INDICATORS = [
    "--vacuum", "restart", "stop", "disable", "mask",
    "-9", "-SIGKILL", "truncate", "rm ", "chmod",
    "-delete", "userdel", "groupdel", "passwd ",
    "usermod", "chown ", "mkfs.", "iptables ",
    "iptables-save", "firewall-cmd", ">", ">>",
    "kill ", "killall", "pkill",
]


def exec_tier_for_resolved_cmd(resolved_cmd: str) -> str:
    """Determine exec tier from resolved command content + manifest.

    Checks manifest first, then falls back to command content analysis
    for LLM outputs that don't use the explicit confirm-tier tool name.
    """
    base = resolved_cmd.strip().split()[0] if resolved_cmd.strip() else ""
    manifest_tier = exec_tier_for(base)
    if manifest_tier in ("veto", "confirm"):
        return manifest_tier
    # Auto-tier tool, but command content suggests a write operation
    cmd_lower = resolved_cmd.lower()
    if any(i.lower() in cmd_lower for i in WRITE_INDICATORS):
        return "confirm"
    return "auto"
