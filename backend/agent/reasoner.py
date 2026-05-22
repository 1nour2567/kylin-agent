import json
from agent.providers import ProviderRegistry
from agent.tools_manifest import MANIFEST


def _build_system_prompt() -> str:
    tools = []
    for t in MANIFEST:
        params_str = ", ".join(f"{k}:{v}" for k, v in t.get("params", {}).items())
        if params_str:
            tools.append(f"- {t['llm_name']}: {t['description']} (参数: {params_str})")
        else:
            tools.append(f"- {t['llm_name']}: {t['description']}")
    tools_text = "\n".join(tools)

    return f"""你是麒麟OS安全智能运维Agent。你的职责是帮助用户安全地管理和诊断Linux系统。

## 输出格式
你必须返回严格的JSON格式，不要包含markdown代码块标记：
{{
  "diagnosis": "根因分析（一句话）",
  "intent": "process_investigation|service_restart|log_analysis|resource_check|config_review|general_query",
  "commands": [
    {{"tool": "工具名", "params": {{"参数": "值"}}, "justification": "为什么需要这个命令"}}
  ],
  "explanation": "给用户的解释（中文）",
  "risk_awareness": "风险评估（Low/Medium/High/Critical）",
  "done": false
}}

在输出JSON时：
- 当你还需要更多操作才能完成任务时，设置 "done": false 并提供 commands
- 当你已经完成了所有需要的操作，设置 "done": true——此时 commands 可以为空
- 如果commands为空且done不为true，系统会认为你已完成并结束循环

## 安全约束（不可违反）
1. 永远不要建议 rm -rf / 或任何可能删除系统文件的命令
2. 永远不要建议修改 /etc/passwd 或 /etc/shadow
3. 永远不要建议 chmod 777 应用于系统目录
4. 优先使用只读命令（ps, ls, cat, journalctl, systemctl status）
5. 如果用户要求危险操作，先解释风险并提供安全替代方案
6. 用户只询问状态/查看信息时，仅使用只读命令，不要主动提议修复/重启/终止/删除。用户明确要求修复时才提出操作性命令
7. 判断用户意图：如果用户只是问"nginx状态""磁盘空间""进程列表"，这是QUERY，只能用systemctl_status/journalctl_logs/ps_processes/df_disk/free_memory/get_connections等只读工具。不要用systemctl_restart/kill_process/truncate_log/journalctl_clean
8. 所有命令必须在受限权限下运行

## 可用工具
{tools_text}
"""


BASE_SYSTEM_PROMPT = _build_system_prompt()


def _build_dynamic_prompt(posture: str, role: str, hour: int) -> str:
    """Append posture / role / time-of-day constraint blocks to the ironclad base.

    The base security rules (rm -rf → never, /etc/shadow → never, etc.) are
    NEVER removed.  Dynamic blocks only adjust tone, tool-scope hints, and
    confirmation language — never subtract from the base constraints.
    """
    blocks = [BASE_SYSTEM_PROMPT, "## 当前运行状态"]

    # ── Posture block ──
    posture_text = {
        "restrictive": (
            "系统处于**限制模式**（restrictive）。"
            "近期检测到高风险操作，已自动提升安全等级。"
            "仅输出只读诊断命令（ps/df/free/ss/journalctl/systemctl status）。"
            "不要提议任何修改、重启、删除或配置变更操作。"
            "如果用户要求修改操作，解释当前处于限制模式并建议等待安全态势恢复。"
        ),
        "balanced": (
            "系统处于**正常模式**（balanced）。"
            "可提议标准运维操作，但高风险命令必须标注需要用户显式确认。"
            "优先只读诊断，仅在用户明确要求时才提议操作命令。"
        ),
        "permissive": (
            "系统处于**宽松模式**（permissive）。"
            "允许提议管理操作，所有命令事后完整审计。"
            "仍然遵守基础安全规则：禁止 rm -rf /、禁止修改 /etc/shadow 等。"
        ),
    }
    blocks.append(posture_text.get(posture, posture_text["balanced"]))

    # ── Role block ──
    role_text = {
        "viewer": (
            "你的调用者是**只读用户**（viewer 角色）。"
            "输出的所有命令必须限制在以下只读工具范围内："
            "ps_processes、df_disk、free_memory、netstat_connections、"
            "journalctl_logs、systemctl_status（仅 status 子命令）、get_services。"
            "**禁止**输出 systemctl_restart、kill_process、truncate_log、"
            "journalctl_clean 或任何修改/操作类工具。"
            "如果用户要求修改操作，礼貌解释其角色为只读，建议联系管理员。"
        ),
        "operator": (
            "你的调用者是**操作员**（operator 角色）。"
            "可输出标准运维命令，高风险操作（kill、restart、truncate、clean）"
            "需要标注确认要求（requires_confirmation: true）。"
        ),
        "admin": (
            "你的调用者是**管理员**（admin 角色）。"
            "可使用全部工具。优先给出建议和解释，而非机械阻止。"
            "高风险命令仍需标注风险标签，但确认门槛较低。"
        ),
    }
    blocks.append(role_text.get(role, role_text["viewer"]))

    # ── Nighttime block (22:00–06:00) ──
    if hour >= 22 or hour < 6:
        blocks.append(
            "当前为**夜间运维窗口**（22:00–06:00）。"
            "避免建议服务重启、下线操作、配置变更。"
            "优先使用只读诊断。如果用户要求夜间操作，先提示风险再提议安全方案。"
        )

    return "\n\n".join(blocks)


class Reasoner:
    def __init__(self, provider_registry: ProviderRegistry):
        self.registry = provider_registry

    def reason(self, perception_ctx: dict) -> dict:
        provider = self.registry.get_active()
        if provider is None:
            return {"diagnosis": "无可用LLM", "intent": "general_query",
                    "commands": [], "explanation": "错误：没有可用的LLM提供商",
                    "risk_awareness": "Unknown"}

        posture_info = perception_ctx.get("posture_info", {})
        if isinstance(posture_info, str):
            posture = "balanced"  # backward compat with old string format
        else:
            posture = posture_info.get("posture", "balanced")
        op = perception_ctx.get("operator", {})
        role = op.get("role", "viewer")
        hour = perception_ctx.get("time", {}).get("hour", 12)

        system_prompt = _build_dynamic_prompt(posture, role, hour)
        user_prompt = self._build_prompt(perception_ctx)
        raw = self._call_with_retry(provider, system_prompt, user_prompt)

        try:
            result = json.loads(raw.strip().lstrip("```json").rstrip("```").strip())
        except json.JSONDecodeError:
            result = {
                "diagnosis": "无法解析LLM输出",
                "intent": "general_query",
                "commands": [],
                "explanation": raw[:500],
                "risk_awareness": "Unknown",
            }

        return result

    def reason_stream(self, perception_ctx: dict):
        """Streaming variant: yields (event_type, data) tuples as tokens arrive.

        Yields:
          ("token", str)  — text chunk from LLM
          ("result", dict) — parsed JSON result (final)
          ("error", str)  — error message
        """
        provider = self.registry.get_active()
        if provider is None:
            yield ("error", "无可用LLM")
            return

        posture_info = perception_ctx.get("posture_info", {})
        if isinstance(posture_info, str):
            posture = "balanced"
        else:
            posture = posture_info.get("posture", "balanced")
        op = perception_ctx.get("operator", {})
        role = op.get("role", "viewer")
        hour = perception_ctx.get("time", {}).get("hour", 12)

        system_prompt = _build_dynamic_prompt(posture, role, hour)
        user_prompt = self._build_prompt(perception_ctx)

        raw = ""
        try:
            for chunk in provider.generate_stream(system_prompt, user_prompt):
                raw += chunk
                yield ("token", chunk)
        except Exception as e:
            yield ("error", str(e))
            return

        try:
            result = json.loads(raw.strip().lstrip("```json").rstrip("```").strip())
        except json.JSONDecodeError:
            result = {
                "diagnosis": "无法解析LLM输出",
                "intent": "general_query",
                "commands": [],
                "explanation": raw[:500],
                "risk_awareness": "Unknown",
            }
        yield ("result", result)

    def _call_with_retry(self, provider, system_prompt: str, user_prompt: str,
                         max_retries: int = 1) -> str:
        """Call LLM with one retry on failure."""
        import logging
        logger = logging.getLogger("kylin-agent")
        last_err = None
        for attempt in range(max_retries + 1):
            try:
                return provider.generate(system_prompt, user_prompt)
            except Exception as e:
                last_err = e
                if attempt < max_retries:
                    logger.warning(f"LLM call failed (attempt {attempt+1}): {e}, retrying...")
        raise last_err

    def _build_prompt(self, ctx: dict) -> str:
        op = ctx.get("operator", {})
        user_id = (op.get("user_id") or ctx.get("user_id") or "unknown")
        role = op.get("role", "viewer")
        parts = [
            f"操作者: {user_id} (角色: {role})",
            f"用户输入: {ctx['user_input']}",
        ]
        # Agentic loop hint
        hint = ctx.get("loop_hint", "")
        if hint:
            parts.append(hint)
        sys = ctx.get("system", {})
        if sys.get("processes"):
            parts.append(f"当前进程(前10): {sys['processes'][:10]}")
        if sys.get("services"):
            parts.append(f"服务状态: {sys['services']}")
        if sys.get("disk"):
            parts.append(f"磁盘使用: {sys['disk']}")
        if sys.get("memory"):
            parts.append(f"内存使用: {sys['memory']}")
        hour = ctx.get("time", {}).get("hour", 12)
        parts.append(f"当前时间: {hour}:00")

        # Conversation history from current session
        history = ctx.get("conversation_history", [])
        if history:
            lines = ["对话历史:"]
            for h in history[-8:]:  # last 8 turns to keep context tight
                role_label = "用户" if h["role"] == "user" else "Agent"
                lines.append(f"  [{role_label}]: {h['content'][:200]}")
            parts.append("\n".join(lines))

        audit = ctx.get("audit_recent", [])
        if audit:
            lines = ["最近操作记录:"]
            for e in audit:
                ts = e.get("timestamp", "")[:19]
                actor = e.get("actor", "")
                etype = e.get("type", "")
                cmd = e.get("command", "")
                if etype == "receive":
                    lines.append(f"  [{ts}] {actor} 输入: {e.get('input_text', '')}")
                elif etype == "execute":
                    lines.append(f"  [{ts}] {actor} 执行: {cmd} (exit={e.get('exit_code', '?')})")
                elif etype == "chain_close":
                    lines.append(f"  [{ts}] {actor} 结果: {e.get('close_type', cmd)}")
            parts.append("\n".join(lines))
        return "\n".join(parts)
