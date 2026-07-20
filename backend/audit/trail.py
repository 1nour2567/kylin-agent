"""Complete audit trail recorder — all pipeline stages with real-time WebSocket broadcast."""
from audit.store import write_event
from security.redaction import redact_text

try:
    from routers.ws import broadcast as _broadcast
except Exception:
    _broadcast = None


def _ws_send(event_type: str, detail: str, actor_user_id: str = "", actor_role: str = ""):
    """Push audit event to WebSocket clients, filtered by actor (#10)."""
    if _broadcast is None:
        return
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(_broadcast({
                "type": "audit",
                "stage": event_type,
                "detail": redact_text(detail),
            }, actor_user_id=actor_user_id, actor_role=actor_role))
    except Exception:
        pass


class AuditTrail:
    def __init__(self, user_id: str = "default", role: str = "viewer"):
        self.user_id = user_id
        self.role = role

    def receive(self, text: str) -> dict:
        safe_text = redact_text(text)
        _ws_send("receive", f"接收指令: {safe_text[:80]}", self.user_id, self.role)
        return write_event("receive", {"input_text": text}, self.user_id)

    def perceive(self, ctx: dict) -> dict:
        _ws_send("perceive", f"感知环境: 进程数={len(ctx.get('system',{}).get('processes',[]))}, 服务数={len(ctx.get('system',{}).get('services',[]))}", self.user_id, self.role)
        return write_event("perceive", {
            "time_of_day": ctx.get("time", {}).get("time_of_day"),
            "hour": ctx.get("time", {}).get("hour"),
            "process_count": len(ctx.get("system", {}).get("processes", [])),
            "service_count": len(ctx.get("system", {}).get("services", [])),
        }, self.user_id)

    def route(self, mode: str, trigger: str = "") -> dict:
        _ws_send("route", f"意图分类: {mode}" + (f" (触发词: {trigger})" if trigger else ""), self.user_id, self.role)
        return write_event("route", {"mode": mode, "trigger": trigger}, self.user_id)

    def reason(self, llm_output: str, commands: list) -> dict:
        _ws_send("reason", f"推理决策: LLM输出{len(llm_output)}字, 建议{len(commands)}个命令", self.user_id, self.role)
        return write_event("reason", {
            "llm_raw": redact_text(llm_output[:2000]),
            "command_count": len(commands),
        }, self.user_id)

    def validate(self, results: list) -> dict:
        blocked = any(not r.get("allowed", True) for r in results)
        passed_count = sum(1 for r in results if r.get("allowed", True))
        blocked_count = len(results) - passed_count
        _ws_send("validate", f"安全校验: {passed_count}通过{'/ ' + str(blocked_count) + '拦截' if blocked else ''}", self.user_id, self.role)
        risks = [r.get("risk_label", "?") for r in results]
        return write_event("validate", {
            "passed": not blocked,
            "risks": risks,
            "command_count": len(results),
        }, self.user_id)

    def execute(self, command: str, exit_code: int, stdout: str, stderr: str) -> dict:
        import hashlib
        safe_command = redact_text(command)
        _ws_send("execute", f"执行: {safe_command[:60]} (exit={exit_code})", self.user_id, self.role)
        return write_event("execute", {
            "command": safe_command,
            "exit_code": exit_code,
            "stdout_hash": hashlib.sha256(stdout.encode()).hexdigest()[:16],
            "stderr_snippet": redact_text(stderr[:500]),
        }, self.user_id)

    def result(self, summary: str) -> dict:
        _ws_send("result", f"完成: {summary[:80]}", self.user_id, self.role)
        return write_event("result", {"summary": summary}, self.user_id)

    def chain_close(self, close_type: str, payload: dict = None) -> dict:
        _ws_send("chain_close", f"链路关闭: {close_type}", self.user_id, self.role)
        return write_event("chain_close", {
            "close_type": close_type,
            **(payload or {}),
        }, self.user_id)

    def security_event(self, event_type: str, payload: dict = None) -> dict:
        """Write a structured security event without tokens or raw attack text."""
        safe_payload = dict(payload or {})
        for forbidden in ("token", "capability_token", "raw", "raw_content"):
            safe_payload.pop(forbidden, None)
        safe_payload = {
            key: redact_text(value) if isinstance(value, str) else value
            for key, value in safe_payload.items()
        }
        _ws_send(event_type, f"安全事件: {event_type}", self.user_id, self.role)
        return write_event(event_type, safe_payload, self.user_id)
