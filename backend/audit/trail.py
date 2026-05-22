"""Complete audit trail recorder — all pipeline stages."""
from audit.store import write_event


class AuditTrail:
    def __init__(self, user_id: str = "default"):
        self.user_id = user_id

    def receive(self, text: str) -> dict:
        return write_event("receive", {"input_text": text}, self.user_id)

    def perceive(self, ctx: dict) -> dict:
        return write_event("perceive", {
            "time_of_day": ctx.get("time", {}).get("time_of_day"),
            "hour": ctx.get("time", {}).get("hour"),
            "process_count": len(ctx.get("system", {}).get("processes", [])),
            "service_count": len(ctx.get("system", {}).get("services", [])),
        }, self.user_id)

    def route(self, mode: str, trigger: str = "") -> dict:
        return write_event("route", {"mode": mode, "trigger": trigger}, self.user_id)

    def reason(self, llm_output: str, commands: list) -> dict:
        return write_event("reason", {
            "llm_raw": llm_output[:2000],
            "command_count": len(commands),
        }, self.user_id)

    def validate(self, results: list) -> dict:
        blocked = any(not r.get("allowed", True) for r in results)
        risks = [r.get("risk_label", "?") for r in results]
        return write_event("validate", {
            "passed": not blocked,
            "risks": risks,
            "command_count": len(results),
        }, self.user_id)

    def execute(self, command: str, exit_code: int, stdout: str, stderr: str) -> dict:
        import hashlib
        return write_event("execute", {
            "command": command,
            "exit_code": exit_code,
            "stdout_hash": hashlib.sha256(stdout.encode()).hexdigest()[:16],
            "stderr_snippet": stderr[:500],
        }, self.user_id)

    def result(self, summary: str) -> dict:
        return write_event("result", {"summary": summary}, self.user_id)

    def chain_close(self, close_type: str, payload: dict = None) -> dict:
        return write_event("chain_close", {
            "close_type": close_type,
            **(payload or {}),
        }, self.user_id)
