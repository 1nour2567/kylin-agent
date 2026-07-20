"""SSE chat pipeline using the same CapBAC and IPI controls as /api/chat."""
import json
import secrets
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from agent.trace import TraceContext
from audit.trail import AuditTrail
from deps import (
    _pending_confirmations,
    capability_token_service,
    classifier,
    execution_gateway,
    guardrail,
    limiter,
    perception,
    posture_engine,
    reasoner,
    session_store,
)
from security.capability_token import CapabilityScope
from security.pending import build_pending_entry


router = APIRouter()


class StreamChatRequest(BaseModel):
    user_id: str = "default"
    input: str = Field(default="", max_length=12000)
    session_id: Optional[str] = None


def _sse(event: str, data) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


@router.post("/api/chat/stream")
@limiter.limit("10/minute")
async def chat_stream(request: Request, req: StreamChatRequest):
    user_id = getattr(request.state, "user_id", req.user_id)
    role = getattr(request.state, "role", "viewer")
    key_id = getattr(request.state, "key_id", "")
    trace = TraceContext.get_or_create(user_id, role)
    actor = {"user_id": user_id, "role": role, "key_id": key_id, "trace_id": trace.trace_id}
    sid = req.session_id or f"ses_{user_id}" + (
        "_" + secrets.token_hex(4) if user_id == "default" else ""
    )
    session_store.get_or_create(sid, user_id)
    trail = AuditTrail(user_id, role=role)

    trail.receive(req.input)
    ok, cleaned, ref = guardrail.validate_input(req.input)
    if not ok:
        trail.chain_close("rejected", {"reason": "injection_detected", "ref": ref})

        async def rejected():
            yield _sse("error", {"message": f"输入被安全策略拒绝 [{ref}]"})
            yield _sse("done", {"risk_awareness": "REJECTED", "trace_id": trace.trace_id})
        return StreamingResponse(rejected(), media_type="text/event-stream")

    ctx = perception.build(
        cleaned,
        user_id,
        role=role,
        key_id=key_id,
        conversation_history=session_store.get_history(sid),
        trace_id=trace.trace_id,
    )
    trail.perceive(ctx)
    if ctx.get("input_security", {}).get("blocked"):
        async def perception_blocked():
            yield _sse("error", {"message": "检测到系统感知数据中的可疑指令，已阻断本轮推理。"})
            yield _sse("done", {
                "risk_awareness": "INDIRECT_INJECTION_BLOCKED",
                "session_id": sid,
                "trace_id": trace.trace_id,
            })
        return StreamingResponse(perception_blocked(), media_type="text/event-stream")

    classification = classifier.classify(cleaned, _ctx=ctx)
    trail.route(classification["mode"], classification.get("trigger", ""))
    ctx["posture_info"] = posture_engine.posture_for_prompt()

    async def sse_pipeline():
        llm_result = None
        generator = None
        try:
            generator = reasoner.reason_stream(ctx)
            for event_type, data in generator:
                if event_type == "token":
                    yield _sse("token", {"text": data})
                elif event_type == "error":
                    yield _sse("error", {"message": data})
                    yield _sse("done", {"risk_awareness": "Error"})
                    return
                elif event_type == "result":
                    llm_result = data
        except GeneratorExit:
            if generator is not None:
                generator.close()
            return
        except Exception as exc:
            yield _sse("error", {"message": str(exc)})
            yield _sse("done", {"risk_awareness": "Error"})
            return
        if llm_result is None:
            return

        commands = llm_result.get("commands", [])
        trail.reason(json.dumps(llm_result, ensure_ascii=False)[:2000], commands)
        guardrail.posture = posture_engine.posture
        gr = guardrail.validate_commands(
            commands,
            role=role,
            intent_profile=llm_result.get("intent_profile", {}),
            actor_context=actor,
            trace_id=trace.trace_id,
        )
        trail.validate(gr.command_results)
        if not gr.passed:
            posture_engine.on_veto()
            trail.chain_close("vetoed", {"blocked_at": gr.blocked_at})
            yield _sse("error", {"message": f"安全策略已阻止操作。原因: {gr.blocked_at}"})
            yield _sse("done", {"risk_awareness": "VETOED", "session_id": sid, "trace_id": trace.trace_id})
            return

        yield _sse("commands", {
            "commands": gr.command_results,
            "diagnosis": llm_result.get("diagnosis", ""),
        })
        needs_confirm = [item for item in gr.command_results if item.get("requires_confirmation")]
        if needs_confirm:
            pending_ids = []
            for item in needs_confirm:
                event_id, pending = build_pending_entry(
                    item, user_id, role, posture_engine.posture, source="stream"
                )
                _pending_confirmations.add(event_id, pending)
                pending_ids.append(event_id)
            trail.chain_close("confirmation_required", {"pending_ids": pending_ids})
            yield _sse("confirm", {
                "response": llm_result.get("explanation", ""),
                "diagnosis": llm_result.get("diagnosis", ""),
                "pending_event_ids": pending_ids,
                "commands": gr.command_results,
            })
            yield _sse("done", {
                "risk_awareness": "CONFIRMATION_REQUIRED",
                "session_id": sid,
                "trace_id": trace.trace_id,
            })
            return

        posture_engine.on_permit()
        executed = []
        ipi_blocked = False
        for item in gr.command_results:
            token = None
            expected_scope = None
            if item.get("capability_required"):
                expected_scope = CapabilityScope.from_dict(item["capability_scope"])
                token = capability_token_service.issue(expected_scope)
            result = execution_gateway.execute_tool(
                item["canonical_tool"],
                item["canonical_params"],
                actor,
                capability_token=token,
                expected_scope=expected_scope,
                timeout=30,
            )
            trail.execute(result.command, result.exit_code, result.sanitized_stdout, result.sanitized_stderr)
            executed.append({
                "command": result.command,
                "tool_name": result.tool_name,
                "exit_code": result.exit_code,
                "stdout": result.sanitized_stdout[:1000],
                "stderr": result.sanitized_stderr[:500],
                "output_security": result.output_security,
                "capability_verification": result.capability_verification,
            })
            if result.blocked_by_ipi:
                ipi_blocked = True
                break

        response_text = (
            "检测到工具输出中的可疑指令，原始内容已阻断。"
            if ipi_blocked
            else llm_result.get("explanation", "")
        )
        session_store.add_turn(sid, "user", cleaned)
        session_store.add_turn(sid, "agent", response_text[:500])
        yield _sse("done", {
            "response": response_text,
            "diagnosis": llm_result.get("diagnosis", ""),
            "commands": gr.command_results,
            "executed": executed,
            "risk_awareness": "INDIRECT_INJECTION_BLOCKED" if ipi_blocked else llm_result.get("risk_awareness", "Low"),
            "posture": posture_engine.posture,
            "session_id": sid,
            "trace_id": trace.trace_id,
        })

    return StreamingResponse(sse_pipeline(), media_type="text/event-stream")
