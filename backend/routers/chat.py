"""POST /api/chat with T0-U/T0-O, Task-Level CapBAC, and unified execution."""
import json
import secrets
from typing import Optional

from fastapi import APIRouter, Request
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
    logger,
    perception,
    posture_engine,
    reasoner,
    session_store,
)
from security.capability_token import CapabilityScope
from security.pending import build_pending_entry


chat_router = APIRouter()


class ChatRequest(BaseModel):
    user_id: str = "default"
    input: str = Field(default="", max_length=12000)
    session_id: Optional[str] = None


@chat_router.post("/api/chat")
@limiter.limit("10/minute")
async def chat(request: Request, req: ChatRequest):
    user_id = getattr(request.state, "user_id", req.user_id)
    role = getattr(request.state, "role", "viewer")
    key_id = getattr(request.state, "key_id", "")
    trace = TraceContext.get_or_create(user_id, role)
    trace.start_span("chat", {"input_length": len(req.input)})
    actor = {"user_id": user_id, "role": role, "key_id": key_id, "trace_id": trace.trace_id}

    sid = req.session_id or f"ses_{user_id}" + (
        "_" + secrets.token_hex(4) if user_id == "default" else ""
    )
    session_store.get_or_create(sid, user_id)
    trail = AuditTrail(user_id, role=role)

    trail.receive(req.input)
    ok, cleaned, ref = guardrail.validate_input(req.input)
    if not ok:
        logger.warning("T0-U injection blocked user=%s ref=%s", user_id, ref)
        trail.chain_close("rejected", {"reason": "injection_detected", "ref": ref})
        trace.end_span({"result": "rejected_injection"})
        return {
            "response": f"输入被安全策略拒绝 [{ref}]",
            "commands": [],
            "risk_awareness": "REJECTED",
            "trace_id": trace.trace_id,
        }

    conversation_history = session_store.get_history(sid)
    ctx = perception.build(
        cleaned,
        user_id,
        role=role,
        key_id=key_id,
        conversation_history=conversation_history,
        trace_id=trace.trace_id,
    )
    trail.perceive(ctx)
    if ctx.get("input_security", {}).get("blocked"):
        trail.chain_close("indirect_injection_blocked", {
            "trace_id": trace.trace_id,
            "source": "perception",
        })
        return {
            "response": "检测到系统感知数据中的可疑指令，已阻断本轮推理。",
            "commands": [],
            "risk_awareness": "INDIRECT_INJECTION_BLOCKED",
            "input_security": ctx.get("input_security", {}),
            "session_id": sid,
            "trace_id": trace.trace_id,
        }

    classification = classifier.classify(cleaned, _ctx=ctx)
    trail.route(classification["mode"], classification.get("trigger", ""))
    agentic_triggers = (
        "排查", "诊断", "为什么", "根因", "检查系统", "系统健康",
        "investigate", "diagnose", "root cause",
    )
    use_agentic = any(item in cleaned.lower() for item in agentic_triggers)
    use_agentic = (use_agentic or classification["mode"] == "emergency") and not req.session_id
    if use_agentic:
        from agent.loop import run_agentic_loop
        return run_agentic_loop(
            reasoner=reasoner,
            guardrail=guardrail,
            posture_engine=posture_engine,
            session_store=session_store,
            sid=sid,
            user_id=user_id,
            role=role,
            trail=trail,
            initial_ctx=ctx,
            logger_instance=logger,
            execution_gateway=execution_gateway,
            capability_token_service=capability_token_service,
            trace_id=trace.trace_id,
        )

    ctx["posture_info"] = posture_engine.posture_for_prompt()
    llm_result = reasoner.reason(ctx)
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
        return {
            "response": f"安全策略已阻止操作。原因: {gr.blocked_at}",
            "diagnosis": llm_result.get("diagnosis", ""),
            "commands": gr.command_results,
            "risk_awareness": "VETOED",
            "session_id": sid,
            "trace_id": trace.trace_id,
        }

    needs_confirm = [item for item in gr.command_results if item.get("requires_confirmation")]
    if needs_confirm:
        pending_ids = []
        for item in needs_confirm:
            event_id, pending = build_pending_entry(
                item, user_id, role, posture_engine.posture, source="chat"
            )
            _pending_confirmations.add(event_id, pending)
            pending_ids.append(event_id)
        trail.chain_close("confirmation_required", {"pending_ids": pending_ids})
        return {
            "response": "以下操作需要确认:\n" + "\n".join(
                f"- {item['display_command']} (风险: {item['risk_label']}) [ID: {event_id}]"
                for item, event_id in zip(needs_confirm, pending_ids)
            ),
            "diagnosis": llm_result.get("diagnosis", ""),
            "commands": gr.command_results,
            "risk_awareness": "CONFIRMATION_REQUIRED",
            "requires_confirmation": True,
            "pending_event_ids": pending_ids,
            "session_id": sid,
            "trace_id": trace.trace_id,
        }

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

    response_text = llm_result.get("explanation", "")
    output_lines = [
        f"[{item['command']}] exit={item['exit_code']}\n{item['stdout'][:400]}".rstrip()
        for item in executed
    ]
    if output_lines:
        response_text += "\n\n执行结果:\n" + "\n".join(output_lines)
    if ipi_blocked:
        response_text = "检测到工具输出中的可疑指令，原始内容已阻断。"

    session_store.add_turn(sid, "user", cleaned)
    session_store.add_turn(sid, "agent", response_text[:800])
    risk_awareness = (
        "INDIRECT_INJECTION_BLOCKED"
        if ipi_blocked
        else llm_result.get("risk_awareness", "Unknown")
    )
    trail.chain_close("completed", {"executed": len(executed), "ipi_blocked": ipi_blocked})
    trace.end_span({"result": risk_awareness})
    return {
        "response": response_text,
        "diagnosis": llm_result.get("diagnosis", ""),
        "commands": gr.command_results,
        "executed": executed,
        "risk_awareness": risk_awareness,
        "posture": posture_engine.posture,
        "session_id": sid,
        "trace_id": trace.trace_id,
    }
