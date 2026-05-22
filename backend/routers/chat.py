"""POST /api/chat — main pipeline endpoint."""
import json
import time
from typing import Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from deps import (
    perception, classifier, reasoner, posture_engine, guardrail,
    session_store,
    _pending_confirmations, _pending_lock, cleanup_pending, logger, limiter,
)
from security.sandbox import execute, execute_restricted, resolve_cmd
from agent.tools_manifest import exec_tier_for_resolved_cmd
from audit.trail import AuditTrail

chat_router = APIRouter()


class ChatRequest(BaseModel):
    user_id: str = "default"
    input: str = Field(default="", max_length=12000)
    session_id: Optional[str] = None
    session_id: Optional[str] = None


@chat_router.post("/api/chat")
@limiter.limit("10/minute")
async def chat(request: Request, req: ChatRequest):
    # Server-verified identity from auth middleware
    user_id = getattr(request.state, "user_id", req.user_id)
    role = getattr(request.state, "role", "viewer")
    key_id = getattr(request.state, "key_id", "")

    # Session management — generate unique ID for anonymous users to avoid cross-user collision
    import secrets as _secrets
    sid = req.session_id or f"ses_{user_id}" + ("_" + _secrets.token_hex(4) if user_id == "default" else "")
    session = session_store.get_or_create(sid, user_id)

    trail = AuditTrail(user_id)

    # ── Stage 0: Anti-injection ──
    trail.receive(req.input)
    ok, cleaned, ref = guardrail.validate_input(req.input)
    if not ok:
        logger.warning(f"T0 injection blocked user={user_id} ref={ref} input={req.input[:80]}")
        trail.chain_close("rejected", {"reason": "injection_detected", "ref": ref})
        return {"response": f"输入被安全策略拒绝 [{ref}]", "commands": [], "risk_awareness": "REJECTED"}

    # ── Stage 1: Perception ──
    conversation_history = session_store.get_history(sid)
    ctx = perception.build(cleaned, user_id, role=role, key_id=key_id,
                           conversation_history=conversation_history)
    trail.perceive(ctx)

    # ── Stage 2: Classifier (LLM-based with rule fallback) ──
    classification = classifier.classify(cleaned, _ctx=ctx)
    trail.route(classification["mode"], classification.get("trigger", ""))

    # ── Check if agentic loop mode ──
    agentic_triggers = ("排查", "诊断", "为什么不", "为什么不能", "什么原因",
                        "查一下", "帮我查", "检查一下", "帮我看看系统",
                        "检查系统", "系统健康", "全面检查", "帮我排查")
    use_agentic = any(t in cleaned for t in agentic_triggers) or classification["mode"] == "emergency"
    use_agentic = use_agentic and not req.session_id  # honor explicit session_id

    if use_agentic:
        from agent.loop import run_agentic_loop
        logger.info(f"Agentic loop mode triggered for user={user_id}")
        result = run_agentic_loop(
            reasoner=reasoner, guardrail=guardrail,
            posture_engine=posture_engine, session_store=session_store,
            sid=sid, user_id=user_id, role=role,
            trail=trail, initial_ctx=ctx, logger_instance=logger,
        )
        return result

    # ── Stage 3: Reasoner (single-turn) ──
    posture_info = posture_engine.posture_for_prompt()
    ctx["posture_info"] = posture_info
    llm_result = reasoner.reason(ctx)
    commands = llm_result.get("commands", [])
    trail.reason(json.dumps(llm_result, ensure_ascii=False)[:2000], commands)

    # ── Stage 4: Security Validation ──
    guardrail.posture = posture_engine.posture
    intent_profile = llm_result.get("intent_profile", {})
    gr = guardrail.validate_commands(commands, role=role,
                                     intent_profile=intent_profile)
    trail.validate(gr.command_results)

    if not gr.passed:
        logger.warning(f"T2 veto user={user_id} reason={gr.blocked_at} posture={posture_engine.posture}")
        posture_engine.on_veto()
        trail.chain_close("vetoed", {
            "blocked_at": gr.blocked_at,
            "alternative": gr.command_results[-1].get("alternative", ""),
            "posture": posture_engine.posture,
        })
        session_store.add_turn(sid, "user", req.input)
        session_store.add_turn(sid, "agent",
            f"安全策略已阻止操作。原因: {gr.blocked_at}")
        return {
            "response": f"安全策略已阻止操作。\n原因: {gr.blocked_at}\n建议: {gr.command_results[-1].get('alternative', '请调整操作')}",
            "diagnosis": llm_result.get("diagnosis", ""),
            "commands": gr.command_results,
            "risk_awareness": "VETOED",
            "session_id": sid,
        }

    # ── Check if any command needs user confirmation ──
    needs_confirm = [c for c in gr.command_results if c.get("requires_confirmation")]
    if needs_confirm:
        pending_ids = []
        for c in needs_confirm:
            eid = f"evt_{int(time.time() * 1_000_000)}_{id(c) % 10000}"
            _pending_confirmations.add(eid, {
                "command": c["command"],
                "display_command": c.get("display_command", c["command"]),
                "risk_label": c.get("risk_label", "?"),
                "user_id": user_id,
                "role": role,
                "created_at": time.time(),
                "posture": posture_engine.posture,
            })
            pending_ids.append(eid)
        trail.chain_close("confirmation_required", {"pending_ids": pending_ids})
        session_store.add_turn(sid, "user", req.input)
        session_store.add_turn(sid, "agent",
            f"以下操作需要确认: " + ", ".join(
                f"{c['command']} (风险: {c['risk_label']})" for c in needs_confirm))
        return {
            "response": f"以下操作需要确认:\n" + "\n".join(
                f"- {c['command']} (风险: {c['risk_label']}) [ID: {eid}]"
                for c, eid in zip(needs_confirm, pending_ids)
            ),
            "diagnosis": llm_result.get("diagnosis", ""),
            "commands": gr.command_results,
            "risk_awareness": "CONFIRMATION_REQUIRED",
            "requires_confirmation": True,
            "pending_event_ids": pending_ids,
            "session_id": sid,
        }

    # ── Stage 5: Tiered Execution ──
    posture_engine.on_permit()
    executed = []
    for cmd in commands:
        cmd_str = cmd.get("command", cmd.get("tool", ""))
        params = cmd.get("params", {})
        display_cmd = f"{cmd_str} {' '.join(f'{k}={v}' for k, v in params.items())}"

        # File/shell tools: pass raw params directly (resolve_cmd can't handle multi-word content)
        if cmd_str in ("create_file", "append_file", "execute_script"):
            params_str = " ".join(f"{k}={v}" for k, v in params.items())
            full_cmd = f"{cmd_str} {params_str}"
        else:
            full_cmd = resolve_cmd(display_cmd)

        tier = exec_tier_for_resolved_cmd(full_cmd)
        if tier == "confirm":
            exit_code, stdout, stderr = execute_restricted(full_cmd, timeout=30)
            logger.info(f"exec_restricted user={user_id} cmd={full_cmd} exit={exit_code}")
        else:
            exit_code, stdout, stderr = execute(full_cmd, timeout=30)
        trail.execute(full_cmd, exit_code, stdout, stderr)
        executed.append({"command": full_cmd, "exit_code": exit_code, "stdout": stdout[:1000]})

    trail.chain_close("completed", {"exit_code": executed[-1]["exit_code"] if executed else -1})

    # Always show execution results to the user
    stdout_lines = []
    for ex in executed:
        out = ex.get("stdout", "").strip()
        if out:
            stdout_lines.append(f"  [{ex['command']}] exit={ex['exit_code']}\n{out[:400]}")
        else:
            stdout_lines.append(f"  [{ex['command']}] exit={ex['exit_code']}")
    stdout_block = "\n".join(stdout_lines) if stdout_lines else ""
    response_text = llm_result.get("explanation", "")
    if stdout_block:
        response_text += f"\n\n执行结果:\n{stdout_block}"

    # Record conversation turn
    session_store.add_turn(sid, "user", req.input)
    session_store.add_turn(sid, "agent", response_text[:800])

    return {
        "response": response_text,
        "diagnosis": llm_result.get("diagnosis", ""),
        "commands": gr.command_results,
        "executed": executed,
        "risk_awareness": llm_result.get("risk_awareness", "Unknown"),
        "posture": posture_engine.posture,
        "session_id": sid,
    }
