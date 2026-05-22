"""POST /api/chat/stream — SSE streaming variant of the chat pipeline.

Sends Server-Sent Events:
  token       — LLM text chunk (one per token group)
  commands    — parsed tool commands with security validation results
  confirm     — confirmation required with pending event IDs
  done        — final result, execution output
  error       — error message
"""
import json
import time
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from deps import (
    perception, classifier, reasoner, posture_engine, guardrail,
    session_store,
    _pending_confirmations, logger, limiter,
)
from security.sandbox import execute, execute_restricted, resolve_cmd
from agent.tools_manifest import exec_tier_for_resolved_cmd
from audit.trail import AuditTrail

router = APIRouter()


class StreamChatRequest(BaseModel):
    user_id: str = "default"
    input: str = Field(default="", max_length=12000)
    session_id: Optional[str] = None


def _sse(event: str, data) -> str:
    payload = json.dumps(data, ensure_ascii=False)
    return f"event: {event}\ndata: {payload}\n\n"


@router.post("/api/chat/stream")
@limiter.limit("10/minute")
async def chat_stream(request: Request, req: StreamChatRequest):
    user_id = getattr(request.state, "user_id", req.user_id)
    role = getattr(request.state, "role", "viewer")
    key_id = getattr(request.state, "key_id", "")

    import secrets as _secrets
    sid = req.session_id or f"ses_{user_id}" + ("_" + _secrets.token_hex(4) if user_id == "default" else "")
    session = session_store.get_or_create(sid, user_id)

    trail = AuditTrail(user_id)

    # ── T0: Anti-injection ──
    trail.receive(req.input)
    ok, cleaned, ref = guardrail.validate_input(req.input)
    if not ok:
        logger.warning(f"T0 injection blocked user={user_id} ref={ref}")
        trail.chain_close("rejected", {"reason": "injection_detected", "ref": ref})

        async def sse_rejected():
            yield _sse("error", {"message": f"输入被安全策略拒绝 [{ref}]"})
            yield _sse("done", {"risk_awareness": "REJECTED"})
        return StreamingResponse(sse_rejected(), media_type="text/event-stream")

    # ── T1: Perception ──
    conversation_history = session_store.get_history(sid)
    ctx = perception.build(cleaned, user_id, role=role, key_id=key_id,
                           conversation_history=conversation_history)
    trail.perceive(ctx)

    # ── T2: Classifier ──
    classification = classifier.classify(cleaned, _ctx=ctx)
    trail.route(classification["mode"], classification.get("trigger", ""))

    # ── T3: Streaming reasoner ──
    posture_info = posture_engine.posture_for_prompt()
    ctx["posture_info"] = posture_info

    posture_text = posture_info.get("text", "") if isinstance(posture_info, dict) else posture_info

    async def sse_pipeline():
        full_text = ""
        llm_result = None
        generator = None
        try:
            generator = reasoner.reason_stream(ctx)
            for event_type, data in generator:
                if event_type == "token":
                    full_text += data
                    yield _sse("token", {"text": data})
                elif event_type == "error":
                    yield _sse("error", {"message": data})
                    yield _sse("done", {"risk_awareness": "Error"})
                    return
                elif event_type == "result":
                    llm_result = data
        except GeneratorExit:
            # Client disconnected mid-stream — close the generator to allow cleanup
            if generator is not None:
                generator.close()
            return
        except Exception as e:
            yield _sse("error", {"message": str(e)})
            yield _sse("done", {"risk_awareness": "Error"})
            return

        if llm_result is None:
            return

        commands = llm_result.get("commands", [])
        trail.reason(json.dumps(llm_result, ensure_ascii=False)[:2000], commands)

        # ── T4: Security Validation ──
        guardrail.posture = posture_engine.posture
        gr = guardrail.validate_commands(commands, role=role)
        trail.validate(gr.command_results)

        if not gr.passed:
            logger.warning(f"T2 veto user={user_id} reason={gr.blocked_at}")
            posture_engine.on_veto()
            trail.chain_close("vetoed", {"blocked_at": gr.blocked_at, "posture": posture_engine.posture})

            session_store.add_turn(sid, "user", req.input)
            session_store.add_turn(sid, "agent", f"安全策略已阻止操作。原因: {gr.blocked_at}")

            yield _sse("error", {"message": f"安全策略已阻止操作。原因: {gr.blocked_at}"})
            yield _sse("done", {"risk_awareness": "VETOED", "session_id": sid})
            return

        yield _sse("commands", {"commands": gr.command_results, "diagnosis": llm_result.get("diagnosis", "")})

        # Confirmation required?
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
            session_store.add_turn(sid, "agent", f"以下操作需要确认: {', '.join(c['command'] for c in needs_confirm)}")

            yield _sse("confirm", {
                "response": llm_result.get("explanation", ""),
                "diagnosis": llm_result.get("diagnosis", ""),
                "pending_event_ids": pending_ids,
                "commands": gr.command_results,
            })
            yield _sse("done", {"risk_awareness": "CONFIRMATION_REQUIRED", "session_id": sid})
            return

        # ── T5: Execution ──
        posture_engine.on_permit()
        executed = []
        for cmd in commands:
            cmd_str = cmd.get("command", cmd.get("tool", ""))
            params = cmd.get("params", {})
            display_cmd = f"{cmd_str} {' '.join(f'{k}={v}' for k, v in params.items())}"
            if cmd_str in ("create_file", "append_file", "execute_script"):
                params_str = " ".join(f"{k}={v}" for k, v in params.items())
                full_cmd = f"{cmd_str} {params_str}"
            else:
                full_cmd = resolve_cmd(display_cmd)
            tier = exec_tier_for_resolved_cmd(full_cmd)
            if tier == "confirm":
                exit_code, stdout, stderr = execute_restricted(full_cmd, timeout=30)
            else:
                exit_code, stdout, stderr = execute(full_cmd, timeout=30)
            trail.execute(full_cmd, exit_code, stdout, stderr)
            executed.append({"command": full_cmd, "exit_code": exit_code, "stdout": stdout[:1000]})

        trail.chain_close("completed", {"exit_code": executed[-1]["exit_code"] if executed else -1})

        response_text = llm_result.get("explanation", "")
        session_store.add_turn(sid, "user", req.input)
        session_store.add_turn(sid, "agent", response_text[:500])

        yield _sse("done", {
            "response": response_text,
            "diagnosis": llm_result.get("diagnosis", ""),
            "commands": gr.command_results,
            "executed": executed,
            "risk_awareness": llm_result.get("risk_awareness", "Low"),
            "posture": posture_engine.posture,
            "session_id": sid,
        })

    return StreamingResponse(sse_pipeline(), media_type="text/event-stream")
