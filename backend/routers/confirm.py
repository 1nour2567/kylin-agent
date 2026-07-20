"""Confirmation endpoint: atomic approval -> TOCTOU -> issue -> verify/consume -> execute."""
import os
import subprocess

from fastapi import APIRouter, Request
from pydantic import BaseModel

from audit.trail import AuditTrail
from deps import (
    _pending_confirmations,
    capability_token_service,
    cleanup_pending,
    execution_gateway,
    logger,
)
from security.capability_token import CapabilityScope, canonicalize_params
from security.constraints import ConstraintEngine
from security.idempotency import get_idempotency_guard
from security.sandbox import snapshot_before_write


router = APIRouter()


class ConfirmRequest(BaseModel):
    event_id: str
    confirmed: bool
    idempotency_key: str = ""


@router.post("/api/confirm")
async def confirm(request: Request, req: ConfirmRequest):
    cleanup_pending()
    user_id = getattr(request.state, "user_id", "anonymous")
    role = getattr(request.state, "role", "viewer")
    trail = AuditTrail(user_id, role=role)

    if role == "viewer":
        return {
            "status": "denied",
            "event_id": req.event_id,
            "message": "Viewer role cannot execute write operations. Request an operator or admin.",
        }

    # 1-2. Read pending and validate the server-authenticated owner.
    pending = _pending_confirmations.get(req.event_id)
    if not pending:
        trail.chain_close("pending_not_found", {"attempted_event_id": req.event_id})
        return {"status": "not_found", "message": f"No pending confirmation for {req.event_id}"}
    pending_user = str(pending.get("user_id") or "")
    if pending_user and user_id != pending_user and role != "admin":
        trail.chain_close("unauthorized_confirm_attempt", {
            "attempted_event_id": req.event_id,
            "owner": pending_user,
        })
        return {
            "status": "denied",
            "event_id": req.event_id,
            "message": f"This confirmation belongs to user '{pending_user}', not '{user_id}'.",
        }

    if not req.confirmed:
        if not _pending_confirmations.compare_and_pop(req.event_id, pending_user):
            return {"status": "already_consumed", "message": "This confirmation was already processed."}
        trail.chain_close("denied_by_user", {"event_id": req.event_id})
        return {"status": "denied", "event_id": req.event_id, "message": "Command execution denied by user"}

    # 3. Atomic event consumption comes before all execution work.
    if not _pending_confirmations.compare_and_pop(req.event_id, pending_user):
        trail.chain_close("already_consumed", {"attempted_event_id": req.event_id})
        return {"status": "already_consumed", "message": "This confirmation was already processed."}

    tool_name = str(pending.get("tool_name") or pending.get("command") or "")
    params = dict(pending.get("params") or {})
    saved_scope_value = pending.get("capability_scope")
    if not saved_scope_value:
        trail.security_event("capability_rejected", {
            "event_id": req.event_id,
            "tool": tool_name,
            "reason": "pending_scope_missing",
        })
        return {"status": "capability_rejected", "message": "Pending capability scope is missing"}

    # 4. Existing idempotency protection.
    idem_guard = None
    if req.idempotency_key:
        idem_guard = get_idempotency_guard()
        duplicate = idem_guard.check_or_record(req.idempotency_key, tool_name)
        if duplicate and duplicate.executed:
            trail.chain_close("idempotency_blocked", {"event_id": req.event_id})
            return {
                "status": "idempotency_blocked",
                "event_id": req.event_id,
                "message": "This operation was already executed. Duplicate confirmation blocked.",
                "original_result": duplicate.result,
            }

    # 5. Existing path/file/PID TOCTOU checks.
    file_path = str(params.get("path") or pending.get("file_path") or "")
    if file_path:
        abs_path = os.path.realpath(os.path.abspath(os.path.expanduser(file_path)))
        engine = ConstraintEngine()
        path_check = engine.check_file_path(abs_path)
        if path_check and not path_check.allowed:
            trail.chain_close("toctou_blocked", {"reason": path_check.reason, "event_id": req.event_id})
            return {"status": "toctou_blocked", "message": path_check.reason}
        critical = engine.check_critical_file(abs_path)
        if critical and critical.risk_score >= 7:
            trail.chain_close("toctou_blocked", {
                "reason": critical.reason,
                "risk_score": critical.risk_score,
                "event_id": req.event_id,
            })
            return {"status": "toctou_blocked", "message": f"Target is now critical: {critical.reason}"}
        snapshot_id = snapshot_before_write(abs_path, pending.get("operation", "write"))
        if snapshot_id:
            trail.security_event("snapshot_created", {
                "event_id": req.event_id,
                "snapshot_id": snapshot_id,
                "file_path": abs_path,
            })

    pid = params.get("pid")
    if pid and tool_name == "kill_process":
        try:
            exists = subprocess.run(
                ["ps", "-p", str(pid), "-o", "pid="],
                capture_output=True, text=True, timeout=5,
            )
            if not exists.stdout.strip():
                return {"status": "toctou_blocked", "message": f"Target PID {pid} no longer exists"}
            current = subprocess.run(
                ["ps", "-p", str(pid), "-o", "comm="],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()
            expected = str(pending.get("comm") or pending.get("target_fingerprint", {}).get("comm") or "")
            if expected and current and expected != current:
                return {
                    "status": "toctou_blocked",
                    "message": f"PID {pid} was reused; operation aborted",
                }
        except Exception:
            pass

    # 6-7. Rebuild the expected scope from canonical tool/params and compare it
    # to the immutable task context captured by T2.
    try:
        canonical_tool, canonical_params = canonicalize_params(tool_name, params)
        saved_scope = CapabilityScope.from_dict(saved_scope_value)
        scope_actor = {"user_id": pending_user, "role": pending.get("role", "operator")}
        rebuilt_scope = capability_token_service.build_scope(
            canonical_tool,
            canonical_params,
            scope_actor,
            trace_id=str(pending.get("trace_id") or ""),
            operation_id=str(pending.get("operation_id") or ""),
            event_id=req.event_id,
        )
        if not capability_token_service.scopes_match(saved_scope, rebuilt_scope):
            trail.security_event("capability_rejected", {
                "event_id": req.event_id,
                "tool": canonical_tool,
                "reason": "pending_scope_mismatch",
            })
            return {"status": "capability_rejected", "message": "Tool or parameters changed after validation"}
    except Exception as exc:
        trail.security_event("capability_rejected", {
            "event_id": req.event_id,
            "tool": tool_name,
            "reason": "scope_rebuild_failed",
        })
        return {"status": "capability_rejected", "message": f"Capability validation failed: {exc}"}

    # 8-11. Only now issue a short-lived token; the gateway immediately verifies
    # and consumes it before restricted execution.
    token = capability_token_service.issue(rebuilt_scope)
    execution_actor = {
        **scope_actor,
        "trace_id": rebuilt_scope.trace_id,
        "approved_by": user_id,
    }
    execution = execution_gateway.execute_tool(
        canonical_tool,
        canonical_params,
        execution_actor,
        capability_token=token,
        expected_scope=rebuilt_scope,
        timeout=30,
    )
    logger.info(
        "confirm_exec user=%s tool=%s event=%s exit=%s capability=%s",
        user_id,
        canonical_tool,
        req.event_id,
        execution.exit_code,
        execution.capability_verification.get("reason", ""),
    )
    trail.execute(
        execution.command,
        execution.exit_code,
        execution.sanitized_stdout,
        execution.sanitized_stderr,
    )
    result = {
        "status": "executed" if execution.exit_code == 0 else "execution_failed",
        "event_id": req.event_id,
        "command": execution.command,
        "exit_code": execution.exit_code,
        "stdout": execution.sanitized_stdout[:2000],
        "stderr": execution.sanitized_stderr[:500],
        "trace_id": rebuilt_scope.trace_id,
        "capability_verification": execution.capability_verification,
        "output_security": execution.output_security,
    }
    if execution.blocked_by_ipi:
        result["risk_awareness"] = "INDIRECT_INJECTION_BLOCKED"
    if idem_guard and req.idempotency_key:
        idem_guard.mark_executed(req.idempotency_key, result)
    return result


@router.get("/api/pending")
async def list_pending(request: Request, user_id: str = ""):
    cleanup_pending()
    verified_user = getattr(request.state, "user_id", "anonymous")
    role = getattr(request.state, "role", "viewer")
    effective_user = user_id if role == "admin" and user_id else verified_user
    items = _pending_confirmations.items_for_user(effective_user)
    return {"pending": items, "count": len(items)}
