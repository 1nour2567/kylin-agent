"""Agentic loop — multi-turn reason → act → observe → reason.

Transforms the single-turn chatbot pipeline into a proper AI Agent:
  User input → Reasoner → Execute → Observe → Reasoner → ... → Done

Max iterations: 5 (prevents infinite loops).
Each iteration runs full T0-T3 pipeline.
Execution results feed back into the next round's context.
"""
import json
import time
import logging
from typing import Optional

from agent.tools_manifest import exec_tier_for_resolved_cmd
from security.sandbox import execute, execute_restricted, resolve_cmd

logger = logging.getLogger("kylin-agent")

MAX_ITERATIONS = 3
LOOP_SYSTEM_HINT = (
    "\n\n## 多轮执行模式"
    "\n这是第 {round} 轮。你可以在多轮中逐步诊断问题。"
    "\n当你有足够信息给出结论时，设置 done: true 并给出最终解释。"
    "\n避免重复执行相同的诊断命令——如果数据没变，不需要再查一遍。"
)


def run_agentic_loop(
    reasoner,
    guardrail,
    posture_engine,
    session_store,
    sid: str,
    user_id: str,
    role: str,
    trail,
    initial_ctx: dict,
    logger_instance,
) -> dict:
    """Run the agentic loop: reason→validate→execute→observe→repeat.

    Returns the final response dict with accumulated history.
    """
    ctx = dict(initial_ctx)
    all_commands = []
    all_executed = []
    all_diagnoses = []
    final_explanation = ""
    final_risk = "Low"
    iteration = 0

    while iteration < MAX_ITERATIONS:
        iteration += 1

        # ── Update posture ──
        posture_info = posture_engine.posture_for_prompt()
        ctx["posture_info"] = posture_info

        # ── Inject round hint into context ──
        ctx["agentic_loop_round"] = iteration
        ctx["loop_hint"] = LOOP_SYSTEM_HINT.format(round=iteration)

        # ── Reasoner ──
        llm_result = reasoner.reason(ctx)
        commands = llm_result.get("commands", [])
        done = llm_result.get("done", len(commands) == 0)
        diagnosis = llm_result.get("diagnosis", "")
        explanation = llm_result.get("explanation", "")

        all_diagnoses.append(f"[R{iteration}] {diagnosis}")
        trail.reason(json.dumps(llm_result, ensure_ascii=False)[:2000], commands)

        # ── If done with no commands, break ──
        if done and not commands:
            final_explanation = explanation
            final_risk = llm_result.get("risk_awareness", "Low")
            break

        # ── If no commands but not done, treat as done ──
        if not commands:
            final_explanation = explanation
            final_risk = llm_result.get("risk_awareness", "Low")
            break

        # ── Security validation ──
        guardrail.posture = posture_engine.posture
        gr = guardrail.validate_commands(commands, role=role)
        trail.validate(gr.command_results)

        if not gr.passed:
            logger_instance.warning(
                f"Agentic loop veto at iteration {iteration}: {gr.blocked_at}"
            )
            posture_engine.on_veto()
            trail.chain_close("vetoed", {
                "blocked_at": gr.blocked_at,
                "posture": posture_engine.posture,
                "iteration": iteration,
            })
            return {
                "response": f"安全策略已阻止操作 (第{iteration}轮)。\n原因: {gr.blocked_at}",
                "diagnosis": "\n".join(all_diagnoses),
                "commands": gr.command_results,
                "risk_awareness": "VETOED",
                "iterations": iteration,
                "loop_ended": "vetoed",
            }

        # ── Track commands ──
        all_commands.extend(gr.command_results)

        # ── Check confirmation ──
        needs_confirm = [c for c in gr.command_results if c.get("requires_confirmation")]
        if needs_confirm:
            pending_ids = []
            from deps import _pending_confirmations
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
            trail.chain_close("confirmation_required", {"pending_ids": pending_ids, "iteration": iteration})
            session_store.add_turn(sid, "user", ctx.get("user_input", ""))
            session_store.add_turn(sid, "agent", f"需要确认: {', '.join(c['command'][:50] for c in needs_confirm)}")
            return {
                "response": f"第{iteration}轮操作需要确认:\n" + "\n".join(
                    f"- {c['command']} (风险: {c['risk_label']}) [ID: {eid}]"
                    for c, eid in zip(needs_confirm, pending_ids)
                ),
                "diagnosis": "\n".join(all_diagnoses),
                "commands": gr.command_results,
                "risk_awareness": "CONFIRMATION_REQUIRED",
                "requires_confirmation": True,
                "pending_event_ids": pending_ids,
                "iterations": iteration,
                "loop_ended": "confirmation_required",
            }

        # ── Execute ──
        posture_engine.on_permit()
        round_executed = []
        observe_lines = []
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
            round_executed.append({"command": full_cmd, "exit_code": exit_code,
                                   "stdout": stdout[:1000]})
            observe_lines.append(
                f"[{full_cmd}] exit={exit_code}"
                + (f"\n{stdout[:300]}" if stdout.strip() else "")
            )
        all_executed.extend(round_executed)

        # ── Feed observation back to context ──
        observation = "\n".join(observe_lines)
        # Append observation as a new "user" message for the next round
        prev_input = ctx.get("user_input", "")
        ctx["user_input"] = (
            f"上一轮操作结果:\n{observation}\n\n请继续分析或确认完成。"
            f"{'如果任务已完成，设置 done: true。' if done else ''}"
        )
        # Append previous round to conversation history
        round_history = session_store.get_history(sid)
        round_history.append({"role": "agent", "content": explanation[:300],
                              "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")})
        round_history.append({"role": "system", "content": f"执行结果: {observation[:500]}",
                              "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")})
        ctx["conversation_history"] = round_history[-10:]

        # Update the loop hint in system prompt context
        ctx["agentic_loop_round"] = iteration

        if done and iteration < MAX_ITERATIONS:
            final_explanation = explanation
            final_risk = llm_result.get("risk_awareness", "Low")
            break

    # ── Build final response ──
    trail.chain_close("completed", {"iterations": iteration,
                      "total_executed": len(all_executed)})

    stdout_lines = []
    for ex in all_executed[-8:]:  # last 8 commands
        out = ex.get("stdout", "").strip()
        if out:
            stdout_lines.append(f"  [{ex['command'][:60]}] exit={ex['exit_code']}\n{out[:200]}")
        else:
            stdout_lines.append(f"  [{ex['command'][:60]}] exit={ex['exit_code']}")
    stdout_block = "\n".join(stdout_lines) if stdout_lines else ""

    response_text = final_explanation or llm_result.get("explanation", "") if 'llm_result' in dir() else ""
    if stdout_block:
        response_text += f"\n\n执行结果 ({iteration}轮, {len(all_executed)}条命令):\n{stdout_block}"

    session_store.add_turn(sid, "user", initial_ctx.get("user_input", ""))
    session_store.add_turn(sid, "agent", response_text[:500])

    return {
        "response": response_text,
        "diagnosis": "\n".join(all_diagnoses),
        "commands": all_commands,
        "executed": all_executed,
        "risk_awareness": final_risk,
        "posture": posture_engine.posture,
        "session_id": sid,
        "iterations": iteration,
        "loop_ended": "completed" if iteration < MAX_ITERATIONS else "max_iterations",
    }
