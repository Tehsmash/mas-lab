#  Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#  SPDX-License-Identifier: Apache-2.0
"""Apply operator HITL resolution — M_gov ingress only (HitlResolve* in TLA)."""

from __future__ import annotations

from collections.abc import Callable

from mas.runtime.kernel.config import KernelConfig
from mas.runtime.kernel.egress_gate import emit_scheduled_egress
from mas.runtime.kernel.ingress_step import commit_engine_io_return
from mas.runtime.kernel.state import (
    CtxState,
    DpState,
    LifecycleState,
    MemoryState,
    ModelState,
    QProduct,
    RunLedger,
    SessionState,
    TransportState,
)
from mas.runtime.machines.gov import gov_clear_hitl, gov_is_hitl_pending, gov_on_hitl_schedule
from mas.runtime.machines.tool import tool_on_abort
from mas.runtime.schema.egress import EgressSymbol, NoOp
from mas.runtime.schema.hitl import HitlResolveChoice
from mas.runtime.schema.ingress import EngineIoReturn, HitlResolve


def _clear_ingress_hitl(q: QProduct) -> None:
    q.hitl_pending_ingress = ""
    q.pending_ingress_return = {}
    gov_clear_hitl(q)


def _operator_tool_text(*, blocked: bool, tool_ran: bool, tool_name: str, steering: object) -> str:
    if not blocked and steering:
        return steering if isinstance(steering, str) else str(steering)
    verb = "blocked" if blocked else "skipped"
    if tool_ran:
        return f"Operator {verb} tool result for '{tool_name}' via HITL."
    return f"Operator {verb} tool '{tool_name}' via HITL."


def _resolve_ingress_hitl(
    q: QProduct,
    run: RunLedger,
    event: HitlResolve,
    *,
    config: KernelConfig,
    evaluate: Callable,
) -> list[EgressSymbol]:
    pending = EngineIoReturn.model_validate(dict(q.pending_ingress_return))
    resolution = event.resolution
    steering = event.operator_context.get("steering") or event.operator_context.get("message")

    if resolution in {HitlResolveChoice.ALLOW, HitlResolveChoice.SCHEDULE}:
        q.hitl_results_approved_turn = True
        _clear_ingress_hitl(q)
        return commit_engine_io_return(
            q,
            run,
            pending,
            config=config,
            evaluate=evaluate,
        )

    tool_name = q.pending_tool_name or "tool"
    if resolution == HitlResolveChoice.BLOCK:
        text = _operator_tool_text(blocked=True, tool_ran=True, tool_name=tool_name, steering=steering)
    elif resolution == HitlResolveChoice.SKIP:
        text = _operator_tool_text(blocked=False, tool_ran=True, tool_name=tool_name, steering=steering)
    else:
        return [NoOp()]

    if pending.response_kind == "TOOL_RESULT":
        modified = pending.model_copy(update={"text": text, "next_step": "LLM_CALL"})
    else:
        modified = pending.model_copy(update={"text": text, "response_kind": "MODEL_TEXT", "next_step": "STOP"})
    _clear_ingress_hitl(q)
    return commit_engine_io_return(
        q,
        run,
        modified,
        config=config,
        evaluate=evaluate,
    )


def apply_hitl_resolve(
    q: QProduct,
    run: RunLedger,
    event: HitlResolve,
    *,
    config: KernelConfig,
    evaluate: Callable | None = None,
) -> list[EgressSymbol]:
    """Governance resolves HITL; DP stays AWAITING_INGRESS (waiting on tool chain)."""
    if not gov_is_hitl_pending(q):
        return [NoOp()]
    if event.request_id != q.hitl_request_id:
        return [NoOp()]

    if q.hitl_pending_ingress:
        if evaluate is None:
            return [NoOp()]
        return _resolve_ingress_hitl(q, run, event, config=config, evaluate=evaluate)

    resolution = event.resolution
    pending = q.hitl_pending_schedule

    if resolution in {HitlResolveChoice.ALLOW, HitlResolveChoice.SCHEDULE} and pending != "NONE":
        q.scheduled_egress = pending
        q.hitl_gov_override = True
        if pending == "TOOL_CALL":
            q.hitl_tools_approved_turn = True
        gov_clear_hitl(q)
        gov_on_hitl_schedule(q)
        return emit_scheduled_egress(q, run, config)

    if resolution == HitlResolveChoice.TERMINATE:
        q.ctrl = LifecycleState.STOPPED
        q.dp = DpState.IDLE
        q.ctx = CtxState.IDLE
        q.scheduled_egress = "NONE"
        q.inflight_kind = "NONE"
        q.model = ModelState.IDLE
        q.tool = tool_on_abort(q.tool)
        q.memory = MemoryState.IDLE
        q.transport = TransportState.IDLE
        q.session = SessionState.IDLE
        gov_clear_hitl(q)
        return [NoOp()]

    if resolution in {HitlResolveChoice.BLOCK, HitlResolveChoice.SKIP}:
        q.scheduled_egress = "NONE"
        q.inflight_kind = "NONE"
        q.tool = tool_on_abort(q.tool)
        gov_clear_hitl(q)
        steering = event.operator_context.get("steering") or event.operator_context.get("message")
        tool_name = q.pending_tool_name or "tool"
        blocked = resolution == HitlResolveChoice.BLOCK
        if blocked:
            q.hitl_block_committed = True
        else:
            q.hitl_skip_committed = True
        result_msg = _operator_tool_text(
            blocked=blocked,
            tool_ran=False,
            tool_name=tool_name,
            steering=steering,
        )
        run.append_placeholder(text=result_msg, next_step="LLM_CALL")
        q.scheduled_egress = "LLM_CALL"
        q.dp = DpState.EGRESS_PENDING
        return emit_scheduled_egress(q, run, config)

    return [NoOp()]
