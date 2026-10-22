import pathlib

ADDITIONS = '''

# FRIDAY Integration & Delegation Endpoints

from datetime import UTC, datetime as _dt_fri
from sentinel.integrations.friday.models import (
    BlockedActionRecord,
    FridayDelegationRequest,
    FridayDelegationResponse,
    FridayResultPayload,
    FridaySummarizer,
)

_delegation_map: dict[str, str] = {}


@app.post(f"{settings.api_prefix}/friday/delegate", response_model=FridayDelegationResponse, tags=["FRIDAY Integration"])
async def friday_delegate(fr: FridayDelegationRequest) -> FridayDelegationResponse:
    task_mode = TaskMode.AUTHORIZED_ASSESSMENT if fr.mode == "authorized_assessment" else TaskMode.PASSIVE_RECON
    scope_data = {
        "id": f"scope-fri-{int(_dt_fri.now(UTC).timestamp())}",
        "name": f"FRIDAY: {fr.objective[:30]}",
        "allowed_targets": [t.value for t in fr.targets],
        "environment": fr.policy_context.environment,
        "authorization": {"reference_ticket_id": fr.policy_context.authorization_reference},
    }
    task = await lifecycle_manager.create_and_submit_task(
        objective=fr.objective,
        targets=[{"type": t.type, "value": t.value} for t in fr.targets],
        scope_data=scope_data,
        mode=task_mode,
        requested_output_type=fr.requested_output.value,
    )
    delegation_id = f"del-{task.id}"
    _delegation_map[delegation_id] = task.id
    return FridayDelegationResponse(
        delegation_id=delegation_id,
        task_id=task.id,
        status=task.status.value,
        stream_url=f"{settings.api_prefix}/tasks/{task.id}/events",
    )


@app.get(f"{settings.api_prefix}/friday/delegations/{delegation_id}", response_model=FridayResultPayload, tags=["FRIDAY Integration"])
async def get_friday_delegation_result(delegation_id: str) -> FridayResultPayload:
    task_id = _delegation_map.get(delegation_id, delegation_id.replace("del-", ""))
    task = await lifecycle_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Delegation {delegation_id!r} not found.")
    findings = finding_engine.list_findings(task_id=task_id)
    evidence_list = evidence_store.query_evidence(task_id=task_id)
    attack_paths = attack_path_analyzer.analyze_paths(asset_graph_store, findings)
    recommendations = recommendation_engine.generate_recommendations(findings, attack_paths)
    blocked = [
        BlockedActionRecord(action_type=a.action_type, target=a.target,
            reason=f"Blocked by Sentinel policy: {a.justification_provided or 'No authorization'}")
        for a in policy_engine.get_pending_approvals(task_id=task_id) if a.status == "rejected"
    ]
    summary = FridaySummarizer.generate_summary(task, findings, blocked)
    return FridayResultPayload(
        delegation_id=delegation_id, task_id=task.id, task_status=task.status.value,
        progress_percentage=task.progress_percentage,
        findings=[f.model_dump() for f in findings],
        evidence_references=[e.id for e in evidence_list],
        blocked_actions=blocked,
        remediation_recommendations=[r.model_dump() for r in recommendations],
        report_artifacts={"json_report_url": f"{settings.api_prefix}/tasks/{task.id}/report?format=json",
                          "evidence_bundle_url": f"{settings.api_prefix}/tasks/{task.id}/evidence-bundle"},
        human_summary=summary,
    )


@app.post(f"{settings.api_prefix}/friday/delegations/{delegation_id}/cancel", tags=["FRIDAY Integration"])
async def cancel_friday_delegation(delegation_id: str, reason: str = Query("FRIDAY Kill Switch")) -> dict[str, Any]:  # noqa: B008
    task_id = _delegation_map.get(delegation_id, delegation_id.replace("del-", ""))
    task = await lifecycle_manager.cancel_task(task_id, reason=reason)
    return {"delegation_id": delegation_id, "task_id": task.id, "status": task.status.value}
'''

fpath = pathlib.Path("sentinel/apps/api/main.py")
content = fpath.read_text(encoding="utf-8")
if "_delegation_map" not in content:
    fpath.write_text(content.rstrip() + ADDITIONS, encoding="utf-8")
    print("DONE")
else:
    print("ALREADY_PRESENT")
