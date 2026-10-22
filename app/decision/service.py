"""Decision service (Phase 7): human review requirements HR-01 to HR-07.

Every rule below is checked here, on the server, in this order. The first
rule that fails refuses the decision and nothing is written.

| Rule | Requirement |
|---|---|
| Only a Vendor Risk Reviewer can decide | HR-02, SR-01 (AC-3) |
| The reviewer signed in within the last 15 minutes | SR-03 (IA-2) |
| The reviewer didn't create the vendor or upload its documents | SR-02 (AC-5) |
| The assessment is the latest one and produced a valid result | HR-03 |
| One of the four decisions, a written rationale, evidence confirmed | FR-10, HR-07 |
| An assessment's final decision is never changed or replaced | No overwrites |
| A Critical vendor needs a second, different reviewer to approve | HR-06, FR-11 |
| Approving a High or Critical vendor, or rejecting a Low one, is an override | HR-05 |

The AI component has no path to this module: app.ai_worker never imports it,
and in AWS the AI worker's IAM role is explicitly denied the decisions table.
"""

from __future__ import annotations

from app.common.auth import PermissionDenied, Session

DECISIONS = ("Approved", "Approved with Conditions", "Further Review Required", "Rejected")
APPROVALS = {"Approved", "Approved with Conditions"}
MIN_RATIONALE = 20


class DecisionRefused(Exception):
    pass


def record_decision(*, store, audit, session: Session, assessment_id: str, decision: str,
                    rationale: str, evidence_confirmed: bool, conditions: str = "") -> dict:
    user = session.user

    def refuse(reason: str, exc=DecisionRefused):
        audit.record(actor=user.id, role=user.role, action="decision.record", target=assessment_id,
                     outcome="denied", details={"reason": reason})
        raise exc(reason)

    if not user.has("decision.record"):
        refuse("Only a Vendor Risk Reviewer can record a decision", PermissionDenied)
    if not session.fresh():
        refuse("Please sign in again: a decision needs a sign-in within the last 15 minutes")

    assessment = store.get_assessment(assessment_id)
    if assessment is None:
        refuse("Assessment not found")
    vendor = store.get_vendor(assessment["vendor_id"])

    uploaders = {doc["uploaded_by"] for doc in store.list_documents(vendor["id"])}
    if user.id == vendor["owner_id"] or user.id in uploaders:
        refuse("Separation of duties: you can't decide on a vendor you requested or uploaded documents for")

    latest = store.latest_assessment(vendor["id"])
    if latest["id"] != assessment_id:
        refuse("A newer assessment exists for this vendor; review that one")
    if assessment["status"] != "ready_for_review":
        refuse("This assessment has no valid result to decide on; run a new assessment")

    rationale = (rationale or "").strip()
    conditions = (conditions or "").strip()
    if decision not in DECISIONS:
        refuse("Choose one of the four decisions")
    if len(rationale) < MIN_RATIONALE:
        refuse(f"Write a rationale of at least {MIN_RATIONALE} characters")
    if decision == "Approved with Conditions" and not conditions:
        refuse("List the conditions for this approval")
    if not evidence_confirmed:
        refuse("Confirm that you examined the source evidence")

    earlier = [d for d in store.list_decisions(vendor["id"]) if d["assessment_id"] == assessment_id]
    if any(d["stage"] == "final" for d in earlier):
        refuse("This assessment already has a final decision. Decisions are never changed; run a new assessment instead")

    classification = assessment["score"]["classification"]
    pending = [d for d in earlier if d["stage"] == "first_approval"]
    if pending and pending[-1]["reviewer_id"] == user.id:
        refuse("Two-person rule: a different reviewer must give the second approval")

    if classification == "Critical" and decision in APPROVALS and not pending:
        stage = "first_approval"   # Not final until a second reviewer agrees (HR-06)
    else:
        stage = "final"

    override = ((decision in APPROVALS and classification in ("High", "Critical"))
                or (decision == "Rejected" and classification == "Low"))

    record = store.append_decision({
        "vendor_id": vendor["id"],
        "assessment_id": assessment_id,
        "assessment_version": assessment["version"],
        "rule_set_version": assessment["score"]["rule_set_version"],
        "score": assessment["score"]["score"],
        "classification": classification,
        "decision": decision,
        "conditions": conditions,
        "rationale": rationale[:2000],
        "evidence_confirmed": True,
        "reviewer_id": user.id,
        "reviewer_name": user.name,
        "stage": stage,
        "override": override,
        "second_approval_of": pending[-1]["id"] if pending else None,
        "prompt_injection_flagged": assessment["score"]["prompt_injection_flagged"],
    })
    audit.record(actor=user.id, role=user.role, action="decision.record", target=assessment_id,
                 details={"vendor_id": vendor["id"], "decision": decision, "stage": stage,
                          "override": override, "classification": classification})
    return record


def vendor_status(store, vendor_id: str) -> dict:
    """A vendor has no final status until a person records one (HR-04)."""
    latest = store.latest_assessment(vendor_id)
    if latest is None:
        return {"status": "No assessment yet", "final": False}
    if latest["status"] != "ready_for_review":
        label = "AI call failed" if latest["status"] == "ai_call_failed" else "AI output rejected"
        return {"status": f"{label}: needs a new assessment", "final": False}
    decisions = [d for d in store.list_decisions(vendor_id) if d["assessment_id"] == latest["id"]]
    final = next((d for d in reversed(decisions) if d["stage"] == "final"), None)
    if final:
        return {"status": final["decision"], "final": True, "decision": final}
    if decisions:
        return {"status": "Awaiting second approval", "final": False, "decision": decisions[-1]}
    return {"status": "Awaiting human decision", "final": False}
