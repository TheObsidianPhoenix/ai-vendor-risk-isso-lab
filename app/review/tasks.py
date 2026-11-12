"""Review tasks (Milestone 2): who has to weigh in before a vendor gets a decision.

A vendor's risk tier (its classification, from the rules engine) decides which
departments must review it. This table is the one the user approved on
2026-11-11: every tier always gets an explicit AI-usage review, on top of
whatever the automated scoring already covers, because "there are few
companies now that don't have some element of AI usage" and a vendor's
self-report shouldn't be the only check on that.

| Tier | Required reviews |
|---|---|
| Low | Security, AI usage, department head (one approver) |
| Moderate | Security, AI usage, IT, department head (one approver) |
| High | Security, AI usage, IT, Legal, Privacy, department head (two-person rule) |
| Critical | Security, AI usage, IT, Legal, Privacy, department head (two-person rule) |

The two-person rule for High and Critical is enforced separately, in
app.decision.service (it already handled Critical; Milestone 2 extends that
to High, matching the approved table).

Tasks are generated once, when an assessment becomes ready for review
(app.web.server.assess). They are never silently skipped: app.decision.service
refuses to record a final decision while any required task is still open.
"""

from __future__ import annotations

REQUIRED_TASKS: dict[str, tuple[str, ...]] = {
    "Low": ("security", "ai_usage", "department_head"),
    "Moderate": ("security", "ai_usage", "it", "department_head"),
    "High": ("security", "ai_usage", "it", "legal", "privacy", "department_head"),
    "Critical": ("security", "ai_usage", "it", "legal", "privacy", "department_head"),
}

LABELS: dict[str, str] = {
    "security": "Security review",
    "ai_usage": "AI usage review",
    "it": "IT review",
    "legal": "Legal review",
    "privacy": "Privacy review",
    "department_head": "Department head approval",
}

MIN_NOTE = 5


def required_kinds(classification: str | None) -> tuple[str, ...]:
    return REQUIRED_TASKS.get(classification or "", ())


def generate(vendor_id: str, assessment_id: str, classification: str) -> list[dict]:
    """The checklist for one assessment, newly created and all open. Call once,
    right after the assessment is scored (never for an assessment that already
    has tasks: app.common.store.create_tasks only writes empty slates)."""
    return [{"vendor_id": vendor_id, "assessment_id": assessment_id, "kind": kind,
             "label": LABELS[kind], "status": "open"}
            for kind in required_kinds(classification)]


def open_kinds(tasks: list[dict]) -> list[str]:
    """Which required tasks, of the ones given, are still open."""
    return [t["kind"] for t in tasks if t["status"] != "done"]


def can_complete(user, kind: str) -> bool:
    """Who may check off a task, whatever its kind. A reviewer who completes
    "legal" or "department_head" is recording that legal, or the department
    head, weighed in -- not acting as counsel or as the department head
    themselves. The note says who, by name, actually gave that answer.

    Administrators don't get this: they have no vendor visibility at all
    (Milestone 1's design, unchanged here), so they can't meaningfully
    complete a task about a vendor they can't see."""
    return user.has("task.complete")
