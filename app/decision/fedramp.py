"""FedRAMP requirement check (decision D-13).

A vendor that will handle federal data must hold a FedRAMP authorization at
least as high as that data's impact level. This module answers one question,
deterministically: is that requirement met?

Who enters what (people, never documents or the AI):
- The REQUESTER says, when creating the vendor, whether it will handle federal
  data and at what impact level (none, low, moderate, high). Same idea as
  "uses AI on our data": a document can't talk its way out of the requirement.
- A REVIEWER records the vendor's FedRAMP status after checking the public
  FedRAMP Marketplace: certified or not, the class or level listed, and the
  date they checked. The requester can't, so they can't vouch for their own
  vendor.

What it changes: nothing in the score (rule set 1.0 is unchanged). It's a
separate requirement shown next to the score, and the decision service
refuses a plain "Approved" while the requirement is unmet. "Approved with
Conditions" is still possible, but it's flagged as an exception and an
override, so a person has to write down why.

The listing proves an independent assessment happened. It doesn't quote
individual controls, so it never marks a control as "verified".
"""

from __future__ import annotations

from datetime import date, datetime, timezone

IMPACT_LEVELS = ("none", "low", "moderate", "high")
STATUSES = ("certified", "in_process", "not_listed")

# What a listing covers, from lowest to highest. FedRAMP is moving from the
# Low/Moderate/High labels to certification classes (CR26), so both are accepted.
LEVELS = {
    "Class B (Low)": 1, "LI-SaaS": 1, "Low": 1,
    "Class C (Moderate)": 2, "Moderate": 2,
    "Class D (High)": 3, "High": 3,
    "Class A (Pilot)": 0,     # Pilot: doesn't meet a requirement on its own; a reviewer must judge
}
NEEDED = {"low": 1, "moderate": 2, "high": 3}
RECHECK_DAYS = 90             # A Marketplace check older than this must be repeated


def requirement(vendor: dict, today: date | None = None) -> dict:
    """Whether the vendor's FedRAMP requirement applies and is met, with a plain reason."""
    impact = vendor.get("federal_data_impact", "none")
    status = vendor.get("fedramp") or {}
    base = {"applies": impact != "none", "federal_data_impact": impact,
            "fedramp_status": status.get("status"), "fedramp_level": status.get("level"),
            "checked_on": status.get("checked_on"), "recorded_by": status.get("recorded_by_name")}
    if impact == "none":
        return dict(base, met=True, reason="Not required: the vendor won't handle federal data")
    if not status:
        return dict(base, met=False, reason="FedRAMP status not recorded yet: a reviewer must check the Marketplace")
    today = today or datetime.now(timezone.utc).date()
    checked = date.fromisoformat(status["checked_on"])
    if (today - checked).days > RECHECK_DAYS:
        return dict(base, met=False, reason=f"FedRAMP status was checked more than {RECHECK_DAYS} days ago; check again")
    if status["status"] != "certified":
        label = "in process, not yet authorized" if status["status"] == "in_process" else "not listed"
        return dict(base, met=False, reason=f"FedRAMP status is {label}")
    if LEVELS.get(status["level"], 0) < NEEDED[impact]:
        return dict(base, met=False,
                    reason=f"Authorized at {status['level']}, but {impact} impact federal data needs a higher level")
    return dict(base, met=True, reason=f"Authorized at {status['level']}, enough for {impact} impact federal data")


def validate_status(body: dict, today: date | None = None) -> dict:
    """Check what a reviewer submits. Returns the clean record or raises ValueError."""
    status, level, checked_on = body.get("status"), body.get("level", ""), body.get("checked_on", "")
    if status not in STATUSES:
        raise ValueError("Choose a FedRAMP status: certified, in_process or not_listed")
    if status == "certified" and level not in LEVELS:
        raise ValueError("Choose the level or class shown on the Marketplace")
    try:
        checked = date.fromisoformat(str(checked_on))
    except ValueError:
        raise ValueError("Give the date you checked the Marketplace (YYYY-MM-DD)") from None
    if checked > (today or datetime.now(timezone.utc).date()):
        raise ValueError("The check date can't be in the future")
    listing = str(body.get("listing", "")).strip()[:200]
    return {"status": status, "level": level if status == "certified" else "", "checked_on": checked.isoformat(),
            "listing": listing, "source": "FedRAMP Marketplace"}
