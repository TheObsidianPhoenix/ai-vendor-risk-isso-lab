"""Comments (Milestone 2): the running discussion on one vendor, visible only
inside its own company (TenantApp already guarantees that; this module adds
nothing that could cross that line).

Append-only, like decisions: a comment is never edited or deleted once
posted, so the discussion a reviewer or department head relied on when they
signed off can't quietly change afterward. Max length keeps the tracking view
readable.
"""

from __future__ import annotations

MAX_LENGTH = 2000


def can_comment(user, vendor: dict) -> bool:
    return user.has("comment.add") or (user.has("comment.add_own") and vendor["owner_id"] == user.id)
