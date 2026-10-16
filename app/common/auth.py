"""Users, roles, sessions and permission checks (SR-01, SR-02, SR-03; AC-3, AC-5, AC-6, IA-2).

Locally, people sign in by choosing one of the fictional demo users below.
In Milestone 3 this is replaced by Amazon Cognito with MFA; the permission
checks stay exactly the same, because they read only the role and the user ID.

Every check happens on the server for every request. Hiding a button in the
browser is a convenience, never a control.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass

ROLES = {
    "app_user": "Application User",
    "reviewer": "Vendor Risk Reviewer",
    "admin": "Administrator",
    "isso": "ISSO (read-only)",
}

# Fictional people for the sandbox. No passwords: in AWS, Cognito handles credentials and MFA.
DEMO_USERS = {
    "usr_priya": {"name": "Priya Shah", "role": "app_user", "title": "Procurement lead"},
    "usr_omar": {"name": "Omar Haddad", "role": "app_user", "title": "Marketing operations"},
    "usr_dana": {"name": "Dana Whitfield", "role": "reviewer", "title": "Senior security analyst"},
    "usr_marcus": {"name": "Marcus Lee", "role": "reviewer", "title": "Security analyst"},
    "usr_sam": {"name": "Sam Ortiz", "role": "admin", "title": "System administrator"},
    "usr_jasmine": {"name": "Jasmine Alexander", "role": "isso", "title": "Information System Security Officer"},
}

SESSION_SECONDS = 8 * 60 * 60
FRESH_SIGN_IN_SECONDS = 15 * 60  # A decision needs a sign-in within the last 15 minutes

# What each role may do. Anything not listed is denied (default deny).
PERMISSIONS = {
    "app_user": {"vendor.create", "vendor.view_own", "document.upload_own", "assessment.run_own"},
    "reviewer": {"vendor.view_all", "assessment.run_any", "decision.record"},
    "admin": {"audit.view", "settings.change", "users.view"},
    "isso": {"vendor.view_all", "audit.view", "users.view"},
}


class PermissionDenied(Exception):
    pass


@dataclass(frozen=True)
class User:
    id: str
    name: str
    role: str
    title: str

    @property
    def role_name(self) -> str:
        return ROLES[self.role]

    def has(self, permission: str) -> bool:
        return permission in PERMISSIONS.get(self.role, set())

    def public(self) -> dict:
        return {"id": self.id, "name": self.name, "role": self.role, "role_name": self.role_name,
                "title": self.title, "permissions": sorted(PERMISSIONS.get(self.role, set()))}


@dataclass(frozen=True)
class Session:
    user: User
    signed_in_at: float  # Like Cognito's auth_time claim

    def fresh(self, seconds: int = FRESH_SIGN_IN_SECONDS, clock=time.time) -> bool:
        return clock() - self.signed_in_at <= seconds


def get_user(user_id: str) -> User | None:
    info = DEMO_USERS.get(user_id)
    return User(user_id, **info) if info else None


class Sessions:
    def __init__(self, clock=time.time):
        self._items: dict[str, Session] = {}
        self._lock = threading.Lock()
        self.clock = clock

    def sign_in(self, user_id: str) -> tuple[str, Session]:
        user = get_user(user_id)
        if user is None:
            raise PermissionDenied("Unknown user")
        token = secrets.token_urlsafe(32)  # Random, unguessable, kept only in server memory
        session = Session(user, self.clock())
        with self._lock:
            self._items[token] = session
        return token, session

    def get(self, token: str | None) -> Session | None:
        if not token:
            return None
        with self._lock:
            session = self._items.get(token)
            if session and self.clock() - session.signed_in_at > SESSION_SECONDS:
                del self._items[token]
                return None
            return session

    def sign_out(self, token: str | None) -> None:
        with self._lock:
            self._items.pop(token or "", None)


# ----- object-level checks (SR-01: "including object ownership") ---------------

def can_view_vendor(user: User, vendor: dict) -> bool:
    return user.has("vendor.view_all") or (user.has("vendor.view_own") and vendor["owner_id"] == user.id)


def can_upload(user: User, vendor: dict) -> bool:
    return user.has("document.upload_own") and vendor["owner_id"] == user.id


def can_run_assessment(user: User, vendor: dict) -> bool:
    return user.has("assessment.run_any") or (user.has("assessment.run_own") and vendor["owner_id"] == user.id)
