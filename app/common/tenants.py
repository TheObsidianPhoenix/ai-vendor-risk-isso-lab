"""Tenants: the client companies that use Counterpart (multi-tenant Milestone 1).

Each client company is a tenant. A tenant's vendors, documents, assessments,
decisions, audit trail and settings live in that tenant's own space, and the code
that serves a request is only ever handed the space of the signed-in user's tenant.

The tenant always comes from the signed-in identity. It is never read from a URL,
header, cookie value or request body, so a caller can't ask for someone else's.

In AWS, the same rule is enforced below the application: each request runs with
temporary credentials limited to DynamoDB items and S3 objects whose key starts
with that tenant's ID, and each tenant's files use that tenant's own KMS key.

Both companies here are fictional.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

TENANT_ID = re.compile(r"ten_[a-z]{3,24}")


@dataclass(frozen=True)
class Tenant:
    id: str
    name: str
    sector: str
    fedramp_required: bool   # Vendors that will handle federal data must hold a FedRAMP authorization
    summary: str

    def public(self) -> dict:
        return {"id": self.id, "name": self.name, "sector": self.sector,
                "fedramp_required": self.fedramp_required, "summary": self.summary}


TENANTS = {
    "ten_harborline": Tenant(
        "ten_harborline", "Harborline Federal", "Software for US government agencies", True,
        "Sells to federal agencies. Strict rules: vendors that touch federal data need a FedRAMP authorization."),
    "ten_larkspur": Tenant(
        "ten_larkspur", "Larkspur Robotics", "Commercial robotics startup", False,
        "Commercial customers only. Lighter rules and no FedRAMP requirement."),
}


class UnknownTenant(Exception):
    pass


def get(tenant_id: str) -> Tenant:
    tenant = TENANTS.get(tenant_id)
    if tenant is None:
        raise UnknownTenant("Unknown tenant")
    return tenant


def space_path(data_dir: Path, tenant_id: str) -> Path:
    """The one folder a tenant's data may live in. Refuses anything that isn't a known tenant ID,
    so a crafted ID can never point outside the tenant area (no '..', no separators)."""
    if not isinstance(tenant_id, str) or not TENANT_ID.fullmatch(tenant_id) or tenant_id not in TENANTS:
        raise UnknownTenant("Unknown tenant")
    root = (Path(data_dir) / "tenants").resolve()
    path = (root / tenant_id).resolve()
    if path.parent != root:
        raise UnknownTenant("Unknown tenant")
    return path
