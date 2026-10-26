"""Role → permission mapping. Permissions are checked server-side on every route."""
from __future__ import annotations

import enum

from .models import Role


class Perm(str, enum.Enum):
    VIEW = "view"
    VIEW_AUDIT = "view_audit"
    INCIDENT_ACK = "incident_ack"
    MITIGATION_PROPOSE = "mitigation_propose"
    MITIGATION_APPROVE = "mitigation_approve"
    MITIGATION_WITHDRAW = "mitigation_withdraw"
    AUTOMATION_STOP = "automation_stop"
    AUTOMATION_ENABLE = "automation_enable"
    CONFIG_NETWORK = "config_network"        # prefixes, routers, upstreams, BGP, customers
    CONFIG_POLICY = "config_policy"
    MANAGE_USERS = "manage_users"
    MANAGE_SETTINGS = "manage_settings"


_READ = {Perm.VIEW, Perm.VIEW_AUDIT}
_NOC = _READ | {
    Perm.INCIDENT_ACK, Perm.MITIGATION_PROPOSE, Perm.MITIGATION_APPROVE,
    Perm.MITIGATION_WITHDRAW, Perm.AUTOMATION_STOP,
}
_ENG = _NOC | {Perm.AUTOMATION_ENABLE, Perm.CONFIG_NETWORK, Perm.CONFIG_POLICY}
_ADMIN = _ENG | {Perm.MANAGE_USERS, Perm.MANAGE_SETTINGS}

ROLE_PERMISSIONS: dict[Role, frozenset[Perm]] = {
    Role.READ_ONLY: frozenset(_READ),
    Role.NOC_OPERATOR: frozenset(_NOC),
    Role.NETWORK_ENGINEER: frozenset(_ENG),
    Role.ADMIN: frozenset(_ADMIN),
}


def has_perm(role: Role | str, perm: Perm) -> bool:
    return perm in ROLE_PERMISSIONS[Role(role)]
