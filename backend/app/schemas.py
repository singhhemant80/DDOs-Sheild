"""Pydantic request/response models. Secrets are write-only: never present in *Out models."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from . import netvalidate as nv
from .models import AccessMode, BgpPurpose, Role, RouterModel, ServiceType


class _Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


def _str(v):
    return None if v is None else str(v)


# ---------------------------------------------------------------- auth
class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    totp_code: str | None = Field(None, max_length=8)


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    mfa_verified: bool


class RefreshIn(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=200)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class MfaSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


class MfaCodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class SessionOut(_Out):
    id: uuid.UUID
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    ip: str | None
    user_agent: str | None
    mfa_verified: bool
    current: bool = False

    _ip = field_validator("ip", mode="before")(_str)


# ---------------------------------------------------------------- users
class UserOut(_Out):
    id: uuid.UUID
    username: str
    email: str | None
    full_name: str | None
    role: Role
    is_active: bool
    mfa_enabled: bool
    last_login_at: datetime | None
    locked_until: datetime | None
    created_at: datetime


class MeOut(UserOut):
    permissions: list[str]
    session_mfa_verified: bool


class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,64}$")
    password: str = Field(max_length=256)
    email: EmailStr | None = None
    full_name: str | None = Field(None, max_length=128)
    role: Role = Role.READ_ONLY


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    full_name: str | None = Field(None, max_length=128)
    role: Role | None = None
    is_active: bool | None = None
    unlock: bool | None = None
    reset_mfa: bool | None = None
    new_password: str | None = Field(None, max_length=256)


# ---------------------------------------------------------------- prefixes
class PrefixBase(BaseModel):
    description: str | None = Field(None, max_length=500)
    enabled: bool = True
    ownership_verified: bool = False
    ownership_evidence: str | None = Field(None, max_length=1000)
    rtbh_allowed: bool = False
    steering_allowed: bool = False
    filtering_allowed: bool = False
    min_mitigation_prefix_len: int | None = Field(None, ge=0, le=128)
    preferred_upstream_id: int | None = None


class PrefixCreate(PrefixBase):
    prefix: str

    @field_validator("prefix")
    @classmethod
    def _v(cls, v: str) -> str:
        return str(nv.validate_public_prefix(v))

    @model_validator(mode="after")
    def _mitigation_needs_ownership(self):
        if (self.rtbh_allowed or self.steering_allowed or self.filtering_allowed) and not (
            self.ownership_verified and self.ownership_evidence
        ):
            raise ValueError("enabling any mitigation requires ownership_verified=true and ownership_evidence")
        return self


class PrefixUpdate(BaseModel):
    description: str | None = Field(None, max_length=500)
    enabled: bool | None = None
    ownership_verified: bool | None = None
    ownership_evidence: str | None = Field(None, max_length=1000)
    rtbh_allowed: bool | None = None
    steering_allowed: bool | None = None
    filtering_allowed: bool | None = None
    min_mitigation_prefix_len: int | None = Field(None, ge=0, le=128)
    preferred_upstream_id: int | None = None


class PrefixOut(_Out):
    id: int
    prefix: str
    description: str | None
    enabled: bool
    ownership_verified: bool
    ownership_evidence: str | None
    rtbh_allowed: bool
    steering_allowed: bool
    filtering_allowed: bool
    min_mitigation_prefix_len: int
    preferred_upstream_id: int | None
    authorized_by_id: uuid.UUID | None
    authorized_at: datetime | None
    created_at: datetime
    updated_at: datetime

    _p = field_validator("prefix", mode="before")(_str)


class EligibilityOut(BaseModel):
    target: str
    protected_prefix: str | None
    protected_prefix_id: int | None
    enabled: bool
    rtbh_allowed: bool
    steering_allowed: bool
    filtering_allowed: bool
    within_scope_limit: bool
    customer: dict | None
    reasons: list[str]


# ---------------------------------------------------------------- routers
class RouterCreate(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    model: RouterModel
    role: str = Field("primary", pattern=r"^(primary|secondary|edge|lab)$")
    mgmt_address: str
    api_port: int = Field(8729, ge=1, le=65535)
    use_tls: bool = True
    verify_tls: bool = True
    api_username: str | None = Field(None, max_length=64)
    api_password: str | None = Field(None, max_length=256)
    access_mode: AccessMode = AccessMode.READ_ONLY
    enabled: bool = True
    notes: str | None = Field(None, max_length=2000)
    tls_fingerprint: str | None = Field(None, max_length=200)

    @field_validator("tls_fingerprint")
    @classmethod
    def _fp(cls, v):
        return _fingerprint(v) or None

    @field_validator("mgmt_address")
    @classmethod
    def _addr(cls, v: str) -> str:
        import ipaddress
        return str(ipaddress.ip_address(v.strip()))

    @model_validator(mode="after")
    def _write_needs_tls(self):
        if self.access_mode == AccessMode.READ_WRITE and not (self.use_tls and self.verify_tls):
            raise ValueError("read_write access requires use_tls=true and verify_tls=true")
        return self


def _fingerprint(v: str | None) -> str | None:
    """Accept 'AB:CD:..', 'abcd..' or '' (clear); store as upper-case colon pairs."""
    if v is None or not v.strip():
        return None if v is None else ""
    from .mikrotik.api import colon_fingerprint
    return colon_fingerprint(v)


class RouterUpdate(BaseModel):
    role: str | None = Field(None, pattern=r"^(primary|secondary|edge|lab)$")
    api_port: int | None = Field(None, ge=1, le=65535)
    use_tls: bool | None = None
    verify_tls: bool | None = None
    api_username: str | None = Field(None, max_length=64)
    api_password: str | None = Field(None, max_length=256)
    access_mode: AccessMode | None = None
    dry_run: bool | None = None
    enabled: bool | None = None
    notes: str | None = Field(None, max_length=2000)
    tls_fingerprint: str | None = Field(None, max_length=200)

    _fp = field_validator("tls_fingerprint")(lambda cls, v: _fingerprint(v))


class RouterOut(_Out):
    id: int
    name: str
    model: RouterModel
    role: str
    mgmt_address: str
    api_port: int
    use_tls: bool
    verify_tls: bool
    api_username: str | None
    has_api_password: bool = False
    access_mode: AccessMode
    dry_run: bool
    enabled: bool
    identity: str | None
    routeros_version: str | None
    status: str
    last_seen_at: datetime | None
    notes: str | None
    tls_fingerprint: str | None = None

    _a = field_validator("mgmt_address", mode="before")(_str)


# ---------------------------------------------------------------- upstreams
class UpstreamCreate(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9 _.-]{1,64}$")
    asn: int
    description: str | None = Field(None, max_length=500)
    router_id: int | None = None
    interface_name: str | None = Field(None, max_length=64)
    capacity_mbps: int | None = Field(None, gt=0)
    saturation_threshold_pct: int = Field(85, ge=1, le=100)
    ddos_protected: bool = False
    enabled: bool = True

    _asn = field_validator("asn")(lambda cls, v: nv.validate_asn(v))


class UpstreamUpdate(BaseModel):
    description: str | None = Field(None, max_length=500)
    router_id: int | None = None
    interface_name: str | None = Field(None, max_length=64)
    capacity_mbps: int | None = Field(None, gt=0)
    saturation_threshold_pct: int | None = Field(None, ge=1, le=100)
    ddos_protected: bool | None = None
    enabled: bool | None = None


class RtbhPolicyIn(BaseModel):
    communities: list[str] = Field(default_factory=list, max_length=8)
    next_hop: str | None = None
    min_prefix_len: int = Field(32, ge=0, le=128)
    max_prefix_len: int = Field(32, ge=0, le=128)
    max_routes: int = Field(10, ge=1, le=10000)
    add_no_export: bool = True
    dedicated_session: bool = False
    documentation_ref: str | None = Field(None, max_length=1000)

    @field_validator("communities")
    @classmethod
    def _c(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(nv.normalise_community(c) for c in v))

    @field_validator("next_hop")
    @classmethod
    def _nh(cls, v):
        import ipaddress
        return None if v is None else str(ipaddress.ip_address(v.strip()))

    @model_validator(mode="after")
    def _order(self):
        if self.min_prefix_len > self.max_prefix_len:
            raise ValueError("min_prefix_len must be <= max_prefix_len")
        return self


class RtbhPolicyOut(_Out):
    id: int
    upstream_id: int
    enabled: bool
    communities: list[str]
    next_hop: str | None
    min_prefix_len: int
    max_prefix_len: int
    max_routes: int
    add_no_export: bool
    dedicated_session: bool
    documentation_ref: str | None
    verified_by_id: uuid.UUID | None
    verified_at: datetime | None

    _nh = field_validator("next_hop", mode="before")(_str)


class UpstreamOut(_Out):
    id: int
    name: str
    asn: int
    description: str | None
    router_id: int | None
    interface_name: str | None
    capacity_mbps: int | None
    saturation_threshold_pct: int
    ddos_protected: bool
    enabled: bool
    rtbh_policy: RtbhPolicyOut | None


# ---------------------------------------------------------------- BGP
class BgpNeighborCreate(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    router_id: int | None = None
    upstream_id: int | None = None
    purpose: BgpPurpose
    local_asn: int
    remote_asn: int
    neighbor_address: str
    local_address: str | None = None
    max_prefix_out: int | None = Field(None, ge=1, le=100000)
    enabled: bool = True
    managed_by_shield: bool = False
    environment: str = Field("staging", pattern=r"^(staging|production)$")
    remote_port: int = Field(179, ge=1, le=65535)
    ebgp_multihop: int | None = Field(None, ge=1, le=255)
    md5_password: str | None = Field(None, pattern=r"^[A-Za-z0-9._-]{8,80}$")
    description: str | None = Field(None, max_length=200)

    @field_validator("local_asn", "remote_asn")
    @classmethod
    def _asn(cls, v: int) -> int:
        return nv.validate_asn(v)

    @field_validator("neighbor_address", "local_address")
    @classmethod
    def _addr(cls, v):
        import ipaddress
        return None if v is None else str(ipaddress.ip_address(v.strip()))

    @model_validator(mode="after")
    def _rules(self):
        if self.managed_by_shield and self.purpose == BgpPurpose.TRANSIT:
            raise ValueError("Shield never manages transit sessions")
        if self.purpose == BgpPurpose.RTBH_UPSTREAM and self.upstream_id is None:
            raise ValueError("rtbh_upstream sessions must reference an upstream")
        if self.managed_by_shield and self.max_prefix_out is None:
            raise ValueError("Shield-managed sessions must set max_prefix_out")
        return self


class BgpNeighborOut(_Out):
    id: int
    name: str
    router_id: int | None
    upstream_id: int | None
    purpose: BgpPurpose
    local_asn: int
    remote_asn: int
    neighbor_address: str
    local_address: str | None
    max_prefix_out: int | None
    enabled: bool
    managed_by_shield: bool
    last_state: str | None
    last_state_change_at: datetime | None
    environment: str = "staging"
    remote_port: int = 179
    ebgp_multihop: int | None = None
    has_md5_password: bool = False
    description: str | None = None

    _a = field_validator("neighbor_address", "local_address", mode="before")(_str)


class BgpNeighborUpdate(BaseModel):
    enabled: bool | None = None
    environment: str | None = Field(None, pattern=r"^(staging|production)$")
    remote_port: int | None = Field(None, ge=1, le=65535)
    ebgp_multihop: int | None = Field(None, ge=1, le=255)
    max_prefix_out: int | None = Field(None, ge=1, le=100000)
    local_address: str | None = None
    md5_password: str | None = Field(None, pattern=r"^([A-Za-z0-9._-]{8,80})?$")  # "" clears
    description: str | None = Field(None, max_length=200)

    @field_validator("local_address")
    @classmethod
    def _addr(cls, v):
        import ipaddress
        return None if not v else str(ipaddress.ip_address(v.strip()))


# ---------------------------------------------------------------- customers
class CustomerIpCreate(BaseModel):
    address: str
    customer_ref: str = Field(min_length=1, max_length=64)
    customer_name: str | None = Field(None, max_length=128)
    service_type: ServiceType
    proxmox_node: str | None = Field(None, max_length=64)
    proxmox_vmid: int | None = Field(None, ge=100, le=999999999)
    rtbh_opt_out: bool = False
    pps_threshold: int | None = Field(None, gt=0)
    bps_threshold: int | None = Field(None, gt=0)
    notes: str | None = Field(None, max_length=2000)

    @field_validator("address")
    @classmethod
    def _a(cls, v: str) -> str:
        return str(nv.parse_target(v))


class CustomerIpOut(_Out):
    id: int
    address: str
    protected_prefix_id: int
    customer_ref: str
    customer_name: str | None
    service_type: ServiceType
    proxmox_node: str | None
    proxmox_vmid: int | None
    rtbh_opt_out: bool
    pps_threshold: int | None
    bps_threshold: int | None
    notes: str | None

    _a = field_validator("address", mode="before")(_str)


# ---------------------------------------------------------------- audit / settings
class AuditOut(_Out):
    id: int
    at: datetime
    actor_user_id: uuid.UUID | None
    actor_username: str
    actor_ip: str | None
    action: str
    entity_type: str | None
    entity_id: str | None
    before: dict | None
    after: dict | None
    hash: str

    _ip = field_validator("actor_ip", mode="before")(_str)


class SettingOut(_Out):
    key: str
    value: object
    description: str | None
    updated_at: datetime


class SettingUpdate(BaseModel):
    value: object
