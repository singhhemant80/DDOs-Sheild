"""SQLAlchemy models for Crapplet DDoS Shield.

Design notes
- Enumerations are stored as VARCHAR with CHECK constraints (not native PG enums) so new
  values can be added with a simple migration.
- Network values use PostgreSQL INET/CIDR with GiST indexes so containment (<<=) and
  overlap (&&) checks run in the database.
- Tables for later phases (flows, incidents, actions, RTBH ledger, notifications) are
  defined now so the data model is stable; Phase 2 exposes no API that writes to them.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, CIDR, INET, JSONB, UUID, ExcludeConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _enum(e: type[enum.Enum], name: str) -> Enum:
    return Enum(
        e,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=32,
        values_callable=lambda x: [m.value for m in x],
        validate_strings=True,
    )


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class Role(str, enum.Enum):
    ADMIN = "admin"
    NETWORK_ENGINEER = "network_engineer"
    NOC_OPERATOR = "noc_operator"
    READ_ONLY = "read_only"


class RouterModel(str, enum.Enum):
    CCR2004 = "ccr2004"
    CCR2116 = "ccr2116"
    OTHER = "other"


class AccessMode(str, enum.Enum):
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"


class DeviceStatus(str, enum.Enum):
    UNKNOWN = "unknown"
    UP = "up"
    DEGRADED = "degraded"
    DOWN = "down"


class BgpPurpose(str, enum.Enum):
    TRANSIT = "transit"
    IBGP = "ibgp"
    RTBH_SIGNAL = "rtbh_signal"        # Shield (FRR) -> own routers
    RTBH_UPSTREAM = "rtbh_upstream"    # dedicated RTBH session to an upstream
    STEERING = "steering"


class Provenance(str, enum.Enum):
    MEASURED = "measured"
    SAMPLED = "sampled"
    ESTIMATED = "estimated"
    UNAVAILABLE = "unavailable"


class IncidentStatus(str, enum.Enum):
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    MITIGATING = "mitigating"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Strategy(str, enum.Enum):
    RTBH_UPSTREAM = "rtbh_upstream"
    RTBH_INTERNAL = "rtbh_internal"
    STEERING = "steering"
    LOCAL_FILTER = "local_filter"
    SCRUBBING = "scrubbing"


class ActionState(str, enum.Enum):
    PROPOSED = "proposed"
    REJECTED = "rejected"
    APPROVED = "approved"
    EXECUTING = "executing"
    ACTIVE = "active"
    WITHDRAWING = "withdrawing"
    WITHDRAWN = "withdrawn"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


TERMINAL_ACTION_STATES = ("rejected", "withdrawn", "rolled_back")


class RtbhMode(str, enum.Enum):
    UPSTREAM = "upstream"
    INTERNAL = "internal"


class RtbhStatus(str, enum.Enum):
    PENDING_ANNOUNCE = "pending_announce"
    ANNOUNCED = "announced"
    VERIFIED = "verified"
    WITHDRAWING = "withdrawing"
    WITHDRAWN = "withdrawn"
    FAILED = "failed"


class ChannelKind(str, enum.Enum):
    EMAIL = "email"
    TELEGRAM = "telegram"
    WEBHOOK = "webhook"


class ServiceType(str, enum.Enum):
    VPS = "vps"
    DEDICATED = "dedicated"
    COLO = "colo"
    INFRA = "infra"
    OTHER = "other"


# ---------------------------------------------------------------------------
# Identity & access
# ---------------------------------------------------------------------------
class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    email: Mapped[str | None] = mapped_column(String(254))
    full_name: Mapped[str | None] = mapped_column(String(128))
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[Role] = mapped_column(_enum(Role, "role"), nullable=False, default=Role.READ_ONLY)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_secret_enc: Mapped[str | None] = mapped_column(Text)
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    password_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("uq_users_username_lower", func.lower(username), unique=True),
        CheckConstraint("username ~ '^[A-Za-z0-9_.-]{3,64}$'", name="ck_users_username_format"),
    )


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    refresh_token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    mfa_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(String(64))
    ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(512))

    user: Mapped[User] = relationship()

    __table_args__ = (Index("ix_auth_sessions_user_active", "user_id", postgresql_where=text("revoked_at IS NULL")),)


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(512))
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        Index("ix_login_attempts_ip_at", "ip", "at"),
        Index("ix_login_attempts_username_at", "username", "at"),
    )


# ---------------------------------------------------------------------------
# Network inventory
# ---------------------------------------------------------------------------
class Router(TimestampMixin, Base):
    __tablename__ = "routers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    model: Mapped[RouterModel] = mapped_column(_enum(RouterModel, "router_model"), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="primary")
    mgmt_address: Mapped[str] = mapped_column(INET, nullable=False, unique=True)
    api_port: Mapped[int] = mapped_column(Integer, nullable=False, default=8729)
    use_tls: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    verify_tls: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    api_username: Mapped[str | None] = mapped_column(String(64))
    api_password_enc: Mapped[str | None] = mapped_column(Text)
    access_mode: Mapped[AccessMode] = mapped_column(
        _enum(AccessMode, "access_mode"), nullable=False, default=AccessMode.READ_ONLY
    )
    dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Discovered (Phase 5)
    identity: Mapped[str | None] = mapped_column(String(128))
    routeros_version: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[DeviceStatus] = mapped_column(
        _enum(DeviceStatus, "device_status"), nullable=False, default=DeviceStatus.UNKNOWN
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str | None] = mapped_column(Text)
    # Phase 5: SHA-256 of the router's API-SSL certificate ("AB:CD:..."). When set, the connection is
    # accepted only if the presented certificate matches, whatever CA signed it.
    tls_fingerprint: Mapped[str | None] = mapped_column(String(95))

    __table_args__ = (
        CheckConstraint("api_port BETWEEN 1 AND 65535", name="ck_routers_port"),
        CheckConstraint("use_tls OR access_mode = 'read_only'", name="ck_routers_write_requires_tls"),
        CheckConstraint("tls_fingerprint IS NULL OR tls_fingerprint ~ '^([0-9A-F]{2}:){31}[0-9A-F]{2}$'",
                        name="ck_routers_fingerprint"),
    )


class RouterState(Base):
    """Latest read-only snapshot of a router, replaced on every full poll (Phase 5)."""

    __tablename__ = "router_state"

    router_id: Mapped[int] = mapped_column(ForeignKey("routers.id", ondelete="CASCADE"), primary_key=True)
    polled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    identity: Mapped[str | None] = mapped_column(String(128))
    version: Mapped[str | None] = mapped_column(String(64))
    board: Mapped[str | None] = mapped_column(String(64))
    uptime_seconds: Mapped[int | None] = mapped_column(BigInteger)
    cpu_load: Mapped[int | None] = mapped_column(SmallInteger)
    resources: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    interfaces: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    addresses: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    bgp: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    routes: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    traffic_flow: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    permissions: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    checks: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)


class RouterEvent(Base):
    """Things that happened on a router: unreachable/recovered, BGP up/down, reboots, version changes."""

    __tablename__ = "router_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    router_id: Mapped[int] = mapped_column(ForeignKey("routers.id", ondelete="CASCADE"), nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (Index("ix_router_events_router_at", "router_id", "at"), Index("ix_router_events_at", "at"))


class UpstreamProvider(TimestampMixin, Base):
    __tablename__ = "upstream_providers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    asn: Mapped[int] = mapped_column(BigInteger, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    router_id: Mapped[int | None] = mapped_column(ForeignKey("routers.id", ondelete="SET NULL"))
    interface_name: Mapped[str | None] = mapped_column(String(64))
    capacity_mbps: Mapped[int | None] = mapped_column(Integer)
    saturation_threshold_pct: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=85)
    ddos_protected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    router: Mapped[Router | None] = relationship()
    rtbh_policy: Mapped[UpstreamRtbhPolicy | None] = relationship(back_populates="upstream", uselist=False)

    __table_args__ = (
        CheckConstraint("asn BETWEEN 1 AND 4294967295", name="ck_upstreams_asn"),
        CheckConstraint("saturation_threshold_pct BETWEEN 1 AND 100", name="ck_upstreams_sat"),
        CheckConstraint("capacity_mbps IS NULL OR capacity_mbps > 0", name="ck_upstreams_capacity"),
    )


class UpstreamRtbhPolicy(TimestampMixin, Base):
    """Per-upstream RTBH rules, taken from that provider's documentation. Nothing is assumed."""

    __tablename__ = "upstream_rtbh_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    upstream_id: Mapped[int] = mapped_column(
        ForeignKey("upstream_providers.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    communities: Mapped[list[str]] = mapped_column(ARRAY(String(64)), nullable=False, default=list)
    next_hop: Mapped[str | None] = mapped_column(INET)
    min_prefix_len: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=32)
    max_prefix_len: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=32)
    max_routes: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    add_no_export: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    dedicated_session: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    documentation_ref: Mapped[str | None] = mapped_column(Text)
    verified_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    upstream: Mapped[UpstreamProvider] = relationship(back_populates="rtbh_policy")

    __table_args__ = (
        CheckConstraint("min_prefix_len BETWEEN 0 AND 128 AND max_prefix_len BETWEEN 0 AND 128", name="ck_rtbh_len_range"),
        CheckConstraint("min_prefix_len <= max_prefix_len", name="ck_rtbh_len_order"),
        CheckConstraint("max_routes BETWEEN 1 AND 10000", name="ck_rtbh_max_routes"),
        # Enabling requires community or next-hop AND a documented, verified policy.
        CheckConstraint(
            "NOT enabled OR ((cardinality(communities) > 0 OR next_hop IS NOT NULL) "
            "AND documentation_ref IS NOT NULL AND verified_at IS NOT NULL)",
            name="ck_rtbh_enable_requirements",
        ),
    )


class BgpNeighbor(TimestampMixin, Base):
    __tablename__ = "bgp_neighbors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # NULL router_id means the session is terminated on Shield's own FRR speaker.
    router_id: Mapped[int | None] = mapped_column(ForeignKey("routers.id", ondelete="CASCADE"))
    upstream_id: Mapped[int | None] = mapped_column(ForeignKey("upstream_providers.id", ondelete="SET NULL"))
    purpose: Mapped[BgpPurpose] = mapped_column(_enum(BgpPurpose, "bgp_purpose"), nullable=False)
    local_asn: Mapped[int] = mapped_column(BigInteger, nullable=False)
    remote_asn: Mapped[int] = mapped_column(BigInteger, nullable=False)
    neighbor_address: Mapped[str] = mapped_column(INET, nullable=False)
    local_address: Mapped[str | None] = mapped_column(INET)
    max_prefix_out: Mapped[int | None] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    managed_by_shield: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_state: Mapped[str | None] = mapped_column(String(32))
    last_state_change_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("router_id", "neighbor_address", name="uq_bgp_router_neighbor"),
        CheckConstraint("local_asn BETWEEN 1 AND 4294967295 AND remote_asn BETWEEN 1 AND 4294967295", name="ck_bgp_asn"),
        # Shield only ever manages its own signalling / RTBH / steering sessions, never transit.
        CheckConstraint("NOT managed_by_shield OR purpose <> 'transit'", name="ck_bgp_no_managed_transit"),
    )


class ProtectedPrefix(TimestampMixin, Base):
    __tablename__ = "protected_prefixes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    prefix: Mapped[str] = mapped_column(CIDR, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    ownership_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ownership_evidence: Mapped[str | None] = mapped_column(Text)  # IRR route object / ROA / LOA reference
    rtbh_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    steering_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    filtering_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Shortest prefix length any mitigation may target inside this prefix (32 = single hosts only).
    min_mitigation_prefix_len: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=32)
    preferred_upstream_id: Mapped[int | None] = mapped_column(
        ForeignKey("upstream_providers.id", ondelete="SET NULL")
    )
    authorized_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    authorized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        ExcludeConstraint(("prefix", "&&"), using="gist", name="ex_protected_prefixes_no_overlap",
                          ops={"prefix": "inet_ops"}),
        CheckConstraint("min_mitigation_prefix_len BETWEEN 0 AND 128", name="ck_pp_min_len"),
        CheckConstraint("min_mitigation_prefix_len >= masklen(prefix)", name="ck_pp_min_len_within"),
        CheckConstraint(
            "NOT (rtbh_allowed OR steering_allowed OR filtering_allowed) OR ownership_verified",
            name="ck_pp_mitigation_requires_ownership",
        ),
    )


class CustomerIpAssignment(TimestampMixin, Base):
    __tablename__ = "customer_ip_assignments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    address: Mapped[str] = mapped_column(CIDR, nullable=False)
    protected_prefix_id: Mapped[int] = mapped_column(
        ForeignKey("protected_prefixes.id", ondelete="RESTRICT"), nullable=False
    )
    customer_ref: Mapped[str] = mapped_column(String(64), nullable=False)
    customer_name: Mapped[str | None] = mapped_column(String(128))
    service_type: Mapped[ServiceType] = mapped_column(_enum(ServiceType, "service_type"), nullable=False)
    proxmox_node: Mapped[str | None] = mapped_column(String(64))
    proxmox_vmid: Mapped[int | None] = mapped_column(Integer)
    rtbh_opt_out: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    pps_threshold: Mapped[int | None] = mapped_column(BigInteger)
    bps_threshold: Mapped[int | None] = mapped_column(BigInteger)
    notes: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        ExcludeConstraint(("address", "&&"), using="gist", name="ex_customer_ip_no_overlap",
                          ops={"address": "inet_ops"}),
        Index("ix_customer_ip_customer_ref", "customer_ref"),
    )


# ---------------------------------------------------------------------------
# Telemetry (compact; raw flows live in ClickHouse from Phase 3)
# ---------------------------------------------------------------------------
class FlowSummary(Base):
    __tablename__ = "flow_summaries"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    bucket_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    dst: Mapped[str] = mapped_column(INET, nullable=False)
    protected_prefix_id: Mapped[int | None] = mapped_column(ForeignKey("protected_prefixes.id", ondelete="SET NULL"))
    ip_protocol: Mapped[int | None] = mapped_column(SmallInteger)
    packets: Mapped[int] = mapped_column(BigInteger, nullable=False)
    bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    flows: Mapped[int] = mapped_column(BigInteger, nullable=False)
    unique_sources: Mapped[int | None] = mapped_column(BigInteger)
    provenance: Mapped[Provenance] = mapped_column(_enum(Provenance, "provenance"), nullable=False)
    sampling_rate: Mapped[int | None] = mapped_column(Integer)
    exporter: Mapped[str | None] = mapped_column(INET)

    __table_args__ = (
        Index("ix_flow_summaries_dst_bucket", "dst", "bucket_start"),
        Index("ix_flow_summaries_bucket", "bucket_start"),
        CheckConstraint("bucket_seconds > 0 AND packets >= 0 AND bytes >= 0 AND flows >= 0", name="ck_flow_nonneg"),
    )


class TrafficBaseline(Base):
    __tablename__ = "traffic_baselines"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    scope: Mapped[str] = mapped_column(CIDR, nullable=False)
    metric: Mapped[str] = mapped_column(String(32), nullable=False)  # pps, bps, fps, syn_pps, udp_pps ...
    slot: Mapped[int] = mapped_column(SmallInteger, nullable=False)  # hour-of-week 0..167
    mean: Mapped[float] = mapped_column(Numeric(20, 4), nullable=False)
    stddev: Mapped[float] = mapped_column(Numeric(20, 4), nullable=False)
    p95: Mapped[float | None] = mapped_column(Numeric(20, 4))
    p99: Mapped[float | None] = mapped_column(Numeric(20, 4))
    samples: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("scope", "metric", "slot", name="uq_baseline_scope_metric_slot"),
        CheckConstraint("slot BETWEEN 0 AND 167", name="ck_baseline_slot"),
    )


# ---------------------------------------------------------------------------
# Incidents & mitigation
# ---------------------------------------------------------------------------
class AttackIncident(TimestampMixin, Base):
    __tablename__ = "attack_incidents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target: Mapped[str] = mapped_column(CIDR, nullable=False)
    protected_prefix_id: Mapped[int | None] = mapped_column(ForeignKey("protected_prefixes.id", ondelete="SET NULL"))
    status: Mapped[IncidentStatus] = mapped_column(_enum(IncidentStatus, "incident_status"), nullable=False)
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"), nullable=False)
    vectors: Mapped[list[str]] = mapped_column(ARRAY(String(32)), nullable=False, default=list)
    confidence: Mapped[Decimal] = mapped_column(Numeric(4, 3), nullable=False)
    peak_pps: Mapped[int | None] = mapped_column(BigInteger)
    peak_bps: Mapped[int | None] = mapped_column(BigInteger)
    peak_provenance: Mapped[Provenance | None] = mapped_column(_enum(Provenance, "provenance"))
    first_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str | None] = mapped_column(Text)
    # Phase 4
    scope: Mapped[str] = mapped_column(String(8), nullable=False, server_default="host")
    profile_id: Mapped[int | None] = mapped_column(ForeignKey("detection_profiles.id", ondelete="SET NULL"))
    resolution: Mapped[str | None] = mapped_column(String(24))
    last_hot_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    current: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict)
    confidence_breakdown: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"),
                                                       default=dict)

    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_incident_confidence"),
        CheckConstraint("scope IN ('host', 'prefix')", name="ck_incident_scope"),
        CheckConstraint(
            "resolution IS NULL OR resolution IN ('ended', 'cleared_unconfirmed', 'false_positive', 'superseded')",
            name="ck_incident_resolution"),
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_first_detected", "first_detected_at"),
        Index("ix_incidents_target_gist", "target", postgresql_using="gist", postgresql_ops={"target": "inet_ops"}),
        # At most one open incident per target: the detector updates it rather than opening duplicates.
        Index("uq_incidents_open_target", "target", unique=True,
              postgresql_where=text("status IN ('suspected','confirmed','mitigating','mitigated')")),
    )


OPEN_INCIDENT_STATES = ("suspected", "confirmed", "mitigating", "mitigated")


class AttackIncidentEvent(Base):
    """Timeline: suspected, confirmed, severity/vector changes, data gaps, operator actions, resolution."""

    __tablename__ = "attack_incident_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("attack_incidents.id", ondelete="CASCADE"), nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str] = mapped_column(String(64), nullable=False, default="detector")
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (Index("ix_incident_events_incident_at", "incident_id", "at"),)


class DetectionProfile(TimestampMixin, Base):
    """Detection thresholds and timers for a scope. The most specific enabled profile containing a
    destination applies; the 0.0.0.0/0 and ::/0 defaults always exist. Threshold NULL = check off.
    All rates are per second, after sampling has been scaled up."""

    __tablename__ = "detection_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    scope: Mapped[str] = mapped_column(CIDR, nullable=False, unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Per destination address
    dst_pps: Mapped[int | None] = mapped_column(BigInteger)
    dst_bps: Mapped[int | None] = mapped_column(BigInteger)
    syn_pps: Mapped[int | None] = mapped_column(BigInteger)
    tcp_flag_pps: Mapped[int | None] = mapped_column(BigInteger)   # ACK-only / RST floods
    udp_pps: Mapped[int | None] = mapped_column(BigInteger)
    icmp_pps: Mapped[int | None] = mapped_column(BigInteger)
    reflect_pps: Mapped[int | None] = mapped_column(BigInteger)    # from one amplification source port
    frag_pps: Mapped[int | None] = mapped_column(BigInteger)
    # Whole protected prefix (carpet bombing)
    prefix_pps: Mapped[int | None] = mapped_column(BigInteger)
    prefix_bps: Mapped[int | None] = mapped_column(BigInteger)
    # Learned baseline
    baseline_factor: Mapped[Decimal] = mapped_column(Numeric(6, 2), nullable=False, default=Decimal("4.00"))
    anomaly_min_pps: Mapped[int] = mapped_column(BigInteger, nullable=False, default=20000)
    # Timers / decision rules
    suspect_hits: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=3)
    suspect_window: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=5)
    confirm_seconds: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=20)
    confirm_confidence: Mapped[Decimal] = mapped_column(Numeric(4, 3), nullable=False, default=Decimal("0.700"))
    release_seconds: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=120)
    suspect_timeout_seconds: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=60)
    notes: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint("suspect_hits BETWEEN 1 AND suspect_window AND suspect_window BETWEEN 1 AND 60",
                        name="ck_profile_suspect"),
        CheckConstraint("confirm_seconds BETWEEN 3 AND 600", name="ck_profile_confirm"),
        CheckConstraint("release_seconds BETWEEN 10 AND 3600 AND suspect_timeout_seconds BETWEEN 10 AND 3600",
                        name="ck_profile_release"),
        CheckConstraint("confirm_confidence > 0 AND confirm_confidence <= 1", name="ck_profile_confidence"),
        CheckConstraint("baseline_factor >= 1", name="ck_profile_baseline_factor"),
        CheckConstraint(
            "coalesce(dst_pps,1) > 0 AND coalesce(dst_bps,1) > 0 AND coalesce(syn_pps,1) > 0 AND "
            "coalesce(tcp_flag_pps,1) > 0 AND coalesce(udp_pps,1) > 0 AND coalesce(icmp_pps,1) > 0 AND "
            "coalesce(reflect_pps,1) > 0 AND coalesce(frag_pps,1) > 0 AND coalesce(prefix_pps,1) > 0 AND "
            "coalesce(prefix_bps,1) > 0", name="ck_profile_positive"),
        CheckConstraint("NOT is_default OR masklen(scope) = 0", name="ck_profile_default_scope"),
    )


# Starting values. Conservative for a hosting network; tune per prefix/customer in the dashboard.
DEFAULT_PROFILE = dict(
    dst_pps=100_000, dst_bps=1_000_000_000, syn_pps=50_000, tcp_flag_pps=100_000, udp_pps=100_000,
    icmp_pps=20_000, reflect_pps=20_000, frag_pps=20_000, prefix_pps=500_000, prefix_bps=5_000_000_000,
)


class DetectionEvidence(Base):
    __tablename__ = "detection_evidence"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("attack_incidents.id", ondelete="CASCADE"), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    metric: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[float] = mapped_column(Numeric(24, 4), nullable=False)
    threshold: Mapped[float | None] = mapped_column(Numeric(24, 4))
    baseline: Mapped[float | None] = mapped_column(Numeric(24, 4))
    provenance: Mapped[Provenance] = mapped_column(_enum(Provenance, "provenance"), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (Index("ix_evidence_incident_at", "incident_id", "observed_at"),)


class MitigationPolicy(TimestampMixin, Base):
    __tablename__ = "mitigation_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    scope: Mapped[str] = mapped_column(CIDR, nullable=False)
    vectors: Mapped[list[str]] = mapped_column(ARRAY(String(32)), nullable=False, default=list)
    min_confidence: Mapped[Decimal] = mapped_column(Numeric(4, 3), nullable=False, default=Decimal("0.900"))
    min_duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    pps_threshold: Mapped[int | None] = mapped_column(BigInteger)
    bps_threshold: Mapped[int | None] = mapped_column(BigInteger)
    allowed_strategies: Mapped[list[str]] = mapped_column(ARRAY(String(32)), nullable=False, default=list)
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    max_scope_prefix_len: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=32)
    mitigation_duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=3600)
    min_hold_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=600)
    recovery_quiet_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=900)
    max_concurrent_actions: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    rollback_procedure: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        CheckConstraint("min_confidence >= 0 AND min_confidence <= 1", name="ck_policy_confidence"),
        CheckConstraint("max_scope_prefix_len BETWEEN 0 AND 128", name="ck_policy_scope_len"),
        CheckConstraint(
            "min_duration_seconds >= 0 AND mitigation_duration_seconds > 0 AND min_hold_seconds >= 0 "
            "AND recovery_quiet_seconds >= 0 AND cooldown_seconds >= 0 AND max_concurrent_actions > 0",
            name="ck_policy_timers",
        ),
        CheckConstraint(
            "allowed_strategies <@ ARRAY['rtbh_upstream','rtbh_internal','steering','local_filter','scrubbing']::varchar[]",
            name="ck_policy_strategies",
        ),
    )


class MitigationAction(TimestampMixin, Base):
    __tablename__ = "mitigation_actions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("attack_incidents.id", ondelete="SET NULL"))
    policy_id: Mapped[int | None] = mapped_column(ForeignKey("mitigation_policies.id", ondelete="SET NULL"))
    strategy: Mapped[Strategy] = mapped_column(_enum(Strategy, "strategy"), nullable=False)
    target: Mapped[str] = mapped_column(CIDR, nullable=False)
    protected_prefix_id: Mapped[int] = mapped_column(ForeignKey("protected_prefixes.id", ondelete="RESTRICT"), nullable=False)
    upstream_id: Mapped[int | None] = mapped_column(ForeignKey("upstream_providers.id", ondelete="SET NULL"))
    router_id: Mapped[int | None] = mapped_column(ForeignKey("routers.id", ondelete="SET NULL"))
    state: Mapped[ActionState] = mapped_column(_enum(ActionState, "action_state"), nullable=False)
    dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    automatic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    approved_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rejected_reason: Mapped[str | None] = mapped_column(Text)
    plan: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    impact: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    expected_state: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    observed_state: Mapped[dict | None] = mapped_column(JSONB)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_actions_state", "state"),
        # At most one live action per (strategy, target, upstream).
        Index(
            "uq_actions_live_target",
            "strategy",
            "target",
            text("coalesce(upstream_id, 0)"),
            unique=True,
            postgresql_where=text("state NOT IN ('rejected','withdrawn','rolled_back','failed')"),
        ),
        CheckConstraint("timeout_seconds BETWEEN 1 AND 3600", name="ck_actions_timeout"),
        CheckConstraint("state <> 'approved' OR approved_at IS NOT NULL OR automatic", name="ck_actions_approval"),
    )


class MitigationActionEvent(Base):
    __tablename__ = "mitigation_action_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    action_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("mitigation_actions.id", ondelete="CASCADE"), nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(32))
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (Index("ix_action_events_action_at", "action_id", "at"),)


class RtbhRoute(TimestampMixin, Base):
    """Ledger of every RTBH announcement and its withdrawal."""

    __tablename__ = "rtbh_routes"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    action_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("mitigation_actions.id", ondelete="RESTRICT"), nullable=False)
    mode: Mapped[RtbhMode] = mapped_column(_enum(RtbhMode, "rtbh_mode"), nullable=False)
    prefix: Mapped[str] = mapped_column(CIDR, nullable=False)
    upstream_id: Mapped[int | None] = mapped_column(ForeignKey("upstream_providers.id", ondelete="SET NULL"))
    communities: Mapped[list[str]] = mapped_column(ARRAY(String(64)), nullable=False, default=list)
    next_hop: Mapped[str | None] = mapped_column(INET)
    status: Mapped[RtbhStatus] = mapped_column(_enum(RtbhStatus, "rtbh_status"), nullable=False)
    announced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    withdraw_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    withdraw_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_verify_result: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        Index("ix_rtbh_status", "status"),
        Index("ix_rtbh_prefix_gist", "prefix", postgresql_using="gist", postgresql_ops={"prefix": "inet_ops"}),
        CheckConstraint("mode = 'internal' OR upstream_id IS NOT NULL", name="ck_rtbh_upstream_required"),
    )


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------
class NotificationChannel(TimestampMixin, Base):
    __tablename__ = "notification_channels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    kind: Mapped[ChannelKind] = mapped_column(_enum(ChannelKind, "channel_kind"), nullable=False)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)   # non-secret settings
    secret_enc: Mapped[str | None] = mapped_column(Text)                       # token / password / HMAC key
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    min_severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"), nullable=False, default=Severity.MEDIUM)
    event_types: Mapped[list[str]] = mapped_column(ARRAY(String(48)), nullable=False, default=list)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    escalate_after_seconds: Mapped[int | None] = mapped_column(Integer)


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    channel_id: Mapped[int] = mapped_column(ForeignKey("notification_channels.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"), nullable=False)
    dedup_key: Mapped[str] = mapped_column(String(128), nullable=False)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("attack_incidents.id", ondelete="SET NULL"))
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_notifications_dedup", "channel_id", "dedup_key", "created_at"),
        CheckConstraint("status IN ('pending','sent','suppressed','failed')", name="ck_notifications_status"),
    )


# ---------------------------------------------------------------------------
# Audit, health, config history, settings
# ---------------------------------------------------------------------------
class AuditLog(Base):
    """Append-only, hash-chained. UPDATE/DELETE blocked by trigger (see migration 0001)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    actor_username: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(512))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(64))
    entity_id: Mapped[str | None] = mapped_column(String(64))
    before: Mapped[dict | None] = mapped_column(JSONB)
    after: Mapped[dict | None] = mapped_column(JSONB)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    __table_args__ = (
        Index("ix_audit_at", "at"),
        Index("ix_audit_entity", "entity_type", "entity_id"),
        Index("ix_audit_actor", "actor_user_id"),
    )


class SystemHealth(Base):
    __tablename__ = "system_health"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    component: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[DeviceStatus] = mapped_column(_enum(DeviceStatus, "device_status"), nullable=False)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (Index("ix_health_component_at", "component", "checked_at"),)


class ConfigVersion(Base):
    __tablename__ = "config_versions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot: Mapped[dict | None] = mapped_column(JSONB)  # NULL = deleted
    changed_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    change_note: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (UniqueConstraint("entity_type", "entity_id", "version", name="uq_config_versions"),)


class SystemSetting(Base):
    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict | list | str | int | bool | None] = mapped_column(JSONB, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


DEFAULT_SETTINGS: dict[str, tuple[object, str]] = {
    "automation_enabled": (False, "Master switch for automatic mitigation. Off by default."),
    "rtbh_emergency_disable": (False, "When true, no new RTBH announcements are permitted."),
    "global_max_rtbh_routes": (50, "Hard ceiling on simultaneously announced RTBH routes."),
    "require_mfa_for_admin": (False, "Require TOTP MFA for administrator logins."),
    "require_mfa_for_mitigation": (False, "Require an MFA-verified session to approve mitigations."),
    "retention_flow_summaries_days": (30, "Retention for flow_summaries rows."),
    "retention_login_attempts_days": (180, "Retention for login_attempts rows."),
    "retention_system_health_days": (30, "Retention for system_health rows."),
    "retention_notifications_days": (90, "Retention for notifications rows."),
    "false_positive_suppress_minutes": (30, "After an incident is marked a false positive, how long the same target is not re-reported."),
    "collector_address": ("", "Address routers should send flow exports to (used to check router configuration)."),
}
