"""Scrubbing-centre adapter (Phase 9 part 3): divert an attacked prefix to an on-demand scrubbing
service, which cleans the traffic and returns it to you (typically over a GRE tunnel or a direct
interconnect that you set up with the provider beforehand).

Providers differ, so the adapter is generic and driven by what the provider documents:

  api     Shield calls the provider's HTTPS API to start and stop diversion of a prefix, with your
          API token, and optionally polls a status URL to confirm it is active.
  manual  Shield records the request and shows the steps; a person triggers it with the provider
          (portal, phone, e-mail) and the action stays active until withdrawn.

Request templates may contain {prefix}, {target}, {action_id}, {incident_id}; values are validated
before they are substituted (addresses, prefixes and UUIDs only). Only HTTPS URLs are allowed, and
not to private, loopback or link-local addresses, so the feature cannot be used to reach internal
services. Redirects are not followed. The token is stored encrypted and never returned.

Where requests go is the `scrubbing_backend` setting: simulated (default; no provider is called)
or live.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import uuid
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx
import redis

from .speaker import SpeakerError, SpeakerRefused

KEY_SIM = "shield:sim:scrub"
KEY_FAULT = "shield:sim:fault"
PLACEHOLDER = re.compile(r"\{(prefix|target|action_id|incident_id)\}")
HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")
TIMEOUT = 15.0


# ---------------------------------------------------------------- configuration
def validate_url(url: str, *, resolve: bool = True) -> str:
    """HTTPS only, and never to an internal address (unless SHIELD_SCRUBBING_ALLOW_PRIVATE=1, lab/tests)."""
    u = urlparse(url or "")
    allow_private = os.environ.get("SHIELD_SCRUBBING_ALLOW_PRIVATE") == "1"
    if u.scheme != "https" and not (allow_private and u.scheme == "http"):
        raise ValueError("provider URLs must use https")
    if not u.hostname or u.username or u.password:
        raise ValueError("the URL needs a host name and no user:password part")
    hosts: list[str] = []
    try:
        hosts = [str(ipaddress.ip_address(u.hostname))]
    except ValueError:
        if resolve:
            try:
                hosts = sorted({i[4][0] for i in socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP)})
            except socket.gaierror:
                raise ValueError(f"cannot resolve {u.hostname}") from None
    for h in hosts:
        ip = ipaddress.ip_address(h.split("%")[0])
        if not allow_private and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                                  or ip.is_reserved or ip.is_unspecified):
            raise ValueError(f"{u.hostname} resolves to an internal address ({ip}); Shield only calls public APIs")
    if PLACEHOLDER.sub("", url).count("{"):
        raise ValueError("unknown placeholder in URL; use {prefix}, {target}, {action_id} or {incident_id}")
    return url


def validate_config(method: str, cfg: dict, *, resolve: bool = True) -> dict:
    out: dict = {}
    if method == "manual":
        return {"steps": str(cfg.get("steps") or "")[:4000]}
    for step in ("activate", "deactivate", "status"):
        c = cfg.get(step) or {}
        if not c:
            if step == "status":
                continue
            raise ValueError(f"the {step} request is required for the api method")
        verb = str(c.get("method") or ("GET" if step == "status" else "POST")).upper()
        if verb not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
            raise ValueError(f"{step}: method must be GET, POST, PUT, DELETE or PATCH")
        body = c.get("body")
        if body not in (None, ""):
            if not isinstance(body, str) or len(body) > 8000:
                raise ValueError(f"{step}: body must be text (a JSON template)")
            try:
                json.loads(PLACEHOLDER.sub('x', body))
            except ValueError:
                raise ValueError(f"{step}: body must be JSON; use placeholders inside strings, e.g. \"{{prefix}}\"") from None
        headers = c.get("headers") or {}
        if not isinstance(headers, dict) or len(headers) > 10:
            raise ValueError(f"{step}: headers must be a small name -> value map")
        for k, v in headers.items():
            if not HEADER_NAME.match(str(k)) or "\n" in str(v) or "\r" in str(v) or len(str(v)) > 500:
                raise ValueError(f"{step}: invalid header {k!r}")
        item = {"url": validate_url(str(c.get("url") or ""), resolve=resolve), "method": verb, "body": body or None,
                "headers": {str(k): str(v) for k, v in headers.items()}}
        if step == "status":
            path = str(c.get("active_path") or "")
            if path and not re.fullmatch(r"[A-Za-z0-9_]+(\.[A-Za-z0-9_]+){0,5}", path):
                raise ValueError("status: active_path is a dotted JSON path, e.g. data.state")
            item |= {"active_path": path or None, "active_value": str(c.get("active_value") or "") or None}
        out[step] = item
    return out


# ---------------------------------------------------------------- requests
@dataclass(frozen=True)
class Diversion:
    provider_id: int
    prefix: str
    target: str
    action_id: str
    incident_id: str | None = None

    def values(self) -> dict[str, str]:
        ipaddress.ip_network(self.prefix)
        ipaddress.ip_network(self.target, strict=False)
        uuid.UUID(self.action_id)
        if self.incident_id:
            uuid.UUID(self.incident_id)
        return {"prefix": self.prefix, "target": self.target, "action_id": self.action_id,
                "incident_id": self.incident_id or ""}

    def to_dict(self) -> dict:
        return {"provider_id": self.provider_id, "prefix": self.prefix, "target": self.target}


def render(template: str | None, values: dict[str, str]) -> str | None:
    if template is None:
        return None
    return PLACEHOLDER.sub(lambda m: values[m.group(1)], template)


def _redact(text: str, secret: str | None) -> str:
    text = (text or "")[:500]
    return text.replace(secret, "***") if secret else text


def _dig(doc, path: str):
    for part in path.split("."):
        if isinstance(doc, dict) and part in doc:
            doc = doc[part]
        else:
            return None
    return doc


class ScrubbingBackend:
    name = "base"

    def call(self, provider, step: str, d: Diversion) -> dict:
        raise NotImplementedError

    def is_active(self, provider, d: Diversion) -> bool | None:
        """True/False if the provider reports it, None if it cannot tell."""
        raise NotImplementedError


class SimulatedScrubbing(ScrubbingBackend):
    """Records diversions in Redis; no provider is called. Fault: SET shield:sim:fault "scrub"."""
    name = "simulated"

    def __init__(self, rds: redis.Redis):
        self.rds = rds

    def call(self, provider, step: str, d: Diversion) -> dict:
        if self.rds.get(KEY_FAULT) == "scrub":
            raise SpeakerError("the provider refused the request (simulated fault)")
        key = f"{provider.id}|{d.prefix}"
        if step == "activate":
            self.rds.hset(KEY_SIM, key, d.action_id)
        elif step == "deactivate":
            self.rds.hdel(KEY_SIM, key)
        return {"status": 200, "body": "simulated"}

    def is_active(self, provider, d: Diversion) -> bool | None:
        return self.rds.hget(KEY_SIM, f"{provider.id}|{d.prefix}") == d.action_id


class HttpScrubbing(ScrubbingBackend):
    name = "live"

    def __init__(self, transport: httpx.BaseTransport | None = None):
        self.transport = transport

    def _secret(self, provider) -> str | None:
        if not provider.secret_enc:
            return None
        from .. import security
        try:
            return security.decrypt_secret(provider.secret_enc)
        except Exception:
            raise SpeakerRefused(f"cannot decrypt the API token of {provider.name}; enter it again") from None

    def _request(self, provider, c: dict, d: Diversion) -> httpx.Response:
        vals = d.values()
        url = render(c["url"], vals)
        try:
            validate_url(url)        # re-check at call time (DNS may have changed)
        except ValueError as e:
            raise SpeakerRefused(f"{provider.name}: {e}") from None
        headers = {"User-Agent": "Crapplet-Shield", **(c.get("headers") or {})}
        body = render(c.get("body"), vals)
        if body is not None:
            headers.setdefault("Content-Type", "application/json")
        secret = self._secret(provider)
        if provider.auth_header and secret:
            headers[provider.auth_header] = secret
        try:
            with httpx.Client(timeout=TIMEOUT, follow_redirects=False, transport=self.transport) as cl:
                return cl.request(c["method"], url, content=body, headers=headers)
        except httpx.HTTPError as e:
            raise SpeakerError(f"{provider.name}: {type(e).__name__}: {_redact(str(e), secret)}") from None

    def call(self, provider, step: str, d: Diversion) -> dict:
        if provider.method == "manual":
            return {"status": None, "body": "manual: trigger it with the provider"}
        c = (provider.config or {}).get(step)
        if not c:
            raise SpeakerRefused(f"{provider.name} has no {step} request configured")
        r = self._request(provider, c, d)
        secret = self._secret(provider)
        if not 200 <= r.status_code < 300:
            msg = f"{provider.name} answered HTTP {r.status_code}: {_redact(r.text, secret)}"
            if r.status_code in (400, 401, 403, 404, 405, 409, 422):
                raise SpeakerRefused(msg)
            raise SpeakerError(msg)
        return {"status": r.status_code, "body": _redact(r.text, secret)}

    def is_active(self, provider, d: Diversion) -> bool | None:
        if provider.method == "manual":
            return None
        c = (provider.config or {}).get("status")
        if not c:
            return None
        r = self._request(provider, c, d)
        if not 200 <= r.status_code < 300:
            raise SpeakerError(f"{provider.name} status answered HTTP {r.status_code}")
        if not c.get("active_path"):
            return True
        try:
            val = _dig(r.json(), c["active_path"])
        except ValueError:
            raise SpeakerError(f"{provider.name} status did not return JSON") from None
        want = c.get("active_value")
        return (str(val).lower() == want.lower()) if want else bool(val)


def make_backend(name: str, rds: redis.Redis) -> ScrubbingBackend:
    return HttpScrubbing() if name == "live" else SimulatedScrubbing(rds)


# ---------------------------------------------------------------- planning
def _scrub_plan(db, req, net, target: str, routes: list, checks: list, impact: list) -> None:
    from sqlalchemy import select

    from ..changes import get_setting
    from ..models import ActionState, MitigationAction, ScrubbingProvider, Strategy

    def chk(level, code, msg):
        checks.append({"level": level, "code": code, "message": msg})

    provs = db.execute(select(ScrubbingProvider).where(ScrubbingProvider.enabled).order_by(ScrubbingProvider.name)).scalars().all()
    if req.scrubbing_provider_id is not None:
        p = next((x for x in provs if x.id == req.scrubbing_provider_id), None)
        if p is None:
            chk("block", "scrub_provider", f"Scrubbing provider {req.scrubbing_provider_id} does not exist or is disabled.")
            return
    else:
        usable = [x for x in provs if x.verified_at]
        if not usable:
            chk("block", "scrub_provider", "No enabled, verified scrubbing provider. Add one under Routers & upstreams → "
                                           "Scrubbing providers.")
            return
        p = usable[0]
    if not p.verified_at:
        chk("block", "scrub_verified", f"{p.name} has not been verified (check its settings against the provider's "
                                       "documentation, then Mark as verified).")
    if not p.min_prefix_len <= net.prefixlen <= p.max_prefix_len:
        chk("block", "scrub_length", f"{p.name} diverts /{p.min_prefix_len} to /{p.max_prefix_len}; {target} is /{net.prefixlen}.")
    live = db.execute(select(MitigationAction).where(
        MitigationAction.strategy == Strategy.SCRUBBING,
        MitigationAction.state.in_([ActionState.PROPOSED, ActionState.APPROVED, ActionState.EXECUTING, ActionState.ACTIVE,
                                    ActionState.WITHDRAWING]))).scalars().all()
    exclude = {str(x) for x in req.exclude_action_ids}
    live = [a for a in live if str(a.id) not in exclude]
    if any(str(a.target) == target for a in live):
        chk("block", "duplicate", f"{target} is already being diverted for scrubbing.")
    mine = [a for a in live if ((a.plan or {}).get("route") or {}).get("scrubbing_provider_id") == p.id]
    if len(mine) + 1 > p.max_prefixes:
        chk("block", "scrub_limit", f"{p.name} allows {p.max_prefixes} diverted prefixes and {len(mine)} are in use.")
    backend = get_setting(db, "scrubbing_backend", "simulated")
    if p.method == "manual":
        chk("warn", "scrub_manual", f"{p.name} is a manual provider: Shield records the diversion, but someone must "
                                    "trigger it with the provider (and stop it again when it is withdrawn).")
    elif backend != "live":
        chk("warn", "scrub_simulated", "Scrubbing backend is simulated: no provider is called. Set scrubbing_backend to "
                                       "live in Settings to divert for real.")
    else:
        chk("warn", "scrub_real", f"This calls {p.name}'s API to divert {target}: traffic to it will flow through their "
                                  "network.")
    if not (p.config or {}).get("status") and p.method == "api":
        chk("warn", "scrub_no_status", f"{p.name} has no status request: Shield can only check that the provider "
                                       "accepted the request, not that diversion is active.")
    if p.verified_at and p.min_prefix_len <= net.prefixlen <= p.max_prefix_len:
        chk("ok", "scrub_provider_ok", f"{p.name}: verified ({p.documentation_ref or 'documented'}).")
    routes.append({"peer": f"scrub:{p.id}", "upstream_id": None, "upstream": None, "asn": None, "prefix": target,
                   "router_id": None, "router": None, "scrubbing_provider_id": p.id, "provider": p.name,
                   "communities": [], "next_hop": None, "no_export": False,
                   "description": f"divert {target} to {p.name}" + (" (manual)" if p.method == "manual" else " (API)")})
    impact.append(f"All traffic to {target} ({net.num_addresses} addresses) is routed through {p.name}, which drops the "
                  "attack and returns clean traffic to you" + (f" ({p.notes})" if p.notes else "") + ".")
    impact.append("Expect some added latency while diverted. Make sure the return path (for example the GRE tunnel) is "
                  "up before relying on it.")
