from __future__ import annotations

import asyncio
import contextlib
import logging

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DBAPIError, IntegrityError

from . import __version__
from . import telemetry
from .api import auth, bgp, customers, devices, prefixes, system, traffic, upstreams, users
from .config import get_settings
from .db import session_factory

log = logging.getLogger("shield.api")

API_PREFIX = "/api/v1"

DESCRIPTION = """
Management API for **Crapplet DDoS Shield**.

All endpoints except `GET /health` and `POST /auth/login` / `POST /auth/refresh` require a
bearer access token. Every state-changing call is recorded in the hash-chained audit log.

Scope (v0.3): identity, RBAC, inventory, settings, audit, and live/historical traffic from the
flow collector (`/traffic/*`, WebSocket `/ws/traffic`). No endpoint in this version contacts a
router or a BGP peer.
"""


def _republish_prefixes() -> None:
    db = session_factory()()
    try:
        telemetry.publish_prefixes(db)
    finally:
        db.close()


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    """Keep the collector's prefix list fresh even if a publish was missed (e.g. Redis restart)."""
    async def loop():
        while True:
            try:
                await asyncio.to_thread(_republish_prefixes)
            except Exception:  # never let telemetry take the API down
                log.exception("prefix republish failed")
            await asyncio.sleep(60)

    task = asyncio.create_task(loop())
    yield
    task.cancel()


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(
        lifespan=lifespan,
        title="Crapplet DDoS Shield API",
        version=__version__,
        description=DESCRIPTION,
        docs_url=f"{API_PREFIX}/docs" if s.docs_enabled else None,
        redoc_url=None,
        openapi_url=f"{API_PREFIX}/openapi.json" if s.docs_enabled else None,
    )
    if s.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=s.cors_origins, allow_credentials=False,
                           allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                           allow_headers=["Authorization", "Content-Type", "Idempotency-Key"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > 1_000_000:
            return JSONResponse({"detail": "Request body too large"}, status_code=413)
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.exception_handler(IntegrityError)
    async def integrity(_: Request, exc: IntegrityError):
        msg = str(exc.orig).split("\n")[0] if exc.orig else "constraint violation"
        code = status.HTTP_409_CONFLICT
        lowered = msg.lower()
        if "check constraint" in lowered or "violates check" in lowered:
            code = 422
        if "ex_protected_prefixes_no_overlap" in msg:
            msg = "Prefix overlaps an existing protected prefix"
        elif "ex_customer_ip_no_overlap" in msg:
            msg = "Address overlaps an existing customer assignment"
        return JSONResponse({"detail": msg}, status_code=code)

    @app.exception_handler(DBAPIError)
    async def dbapi(_: Request, exc: DBAPIError):
        sqlstate = getattr(exc.orig, "sqlstate", None)
        if sqlstate == "23514":  # check_violation raised by our triggers
            return JSONResponse({"detail": str(exc.orig).split("\n")[0]}, status_code=422)
        log.exception("database error")
        return JSONResponse({"detail": "Database error"}, status_code=503)

    for module in (system, auth, users, prefixes, devices, upstreams, bgp, customers, traffic):
        app.include_router(module.router, prefix=API_PREFIX)
    return app


app = create_app()
