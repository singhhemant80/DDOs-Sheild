"""Delivery to e-mail (SMTP), Telegram and webhooks. Secrets come decrypted from the channel."""
from __future__ import annotations

import hashlib
import hmac
import json
import smtplib
import ssl
from email.message import EmailMessage
from urllib.parse import urlparse

import httpx

from .events import Alert

TIMEOUT = 10.0


class SendError(RuntimeError):
    pass


def validate(kind: str, cfg: dict) -> dict:
    """Check a channel's non-secret settings; returns the cleaned config."""
    if kind == "email":
        host = str(cfg.get("host") or "").strip()
        to = [str(x).strip() for x in (cfg.get("to") or []) if str(x).strip()]
        if not host or not to:
            raise ValueError("e-mail needs an SMTP host and at least one recipient")
        if any("@" not in x or "\n" in x for x in to) or "\n" in host:
            raise ValueError("recipients must be e-mail addresses")
        port = int(cfg.get("port") or 587)
        security = cfg.get("security") or "starttls"
        if security not in ("starttls", "tls", "none"):
            raise ValueError("security must be starttls, tls or none")
        sender = str(cfg.get("from") or "").strip()
        if "@" not in sender or "\n" in sender:
            raise ValueError("from must be an e-mail address")
        return {"host": host, "port": port, "security": security, "username": str(cfg.get("username") or "") or None,
                "from": sender, "to": to[:20]}
    if kind == "telegram":
        chat = str(cfg.get("chat_id") or "").strip()
        if not chat or not chat.lstrip("-").isdigit() and not chat.startswith("@"):
            raise ValueError("Telegram needs a chat id (a number, or @channelname)")
        return {"chat_id": chat}
    if kind == "webhook":
        url = str(cfg.get("url") or "").strip()
        u = urlparse(url)
        if u.scheme not in ("https", "http") or not u.hostname or u.username:
            raise ValueError("webhook URL must be http(s)://host/... without user:password")
        fmt = cfg.get("format") or "json"
        if fmt not in ("json", "slack"):
            raise ValueError("format must be json or slack (Slack/Mattermost/Teams-compatible text)")
        return {"url": url, "format": fmt}
    raise ValueError("unknown channel kind")


def send(kind: str, cfg: dict, secret: str | None, alert: Alert, transport: httpx.BaseTransport | None = None,
         smtp_factory=None) -> None:
    if kind == "email":
        return _email(cfg, secret, alert, smtp_factory)
    if kind == "telegram":
        return _telegram(cfg, secret, alert, transport)
    if kind == "webhook":
        return _webhook(cfg, secret, alert, transport)
    raise SendError(f"unknown channel kind {kind}")


def _email(cfg: dict, password: str | None, a: Alert, smtp_factory=None) -> None:
    msg = EmailMessage()
    msg["Subject"] = f"[Shield {a.severity}] {a.title}"[:200]
    msg["From"] = cfg["from"]
    msg["To"] = ", ".join(cfg["to"])
    msg.set_content(a.text() + "\n\n-- Crapplet DDoS Shield")
    try:
        if smtp_factory:
            s = smtp_factory(cfg)
        elif cfg["security"] == "tls":
            s = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=TIMEOUT, context=ssl.create_default_context())
        else:
            s = smtplib.SMTP(cfg["host"], cfg["port"], timeout=TIMEOUT)
        with s:
            if cfg["security"] == "starttls" and not smtp_factory:
                s.starttls(context=ssl.create_default_context())
            if cfg.get("username") and password:
                s.login(cfg["username"], password)
            s.send_message(msg)
    except (OSError, smtplib.SMTPException) as e:
        raise SendError(f"SMTP: {e}") from None


def _telegram(cfg: dict, token: str | None, a: Alert, transport=None) -> None:
    if not token:
        raise SendError("no bot token stored")
    try:
        with httpx.Client(timeout=TIMEOUT, transport=transport) as c:
            r = c.post(f"https://api.telegram.org/bot{token}/sendMessage",
                       json={"chat_id": cfg["chat_id"], "text": a.text()[:4000], "disable_web_page_preview": True})
    except httpx.HTTPError as e:
        raise SendError(f"Telegram: {type(e).__name__}") from None
    if r.status_code != 200:
        raise SendError(f"Telegram answered {r.status_code}: {r.text[:200].replace(token, '***')}")


def _webhook(cfg: dict, key: str | None, a: Alert, transport=None) -> None:
    body = {"text": a.text()} if cfg.get("format") == "slack" else {"source": "crapplet-shield", **a.payload()}
    raw = json.dumps(body).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "Crapplet-Shield"}
    if key:
        headers["X-Shield-Signature"] = "sha256=" + hmac.new(key.encode(), raw, hashlib.sha256).hexdigest()
    try:
        with httpx.Client(timeout=TIMEOUT, transport=transport, follow_redirects=False) as c:
            r = c.post(cfg["url"], content=raw, headers=headers)
    except httpx.HTTPError as e:
        raise SendError(f"webhook: {type(e).__name__}: {e}") from None
    if not 200 <= r.status_code < 300:
        raise SendError(f"webhook answered {r.status_code}: {r.text[:200]}")
