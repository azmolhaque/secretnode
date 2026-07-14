"""
SecretNode v2.0 — main.py
FastAPI application: REST API + WebSocket live streaming + static file server
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import ipaddress
import secrets
import socket
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, field_validator
import uvicorn

# uvloop is a performance optimisation (2–4× faster loop), not a requirement.
# On some platforms (ARM64 wheels, partial installs) it may be missing or broken —
# fall back to the stdlib asyncio loop rather than crashing the whole server on import.
try:
    import uvloop  # noqa: F401 — presence gates the fast event loop selection below
    _HAS_UVLOOP = True
except Exception:  # noqa: BLE001 — any import/runtime failure must degrade gracefully
    _HAS_UVLOOP = False

load_dotenv()
# We deliberately do NOT call uvloop.install() here: it is deprecated on Python
# 3.12+, and uvicorn already selects the event loop itself via --loop (auto/uvloop),
# so the speed-up is preserved without a module-level global side effect.

from scanner import run_scan, ScanState
from storage import (
    init_db, save_scan, load_scans, load_scan, get_previous_scan_for_target,
    mark_false_positive, unmark_false_positive, get_suppressed_fingerprints,
    list_false_positives,
)
import report as report_gen

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("secretnode.api")

# ─────────────────────────────────────────────────────────────────────────────
# Auth: simple API-key gate (required — the tool refuses to boot without one)
# ─────────────────────────────────────────────────────────────────────────────

API_KEY = os.environ.get("SECRETNODE_API_KEY", "")
if not API_KEY:
    raise RuntimeError(
        "SECRETNODE_API_KEY is not set. Generate one (e.g. `openssl rand -hex 24`) "
        "and put it in .env before starting SecretNode. This tool scans and stores "
        "live credentials — it must never be reachable without authentication."
    )

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(key: str | None = Depends(_api_key_header)) -> None:
    if not key or not secrets.compare_digest(key, API_KEY):
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key")


# ─────────────────────────────────────────────────────────────────────────────
# SSRF guard: block scans against loopback / private / link-local targets
# unless explicitly allowed (useful only for testing your own lab infra)
# ─────────────────────────────────────────────────────────────────────────────

ALLOW_PRIVATE_TARGETS = os.environ.get("ALLOW_PRIVATE_TARGETS", "false").lower() == "true"


def assert_public_target(url: str) -> None:
    if ALLOW_PRIVATE_TARGETS:
        return
    host = urlparse(url).hostname
    if not host:
        raise ValueError("Could not parse hostname from target_url")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target host: {host}") from exc
    for family, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast
        ):
            raise ValueError(
                f"Target {host} resolves to a private/internal address ({ip}). "
                "Refusing to scan — set ALLOW_PRIVATE_TARGETS=true in .env only "
                "for authorized internal lab testing."
            )


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket Connection Manager
# ─────────────────────────────────────────────────────────────────────────────

class ConnectionManager:
    """Manages all active WebSocket connections and per-scan subscriptions."""

    def __init__(self) -> None:
        # scan_id → set of websockets subscribed to that scan
        self._subscriptions: dict[str, set[WebSocket]] = {}
        # global listeners (receive all events)
        self._global: set[WebSocket] = set()

    async def connect_global(self, ws: WebSocket) -> None:
        await ws.accept()
        self._global.add(ws)
        logger.info("WS global connected — total: %d", len(self._global))

    async def connect_scan(self, ws: WebSocket, scan_id: str) -> None:
        await ws.accept()
        self._subscriptions.setdefault(scan_id, set()).add(ws)
        logger.info("WS scan/%s connected", scan_id)

    def disconnect(self, ws: WebSocket, scan_id: str | None = None) -> None:
        self._global.discard(ws)
        if scan_id:
            bucket = self._subscriptions.get(scan_id, set())
            bucket.discard(ws)
        logger.info("WS disconnected")

    async def broadcast_scan(self, scan_id: str, event: dict[str, Any]) -> None:
        """Send event to all subscribers of a scan AND all global listeners."""
        payload = json.dumps(event)
        targets = (
            self._subscriptions.get(scan_id, set()) | self._global
        )
        dead: list[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws, scan_id)

    async def broadcast_global(self, event: dict[str, Any]) -> None:
        payload = json.dumps(event)
        dead: list[WebSocket] = []
        for ws in self._global:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


# ─────────────────────────────────────────────────────────────────────────────
# In-Memory Scan Registry
# ─────────────────────────────────────────────────────────────────────────────

# scan_id → {"state": ScanState, "task": asyncio.Task, "meta": dict}
_registry: dict[str, dict[str, Any]] = {}


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SecretNode v2.4.0 starting…")
    await init_db()
    yield
    # Cancel any running scans on shutdown
    for entry in _registry.values():
        task: asyncio.Task = entry.get("task")
        if task and not task.done():
            task.cancel()
    logger.info("SecretNode v2.4.0 shut down cleanly")


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI App
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SecretNode v2.4.0",
    description="Real-time passive ASM scanner for credential leak detection",
    version="2.4.0",
    lifespan=lifespan,
)

_allowed_origins = [
    o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,          # explicit list — no wildcard
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "Content-Type"],
)
if not _allowed_origins:
    logger.warning(
        "ALLOWED_ORIGINS is empty — cross-origin browser requests will be blocked. "
        "Set it in .env (comma-separated) if the dashboard is served from a different origin."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic Models
# ─────────────────────────────────────────────────────────────────────────────

MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "3"))

_discord_webhook = os.environ.get("DISCORD_WEBHOOK_URL", "")
if _discord_webhook and not _discord_webhook.startswith("https://discord.com/api/webhooks/") \
        and not _discord_webhook.startswith("https://discordapp.com/api/webhooks/"):
    logger.warning(
        "DISCORD_WEBHOOK_URL doesn't look like a real Discord webhook URL — "
        "alerts will silently fail. Double-check it in .env."
    )


DEFAULT_CRAWL_PAGES = int(os.environ.get("DEFAULT_CRAWL_PAGES", "1"))
MAX_CRAWL_PAGES_CAP  = int(os.environ.get("MAX_CRAWL_PAGES_CAP", "15"))


class ScanRequest(BaseModel):
    target_url: str
    crawl_pages: int = DEFAULT_CRAWL_PAGES
    verify: bool = False          # live-verify confirmed findings against provider APIs (opt-in)
    only_verified: bool = False   # drop confirmed-inactive findings (TruffleHog-style)

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must begin with http:// or https://")
        if len(v) > 2048:
            raise ValueError("URL too long (max 2048 characters)")
        return v

    @field_validator("crawl_pages")
    @classmethod
    def validate_crawl_pages(cls, v: int) -> int:
        if v < 1:
            return 1
        if v > MAX_CRAWL_PAGES_CAP:
            return MAX_CRAWL_PAGES_CAP
        return v


# ─────────────────────────────────────────────────────────────────────────────
# REST Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "SecretNode v2.4.0",
        "gemini_configured": bool(os.environ.get("GEMINI_API_KEY")),
        "discord_configured": bool(os.environ.get("DISCORD_WEBHOOK_URL")),
        "max_concurrent_scans": MAX_CONCURRENT_SCANS,
        "verification_default": os.environ.get("VERIFY_SECRETS", "false").lower() == "true",
        "active_scans": sum(1 for e in _registry.values() if not e["task"].done()),
    }


@app.post("/api/scans", status_code=202, dependencies=[Depends(require_api_key)])
async def start_scan(request: ScanRequest, http_request: Request) -> dict[str, Any]:
    """
    Start a new background scan. Returns immediately with scan_id.
    Connect to /ws/logs/{scan_id} to stream results. Requires X-API-Key header.
    Limited to MAX_CONCURRENT_SCANS simultaneous scans to protect the host.
    """
    client_ip = http_request.client.host if http_request.client else "unknown"
    logger.info("AUDIT scan_request client=%s target=%s", client_ip, request.target_url)

    try:
        assert_public_target(request.target_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    active_count = sum(1 for e in _registry.values() if not e["task"].done())
    if active_count >= MAX_CONCURRENT_SCANS:
        raise HTTPException(
            status_code=429,
            detail=(
                f"{active_count} scan(s) already running "
                f"(limit: {MAX_CONCURRENT_SCANS}). Wait for one to finish or "
                f"raise MAX_CONCURRENT_SCANS in .env if the host can handle more."
            ),
        )

    scan_id = str(uuid.uuid4())
    state   = ScanState()

    async def broadcaster(event: dict[str, Any]) -> None:
        await manager.broadcast_scan(scan_id, event)

    async def _run() -> None:
        try:
            previous_scan = await get_previous_scan_for_target(request.target_url, scan_id)
            known_fps = frozenset(
                f["fingerprint"] for f in (previous_scan or {}).get("confirmed_findings", [])
                if "fingerprint" in f
            )
            suppressed_fps = await get_suppressed_fingerprints(request.target_url)

            result = await run_scan(
                target_url=request.target_url,
                scan_id=scan_id,
                broadcast=broadcaster,
                state=state,
                known_fingerprints=known_fps,
                suppressed_fingerprints=suppressed_fps,
                max_crawl_pages=request.crawl_pages,
                verify=request.verify,
                only_verified=request.only_verified,
            )
            _registry[scan_id]["meta"] = result
            await save_scan(scan_id, result)
        except asyncio.CancelledError:
            logger.info("Scan %s task cancelled", scan_id)
            await manager.broadcast_scan(scan_id, {
                "type": "scan_cancelled",
                "scan_id": scan_id,
            })
        except Exception as exc:
            logger.exception("Scan %s crashed", scan_id)
            await manager.broadcast_scan(scan_id, {
                "type": "scan_error",
                "scan_id": scan_id,
                "error": str(exc),
            })

    task = asyncio.create_task(_run(), name=f"scan-{scan_id}")
    _registry[scan_id] = {
        "state":      state,
        "task":       task,
        "meta":       {
            "scan_id":    scan_id,
            "target_url": request.target_url,
            "status":     "running",
        },
    }

    logger.info("Scan %s started for %s", scan_id, request.target_url)
    return {
        "scan_id":    scan_id,
        "target_url": request.target_url,
        "status":     "started",
        "ws_url":     f"/ws/logs/{scan_id}",
        "message":    "Connect to ws_url to receive live events.",
    }


@app.post("/api/scans/{scan_id}/stop", status_code=200, dependencies=[Depends(require_api_key)])
async def stop_scan(scan_id: str) -> dict[str, Any]:
    """Signal a running scan to stop cooperatively."""
    entry = _registry.get(scan_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Scan not found")

    state: ScanState = entry["state"]
    task: asyncio.Task = entry["task"]

    state.cancel()
    if not task.done():
        task.cancel()

    logger.info("Scan %s stop signal sent", scan_id)
    return {"scan_id": scan_id, "status": "stopping"}


@app.get("/api/scans", dependencies=[Depends(require_api_key)])
async def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """List known scans for this session (in-memory)."""
    scans = [
        entry["meta"]
        for entry in list(_registry.values())[offset: offset + limit]
    ]
    return {"scans": scans, "count": len(scans)}


@app.get("/api/scans/history", dependencies=[Depends(require_api_key)])
async def scan_history(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """List all scans ever run, persisted in SQLite — survives restarts."""
    scans = await load_scans(limit=limit, offset=offset)
    return {"scans": scans, "count": len(scans)}


@app.get("/api/scans/{scan_id}", dependencies=[Depends(require_api_key)])
async def get_scan(scan_id: str) -> dict[str, Any]:
    entry = _registry.get(scan_id)
    if entry:
        meta = entry["meta"].copy()
        task: asyncio.Task = entry["task"]
        if task.done():
            meta["status"] = "complete" if not task.cancelled() else "cancelled"
        return meta
    persisted = await load_scan(scan_id)
    if persisted:
        return persisted
    raise HTTPException(status_code=404, detail="Scan not found")


@app.get("/api/scans/{scan_id}/status", dependencies=[Depends(require_api_key)])
async def get_scan_status(scan_id: str) -> dict[str, Any]:
    entry = _registry.get(scan_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Scan not found")
    task: asyncio.Task = entry["task"]
    status = "running"
    if task.done():
        status = "cancelled" if task.cancelled() else "complete"
    return {
        "scan_id": scan_id,
        "status":  status,
        "meta":    entry["meta"],
    }


async def _resolve_scan(scan_id: str) -> dict[str, Any]:
    entry = _registry.get(scan_id)
    if entry:
        return entry["meta"]
    persisted = await load_scan(scan_id)
    if persisted:
        return persisted
    raise HTTPException(status_code=404, detail="Scan not found")


@app.get("/api/scans/{scan_id}/report", dependencies=[Depends(require_api_key)])
async def get_scan_report(
    scan_id: str,
    format: str = Query(default="html", pattern="^(html|csv|json|sarif)$"),
    agency_name: str = Query(default="Independent Security Research", max_length=120),
) -> Any:
    """
    Client-deliverable report for a completed scan.
    - format=html: self-contained, printable report (Print → Save as PDF in browser)
    - format=csv:  spreadsheet-friendly export of all findings
    - format=json: raw structured data
    - format=sarif: SARIF 2.1.0 for GitHub code scanning / CI ingestion
    """
    scan = await _resolve_scan(scan_id)
    if scan.get("status") != "complete":
        raise HTTPException(status_code=409, detail=f"Scan is not complete yet (status: {scan.get('status')})")

    if format == "html":
        body = report_gen.generate_html_report(scan, agency_name=agency_name)
        return HTMLResponse(content=body, headers={
            "Content-Disposition": f'inline; filename="secretnode_report_{scan_id[:8]}.html"'
        })
    if format == "csv":
        body = report_gen.generate_csv_report(scan)
        return Response(content=body, media_type="text/csv", headers={
            "Content-Disposition": f'attachment; filename="secretnode_report_{scan_id[:8]}.csv"'
        })
    if format == "sarif":
        body = report_gen.generate_sarif_report(scan)
        return Response(content=body, media_type="application/sarif+json", headers={
            "Content-Disposition": f'attachment; filename="secretnode_report_{scan_id[:8]}.sarif"'
        })
    return JSONResponse(content=scan)


@app.post("/api/findings/suppress", dependencies=[Depends(require_api_key)])
async def suppress_finding(payload: dict[str, str]) -> dict[str, Any]:
    """
    Mark a finding as a false positive by fingerprint. Future scans of the
    same target_url will silently filter it out and never re-alert on it.
    Body: {"fingerprint": "...", "target_url": "...", "secret_type": "...",
           "source_url": "...", "note": "optional reason"}
    """
    fingerprint = payload.get("fingerprint", "").strip()
    target_url  = payload.get("target_url", "").strip()
    if not fingerprint or not target_url:
        raise HTTPException(status_code=400, detail="fingerprint and target_url are required")
    await mark_false_positive(
        fingerprint=fingerprint,
        target_url=target_url,
        secret_type=payload.get("secret_type", ""),
        source_url=payload.get("source_url", ""),
        note=payload.get("note", ""),
    )
    return {"status": "suppressed", "fingerprint": fingerprint}


@app.delete("/api/findings/suppress/{fingerprint}", dependencies=[Depends(require_api_key)])
async def unsuppress_finding(fingerprint: str) -> dict[str, Any]:
    removed = await unmark_false_positive(fingerprint)
    if not removed:
        raise HTTPException(status_code=404, detail="Fingerprint not found in suppression list")
    return {"status": "unsuppressed", "fingerprint": fingerprint}


@app.get("/api/findings/suppressed", dependencies=[Depends(require_api_key)])
async def list_suppressed_findings(
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict[str, Any]:
    items = await list_false_positives(limit=limit)
    return {"suppressed": items, "count": len(items)}


@app.get("/api/active", dependencies=[Depends(require_api_key)])
async def active_scans() -> dict[str, Any]:
    active = [
        entry["meta"]
        for entry in _registry.values()
        if not entry["task"].done()
    ]
    return {"active": active, "count": len(active)}


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.websocket("/ws/logs/{scan_id}")
async def ws_scan_logs(websocket: WebSocket, scan_id: str, api_key: str = Query(default="")) -> None:
    """
    Subscribe to live events for a specific scan.
    Sends JSON messages of types: log, finding, scan_start, scan_complete, etc.
    Requires ?api_key=... (browsers cannot set custom headers on WebSocket).
    """
    if not api_key or not secrets.compare_digest(api_key, API_KEY):
        await websocket.close(code=4401)
        return
    await manager.connect_scan(websocket, scan_id)
    try:
        while True:
            # Keep connection alive; client may send pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)
    except Exception as exc:
        logger.warning("WS error for scan %s: %s", scan_id, exc)
        manager.disconnect(websocket, scan_id)


@app.websocket("/ws/logs")
async def ws_global_logs(websocket: WebSocket, api_key: str = Query(default="")) -> None:
    """Subscribe to all scan events across the server. Requires ?api_key=..."""
    if not api_key or not secrets.compare_digest(api_key, API_KEY):
        await websocket.close(code=4401)
        return
    await manager.connect_global(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as exc:
        logger.warning("Global WS error: %s", exc)
        manager.disconnect(websocket)


# ─────────────────────────────────────────────────────────────────────────────
# Static Frontend
# ─────────────────────────────────────────────────────────────────────────────

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
STATIC_DIR   = FRONTEND_DIR / "static"
INDEX_HTML   = FRONTEND_DIR / "index.html"

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=FileResponse)
async def serve_index() -> FileResponse:
    if not INDEX_HTML.exists():
        return JSONResponse(
            {"error": "Frontend not found. Build the frontend first."},
            status_code=404,
        )
    return FileResponse(str(INDEX_HTML))


_FRONTEND_DIR_RESOLVED = FRONTEND_DIR.resolve()


@app.get("/{path:path}", response_class=FileResponse)
async def serve_spa(path: str) -> FileResponse:
    # Resolve symlinks/".." and verify the result is still inside FRONTEND_DIR
    # before serving — prevents path traversal (e.g. path="../../etc/passwd").
    requested = (FRONTEND_DIR / path).resolve()
    try:
        requested.relative_to(_FRONTEND_DIR_RESOLVED)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found")
    if requested.exists() and requested.is_file():
        return FileResponse(str(requested))
    if INDEX_HTML.exists():
        return FileResponse(str(INDEX_HTML))
    raise HTTPException(status_code=404, detail="Not found")


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        loop="uvloop" if _HAS_UVLOOP else "auto",
        log_level=LOG_LEVEL.lower(),
        access_log=True,
        workers=1,
    )
