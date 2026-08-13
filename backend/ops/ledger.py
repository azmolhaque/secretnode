#!/usr/bin/env python3
"""
Authorization ledger — the gate every scan passes through.

WHY THIS EXISTS
---------------
"No scan without a signed Rules of Engagement" is stated on the website, in the
FAQ, in the process diagram and in every client report. Today it is enforced by
one careful person remembering. That is adequate for one client and untenable
for ten, and the failure mode is not a bug — it is scanning an organisation that
never agreed to be scanned.

This module turns the promise into a check. Nothing else in the operations layer
is permitted to initiate a request against a target without `assert_authorized`
returning cleanly first.

THE MATCHING RULES ARE THE SECURITY BOUNDARY
--------------------------------------------
Scope matching is the single place in this codebase where a subtle bug has legal
consequences, so the rules are deliberately strict and deliberately dumb:

  * **Nothing is inferred.** `example.com` authorises exactly that host. It does
    *not* imply `www.example.com`, and it does *not* imply subdomains. If a
    client meant subdomains, the RoE says `*.example.com` and so does the ledger.
    Inference is how scope creep happens quietly.
  * **Substring matching is never used.** `notexample.com` ends with
    `example.com`; `example.com.evil.net` contains it. Both must be denied, and
    a matcher written with `in` or a bare `endswith` allows one or both. Hosts
    are compared label-wise, on parsed hostnames.
  * **Exclusions beat inclusions, always.** A host matching both is denied. An
    RoE that carves something out means it, and the carve-out is usually the
    part someone will be upset about.
  * **Everything fails closed.** No ledger, no matching authorisation, expired
    window, revoked engagement, unparseable target — all deny. There is no
    configuration that makes an unknown host allowed.

REVOCATION IS IMMEDIATE
-----------------------
The privacy notice promises a client can withdraw authorisation in writing at
any moment and "testing stops immediately". `revoke()` is therefore checked on
every decision rather than at scan-start, so an in-flight campaign stops at the
next target rather than at the end of the run.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiosqlite

# Separate from secretnode.db on purpose: authorization records and scan results
# have different retention rules. Scan data is purged 30 days after delivery;
# the authorization that permitted it is the evidence the scan was lawful and
# outlives it. Covered by the existing `backend/data/*.db` gitignore rule.
DB_PATH = Path(__file__).parent.parent / "data" / "ops.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS authorizations (
    engagement_id   TEXT PRIMARY KEY,
    client          TEXT NOT NULL,
    scope_json      TEXT NOT NULL,
    exclusions_json TEXT NOT NULL,
    starts_at       TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    passive_only            INTEGER NOT NULL DEFAULT 1,
    permit_verification     INTEGER NOT NULL DEFAULT 0,
    permit_deep_scan        INTEGER NOT NULL DEFAULT 0,
    recipient       TEXT NOT NULL,
    roe_reference   TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    revoked_reason  TEXT,
    notes           TEXT,
    created_at      TEXT DEFAULT (datetime('now'))
);

-- Every decision, allow or deny. "We only scanned what was authorised" is a
-- claim; this is the evidence for it. Deliberately append-only.
CREATE TABLE IF NOT EXISTS scope_decisions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT NOT NULL,
    allowed       INTEGER NOT NULL,
    engagement_id TEXT,
    matched_rule  TEXT,
    reason        TEXT NOT NULL,
    decided_at    TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_decisions_target ON scope_decisions (target);
CREATE INDEX IF NOT EXISTS idx_decisions_time ON scope_decisions (decided_at DESC);
"""


class LedgerError(Exception):
    """Base for ledger failures."""


class NotAuthorized(LedgerError):
    """The target is not covered by any active authorization. Always fatal."""


@dataclass
class Authorization:
    engagement_id: str
    client: str
    scope: list[str]
    starts_at: str                      # ISO date, inclusive
    expires_at: str                     # ISO date, inclusive
    recipient: str
    roe_reference: str
    exclusions: list[str] = field(default_factory=list)
    passive_only: bool = True
    permit_verification: bool = False
    permit_deep_scan: bool = False
    status: str = "active"
    revoked_reason: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        missing = [
            n for n in ("engagement_id", "client", "recipient", "roe_reference")
            if not getattr(self, n)
        ]
        if missing:
            raise ValueError(f"authorization missing required field(s): {', '.join(missing)}")
        if not self.scope:
            raise ValueError(
                "authorization has an empty scope. An authorization that permits "
                "nothing is almost certainly a mistake, and an empty list is one "
                "keystroke away from being read as 'everything'."
            )
        for d in (self.starts_at, self.expires_at):
            date.fromisoformat(d)       # raises on a malformed date
        if date.fromisoformat(self.expires_at) < date.fromisoformat(self.starts_at):
            raise ValueError("authorization expires before it starts")


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    engagement_id: str | None = None
    matched_rule: str | None = None
    # Was the host inside this engagement's *declared scope*, irrespective of
    # whether it was then allowed? Used to pick the informative reason when
    # several authorizations all decline: "ENG-002 was revoked" is actionable,
    # "not covered by any of 3 authorizations" is not. An engagement only gets
    # to explain a denial for hosts it actually covers.
    in_scope: bool = False
    # Set when an exclusion rule matched. Exclusions deny globally, so this
    # marks a decision that no other authorization may override.
    excluded: bool = False

    def __bool__(self) -> bool:
        return self.allowed


# ── Pure matching (no DB, no clock) ──────────────────────────────────────────

def normalise_host(target: str) -> str | None:
    """Extract a comparable hostname from a URL or bare host. None if unusable.

    Strips the scheme, any port, a trailing FQDN dot, and lowercases. Returns
    None rather than guessing when the input cannot be parsed — an unparseable
    target must reach the deny path, not a best-effort interpretation of it.
    """
    if not target or not target.strip():
        return None
    t = target.strip()
    if "://" not in t:
        t = "//" + t                     # let urlparse treat it as a netloc
    try:
        host = urlparse(t).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.strip().rstrip(".").lower()
    return host or None


def host_matches(host: str, pattern: str) -> bool:
    """Does `host` match a single scope `pattern`?

    Supported forms, and nothing else:
      example.com     — that exact host
      *.example.com   — any subdomain, at least one label deep; NOT the apex
      192.0.2.10      — that exact address
      192.0.2.0/24    — any address inside the network

    Comparison is label-wise. `notexample.com` and `example.com.evil.net` are
    denied against `example.com`, which a substring or bare-suffix check would
    not guarantee.
    """
    if not host or not pattern:
        return False
    host = host.strip().rstrip(".").lower()
    pattern = pattern.strip().rstrip(".").lower()

    # CIDR / IP scope
    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return False
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False               # a hostname is never inside a CIDR

    if pattern.startswith("*."):
        base = pattern[2:]
        if not base:
            return False
        # Must be strictly deeper than the base: the apex is not a subdomain of
        # itself, and authorising subdomains is not authorising the apex.
        return host.endswith("." + base) and host != base

    return host == pattern


def matches_any(host: str, patterns: list[str]) -> str | None:
    """First pattern in `patterns` that matches, or None."""
    for p in patterns:
        if host_matches(host, p):
            return p
    return None


def evaluate(
    auth: Authorization,
    target: str,
    *,
    now: date | None = None,
) -> ScopeDecision:
    """Decide whether `auth` permits touching `target`. Pure and clock-injectable.

    Order is deliberate, and it is *relevance first*:

      1. Parse the host — an unparseable target can never be allowed.
      2. Exclusions, which deny regardless of everything else, including a
         revoked or expired status. A carve-out is a safety rule, and honouring
         it in a dead engagement fails closed.
      3. Scope membership. A host outside this engagement's declared scope is
         simply not this engagement's business, and it says so.
      4. Only then status and window.

    Steps 3 and 4 are in that order for a reason found by a test: checking
    status first meant a revoked engagement reported "revoked" for every host in
    the world, including hosts it had never covered. That is both wrong and
    actively misleading in an audit trail, where it would look like a client had
    withdrawn consent for infrastructure that was never theirs.
    """
    today = now or datetime.now(timezone.utc).date()

    host = normalise_host(target)
    if host is None:
        return ScopeDecision(False, f"target {target!r} could not be parsed as a host")

    excluded = matches_any(host, auth.exclusions)
    if excluded:
        return ScopeDecision(
            False, f"{host} is explicitly excluded by rule '{excluded}' "
                   f"under {auth.engagement_id}",
            auth.engagement_id, excluded, in_scope=True, excluded=True,
        )

    included = matches_any(host, auth.scope)
    if not included:
        return ScopeDecision(
            False, f"{host} is not in the scope of {auth.engagement_id}",
            auth.engagement_id,
        )

    # From here the host *is* this engagement's business, so its reasons are
    # the informative ones.
    if auth.status == "revoked":
        return ScopeDecision(
            False,
            f"{host} is in scope for {auth.engagement_id}, but that engagement "
            f"was revoked" + (f": {auth.revoked_reason}" if auth.revoked_reason else ""),
            auth.engagement_id, included, in_scope=True,
        )
    if auth.status != "active":
        return ScopeDecision(
            False, f"engagement {auth.engagement_id} is '{auth.status}', not active",
            auth.engagement_id, included, in_scope=True,
        )

    starts = date.fromisoformat(auth.starts_at)
    expires = date.fromisoformat(auth.expires_at)
    if today < starts:
        return ScopeDecision(
            False, f"testing window for {auth.engagement_id} has not opened "
                   f"(starts {auth.starts_at})",
            auth.engagement_id, included, in_scope=True,
        )
    if today > expires:
        return ScopeDecision(
            False, f"authorization {auth.engagement_id} expired on {auth.expires_at}",
            auth.engagement_id, included, in_scope=True,
        )

    return ScopeDecision(
        True, f"{host} authorised by rule '{included}' under {auth.engagement_id}",
        auth.engagement_id, included, in_scope=True,
    )


def evaluate_all(
    auths: list[Authorization],
    target: str,
    *,
    now: date | None = None,
) -> ScopeDecision:
    """Decide against every authorization. Any explicit exclusion denies outright.

    A host excluded by one engagement is not made allowable by being in another's
    scope — that is precisely the case where two clients share infrastructure and
    one of them has carved something out.
    """
    if not auths:
        return ScopeDecision(
            False,
            f"no authorizations on record — {target} is denied. An empty ledger "
            f"denies everything by design.",
        )

    decisions = [evaluate(a, target, now=now) for a in auths]

    # An exclusion anywhere denies outright and cannot be overridden.
    for d in decisions:
        if d.excluded:
            return d
    for d in decisions:
        if d.allowed:
            return d

    # All denied. Prefer a reason from an engagement that actually covers this
    # host — "ENG-002 was revoked" tells the operator what to do; "not covered
    # by any of 3 authorizations" does not.
    for d in decisions:
        if d.in_scope:
            return d

    # Nothing covers this host. With a single authorization its own reason is
    # the whole story and is more useful than a count. With several, naming one
    # arbitrarily would imply a relationship to that engagement that does not
    # exist, so the summary stays deliberately generic.
    if len(decisions) == 1:
        return decisions[0]

    return ScopeDecision(False, f"{target} is not covered by any of the "
                                f"{len(auths)} authorization(s) on record")


# ── Persistence ──────────────────────────────────────────────────────────────

def _row_to_auth(row: aiosqlite.Row) -> Authorization:
    d = dict(row)
    return Authorization(
        engagement_id=d["engagement_id"],
        client=d["client"],
        scope=json.loads(d["scope_json"]),
        exclusions=json.loads(d["exclusions_json"]),
        starts_at=d["starts_at"],
        expires_at=d["expires_at"],
        passive_only=bool(d["passive_only"]),
        permit_verification=bool(d["permit_verification"]),
        permit_deep_scan=bool(d["permit_deep_scan"]),
        recipient=d["recipient"],
        roe_reference=d["roe_reference"],
        status=d["status"],
        revoked_reason=d["revoked_reason"] or "",
        notes=d["notes"] or "",
    )


async def init_db(db_path: Path | None = None) -> None:
    p = db_path or DB_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(p) as db:
        await db.executescript(_SCHEMA)
        await db.commit()


async def save_authorization(auth: Authorization, db_path: Path | None = None) -> None:
    async with aiosqlite.connect(db_path or DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO authorizations (
                engagement_id, client, scope_json, exclusions_json, starts_at,
                expires_at, passive_only, permit_verification, permit_deep_scan,
                recipient, roe_reference, status, revoked_reason, notes
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(engagement_id) DO UPDATE SET
                client=excluded.client, scope_json=excluded.scope_json,
                exclusions_json=excluded.exclusions_json, starts_at=excluded.starts_at,
                expires_at=excluded.expires_at, passive_only=excluded.passive_only,
                permit_verification=excluded.permit_verification,
                permit_deep_scan=excluded.permit_deep_scan,
                recipient=excluded.recipient, roe_reference=excluded.roe_reference,
                status=excluded.status, revoked_reason=excluded.revoked_reason,
                notes=excluded.notes
            """,
            (
                auth.engagement_id, auth.client, json.dumps(auth.scope),
                json.dumps(auth.exclusions), auth.starts_at, auth.expires_at,
                int(auth.passive_only), int(auth.permit_verification),
                int(auth.permit_deep_scan), auth.recipient, auth.roe_reference,
                auth.status, auth.revoked_reason, auth.notes,
            ),
        )
        await db.commit()


async def load_authorizations(
    db_path: Path | None = None, *, active_only: bool = False,
) -> list[Authorization]:
    p = db_path or DB_PATH
    if not p.exists():
        return []                       # an absent ledger denies everything
    async with aiosqlite.connect(p) as db:
        db.row_factory = aiosqlite.Row
        sql = "SELECT * FROM authorizations"
        if active_only:
            sql += " WHERE status = 'active'"
        cursor = await db.execute(sql + " ORDER BY created_at DESC")
        return [_row_to_auth(r) for r in await cursor.fetchall()]


async def revoke(
    engagement_id: str, reason: str, db_path: Path | None = None,
) -> bool:
    """Withdraw authorization. Takes effect on the very next decision."""
    async with aiosqlite.connect(db_path or DB_PATH) as db:
        cur = await db.execute(
            "UPDATE authorizations SET status='revoked', revoked_reason=? "
            "WHERE engagement_id=?",
            (reason, engagement_id),
        )
        await db.commit()
        return cur.rowcount > 0


async def _record(decision: ScopeDecision, target: str, db_path: Path | None) -> None:
    p = db_path or DB_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(p) as db:
        await db.executescript(_SCHEMA)
        await db.execute(
            "INSERT INTO scope_decisions (target, allowed, engagement_id, "
            "matched_rule, reason) VALUES (?,?,?,?,?)",
            (target, int(decision.allowed), decision.engagement_id,
             decision.matched_rule, decision.reason),
        )
        await db.commit()


async def check_target(
    target: str, *, db_path: Path | None = None, now: date | None = None,
    record: bool = True,
) -> ScopeDecision:
    """Evaluate `target` against the ledger and log the decision."""
    auths = await load_authorizations(db_path)
    decision = evaluate_all(auths, target, now=now)
    if record:
        await _record(decision, target, db_path)
    return decision


async def assert_authorized(
    target: str, *, db_path: Path | None = None, now: date | None = None,
) -> Authorization:
    """Return the authorization covering `target`, or raise `NotAuthorized`.

    This is the call every scan path must make. It raises rather than returning
    a falsy value so that a caller which forgets to check the result still fails
    safe instead of scanning.
    """
    decision = await check_target(target, db_path=db_path, now=now)
    if not decision.allowed:
        raise NotAuthorized(decision.reason)
    auths = await load_authorizations(db_path)
    for a in auths:
        if a.engagement_id == decision.engagement_id:
            return a
    raise NotAuthorized(                # unreachable in practice; fail closed anyway
        f"{target} was allowed but its authorization could not be re-loaded"
    )


async def recent_decisions(
    limit: int = 100, db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """The audit trail — evidence for 'we only scanned what was authorised'."""
    p = db_path or DB_PATH
    if not p.exists():
        return []
    async with aiosqlite.connect(p) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM scope_decisions ORDER BY decided_at DESC, id DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in await cursor.fetchall()]
