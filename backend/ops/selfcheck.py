#!/usr/bin/env python3
"""
Pi self-check — verify the operations layer actually works on this machine.

The unit tests mock Ollama so they run anywhere, which means a green suite says
nothing about whether a Raspberry Pi can really serve this model at a workable
speed. This does the other half: it talks to the real daemon, runs real
inference, and reports honest numbers.

    cd ~/secretnode/backend && python3 -m ops.selfcheck

Exit code 0 means the layer is usable on this machine. Non-zero means it is not,
and the output says which part failed and what to do about it.

The timing numbers matter as much as the pass/fail. A 3B model on a Pi 5 that
takes 90 seconds for a two-field extraction is technically working and
practically useless for anything with more than a handful of items, and it is
better to learn that from this script than from a monitoring run that quietly
takes all night.
"""

from __future__ import annotations

import asyncio
import pathlib
import sys
import time

# Dependency preflight, before anything third-party is imported.
#
# The first real run of this script on the Pi failed with a bare
# ModuleNotFoundError traceback because it was invoked with the system
# interpreter rather than the project's virtualenv. A diagnostic tool that
# cannot diagnose its own most likely failure is not doing its job — and
# "wrong interpreter" is far and away the most likely one, since the correct
# invocation requires activating a venv two directories up.
def _preflight() -> None:
    try:
        import httpx  # noqa: F401
        from ops import guards, llm  # noqa: F401
    except ModuleNotFoundError as exc:
        here = pathlib.Path(__file__).resolve()
        venv = here.parent.parent.parent / ".venv"
        print(f"\n\033[91m✗\033[0m Missing dependency: {exc.name}")
        print(f"  Running under: {sys.executable}")
        if venv.exists():
            print("\n  A virtualenv exists but is not active. Run:\n")
            print(f"    cd {venv.parent} && source .venv/bin/activate && "
                  f"cd backend && python3 -m ops.selfcheck\n")
        else:
            print(f"\n  No virtualenv found at {venv}. Create one:\n")
            print(f"    cd {venv.parent} && python3 -m venv .venv && "
                  f"source .venv/bin/activate && pip install -r requirements.txt\n")
        sys.exit(2)


_preflight()

from ops import guards, llm  # noqa: E402 — must follow the preflight above

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
WARN = "\033[93m!\033[0m"

# Above this, a per-item model call is too slow to use in a loop over anything
# larger than a short list. Not a failure — a warning with a consequence.
SLOW_CALL_SECONDS = 20.0


def line(mark: str, label: str, detail: str = "") -> None:
    print(f"  {mark} {label}" + (f" — {detail}" if detail else ""))


async def main() -> int:
    failures = 0
    warnings = 0

    print("\nSecretNode ops — Raspberry Pi self-check")
    print("=" * 52)

    # ── 1. Guards work with no model at all ─────────────────────────────────
    # Deliberately first: these are pure functions and must hold even when
    # Ollama is unavailable, because they are what make model output safe to
    # use. If they are broken, nothing below matters.
    print("\n[1/4] Guards (no model required)")
    try:
        src = {"https://example.test/": "Contact us at hello@example.test today."}
        assert guards.assert_grounded("hello@example.test", src) == "https://example.test/"
        line(PASS, "grounding accepts a value present in the source")

        try:
            guards.assert_grounded("invented@example.test", src)
            line(FAIL, "grounding accepted an invented value")
            failures += 1
        except guards.Ungrounded:
            line(PASS, "grounding rejects an invented value")

        try:
            guards.assert_no_secrets('tok = "ghp_1234567890abcdEFGHijklMNOPqrstUVWX12"')
            line(FAIL, "prompt guard let a credential through")
            failures += 1
        except guards.SecretInPrompt:
            line(PASS, "prompt guard refuses credential-bearing text")
    except Exception as exc:  # noqa: BLE001
        line(FAIL, "guards raised unexpectedly", str(exc))
        failures += 1

    # ── 2. Is Ollama there, and is the model pulled? ────────────────────────
    print(f"\n[2/4] Ollama at {llm.OLLAMA_URL}")
    ok, msg = await llm.health()
    if not ok:
        line(FAIL, "not usable", msg)
        print("\n" + "=" * 52)
        print(f"{FAIL} Cannot continue without Ollama. Fix the above and re-run.")
        return 1
    line(PASS, "reachable", msg)

    # ── 3. Real constrained inference ───────────────────────────────────────
    print(f"\n[3/4] Constrained inference ({llm.DEFAULT_MODEL})")
    schema = {
        "type": "object",
        "properties": {
            "email": {"type": "string"},
            "company": {"type": "string"},
        },
        "required": ["email", "company"],
    }
    page = (
        "Acme Robotics Ltd — About\n\n"
        "We build warehouse automation. Press enquiries: press@acme-robotics.test\n"
        "For anything security related, email hello@acme-robotics.test.\n"
    )
    system = "You extract facts that appear verbatim in the text. Never guess."

    async def extract(variant: str):
        return await llm.complete_json(
            prompt=(
                f"Extract the security contact email and the company name from this "
                f"page.{variant}\n\n---\n{page}\n---"
            ),
            schema=schema,
            system=system,
        )

    try:
        # Two calls, because one number conflates two very different costs.
        #
        # The first call may include loading the model from disk — on a Pi that
        # is tens of seconds and dominates everything. The second runs inside
        # the keep_alive window with weights already resident, so it measures
        # inference alone. Those have opposite design implications: a slow cold
        # start is fixed by batching work into one session and keeping the model
        # warm, whereas slow warm inference means the model is simply too slow
        # for per-item work and the design has to avoid it.
        #
        # Reporting a single figure, as this script originally did, hides which
        # problem you have.
        t0 = time.monotonic()
        res = await extract("")
        first = time.monotonic() - t0

        t1 = time.monotonic()
        res2 = await extract(" Answer concisely.")
        warm = time.monotonic() - t1

        line(PASS, "schema-valid response",
             f"first {first:.1f}s, warm {warm:.1f}s, "
             f"{res.eval_count} tokens, attempt {res.attempts}")
        print(f"      → {res.data}")

        load_cost = first - warm
        if load_cost > 3.0:
            line(PASS, f"model load cost ≈ {load_cost:.1f}s",
                 f"paid once per {llm.KEEP_ALIVE} idle window, not per call")

        if warm > 0:
            tps = res2.eval_count / warm
            print(f"      warm throughput ≈ {tps:.1f} tokens/sec")

        if warm > SLOW_CALL_SECONDS:
            line(WARN, f"warm inference is slow ({warm:.1f}s per call)",
                 "usable one-at-a-time; too slow to loop over a large list")
            warnings += 1
        else:
            line(PASS, f"warm inference is workable ({warm:.1f}s per call)",
                 "batch work in one session to keep the model resident")

        # ── 4. The property that actually matters ───────────────────────────
        # A schema-valid answer can still be invented. Ground it.
        print("\n[4/4] Grounding real model output")
        sources = {"https://acme-robotics.test/about": page}
        try:
            cites = guards.ground_all(
                {"email": res.data["email"], "company": res.data["company"]},
                sources,
            )
            line(PASS, "every extracted field traced to the source", str(cites))
        except guards.Ungrounded as exc:
            # Not a bug — this is the guard doing its job on a small model, and
            # seeing it fire here is more informative than seeing it pass.
            line(WARN, "model produced an ungrounded field; correctly rejected")
            print(f"      → {exc}")
            warnings += 1

    except llm.OllamaUnavailable as exc:
        line(FAIL, "inference unavailable", str(exc))
        failures += 1
    except llm.SchemaViolation as exc:
        line(FAIL, "no schema-valid response after retries", str(exc))
        failures += 1
    except Exception as exc:  # noqa: BLE001
        line(FAIL, "unexpected error", f"{type(exc).__name__}: {exc}")
        failures += 1

    # ── Verdict ─────────────────────────────────────────────────────────────
    print("\n" + "=" * 52)
    if failures:
        print(f"{FAIL} {failures} check(s) failed — the ops layer is not usable here yet.")
        return 1
    if warnings:
        print(f"{WARN} Usable, with {warnings} caveat(s) above. Read them before "
              f"scheduling unattended work.")
        return 0
    print(f"{PASS} All checks passed. The ops layer is usable on this machine.")
    return 0


if __name__ == "__main__":
    import httpx      # safe here: the preflight above proved it is importable

    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\ninterrupted")
        sys.exit(130)
    except httpx.HTTPError as exc:
        print(f"\n{FAIL} transport error: {exc}")
        sys.exit(1)
