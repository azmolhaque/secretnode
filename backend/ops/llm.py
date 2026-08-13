#!/usr/bin/env python3
"""
Ollama adapter — schema-constrained, deterministic, Pi-tuned.

WHY NOT JUST CALL THE API
-------------------------
A 3B model asked for JSON in a prompt will, often enough to matter, return
prose, a code fence, a trailing apology, or valid JSON with invented values.
Every one of those is a wrong answer that looks like a right answer, which is
the worst failure mode an unattended business process can have.

Three layers stop that, and only the third is interesting:

  1. **Shape** — Ollama's `format` accepts a full JSON Schema and constrains
     generation against it, so structurally invalid output is not merely
     rejected, it cannot be produced.
  2. **Parse and validate** — the response is still parsed and re-validated
     here, because a schema can be satisfied by a truncated stream that never
     closed, and because relying on a remote guarantee for a local invariant is
     how silent breakage happens.
  3. **Grounding** — shape says nothing about truth. `{"email": "x@y.com"}` is
     schema-perfect and possibly invented. `guards.assert_grounded` requires
     every extracted fact to literally appear in a source document. That is what
     makes hallucination structurally unable to pass through, and it lives in
     `guards.py` because it applies to any model, not just this one.

FAILURE PHILOSOPHY
------------------
This module raises. It never returns a plausible-looking default, never retries
into a fabrication, and never degrades quietly. A caller that cannot reach the
model must find out and decide — queue the work, fall back to deterministic
logic, or stop. A business process that continues on an invented value is worse
than one that halts.

PI 5 TUNING
-----------
* `keep_alive` defaults to 10m: loading a 3B model on a Pi costs seconds, and
  paying that on every call dominates the actual inference.
* `num_ctx` is bounded (4096): context is the main driver of RAM and of
  prompt-eval time on ARM64, and nothing here needs a long window.
* Timeouts are generous (120s): a Pi generating 200 tokens at single-digit
  tokens/sec is normal, not hung.
* `temperature=0` and a fixed `seed` make runs reproducible, which matters when
  a business decision has to be explained later.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any

import httpx

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
DEFAULT_MODEL = os.environ.get("OPS_LLM_MODEL", "llama3.2:3b")
DEFAULT_TIMEOUT = float(os.environ.get("OPS_LLM_TIMEOUT", "120"))
DEFAULT_NUM_CTX = int(os.environ.get("OPS_LLM_NUM_CTX", "4096"))
DEFAULT_NUM_PREDICT = int(os.environ.get("OPS_LLM_NUM_PREDICT", "512"))
KEEP_ALIVE = os.environ.get("OPS_LLM_KEEP_ALIVE", "10m")
DEFAULT_SEED = int(os.environ.get("OPS_LLM_SEED", "42"))
MAX_ATTEMPTS = int(os.environ.get("OPS_LLM_ATTEMPTS", "3"))

# A prompt larger than this is a bug in the caller, not a big job. On a Pi it is
# also minutes of prompt evaluation. Callers must summarise or chunk first.
MAX_PROMPT_CHARS = int(os.environ.get("OPS_LLM_MAX_PROMPT_CHARS", "24000"))


class LLMError(Exception):
    """Base for every failure in this module."""


class OllamaUnavailable(LLMError):
    """Ollama could not be reached, or the model is not present."""


class SchemaViolation(LLMError):
    """The model's output could not be parsed or did not satisfy the schema."""


class PromptTooLarge(LLMError):
    """The caller passed more text than this layer will send to a small model."""


@dataclass
class LLMResult:
    data: dict[str, Any]
    model: str
    duration_s: float
    attempts: int
    eval_count: int = 0

    def __getitem__(self, key: str) -> Any:
        return self.data[key]


async def health(client: httpx.AsyncClient | None = None) -> tuple[bool, str]:
    """Is Ollama up, and is the configured model actually pulled?

    Checked separately because "Ollama is running" and "the model exists" fail
    differently and a caller deserves to know which. A missing model on the Pi
    is a one-line `ollama pull`; a dead daemon is not.
    """
    own = client is None
    c = client or httpx.AsyncClient(timeout=10.0)
    try:
        r = await c.get(f"{OLLAMA_URL}/api/tags")
        if r.status_code != 200:
            return False, f"Ollama responded HTTP {r.status_code} at {OLLAMA_URL}"
        names = {m.get("name", "") for m in (r.json().get("models") or [])}
        # Ollama reports "llama3.2:3b"; tolerate a caller writing "llama3.2".
        if DEFAULT_MODEL in names or any(n.split(":")[0] == DEFAULT_MODEL for n in names):
            return True, f"ok — {DEFAULT_MODEL} available"
        return False, (
            f"Ollama is up but '{DEFAULT_MODEL}' is not pulled. "
            f"Run: ollama pull {DEFAULT_MODEL}"
        )
    except Exception as exc:  # noqa: BLE001 — any transport failure is "unavailable"
        return False, f"Ollama unreachable at {OLLAMA_URL}: {exc}"
    finally:
        if own:
            await c.aclose()


def _validate_against_schema(data: Any, schema: dict[str, Any]) -> None:
    """Minimal structural re-check of what came back.

    Deliberately not a full JSON-Schema implementation — this is defence in
    depth behind Ollama's own grammar constraint, catching the cases that
    actually occur in practice (a truncated object, a missing required key, a
    string where an integer was asked for) without taking a dependency on a
    validator the Pi would also have to install.
    """
    if schema.get("type") == "object":
        if not isinstance(data, dict):
            raise SchemaViolation(f"expected an object, got {type(data).__name__}")
        for key in schema.get("required", []):
            if key not in data:
                raise SchemaViolation(f"required field '{key}' missing from response")
        props = schema.get("properties", {})
        for key, spec in props.items():
            if key not in data:
                continue
            want = spec.get("type")
            val = data[key]
            checks = {
                "string": str, "integer": int, "number": (int, float),
                "boolean": bool, "array": list, "object": dict,
            }
            # bool is a subclass of int in Python; an integer field must not
            # silently accept True.
            if want == "integer" and isinstance(val, bool):
                raise SchemaViolation(f"field '{key}' expected integer, got boolean")
            if want in checks and not isinstance(val, checks[want]):
                raise SchemaViolation(
                    f"field '{key}' expected {want}, got {type(val).__name__}"
                )
            if want == "string" and spec.get("enum") and val not in spec["enum"]:
                raise SchemaViolation(
                    f"field '{key}' value {val!r} not in allowed {spec['enum']}"
                )


async def complete_json(
    prompt: str,
    schema: dict[str, Any],
    *,
    system: str | None = None,
    model: str | None = None,
    temperature: float = 0.0,
    seed: int | None = None,
    timeout: float | None = None,
    num_ctx: int | None = None,
    num_predict: int | None = None,
    attempts: int | None = None,
    client: httpx.AsyncClient | None = None,
) -> LLMResult:
    """Ask the local model for a JSON object matching `schema`.

    Raises rather than guessing: `OllamaUnavailable` if the model cannot be
    reached, `SchemaViolation` if every attempt produced unusable output,
    `PromptTooLarge` if the caller should have chunked first.

    Retries vary the seed. Retrying a deterministic failure with identical
    inputs reproduces it exactly, so a retry that changes nothing is just a
    slower way to fail — on a Pi, an expensively slower way.
    """
    if len(prompt) > MAX_PROMPT_CHARS:
        raise PromptTooLarge(
            f"prompt is {len(prompt)} chars, limit is {MAX_PROMPT_CHARS}. "
            f"Summarise or chunk before calling a 3B model."
        )

    mdl = model or DEFAULT_MODEL
    max_attempts = attempts if attempts is not None else MAX_ATTEMPTS
    base_seed = seed if seed is not None else DEFAULT_SEED

    messages: list[dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    own = client is None
    c = client or httpx.AsyncClient(timeout=timeout or DEFAULT_TIMEOUT)
    started = time.monotonic()
    last_error: Exception | None = None

    try:
        for attempt in range(1, max_attempts + 1):
            payload = {
                "model": mdl,
                "messages": messages,
                "stream": False,
                "format": schema,          # grammar-constrained generation
                "keep_alive": KEEP_ALIVE,
                "options": {
                    "temperature": temperature,
                    "seed": base_seed + attempt - 1,
                    "num_ctx": num_ctx or DEFAULT_NUM_CTX,
                    "num_predict": num_predict or DEFAULT_NUM_PREDICT,
                },
            }
            try:
                r = await c.post(f"{OLLAMA_URL}/api/chat", json=payload,
                                 timeout=timeout or DEFAULT_TIMEOUT)
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                # A refused connection will not fix itself inside this call.
                raise OllamaUnavailable(
                    f"Cannot reach Ollama at {OLLAMA_URL}. Is the service running? ({exc})"
                ) from exc
            except httpx.ReadTimeout as exc:
                last_error = exc
                continue      # a Pi under load can genuinely exceed the timeout

            if r.status_code == 404:
                raise OllamaUnavailable(
                    f"Model '{mdl}' not found on this Ollama instance. "
                    f"Run: ollama pull {mdl}"
                )
            if r.status_code >= 500:
                last_error = LLMError(f"Ollama HTTP {r.status_code}: {r.text[:200]}")
                continue
            if r.status_code != 200:
                raise LLMError(f"Ollama HTTP {r.status_code}: {r.text[:200]}")

            body = r.json()
            content = (body.get("message") or {}).get("content", "")
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                # Reachable despite the grammar: a response cut off at
                # num_predict is a prefix of valid JSON, not valid JSON.
                last_error = SchemaViolation(
                    f"response was not parseable JSON (likely truncated at "
                    f"num_predict={num_predict or DEFAULT_NUM_PREDICT}): {content[:160]!r}"
                )
                continue

            try:
                _validate_against_schema(data, schema)
            except SchemaViolation as exc:
                last_error = exc
                continue

            return LLMResult(
                data=data,
                model=mdl,
                duration_s=round(time.monotonic() - started, 2),
                attempts=attempt,
                eval_count=int(body.get("eval_count") or 0),
            )

        raise SchemaViolation(
            f"{max_attempts} attempts produced no schema-valid response. "
            f"Last error: {last_error}"
        )
    finally:
        if own:
            await c.aclose()


async def classify(
    text: str,
    question: str,
    options: list[str],
    *,
    client: httpx.AsyncClient | None = None,
    **kwargs: Any,
) -> tuple[str, str]:
    """Pick one of `options`. Returns (choice, reason).

    The one task shape a 3B model is genuinely reliable at, and the enum in the
    schema means it cannot answer with anything outside the list. Use this in
    preference to free-form prompting anywhere a decision has fixed outcomes.
    """
    schema = {
        "type": "object",
        "properties": {
            "choice": {"type": "string", "enum": options},
            "reason": {"type": "string"},
        },
        "required": ["choice", "reason"],
    }
    prompt = (
        f"{question}\n\n"
        f"Choose exactly one of: {', '.join(options)}\n\n"
        f"---\n{text}\n---\n\n"
        f"Answer with the choice and a one-sentence reason."
    )
    res = await complete_json(prompt, schema, client=client, **kwargs)
    return res.data["choice"], res.data["reason"]
