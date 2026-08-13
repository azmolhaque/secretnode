"""
Cindrasec operations layer — agent runtime for business operations.

SCOPE AND LOCATION
------------------
This package lives inside SecretNode because that is where its dependencies
already are (async HTTP, SQLite storage, the scanner's own detectors) and
because the Raspberry Pi already runs this repo — a `git pull` deploys it with
no new environment.

The *code* here is generic. The *data* it operates on — client rosters,
authorization records, pipeline state — is confidential and is gitignored,
never committed. If this package ever grows business logic that would embarrass
a public repository, it should be extracted rather than quietly made private.

DESIGN CONSTRAINT: A 3B MODEL ON A RASPBERRY PI
-----------------------------------------------
Everything here is built for `llama3.2:3b` running locally on Ollama. That is a
hard constraint and it shapes every decision:

  * A 3B model cannot be trusted to reason. It can classify into a few options,
    extract a value it can see, and rewrite a sentence. It cannot plan, judge
    severity, or be relied on for multi-step inference.
  * So the deterministic Python does the logic and the model does narrow,
    bounded, schema-constrained tasks — never the reverse.
  * Ollama serialises requests. Firing these concurrently queues them and gains
    nothing, so this layer is deliberately sequential.

"Error-free" is not achievable by making a small model reliable. It is achieved
by never trusting its output: constrain the shape, validate the semantics, and
require every factual claim to be checkable against a source (`guards.py`).
"""

from __future__ import annotations

__all__ = ["llm", "guards"]
