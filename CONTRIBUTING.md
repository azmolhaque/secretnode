# Contributing to SecretNode

Thanks for your interest in improving SecretNode. This is an **authorized-use security
tool** — please read [`SECURITY.md`](SECURITY.md) before contributing, and never submit
real credentials, live targets, or exploitation code.

## Development setup

```bash
git clone https://github.com/azmolhaque/secretnode
cd secretnode
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SECRETNODE_API_KEY=$(openssl rand -hex 24)
```

## Before you open a PR

```bash
ruff check backend/     # lint (must pass)
pytest                  # full test suite (must pass)
```

- **Add tests** for any new behaviour. Detection patterns must ship with a test that
  proves they match a realistic (high-entropy, synthetic) value and a test that they
  don't match an obvious placeholder.
- **New secret patterns** must include a `severity`, a `cwe`, and a `remediation` string
  so they flow correctly into reports and SARIF output.
- Keep the scanner **passive** — no exploitation, no use of discovered credentials, no
  write operations against targets.
- Match the existing code style; `ruff` enforces the correctness subset (`E9`, `F`).

## Commit / PR conventions

- Small, focused commits with clear messages.
- Reference any related issue in the PR description.
- CI (lint + tests on Python 3.11 and 3.12, plus a Docker build) must be green.
