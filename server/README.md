# DRA Server

Phase 0/1 implementation of the DRA platform per the integrated design doc
(`DRA — Driver Research Automation 整合方案 v2.md`).

## Scope this milestone

- Reference-typed `ResearchState` (only IDs + summaries in LangGraph state)
- 11-Agent skeleton + Static Research MVP
- Tool Gateway (async, idempotent, audit, approval)
- Evidence Registrar with E0-E7 strength + lineage
- QA Auditor (Rule + Evidence + LLM)
- Compliance / Authorization framework
- Untrusted Input Wrapper
- FastAPI surface covering Phase 0/1 routes; Phase 2+ routes return 501
- Local JSON + filesystem storage (Postgres/S3 swap-in path preserved)
- Mock LLM, Mock Lab (real implementations behind interfaces)

## Quick start

```bash
# Use Python 3.13 (this repo)
PY="D:/every/python/python313/python.exe"

# (Optional) install deps into a venv
"$PY" -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[dev]"

# Run the API
"$PY" -m uvicorn dra.main:app --reload --port 8000

# Run tests
"$PY" -m pytest -q
```

## Layout

```
dra/
  main.py                 FastAPI entry
  config.py               env / paths
  models/                 Pydantic v2 data models
  compliance/             authz, threat model, variant policy
  untrusted/              untrusted input wrapper
  storage/                filesystem + repository + artifact store
  evidence/               evidence registrar + lineage
  qa/                     QA auditor (rule + evidence + llm)
  tools/                  tool gateway + policy + approval + audit + tools
  llm/                    LLM client abstraction + mock + router
  agents/                 11 agents
  graph/                  LangGraph state + subgraphs + main graph
  api/                    FastAPI routers
tests/                    smoke tests
```

## What is NOT in this milestone

- Real LLM calls (mock client)
- Real Postgres / Redis / S3 (local JSON + filesystem, interfaces preserved)
- Real Windows Lab / Ghidra / WinDbg (mock_lab)
- Real PE parsing (pefile absent from the 3.13 env this repo targets)
- Full Reverse Agent, Validation, Detection, Replay execution
- OpenAI Agents SDK, MCP (deliberately not introduced in Phase 0/1)

See `../.hermes/plans/dra-implementation.md` for the full plan.
