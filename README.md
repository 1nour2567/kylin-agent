# Kylin Agent

Security-hardened AI operations agent for Kylin OS. Natural language → structured tool calls → security validation → sandboxed execution.

## Architecture

```
User Input → T0 → Perception → Router → Reasoner (LLM) → T1 Risk → T2 Constraints → T3 Sandbox
                                                          ↓                                           ↓
                                                    CONFIRMATION_REQUIRED ← POST /api/confirm → Execution
```

| Stage | Module | What it does |
|-------|--------|---------------|
| T0 | `security/anti_injection.py` | Blocks prompt injection, role-switch, overflow |
| — | `agent/perception.py` | Builds context from mock/real OS sensors |
| — | `agent/router.py` | Classifies intent: query / action / emergency |
| — | `agent/reasoner.py` | LLM generates structured tool calls (JSON) |
| T1 | `security/risk_model.py` | Deterministic risk score (1-10), no LLM |
| T2 | `security/constraints.py` | Tool semantics + raw regex, dual-path veto/confirm |
| T3 | `security/sandbox.py` | Command allowlist enforcement |

## Tool naming convention

All 9 tools defined in a single source of truth — `agent/tools_manifest.py`:

```
llm_name            →  mcp_name          →  sandbox name
ps_processes        →  get_processes     →  ps
df_disk             →  get_disk          →  df
free_memory         →  get_memory        →  free
netstat_connections →  get_connections   →  ss
journalctl_logs     →  journalctl_logs   →  journalctl
systemctl_status    →  systemctl_status  →  systemctl
get_services        →  get_services      →  systemctl
lsof_files          →  lsof_files        →  lsof
rpm_verify          →  rpm_verify        →  rpm
```

Every module (reasoner system prompt, MCP registry, sandbox allowlist, risk model) derives its tool lists from the manifest.

## Setup

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env   # edit with your DeepSeek API key
python main.py          # starts on port 8008
```

### Agent modes

| `AGENT_MODE` | LLM provider | OS sensor | Use case |
|--------------|-------------|-----------|----------|
| `mock` | MockProvider (deterministic) | MockOSSensor (fake data) | Development / testing |
| `live` | MockProvider (deterministic) | RealOSSensor (real `ps`/`df`/`free`/`ss`) | VM demo (no LLM API) |
| (default) | DeepSeek API | MockOSSensor | LLM evaluation |

Combine `live` sensor with DeepSeek by removing `AGENT_MODE` + setting the API key.

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/chat` | POST | Main pipeline: `{"user_id":"...", "input":"..."}` |
| `/api/confirm` | POST | Confirm/deny pending command: `{"event_id":"...", "confirmed":true}` |
| `/api/pending` | GET | List pending confirmations for user |
| `/api/context` | GET | Current system context |
| `/api/posture` | GET | Risk posture and veto/drift stats |
| `/api/audit/trail` | GET | Query audit trail (date range) |
| `/api/audit/event/{id}` | GET | Single audit event by ID |
| `/api/audit/verify` | GET | Verify audit chain integrity |
| `/api/mcp/tools` | GET | List registered MCP tools |
| `/mcp` | POST | Raw MCP protocol endpoint |
| `/stream` | WS | WebSocket for context push |
| `/health` | GET | Health check |

## Risk postures

| Posture | T2 confirm threshold | Audit intensity | Auto-triggers |
|---------|---------------------|-----------------|---------------|
| `permissive` | 7 | full | — |
| `balanced` (default) | 5 | normal | — |
| `restrictive` | 2 | summary | 2 vetos, night-time (22-06) |

## Testing

```bash
cd backend
python -m pytest tests/ -v          # Run all 108+ tests
```

| Test file | Tests | Coverage |
|-----------|------:|----------|
| `test_guardrail.py` | 15 | T0-T3 unit tests |
| `test_pipeline.py` | 11 | E2E pipeline + audit chain |
| `test_risk_posture.py` | 8 | Posture engine state machine |
| `test_jailbreak.py` | 4 | Jailbreak attack vectors |
| `test_jailbreak_corpus.py` | 5 | 35-entry corpus regression |
| `test_key_auth.py` | 17 | KeyStore CRUD + role thresholds |
| `test_confirm_audit_api.py` | 9 | Confirm flow + audit endpoints |
| `test_api.py` | 11 | HTTP-level API tests |
| `test_pessimistic.py` | 19 | Edge cases, concurrency, manifest |
| `test_session_store.py` | 10 | Session TTL, history, concurrency |

All structural — no LLM calls needed.

## Key design decisions

- **Manifest as single source of truth** — tool names, params, risk levels defined once in `tools_manifest.py`; all modules derive their lists from it
- **T2 dual-path validation** — structured tool semantics (primary) + raw regex (defense-in-depth); `rm -rf` patterns caught regardless of format
- **Confirmation loop** — commands flagged by T1 risk score or T2 dangerous params require explicit user `POST /api/confirm` before execution
- **Decay is checked on read** — `posture_for_prompt()` calls `_decay_veto_count()` before every LLM invocation, not just on veto/permit events
- **PATH inherits from environment** — sandbox appends standard paths rather than replacing the OS PATH
- **T0 Sanitizer uses internal ref counter** — rejection references are sequential `REF-00001-ROLE`, trivially auditable
