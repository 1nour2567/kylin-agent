# Kylin Agent

Security-hardened AI operations agent for Kylin OS.  Natural language → classifier → dynamic system prompt → T0-T3 security validation → sandboxed execution.

**Security reference implementation of [Constraint Architecture](https://github.com/1nour2567/kylin-agent/blob/master/CONSTRAINT.md) — LLM reasons. Code decides what's allowed.**
See also: [Malio](https://github.com/1nour2567/Malio) (embodied AI reference implementation).

**Deployed on:** Kylin Linux Advanced Server V11 (Swan25) · x86_64 · DeepSeek LLM

![Constraint Architecture](constraint-architecture.svg)

## Architecture

```
User Input → T0 → Perception → Classifier (LLM) → Reasoner (LLM + Dynamic Prompt)
                                                          ↓
                              CONFIRMATION_REQUIRED ← POST /api/confirm → Execution
                                              ↓
                              T1 Risk → T2 Constraints → T3 Sandbox
```

| Stage | Module | What it does |
|-------|--------|---------------|
| T0 | `security/anti_injection.py` | Blocks prompt injection, hex/base64/unicode obfuscation, overflow |
| — | `agent/perception.py` | Builds context: OS sensors + conversation history + audit trail |
| — | `agent/classifier.py` | LLM-based intent classifier (query/action/emergency), rule fallback |
| — | `agent/reasoner.py` | DeepSeek LLM with dynamic system prompt (posture/role/time-aware) |
| T1 | `security/risk_model.py` | Deterministic risk score (1-10), manifest-derived |
| T2 | `security/constraints.py` | Dual-path: structured tool semantics + raw regex; role-based thresholds; path/content inspection |
| T3 | `security/sandbox.py` | Allowlist enforcement, tiered execution (auto/confirm/veto), `sudo -n` |
| — | `auth/key_store.py` | SHA256-hashed API keys with role assignment (admin/operator/viewer) |
| — | `middleware/auth.py` | Bearer token middleware, public path whitelist |
| — | `audit/store.py` | Append-only JSONL with SHA256 hash chain, cross-restart persistence |
| — | `audit/baseline.py` | Daily behavioral profiles + 3σ anomaly detection |
| — | `agent/session_store.py` | Per-session conversation history with TTL eviction |
| — | `agent/proactive.py` | Scheduled system inspection (disk/memory/services) every 5 min |

## Defense layers

```
Layer 1: Dynamic System Prompt → "你是viewer" → LLM refuses dangerous commands
Layer 2: T2 constraints.py      → destructive tool / dangerous path / role veto
Layer 3: Guardrail tier check   → viewer + confirm-tier → VETO
Layer 4: T3 sandbox             → allowlist whitelist, sudo -n
```

All four layers are deterministic code — no LLM participates in security decisions.

## Tools (16)

| Type | Tools |
|------|-------|
| Read-only (9) | ps_processes, df_disk, free_memory, netstat_connections, journalctl_logs, systemctl_status, get_services, lsof_files, rpm_verify |
| Confirm (4) | systemctl_restart, journalctl_clean, kill_process, truncate_log |
| File ops (3) | create_file, append_file, execute_script |

File ops enforce path whitelist (/etc /boot /sys /proc /root blocked) and content inspection (dangerous patterns upgrade to confirm tier).

## Roles

| Role | Threshold offset | Tool scope |
|------|---------|-------------|
| Admin | +2 | All tools, lower confirm bar |
| Operator | 0 | All tools, standard confirm |
| Viewer | -999 | Read-only only |

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
| `mock` | MockProvider | MockOSSensor | Dev / testing |
| `live` | MockProvider | RealOSSensor | VM demo (no LLM) |
| `default` | DeepSeek API | RealOSSensor | Production |

## API

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/chat` | POST | Bearer | Main pipeline with streaming support |
| `/api/chat/stream` | POST | Bearer | SSE streaming variant |
| `/api/confirm` | POST | Bearer | Confirm/deny pending (viewer blocked) |
| `/api/pending` | GET | Bearer | List pending confirmations |
| `/api/context` | GET | Public | Role-gated system context |
| `/api/whoami` | GET | Public | Current user identity |
| `/api/posture` | GET | Public | Risk posture, veto count, drift log |
| `/api/inspect` | GET | Public | Latest proactive inspection |
| `/api/baseline` | GET | Admin | Baseline profiles + anomaly detection |
| `/api/audit/trail` | GET | Admin | Query audit trail |
| `/api/audit/event/{id}` | GET | Admin | Single audit event |
| `/api/audit/verify` | GET | Admin | Verify SHA256 chain integrity |
| `/api/session/{id}` | GET | Bearer | Session history |
| `/api/mcp/tools` | GET | Public | Registered MCP tools |
| `/mcp` | POST | Bearer | Raw MCP protocol |
| `/stream` | WS | Token | WebSocket with auth |
| `/health` | GET | Public | DeepSeek reachability + posture |

## Risk postures

| Posture | T2 confirm threshold | Audit | Auto-triggers |
|---------|---------------------|-------|---------------|
| `restrictive` | 0 | summary | 2 vetos, nighttime (22-06) |
| `balanced` (default) | 5 | normal | — |
| `permissive` | 7 | full | Manual opt-in |

Veto decay: 1h. Auto-regress: 24h no veto → balanced.

## Testing

```bash
cd backend
python -m pytest tests/ -v          # 135 tests, all structural
```

| Test file | Tests | Coverage |
|-----------|------:|----------|
| `test_guardrail.py` | 15 | T0-T3 individual layers |
| `test_pipeline.py` | 11 | E2E pipeline + audit chain |
| `test_risk_posture.py` | 8 | Posture state machine |
| `test_jailbreak.py` | 4 | Known attack vectors |
| `test_jailbreak_corpus.py` | 5 | 35-entry corpus regression |
| `test_key_auth.py` | 17 | KeyStore CRUD + role thresholds |
| `test_confirm_audit_api.py` | 9 | Confirm/deny flow + audits |
| `test_api.py` | 11 | HTTP-level integration |
| `test_pessimistic.py` | 19 | Edge cases, concurrency |
| `test_session_store.py` | 10 | Session TTL, concurrent access |
| `test_semantic_ambiguity.py` | 7 | Chinese ambiguity corpus (25 cases) |
| `test_baseline.py` | 9 | Baseline learning + 3σ detection |

All tests are structural — no LLM calls needed. Run in <1s.

## Deploy

```bash
# On Kylin VM:
tar xzf kylin-agent-deploy.tar.gz -C /opt/kylin-agent/
cd /opt/kylin-agent
sudo bash deploy/kylin-install.sh

# Requires: /etc/sudoers.d/augustus-agent with NOPASSWD + !requiretty
```

## Key design decisions

- **Manifest as single source of truth** — 16 tools, all modules derive from `tools_manifest.py`
- **LLM is always distrusted** — T2/T3 are deterministic code; the LLM provides tool suggestions, security layers validate them
- **Dynamic system prompt** — Posture, role, and time-of-day appended to base security rules (which are never removed)
- **Defense-in-depth** — Four independent layers; bypassing one doesn't bypass all
- **SHA256 audit chain** — Tamper-evident, cross-restart persistence, FOIA endpoints
- **Proactive + baseline** — 5-min inspection + daily baseline + 3σ anomaly detection
- **Role-gated visibility** — Anonymous sees nothing, viewer sees basic, admin sees full system
