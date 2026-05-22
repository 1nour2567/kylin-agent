# Constraint Architecture

## How should an LLM agent define its boundaries?

The current answer: **the prompt says so.**

You write "do not perform dangerous operations" in your system prompt. You expect the LLM to enforce those rules on itself.

This defense is soft. A prompt injection bypasses it. The deeper problem: **letting an LLM define its own boundaries is the wrong idea to begin with.**

---

## Boundaries shouldn't be defined by the LLM. They should be defined by code.

This is Constraint Architecture.

Boundaries are the *result*. Constraints are the *implementation*. Boundaries say "what's not allowed." Constraints say "how code makes it not happen."

LLM reasons. Code decides what's allowed. Audit ensures no one can deny.

Constraints live in code — deterministic, non-bypassable, independently verified at each layer.

Every domain has its boundaries. Security ops: "no `rm -rf /`." Embodied AI: "no `light_burst` when energy < 0.3." Boundaries differ — the architecture that enforces them is the same.

---

## Four layers

```
Layer 1: Reasoning (LLM)
    → Free reasoning. Outputs structured instructions.
    The LLM's output is information, not permission to act.

          ↓

Layer 2: Constraints (Deterministic)
    → Reads LLM output. Dual-path validation.
    Structured tool params + raw regex. Two paths, independently verified.
    This layer is opaque to the LLM — even an attacker controlling the LLM
    cannot bypass it.
    Constraints are additive only: the baseline never retreats.

          ↓

Layer 3: Execution (Sandbox)
    → Whitelist. Tiered: auto / confirm / veto.
    Non-whitelisted commands cannot execute.
    Role and permission are enforced here — no override path.

          ↓

Layer 4: Audit (Immutable Record)
    → Every action recorded. Tampering detectable.
    Ideal form: SHA256 chain, cryptographically immutable.
    Lightweight form: rule-health feedback loop — constraints kept
    continuously valid rather than written once and forgotten.
```

**Priority rule: Layer 2 hard constraints > Layer 1 reasoning preference.**

When the execution layer says "no," the reasoning layer's "yes" does not take effect. Not negotiation — hard override.

---

## "LLM is the observer. Code is the decider."

This is the most easily overlooked and most valuable line in the whole thing.

**The LLM does not decide to lower a threshold. The LLM provides an observation. Code receives the observation and makes its own decision.**

Kylin-Agent's Intent Profile is built on this principle:

```
LLM observes: "The user was just denied as viewer.
              Now they switched to an operator key and retried the same request.
              Possible privilege escalation retry."

LLM outputs: intent_profile = {risk_hint: "privilege_retry"}

Constraint layer receives this signal and queries its rule table:
  risk_hint="privilege_retry" → intent_boost = 4
  effective_threshold = posture_base + role_offset - intent_boost
                      = 5 + 0 - 4 = 1

  Normally risk ≥ 5 requires confirmation. Now risk ≥ 1 requires confirmation.
  Same operator — normal request goes through, privilege retry gets stepped-up scrutiny.
```

**LLM provided behavioral analysis. Code made the security decision.**

LLM gets it wrong (false positive on privilege retry) — user confirms an extra time. LLM misses it (false negative) — the existing role and command rules still hold.

Separate observation from decision. The observer's error cannot cause catastrophe — only affect experience. The decision authority stays in deterministic code.

---

## Multi-agent: no one holds all the keys

Constraint has a second meaning: **constraining each agent module to its responsibility.**

Both reference implementations decompose into specialized agents with non-overlapping authority:

**Malio:** MusicAgent cannot modify particles. VisualAgent cannot override PersonaEngine. LLMAutonomous's microphone can be cut by the dismissal gate. No single agent has full control.

**Kylin-Agent:** Classifier only classifies. Reasoner cannot skip T2. ProactiveInspector only observes — even on critical findings, it can only push alerts, never execute commands. BaselineLearner learns but does not participate in real-time decisions. RiskPostureEngine is independent of all modules — the Reasoner cannot override it.

**The principle: split authority. No single point can take full control.**

---

## How to use it

Building an agent in a new domain? What's your constraint dimension? Fill in the four layers.

Medical dosing constraint, for example:

```
Layer 1: LLM analyzes symptoms, suggests "Digoxin 0.5mg"
Layer 2: Constraint layer checks — Digoxin starting dose ceiling is 0.25mg. Rejected. Suggests 0.125mg.
Layer 3: Suggestion marked confirm (medical decisions require human), never auto-execute.
Layer 4: Original suggestion + rejection reason + final decision recorded — traceable, non-repudiable.
```

The point isn't "LLM says something and code rubber-stamps it." Code draws a line where harm can occur. The LLM operates freely inside that line.

---

## Two reference implementations

| | Kylin-Agent | Malio |
|---|---|---|
| **Domain** | Security ops Agent | Embodied AI music Agent |
| **Reasoning** | Diagnosis + tool selection + Agentic Loop | Atmosphere perception + DSL rule creation + proactive heartbeat |
| **Constraints** | Security rules + 3-tier role + dynamic posture + Intent Profile | Persona 3D constraints + DSL rule engine + VisualAgent governance |
| **Execution** | auto/confirm/veto + sudo -n + persistent confirm queue | VisualAgent rule evaluation + particle rendering + Feedback push |
| **Audit** | SHA256 chain, immutable, _seed_from_disk restart recovery | Lightweight: OODA rule feedback loop for continuous constraint health |
| **Verification** | Kylin V11 deployment · 149 tests · 16 red-team attacks, 0 penetrations | 800 particles, 9 physics systems · 75 tests · Proactive Heartbeat |

Kylin-Agent's constraint layer is deep in identity, permissions, rule coverage, and tamper-proof audit. Malio's constraint layer is deep in persona boundaries, rule governance, semantic clustering, and trust evolution for autonomous behavior. Malio's Layer 4 is lightweight — it lacks cryptographic non-repudiation, but the OODA feedback loop ensures rules are continuously evaluated at runtime (dead rule archiving, conflict downgrading, hits scoring), which is itself a verifiable guarantee of constraint health.

Same architecture. Different depth. Two independent validations in completely different domains.

---

## Design principles

### 1. The LLM's boundary judgments are not trustworthy

Prompt-layer rejection is soft — the LLM can be talked out of its own restrictions by round 5 of a conversation. Constraint-layer rejection is hard — code does not retract, regardless of what the LLM says in any round.

### 2. Constraints are additive only

The same baseline applies in permissive mode and restrictive mode. Admin is subject to the same baseline constraints. New contexts can add more — but never relax existing ones.

### 3. Constraints self-regulate with system state

Constraints are not static values — they adjust with system state, time, and behavioral history. In Kylin-Agent: 2 consecutive T2 vetos → posture tightens from balanced to restrictive. In restrictive mode the confirmation threshold drops to 0 — commands that normally auto-execute now all require explicit confirmation. After 24h of calm, posture auto-regresses. This isn't an operator turning a dial — it's the system's immune response, locking down its own capabilities.

### 4. Interfaces do not bind to domain

ConstraintEngine does not care whether the domain is security, music, or medical dosing. Sandbox does not care whether upstream produces ops commands, particle parameters, or medical suggestions. Each layer is independently replaceable. The interface stays the same; the implementation can change.

---

## What it's not

- Not an open-source framework — currently an architecture description with two reference implementations
- Not a "security architecture" — security is one application
- Not making LLMs weaker — Layer 1 reasoning is completely free; constraints apply only to *action*
- Not new theory — defense-in-depth, least privilege, and non-repudiable audit have held in security engineering for 50 years. What's new is them being applied in the LLM agent domain
- Not Prompt Engineering — not "write better prompts." It's *not using prompts for constraints at all*

---

## Why "Constraint"

Not "guardrail." Not "security layer."

Constraint. This word carries three meanings, all present in this architecture.

For the LLM: **constraining** its action boundary — not limiting what it thinks, but what it can do.

For the modules: **constraining** each agent's responsibility — reasoning only reasons, validation only validates, execution only executes. No module can cross its boundary.

For the architecture: **constraining** the dependency direction — Layer 1 can only pass downward, Layer 2 can only receive from Layer 1. Unidirectional data flow. No circular permissions.

One word. Three layers of meaning. All domains.

---

*May 2026. Two projects. Three weeks. Two domains. One architecture.*
