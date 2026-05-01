# Architectural Decision Records

## ADR-1: PDP/PEP architecture over transparent network proxy

**Status:** Accepted

**Context:** An alternative interception approach is a network-layer proxy (mitmproxy,
iptables redirect) that intercepts HTTP calls from the agent process. This would be
"transparent" — no agent code changes required.

**Decision:** Use a PEP/PDP model where the PEP is a thin wrapper in the agent's tool
client code, and the PDP is a co-located FastAPI process.

**Reasoning:**
- Network proxies can't inspect the semantic meaning of a tool call — they see HTTP
  bytes, not "this is a read_email call with email_id=4." Policy at the tool-call
  level requires tool-call-level visibility.
- The PEP/PDP boundary is the right abstraction for a control plane product: it maps
  directly to the "authorization request" mental model (OPA/Cedar/AWS IAM), which is
  what customers already reason about.
- A transparent proxy requires privileged network config (iptables, routing) that is
  fragile on laptops and requires root. A co-located PDP needs only a localhost port.
- The honest description — "we intercept at the tool dispatch boundary" — is more
  accurate and more interesting than "we are a network proxy," and better supports
  the product's extension to MCP (where the boundary is protocol-level, not network).

---

## ADR-2: Three independent checks over a single classifier

**Status:** Accepted

**Context:** A single ML classifier trained on injection examples would be simpler to
deploy and potentially higher recall on known attack patterns.

**Decision:** Use three independent rule-based checks: egress allowlist, prompt-carrier
scan, canary token.

**Reasoning:**
- Each check captures a distinct signal with a different FP profile. Composing them
  gives defense in depth: an attack that evades one check is likely caught by another.
- Rule-based checks are auditable — the customer can read the policy and understand
  exactly what will be blocked. A classifier is a black box.
- A classifier needs labeled training data. Without a design partner's production
  traffic, any classifier we train today will have unknown generalization. The three
  checks have honest, characterizable accuracy (see docstrings in sensor.py).
- The egress check is provably correct (binary allowlist). The canary check has near-
  zero FP by construction. Putting them in the same "classifier" would obscure their
  accuracy guarantees.

---

## ADR-3: Canary tokens as an influence signal

**Status:** Accepted

**Context:** Egress blocking and carrier scanning operate on static signals (destination,
content patterns). An adversary who knows the policy can craft an injection that targets
an allowed destination with no flagged keywords.

**Decision:** Inject unique per-call canary tokens into tool output and detect them in
subsequent tool call parameters.

**Reasoning:**
- The canary operates on the influence signal rather than the destination or content
  signal. If the LLM copies a canary into a tool call, that is direct evidence that
  the tool call was influenced by retrieved content rather than user intent — regardless
  of where it's going or what it says.
- FP rate is near-zero by construction: the canary is a cryptographically random
  8-hex-char token. The probability of a collision with legitimate user content is ~1
  in 4 billion per call.
- The main evasion path is LLM paraphrasing: the model follows the injected instruction
  semantically rather than copying the canary literally. This is a real limitation and
  is documented. It motivates semantic similarity checks in Phase 2.
- The canary also serves as a debugging tool: it shows exactly which tool call seeded
  the content that influenced a later call.

---

## ADR-4: Local LLM via Ollama over cloud API

**Status:** Accepted

**Context:** The demo could use Claude or GPT-4 via API, which would give more reliable
tool-calling behavior.

**Decision:** Use Ollama with qwen2.5:3b (or llama3.2:3b as fallback) on localhost.

**Reasoning:**
- The demo runs at a coffee shop / restaurant. API calls require reliable internet.
  Ollama runs offline after model pull — zero network dependency during the demo.
- No API spend during the demo session or development iteration.
- The PDP/PEP architecture is the interview artifact, not the LLM's sophistication.
  A 3B model that reliably emits tool calls is sufficient. If it doesn't (verify
  before committing), the replay trace covers the same attack path deterministically.
- qwen2.5:3b has decent tool-calling support for its size. Fallback: llama3.2:3b.

---

## ADR-5: No Docker

**Status:** Accepted

**Context:** Docker would provide better isolation and reproducible environments.

**Decision:** Run sensor.py and agent.py as plain Python processes started by run.sh.

**Reasoning:**
- The demo runs on a single laptop. Two Python processes plus a browser tab is the
  simplest possible setup — one more thing to go wrong is one more thing that will go
  wrong at the worst moment.
- Docker adds: installation check, daemon start, image pull or build, network config,
  volume mounts. Each step is a potential failure point with no recovery time.
- The code runs in a venv. Dependencies are pinned in requirements.txt. Reproducibility
  is achieved through simplicity, not containerization.

---

## ADR-6: Explicit scope boundary — what's out of scope and why

**Status:** Accepted

**Decision:** The demo scope is: one agent, one attack path (indirect prompt injection
via email), three PDP checks, one attacker destination.

**Explicitly out of scope:**
- Behavioral baselining / ML anomaly detection: requires real customer telemetry to
  build an honest baseline. Building a fake one would be worse than not having one.
- Multi-agent correlation: adds significant complexity for no additional clarity in a
  5-minute demo. Single-agent, maximum depth.
- MCP protocol support: the architecture extends naturally (see ARCHITECTURE.md), but
  implementing a full MCP proxy requires more time than the interview prep window.
- OWASP Agentic Top 10 items #2-10: demonstrating one attack with depth and complete
  detection beats four shallow demonstrations. Breadth is covered in conversation.
- Real network exfiltration: the evil.example endpoint is simulated inside the agent
  process. The PDP blocks before execution in active mode; the simulation is only
  reached in monitor mode to show the contrast. This is the honest description and
  matches what the PDP actually intercepts (tool dispatch, not network packets).
