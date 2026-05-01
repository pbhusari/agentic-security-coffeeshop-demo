# Threat Model

## Assets

| Asset | Description |
|-------|-------------|
| Agent | The LLM-powered process with tool access |
| Tools | read_email, read_file, http_get — capabilities that produce effects |
| User data | Inbox contents, files — the attacker's target |
| Internal services | mail.internal, docs.internal — reachable via tools |
| Model context | The LLM's in-context state — the attack surface for injection |

## Trust boundaries

```
[User prompt]            TRUSTED — originates from authenticated user
    │
    ▼
[Agent / LLM]            PARTIALLY TRUSTED — honest intent, but manipulable context
    │
    ▼
[PEP → PDP]              ENFORCEMENT BOUNDARY — policy evaluated here
    │
    ▼
[Tool execution]         TRUSTED IF AUTHORIZED — PDP has approved this call
    │
    ▼
[Tool output]            UNTRUSTED — may contain adversarial content from external sources
    │
    └── [Internal sources (mail.internal)]   SEMI-TRUSTED
    └── [External sources (newsletters, web)] UNTRUSTED
```

The critical distinction: tool *parameters* come from the LLM (semi-trusted); tool
*output* comes from external sources (untrusted). Indirect prompt injection exploits
this asymmetry — untrusted output influences the LLM, which then produces adversarial
parameters in the next tool call.

## Adversary capabilities

**In scope:**
- Can plant content in any source the agent may retrieve: email, documents, web pages,
  API responses, vector store entries
- Content can include arbitrary text, HTML, structured data, encoded payloads
- Cannot directly access the agent host, model weights, or PDP process
- Cannot observe the agent's context window or PDP decision log in real time

**Out of scope (explicitly):**
- Direct host compromise (assume the agent host is hardened)
- Supply chain attacks on model weights or agent dependencies
- Physical access or side-channel attacks
- Insider threat (authorized user issuing malicious prompts)

## Attack tree: indirect prompt injection

```
Exfiltrate user data via compromised agent
├── [DEMO] Plant injection in email body
│   ├── Social engineering framing ("compliance logging") — evades user suspicion
│   ├── HTML comment wrapping — may evade simple string scanning
│   └── Instruction to call http_get with encoded payload
├── Plant injection in retrieved document
│   └── Same attack surface, different retrieval vector
├── Plant injection in web search result
│   └── Relevant for agents with web access (not in this demo scope)
└── Plant injection in vector store chunk
    └── Relevant for RAG agents (not in this demo scope)
```

The demo implements the first leaf: email body injection with social engineering
framing, HTML comment hiding, and exfiltration via http_get.

## What this PDP detects

| Attack | Check that catches it |
|--------|-----------------------|
| Exfiltration to undeclared destination | check_egress (binary) |
| Injection patterns in retrieved content | check_prompt_carrier (pattern match) |
| LLM copying retrieved content into tool params | check_provenance_token (influence signal) |
| Novel injection idiom, allowed destination | check_provenance_token (complements check_egress) |

## What this PDP explicitly does NOT detect

| Attack | Why it's out of scope |
|--------|-----------------------|
| Model jailbreak via user prompt | User is trusted; model-layer concern |
| Supply chain compromise of agent dependencies | Host security concern |
| Exfiltration via covert channels (timing, DNS) | Network/syscall layer, not tool layer |
| Semantic paraphrasing of provenance token | Evasion path; mitigated by multiple tokens or semantic similarity (Phase 2) |
| Injection that produces correct-looking benign tool calls | Low-signal; needs behavioral baselines (Phase 2) |
| Multi-agent relay attacks | Single-agent scope; multi-agent correlation is Phase 2 |

Scope honesty matters. The PDP is an action-layer policy system. It does not replace
model safety, host security, or network controls. It adds a distinct layer that those
controls cannot provide: per-call authorization with full decision audit trail.
