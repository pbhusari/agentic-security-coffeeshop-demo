# Architecture: Agentic Security Control Plane

## The control plane thesis

Agents act through tools. A tool call is the atomic unit of agent action — it is where
the agent's intent becomes a real-world effect (reading data, fetching a URL, sending a
message). This is also where indirect prompt injection attacks materialize: an adversary
plants a malicious instruction in retrievable content (an email, a doc, a web page), the
agent reads it, and the LLM is influenced to call tools it shouldn't.

The insight is that tool calls are authorization requests. Like a service-to-service API
call or a cloud IAM request, they can be evaluated against policy before execution. The
control plane is that evaluator — a Policy Decision Point (PDP) that stands between the
agent's intent and its actions, checking every call against declared policy and returning
a verdict before the agent acts.

This is not model-level guardrails. It is not network-level interception. It is policy
enforcement at the tool dispatch boundary — the right architectural altitude because it
is close enough to the action to be deterministic, far enough from the model to be
auditable and separately deployable.

## PDP / PEP separation

```
agent.py                              sensor.py (PDP)
────────────────────────────          ──────────────────────────────
Policy Enforcement Point (PEP)        Policy Decision Point (PDP)
  - wraps tool client                   - evaluates policy
  - submits every tool call             - runs three checks
    to PDP via POST /check              - returns Verdict
  - honors verdict:                     - logs every decision
    allow → execute                     - serves SSE feed
    block → raise PolicyViolation       - owns policy.yaml
    flag  → execute, log warning
```

The PEP knows nothing about policy. It only knows how to call the PDP and honor the
verdict. The PDP knows nothing about the agent's task — it sees tool name, params, and
output, evaluates against policy, and returns a verdict. This separation means:

- **Auditability**: every decision is logged before the agent acts, by a process the
  agent cannot influence. The log is the authoritative record of what the agent did.

- **Testability**: the PDP is a FastAPI service; its check logic is pure functions; the
  test suite runs against it directly without Ollama. Policy correctness is tested
  independently of LLM behavior.

- **Composability**: the same PDP can serve multiple agents, multiple tools, multiple
  sessions. Policy is centralized; enforcement is local to each PEP.

## Where this sits in the defense stack

Three layers defend against agent compromise:

1. **Model-layer guardrails** (e.g., Lakera Guard, Nemo Guardrails): detect adversarial
   content in prompts and model outputs via classifiers. Operate at inference time.
   High recall, moderate precision, LLM-dependent.

2. **Action-layer policy** (this system): evaluate tool calls against declared policy.
   Operate at dispatch time. Binary for egress, tunable for carriers, near-zero FP for
   provenance token. LLM-independent — the policy evaluates the call, not the model's reasoning.

3. **Runtime sandboxes** (e.g., e2b, Firecracker): restrict what the agent process can
   do at the OS level. Operate at syscall time. Broad containment, not call-specific.

These are complementary. A model-layer guardrail that misses a novel injection idiom
is caught by the action-layer policy. An action-layer policy that allows a call to a
permitted destination with a novel exfiltration technique is caught by the provenance
token check. A provenance token check that's evaded by semantic paraphrasing is caught
by the runtime sandbox. Depth
of defense; different altitude; different failure modes.

## Extension to multi-agent and MCP deployments

In a multi-agent fleet, each agent embeds a PEP. All PEPs point to the same PDP.
Policy is centrally authored, versioned, and audited. The decision log shows the full
fleet's tool-call behavior in one place.

For MCP-based deployments, the PEP becomes an MCP proxy or sidecar: it intercepts
tool calls at the MCP protocol boundary, submits them to the PDP, and forwards or
drops them based on the verdict. The same policy model applies; only the wire format
changes. This is a natural extension — MCP is already an authorization boundary (it
defines what tools an agent can call); the PDP adds a what-it-can-call-under-what-
conditions layer on top.

## Phase 2 (deferred — needs real customer telemetry)

- **Behavioral baselines**: learned policy from observed agent behavior (what tools
  does this agent normally call, at what frequency, with what param distributions).
  Deviations from baseline are a signal. Requires a design partner with production
  traffic to build an honest baseline — not demo-able without real data.

- **Policy DSL**: a richer policy language than YAML key-value allowlists (temporal
  constraints, context-conditional rules, cross-agent correlation). The current YAML
  is correct and auditable but not expressive enough for production policies.

- **Eval harness**: automated evaluation of policy accuracy across a diverse set of
  attack traces and benign workloads. Requires ground-truth labels — again, needs
  real data to be honest.
