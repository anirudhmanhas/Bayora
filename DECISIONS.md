# Architecture Decision Records (ADRs) — Bayora

This document records the architectural decisions, trade-offs, and rationale adopted throughout the design and hardening of the Bayora POC.

---

## ADR-001: Declarative Rule Matching vs. Arbitrary Code Execution for Blue Defense
* **Status**: Accepted
* **Context**: Blue team submits defensive logic to filter red-team prompts and model responses. Allowing Blue to submit executable scripts (e.g., Python code, custom binaries) introduces arbitrary code execution (RCE) risks, container breakouts, and infinite loop/denial-of-service vulnerabilities.
* **Decision**: Defense logic is strictly declarative JSON containing pattern tokens, regexes, thresholds, and target specifications (`prompt`, `response`, or `all`). The `defense-runner` interprets these declaratively using safe `re.escape()` matching.
* **Consequences**: Zero arbitrary code execution within the defense pipeline; defense logic can be inspected, audited, and executed safely in a sub-millisecond evaluation sandbox.

---

## ADR-002: Dual-Stage Commit-Reveal Hash Ledger before Model Execution
* **Status**: Accepted
* **Context**: Red team submits prompts, and Blue team must not see them during the active test. However, after test conclusion, both parties need non-repudiation and proof that payloads were not altered.
* **Decision**: Before any prompt is evaluated or forwarded to the model, the Gateway computes a SHA-256 hash of the prompt and logs a `payload_commit` block into an append-only cryptographic ledger (`bayora-audit`). The model response is similarly committed via `response_commit`. Raw payloads remain sequestered in `red_payloads` volume. Upon conclusion, hashes are recomputed from storage and cryptographically verified against the chain before releasing read-only files to Blue.
* **Consequences**: Cryptographic non-repudiation without data leakage; any retroactive tampering with payloads or model replies causes an immediate verification failure.

---

## ADR-003: Real Groq Cloud API Integration with Ephemeral RAM Sessions
* **Status**: Accepted
* **Context**: The competition requirements transitioned from a static echo stub to real LLM inference with multi-turn conversation memory within a test, while ensuring strict zero-context carryover between tests and tenants.
* **Decision**: Implemented real Groq Cloud API integration (`llama-3.1-8b-instant`) in `model-service`. Multi-turn history is stored in an in-memory dictionary keyed by `session_id` (`test_id`). When a test concludes, `DELETE /sessions/{test_id}` immediately drops the session from RAM. No conversation history is ever written to disk.
* **Consequences**: Enables realistic adversarial jailbreak and multi-turn testing while maintaining provable tenant isolation (demonstrated via canary secret testing).

---

## ADR-004: Dedicated Egress Proxy with Hardened Host Allowlist
* **Status**: Accepted
* **Context**: The `model-service` requires outbound network connectivity to communicate with Groq Cloud, but granting arbitrary internet egress violates the zero-trust environmental isolation requirement and enables data exfiltration.
* **Decision**: `model-service` is restricted to `model-net` (`internal: true`). All outbound HTTPS traffic is forced through an isolated, dual-homed `egress-proxy` service (`HTTP_PROXY`/`HTTPS_PROXY`) connected to `model-net` and `egress-net`. The proxy intercepts HTTP `CONNECT` tunnels and enforces an explicit allowlist permitting only `api.groq.com:443`.
* **Consequences**: Arbitrary outbound connections, DNS tunneling, and command-and-control egress from `model-service` are blocked at the network proxy layer.

---

## ADR-005: Multi-Layer Output Sanitization on LLM Responses
* **Status**: Accepted
* **Context**: Raw LLM responses may inadvertently leak system prompt instructions, reveal backend stack traces, embed malicious markdown images for out-of-band data exfiltration, or emit internal reasoning tokens.
* **Decision**: Implemented `model-service/sanitizer.py`, which strips:
  1. Internal reasoning tags (`<think>...</think>`).
  2. System prompt leakage patterns.
  3. Python/Linux error stack traces.
  4. Markdown external image embeds (`![...](http...)`).
  5. Raw URLs pointing to external hosts.
* **Consequences**: Responses leaving `model-service` cannot be used as an exfiltration vector or expose backend infrastructure diagnostics to the red team.

---

## ADR-006: Response Time Padding against Timing Oracles
* **Status**: Accepted
* **Context**: A red team can infer whether Blue's defense triggered by measuring the latency difference between an allowed prompt (which travels to the LLM) and a blocked prompt (which returns immediately from defense-runner).
* **Decision**: Implemented configurable `RESPONSE_PADDING_MS` in the Gateway. If total elapsed time is less than the padding target, the gateway sleeps until the minimum duration is met.
* **Consequences**: Closes the timing side-channel oracle. Benchmarking shows that 100 ms padding compresses the measured Δp50 between Blue idle and Blue busy from +13.65 ms to −4.57 ms.

---

## ADR-007: Judge Adjudication Dashboard Network & Role Partitioning
* **Status**: Accepted
* **Context**: Competition adjudicators require a live, projector-readable console to observe test lifecycles, inspect the cryptographic audit chain, trigger integrity verification, and view security violation events without exposing telemetry to competitors.
* **Decision**: The Judge Dashboard is served directly through the Gateway (`GET /judge` and `/judge/api/*`). Access requires `X-Role: judge` or a pre-shared `JUDGE_TOKEN`. Crucially, requests originating from tenant subnets (`172.28.2.0/24` red-net, `172.28.3.0/24` blue-net) or carrying tenant headers are unconditionally rejected with HTTP 403 Forbidden. The existing `/logs` endpoint is brought under the same judge authentication umbrella.
* **Consequences**: Adjudicators have full, real-time observability on a projector screen while competitor tenants are mathematically and architecturally barred from inspecting monitoring or audit data.

---

## ADR-008: Global Audit Chain Verification Query (`__all__`)
* **Status**: Accepted
* **Context**: The audit service originally required a single `test_id` to verify integrity. Adjudicators need to verify the entire blockchain integrity and validate all concluded tests in a single click from the dashboard.
* **Decision**: Updated `audit/main.py` `/verify` to accept `test_id: "__all__"`, verifying both full block chain linkage (`prev_hash` check and SHA-256 block recomputation) and matching all candidate items from storage against logged hashes.
* **Consequences**: A single click on the Judge Dashboard's "Verify Integrity" button provides an instant green/red cryptographic health check across the entire competition ledger.
