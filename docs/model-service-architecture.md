# Model Service Architecture & Security Guarantees

This document details the architecture, session lifecycle, egress boundaries, output filtering, and security assumptions for the `model-service` integrated with the hosted Groq API.

---

## 1. Provider-Side Caching & Scope of Guarantee

> [!IMPORTANT]
> ### Provider-Side KV-Cache Disclaimer
> Because Groq is an external, hosted third-party inference provider, **we cannot inspect, flush, or audit provider-side caching, hardware KV-caches, speculative decoding caches, or shared prefix caches** managed by Groq's cloud infrastructure.
>
> ### Our Guarantee
> **Our platform guarantees that we carry zero context between sessions.**
> - Each test session maintains an ephemeral, isolated conversation history strictly in volatile RAM.
> - Multi-turn conversation history is strictly scoped to the active `session_id` (`test_id`).
> - When a test concludes (`POST /tests/{test_id}/conclude`), the gateway dispatches a session termination signal that completely purges that conversation state from `model-service` memory.
> - No conversation history is written to persistent storage, shared across tests, or leaked between tenants.
> - Every submission records the `session_id` in the immutable audit ledger.

---

## 2. Network Layout & Egress Proxy

`model-service` has **no direct outbound internet access**. It is attached exclusively to `model-net` (`internal: true`).

To reach the Groq API (`api.groq.com:443`), outbound traffic must transit through a dedicated `egress-proxy`:

```
┌──────────────────────────────── model-net (internal: true) ──────────────────────────┐
│                                                                                      │
│   ┌─────────────────────────────┐            ┌───────────────────────────────────┐   │
│   │        model-service        │            │           egress-proxy            │   │
│   │        (172.28.4.3)         │            │      (172.28.4.4 / 172.28.7.2)    │   │
│   │  - Ephemeral Sessions       │            │  - Strict CONNECT filter          │   │
│   │  - Output Filter Sanitizer  │───────────>│  - ALLOW: api.groq.com:443        │   │
│   │  - NEVER logs GROQ_API_KEY  │ (TCP 3128) │  - DENY: all other destinations   │   │
│   └─────────────────────────────┘            └─────────────────┬─────────────────┘   │
└────────────────────────────────────────────────────────────────┼─────────────────────┘
                                                                 │ (egress-net)
                                                                 ▼
                                                      ┌─────────────────────┐
                                                      │   api.groq.com:443  │
                                                      │     (Groq Cloud)    │
                                                      └─────────────────────┘
```

### Network Isolation Policies:
1. **`model-net`** (`internal: true`): Joined by `gateway` (`172.28.4.2`), `model-service` (`172.28.4.3`), and `egress-proxy` (`172.28.4.4`). No public internet routing.
2. **`egress-net`** (`internal: false`): Joined exclusively by `egress-proxy` (`172.28.7.2`) to establish TCP streams to `api.groq.com:443`.
3. **Egress Allowlist**: The proxy inspects the HTTP `CONNECT` target.
   - If destination is `api.groq.com:443`, the tunnel is established.
   - If destination is any other host (e.g., `google.com`, `attacker-c2.com`) or port (e.g., 80, 8080), the proxy immediately returns `HTTP 403 Forbidden` and terminates the connection.

---

## 3. Ephemeral Sessions & Multi-Turn Jailbreak Sequences

- **Within an active test**: Multi-turn jailbreak attempts and iterative prompts are preserved in RAM under `sessions[session_id]`. Both user messages and model replies are recorded so multi-turn interactions function properly.
- **On Test Conclusion**: When `POST /tests/{test_id}/conclude` is called, the gateway calls `DELETE /sessions/{test_id}` on `model-service`. The session dictionary entry is popped and dereferenced.
- **Cross-Tenant Isolation**: Each test generates a cryptographically unique `test_id` / `session_id`. Tenants are partitioned into independent network namespaces (`red-net`, `blue-net`) and isolated session buckets.

---

## 4. Multi-Layer Output Filter

Before any model response leaves `model-service`, it is passed through `sanitize_model_output`:

| Category | Filter Rule | Replacement / Action |
| :--- | :--- | :--- |
| **Reasoning Tags** | `<think>...</think>`, `<thought>...</thought>`, `<reasoning>...</reasoning>`, unclosed tags | Stripped completely |
| **Markdown Images** | `![alt](url)` (can carry data out via URL parameters) | Replaced with `[IMAGE_REMOVED]` |
| **URLs** | `https?://...`, `ftp://...`, `data:...` | Replaced with `[URL_REMOVED]` |
| **Stack Traces** | Python `Traceback...`, `File "...", line...`, Java/Node stack traces | Replaced with `[STACK_TRACE_REMOVED]` |
| **System Prompt Leaks**| `<<SYS>>...<</SYS>>`, `System:`, `System Prompt:`, internal instructions | Replaced with `[SYSTEM_PROMPT_FILTERED]` |

---

## 5. Secret Handling: Zero-Logging Policy

- `GROQ_API_KEY` is loaded from the environment (`.env`).
- Custom log formatting masks any occurrence of the API key string:
  ```python
  if self.secret and self.secret in msg:
      msg = msg.replace(self.secret, "[REDACTED_API_KEY]")
  ```
- Authorization headers (`Bearer ...`) are never written to disk, standard output, or the audit chain.

---

## 6. Rate Limit & Error Handling

- **HTTP 429 (Too Many Requests)**: Caught and transformed into a clean HTTP 429 response detailing retry guidance without crashing the gateway or model-service.
- **HTTP 5xx (Upstream Groq Server Errors)**: Caught and mapped to HTTP 502 Bad Gateway with sanitized error details.
- **Network Timeouts**: Caught and mapped to HTTP 504 Gateway Timeout.

---

## 7. Canary Test Verification

The canary test in `tests/test_canary_and_sessions.py` verifies our zero-context guarantee:
1. In Test Session 1, a high-entropy canary secret (`CANARY_TOKEN_<UUID>`) is submitted.
2. Test Session 1 is concluded via `POST /tests/{id}/conclude`.
3. In Test Session 2 (a fresh session), the model is prompted to repeat the secret from the previous test.
4. **Pass Criterion**: The test passes strictly if the model has no recollection of the canary secret.
5. In addition, cross-tenant tests assert that secrets submitted under Tenant A cannot be elicited by Tenant B.
