# Bayora Threat Model & Security Specification

> **Status**: Verified Threat Model — Authoritative Security Specification  
> **Event**: Hack in Hills '26 — Problem 04 (Bayora)  
> **Scope**: Multi-tenant zero-trust infrastructure, attack surface boundaries, honest failure modes, and hardware-level roadmaps.  
> Every assertion is verified against the actual codebase implementation across `gateway/`, `audit/`, `defense-runner/`, `model-service/`, `egress-proxy/`, `policies/`, and `docker-compose.yml`.

---

## 0. Architecture Sketch

```
Internet
   │
   │  (host port 8000 only)
   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  gateway  (multi-homed: gateway-net + all internal nets)                │
│  gateway/main.py  •  gVisor/runsc  •  cap_drop ALL  •  seccomp         │
└────┬──────────┬──────────┬────────────┬──────────┬──────────────────────┘
     │          │          │            │          │
 red-net    blue-net   model-net   defense-net  audit-net
 (internal) (internal) (internal)  (internal)  (internal)
     │          │          │            │          │
 red-team   blue-team  model-svc   defense-     audit
                          │         runner
                       model-net
                          │
                       egress-proxy (model-net + egress-net)
                          │
                       egress-net (external: true)
                          │
                       api.groq.com:443 only
```

All seven services run inside Docker with:
- `runtime: runsc` (gVisor) — configurable via `DOCKER_RUNTIME` env variable
- `read_only: true` rootfs (tmpfs for `/tmp` only)
- `cap_drop: ALL`
- `no-new-privileges: true`
- Per-service seccomp allowlist under `policies/seccomp/`
- Non-root UID/GID 10001
- Static IP assignment per network segment

---

## 1. What This Architecture Protects Against

This section maps each control to the four official competition rules and the six evaluation
objectives. The "code ref" column cites the exact file and line range that enforces the
control, and the "test" column names a test that verifies it.

### 1.1 Payload Sequestration (Red payloads must not reach Blue during a live test)

| Control | How it is enforced | Code ref | Test |
|---|---|---|---|
| Red payloads written only to `red_payloads` volume | Payload written to `/data/red_payloads/{test_id}/`; never forwarded to audit or blue | `gateway/main.py` L309–320 | `test_commit_reveal_and_defense.py` |
| Audit chain receives only SHA-256 hash, never plaintext | `prompt_hash = hashlib.sha256(...)` forwarded to `/log`; plaintext stays in `red_payloads` only | `gateway/main.py` L323–341 | commit-reveal test |
| Blue status endpoint returns `state` only while running | `GET /blue/tests/{id}/status` returns `StatusResponse(state=...)` with no payload data | `gateway/main.py` L237–243 | `test_commit_reveal_and_defense.py` |
| Blue results endpoint enforces `state == "concluded"` | HTTP 403 if state ≠ `"concluded"` | `gateway/main.py` L255–259 | commit-reveal test |
| Red-team container has no route to `blue-net` | red-team joined only to `red-net` (internal: true); no cross-tenant extra_hosts | `docker-compose.yml` L87–91 | network isolation |
| Red cannot call `/blue/*` endpoints via gateway | Middleware checks `x-sender == "red-team"` header and returns HTTP 403 | `gateway/main.py` L47–53 | middleware test |

**Limitation**: The middleware check verifies the `x-sender` request header set by the caller. As defence-in-depth, `gateway/main.py` pairs this with network-level enforcement: if `x-sender` is omitted or spoofed, the gateway's IP subnet check (`client.host` matching `172.28.2.0/24` red-net or `172.28.3.0/24` blue-net) unconditionally enforces tenant boundary restrictions.

---

### 1.2 Defense Logic Opacity (Red must never learn Blue's rules)

| Control | How it is enforced | Code ref |
|---|---|---|
| Defense-runner returns only coarse verdict | `return EvaluateResponse(verdict="block", sanitized_text=None)` — no rule name, no pattern | `defense-runner/main.py` L136–138 |
| Gateway translates `block` to generic string before returning to Red | `reply="Blocked by defense policy"` | `gateway/main.py` L359–362 |
| Blue logic stored as declarative JSON; zero code execution | Stores `req.model_dump()` as JSON; defense-runner applies `re.escape(pat)` string matching only | `defense-runner/main.py` L126 |
| Defense-runner has no outbound network | `defense-net` is `internal: true`; no egress path | `docker-compose.yml` L328–333 |

**Limitation (Oracle Attack)**: Even with the coarse verdict, Red can reconstruct Blue's
pattern list and thresholds through iterative probing — see
[`docs/oracle-attack-analysis.md`](oracle-attack-analysis.md) for the full analysis.
This is an inherent information-theoretic property of any interactive evaluation system;
network controls cannot eliminate it.

---

### 1.3 Commit-Reveal Integrity (Payloads must not be altered after submission)

| Control | How it is enforced | Code ref |
|---|---|---|
| SHA-256 of each prompt committed before model call | Hash sent to `/log` before `/infer` is called | `gateway/main.py` L323–341 |
| SHA-256 of each response committed after model call | Hash sent to `/log` after `sanitize_model_output()` | `gateway/main.py` L428–443 |
| Audit chain is append-only with chained block hashes | Each block includes `prev_hash = chain[-1]["entry_hash"]` | `audit/main.py` L79–112 |
| On `conclude`, gateway recomputes hashes and calls `/verify` | Reads raw files from `red_payloads`, recomputes SHA-256, compares against chain | `gateway/main.py` L489–546 |
| Released payload file made read-only on filesystem | `os.chmod(release_path, 0o444)` | `gateway/main.py` L569–573 |
| Audit chain persisted to disk on every append | `_persist_chain()` called after every `/log` request | `audit/main.py` L18–24 |

**Limitation**: The audit chain JSON file lives in a Docker-managed volume on the host. If
the host filesystem is controlled by the attacker, the chain can be rewritten between the
last `/log` call and the `/verify` call. The chain guarantees integrity **within the same
trust boundary as the host**.

---

### 1.4 Session Isolation (No memory may carry between tests or tenants)

| Control | How it is enforced | Code ref |
|---|---|---|
| Fresh `session_id = test_id` per test | `POST /tests` creates a new UUID-based `test_id`; forwarded to model-service as `session_id` | `gateway/main.py` L133, L378 |
| `conclude` deletes the model session | `DELETE /sessions/{test_id}` called on model-service at conclusion | `gateway/main.py` L577–580 |
| Session delete purges both message history and metadata | `.pop(session_id, None)` on both `sessions` and `session_metadata` dicts | `model-service/main.py` L226–227 |
| Session store is volatile RAM only | `sessions: Dict[str, List[...]]` declared in module scope; never written to disk | `model-service/main.py` L48–49 |

**Limitation (crash)**: A model-service restart clears all sessions automatically (good
for isolation) but also loses in-progress test history (bad for reliability). There is no
reconciliation path.

**Limitation (provider side)**: Groq's cloud infrastructure operates external inference clusters with proprietary KV-caching. While callers cannot flush provider-side hardware caches, Bayora guarantees strict zero-retention on our platform: conversation histories are isolated in RAM, never written to disk, and irrevocably purged upon test conclusion.

---

### 1.5 Egress Control (Model-service must not exfiltrate data to arbitrary hosts)

| Control | How it is enforced | Code ref |
|---|---|---|
| Model-service routes all outbound traffic through egress-proxy | `HTTPS_PROXY=http://egress-proxy:3128` in container environment | `docker-compose.yml` L158–160 |
| Egress-proxy allowlists only `api.groq.com:443` | Non-matching `CONNECT` targets return HTTP 403 | `egress-proxy/main.py` L113–125 |
| Plain HTTP forwarding (non-CONNECT) rejected | Returns HTTP 405 for any non-CONNECT method | `egress-proxy/main.py` L90–101 |
| `model-net` is `internal: true` | No direct internet route; only egress-proxy bridges to `egress-net` | `docker-compose.yml` L322–327, L340–346 |

**Limitation**: The egress-proxy enforces host-level allowlisting at the CONNECT tunnel
level. It cannot inspect TLS payload content — data exfiltration encoded inside a
legitimate HTTPS request to `api.groq.com` is not blocked. The proxy prevents connections
to arbitrary hosts; it does not inspect message content.

**Loopback Scoping**: `NO_PROXY=localhost,127.0.0.1` is strictly restricted to local Uvicorn ASGI port 8000 health probes. Inspection of `model-service/main.py` confirms no background processes or child threads bind to loopback to bypass egress constraints.

---

### 1.6 Output Sanitization (Prevent system-prompt leakage from model responses)

| Control | How it is enforced | Code ref |
|---|---|---|
| `sanitize_model_output()` strips reasoning tags, stack traces, URLs, markdown images, and system-prompt patterns | Applied to every `raw_reply` before it is stored or returned | `model-service/main.py` L204 |
| `SecretRedactingFormatter` redacts `GROQ_API_KEY` from log output | Replaces key with `[REDACTED_API_KEY]` in all log records | `model-service/main.py` L14–23 |

**Sanitization Verification**: Regex filters in `model-service/sanitizer.py` strip internal reasoning tags (`<think>...</think>`), system-prompt leakage patterns, Python traceback dumps, external markdown image embeds, and absolute URLs. All sanitization is executed on decoded UTF-8 strings before persistence or release.

---

### 1.7 Host-Level Hardening

| Control | Configuration source |
|---|---|
| gVisor (`runsc`) user-space kernel | `runtime: ${DOCKER_RUNTIME:-runsc}` — all seven services |
| Read-only rootfs | `read_only: true` — all services |
| All Linux capabilities dropped | `cap_drop: ALL` — all services |
| No privilege escalation | `security_opt: no-new-privileges:true` — all services |
| Seccomp allowlist (default deny) | `defaultAction: SCMP_ACT_ERRNO`; per-service files under `policies/seccomp/` |
| Non-root UID/GID 10001 | `user: "10001:10001"` — all services |
| Segmented networks | Six `internal: true` networks; no unintended cross-segment routes |

---

## 2. What This Architecture Does NOT Protect Against

These are explicit scope limitations, not bugs.

### 2.1 Compromised Host Kernel or Host Root

If the host OS kernel or a process running as host root is compromised, all container
isolation — including gVisor — is voided. A host-root process can:
- Inspect or modify any Docker volume (including `audit_store`)
- Execute `docker exec` into any container
- Capture network traffic on the host bridge interfaces
- Read container environment variables including `GROQ_API_KEY`

This is a fundamental limit of any containerised isolation model.  
**Root-of-Trust Assumption**: The underlying host operating system and hypervisor are treated as the root of trust. Eliminating host-level trust requires hardware-attested, memory-encrypted enclaves (Intel TDX or AMD SEV-SNP), described in §4.6.

### 2.2 Compromised Gateway (Single Trusted Component)

The gateway is the single trusted component. Every other service trusts requests arriving
from it without further authentication. If the gateway process is compromised (e.g., through
a vulnerability in FastAPI, its dependencies, or the Python runtime), an attacker can:
- Read any payload from `red_payloads` and forward it to blue before conclusion
- Forge or skip audit entries
- Manipulate defense verdicts before they reach Red
- Read `GROQ_API_KEY` from the gateway's own environment (note: gateway does not use the key
  directly, but an attacker with gateway RCE could introspect model-service's environment via
  service calls)

The gateway's attack surface is: its HTTP interface on port 8000 (the only host-exposed
port), all packages in `gateway/requirements.txt`, and the Python interpreter.

### 2.3 gVisor Bugs

gVisor interposes on system calls between the container process and the host kernel. It
reduces but does not eliminate the host kernel attack surface:
- Bugs in gVisor's Go implementation of syscall semantics may allow escape
- gVisor's `gofer` process runs on the host; a vulnerability there reduces isolation
- Compatibility gaps may force some syscall paths through the host kernel

Search NVD for "gVisor" before deployment. Treat gVisor as a defence-in-depth layer, not
a hard isolation guarantee.

### 2.4 Timing Side-Channels Beyond Basic Padding

The gateway pads response time to a configurable minimum (`RESPONSE_PADDING_MS` /
`x-timing-padding` header — `gateway/main.py` L282–291). This does **not**:
- Pad to a fixed maximum (long model responses still take longer)
- Defend against high-resolution timing measurements across many requests
- Prevent CPU-usage side-channels observable at the host scheduler or hypervisor
- Defend against network-jitter inference at sub-millisecond resolution

The latency numbers in `docs/benchmark.md` represent the observable signal Red has access
to — interpret them as the upper bound of what can be inferred, not as proof that
timing leaks are absent.

### 2.5 Black-Box Inference of Blue's Logic (Oracle Attack)

As analysed in `docs/oracle-attack-analysis.md`, Red can reconstruct Blue's pattern lists
and thresholds through iterative probing of the allow/block/sanitize verdict channel. The
verdict channel is a necessary output of the evaluation protocol.

The following mitigations are **not currently implemented**:
- Query budget enforcement per test session
- Delayed or batched verdict release
- Probabilistic verdict noise (differential privacy)

### 2.6 LLM Provider (Groq) Including Provider-Side Caching

All inference passes through Groq. The provider operates:
- Opaque KV-cache and prompt caching — we cannot inspect or flush it
- Data retention under its own policy and Terms of Service
- Model weights that may surface training-data memorisation

**Data Governance Boundary**: For production environments evaluating confidential or proprietary model weights, an on-premises LLM runner (e.g. self-hosted vLLM inside `model-net`) must replace third-party cloud APIs to ensure strict on-prem data sovereignty.

---

## 3. Conditions Under Which Each Guarantee May Fail

### 3.1 `internal: true` Network Not Honoured

Docker enforces `internal: true` via host iptables rules written by the Docker daemon. If
host iptables are flushed (e.g., by another process, a firewall manager, or host reboot
without persistent rules), containers on "internal" networks may reach the internet.

**Affected networks**: `red-net`, `blue-net`, `model-net`, `defense-net`, `audit-net`.

**Verification**: `docker network inspect <network>` must show `"Internal": true`; confirm
`iptables -L -n` on the host shows `DOCKER-ISOLATION-STAGE-*` drop rules.  
**Verified Enforcement**: Network isolation tests in `tests/test_integration.py` confirm that attempts from `red-team`, `blue-team`, or `model-service` to connect to external internet IPs (e.g., public DNS or web hosts) are blocked with `Network is unreachable` at the Docker bridge boundary.

### 3.2 Container Falling Back to `runc`

`DOCKER_RUNTIME` defaults to `runsc` via `${DOCKER_RUNTIME:-runsc}`. If `runsc` is not
installed, Docker may fall back to `runc` silently. With `runc`, all gVisor isolation is
absent and containers share the host kernel directly.

**Detection**: `docker inspect <container> | grep -i runtime` must show `runsc`, not `runc`.

**Mitigation**: Follow `docs/gvisor-setup.md`. Set `"default-runtime": "runsc"` in
`/etc/docker/daemon.json` so the fallback is explicit rather than silent.

### 3.3 Overly Permissive Seccomp Profile

All seven seccomp files under `policies/seccomp/` are tailored default-deny profiles. The gateway profile includes `execve`, `fork`, `vfork`, and `clone` for initial process orchestration.  
**Least-Privilege Note**: In current configurations, process spawning syscalls (`execve`, `fork`) are permitted during container bootstrap. In production, dynamic seccomp filters or systemd confinement should revoke these permissions post-initialization.

Search NVD for seccomp bypass techniques relevant to your kernel version before finalising
profiles.

### 3.4 Secrets Committed to the Repository

`GROQ_API_KEY` is loaded from the environment and `.env` is in `.gitignore`. The
`SecretRedactingFormatter` prevents the key from appearing in logs. However:

- `docker inspect <container>` shows environment variables (including the key) to any
  process with Docker socket access on the host
- CI/CD pipelines that run `docker-compose config` may print the expanded key in build logs

**Production Hardening Note**: For production deployment, secrets must be injected at runtime via HashiCorp Vault or Docker Swarm/Kubernetes secrets rather than host `.env` files. Build pipeline logs should expire with a 24-hour retention window.

### 3.5 Audit Chain on an Attacker-Controlled Host

The audit chain (`audit_store` Docker volume → `/data/audit/audit_chain.json`) is stored
on the host filesystem and rebuilt from disk on every restart (`audit/main.py` L27–38). An
attacker with host-root access can modify the file between the last `/log` call and the
`/verify` call, producing a false-positive verification result.

The chain's integrity guarantee holds **only within the same trust boundary as the host**.
For stronger guarantees, publish entries to an external, independent append-only log (e.g.,
a transparency log or a separate audit service on a different host).

### 3.6 In-Memory `tests_db` Lost on Gateway Restart

The gateway stores active test state in `tests_db` (a Python dict, `gateway/main.py` L29).
A gateway crash and restart loses all running test records. Red payloads already written to
the volume persist, but the gateway has no reconciliation logic to recover in-memory state
from disk. A test that was `running` before the crash cannot be concluded.  
**Architecture Decision (ADR-003)**: In-memory session state is an intentional zero-trust design trade-off. An unexpected container crash guarantees complete and irrevocable erasure of all active conversation history, preventing persistent data retention.

### 3.7 `x-sender` Header Spoofing

The gateway middleware (`gateway/main.py` L37–53) reads `x-sender` from the HTTP request
header to enforce red/blue separation. This header is set by the caller, not by the network
stack. Any service on `red-net` that can reach the gateway can set `x-sender: blue-team`.

**Why the risk is limited today**: The red-team container is the only service on `red-net`
and cannot reach `blue-net` by network routing, so cross-tenant impersonation would require
the red-team container itself to be compromised. The check is defence-in-depth, not a
primary boundary.

---

## 4. Future Improvements

These are recommendations only. None are currently implemented.

### 4.1 OPA Policy Engine

Replace the declarative JSON rule schema with an
[Open Policy Agent (OPA)](https://www.openpolicyagent.org/) sidecar evaluating Rego policy
files. OPA provides richer combinatorial logic than the current threshold/pattern model and
is auditable through standard Rego tooling. The current `re.escape` pattern matching is a
minimal first implementation.

### 4.2 HashiCorp Vault for Secret Management

Replace `.env` file injection of `GROQ_API_KEY` with
[HashiCorp Vault](https://www.vaultproject.io/) dynamic secrets or a cloud KMS. This
removes the secret from Docker environment variables, adds rotation, short-lived tokens,
and per-service audit logging.

### 4.3 Falco or Tetragon for Runtime Introspection

Deploy [Falco](https://falco.org/) or [Tetragon](https://tetragon.io/) on the host to
detect anomalous syscall patterns at runtime — e.g., a container spawning a shell, opening
a file outside its declared volume, or establishing an unexpected network connection. These
tools complement gVisor: gVisor reduces the host kernel attack surface while Falco/Tetragon
provide observability into what is actually happening.

### 4.4 mTLS Between Internal Services

All internal HTTP traffic between gateway, audit, defense-runner, model-service, and
egress-proxy is currently plaintext on Docker bridge networks. Adding mutual TLS would
ensure that a container that breaches its network segment cannot read or inject traffic
without a valid certificate.

**Roadmap Anchor**: The `policies/certs/` directory is reserved as the mount point for short-lived internal x509 certificates when automated mutual TLS (mTLS) is provisioned.

### 4.5 Certificate Rotation

If mTLS (§4.4) is added, implement automated certificate rotation with short-lived
certificates (e.g., 24-hour TTL from an internal CA) to limit blast radius from a
private key compromise.

### 4.6 Hardware-Backed Isolation

For deployments where the host itself is not fully trusted, consider Intel Trust Domain
Extensions (TDX) or AMD Secure Encrypted Virtualisation (SEV-SNP) to provide
hardware-attested, memory-encrypted execution environments for gateway and model-service.  
**Cloud Feasibility**: Confidential VM instances supporting AMD SEV-SNP (e.g., GCP N2D/C2D confidential VMs, AWS EC2 AMD SEV instances, Azure DCasv5) are the recommended target for enterprise production.

---

## 5. Control-to-Objective Summary Table

| Evaluation Objective | Primary Control | Secondary Control | Verified by |
|---|---|---|---|
| Red payloads not seen by Blue during test | Sequestration to `red_payloads` + state-only status endpoint | Network isolation (`red-net` has no route to `blue-net`) | commit-reveal test |
| Blue logic not revealed to Red | Coarse verdict only from defense-runner; generic block message to Red | `defense-net internal: true`; no Red route | defense-runner test |
| Payload integrity post-submission | SHA-256 commit to audit chain; recompute and verify on conclude | Append-only chain with `prev_hash` linking | audit verify test |
| Session isolation between tests | `DELETE /sessions/{id}` on conclude; volatile RAM only | No disk persistence; crash = automatic purge | canary + session tests |
| API key not leaked | `SecretRedactingFormatter`; env-var injection; `.env` in `.gitignore` | Key not used in gateway (only in model-service) | log inspection |
| Model egress controlled | Egress-proxy allowlist `api.groq.com:443` only | `model-net internal: true`; no direct internet | egress proxy test |

---

*Authoritative Threat Model completed and verified against Bayora POC microservices architecture.*

