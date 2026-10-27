# Bayora POC: Secure Adversarial AI Testing Infrastructure
> **Hack in Hills '26 — Problem 04 (Bayora)**  
> **Team**: Boiler_Plate_dine  
> A multi-tenant, zero-trust shared testing environment enabling concurrent adversarial red-teaming, defensive guardrail evaluation, and client LLM testing without exposing sensitive state, leaking defensive logic, or creating exploitable side channels.

---

## 1. Executive Summary & Hardening Standards

### 1a. Four Official Rules

| Security Requirement | Architectural Guarantee | Implementation | Status |
| :--- | :--- | :--- | :---: |
| **Rule 1: Red Payload Sequestration** | Lifecycle state machine (`created` → `running` → `concluded`). During `running`, only SHA-256 hashes go to the audit chain; payloads stay in `red_payloads` volume; Blue gets state only. | `gateway/main.py` L309–362; `/blue/tests/{id}/results` returns HTTP 403 while running. | **VERIFIED** — `test_commit_reveal_and_defense.py` |
| **Rule 2: Blue Defense Shielding** | `defense-runner` is on `defense-net` (`internal: true`) with zero lateral route to red-team. Red receives only a generic `"Blocked by defense policy"` string — no rule name, no pattern. | `gateway/main.py` L359–362; `defense-runner/main.py` L136–138. | **VERIFIED** — `test_commit_reveal_and_defense.py` |
| **Rule 3: Client LLM Uncontaminated** | Each test gets a fresh model session keyed by `test_id`. On `conclude`, `DELETE /sessions/{test_id}` purges conversation history from RAM. No disk persistence. | `model-service/main.py` L48–49, L226–227; `gateway/main.py` L577–580. | **VERIFIED** — `test_canary_and_sessions.py` (canary + cross-tenant tests) |
| **Rule 4: Multi-Tenant Environmental Isolation** | 7 Docker bridge networks (5 `internal: true`; egress-net and gateway-net external). No tenant service shares any network with another tenant service. | `docker-compose.yml` L303–346; static IP assignment per segment. | **VERIFIED** — `test_integration.py` network isolation tests |

### 1b. Infrastructure Hardening

| Control | Guarantee | Implementation | Status |
| :--- | :--- | :--- | :---: |
| **Container Sandboxing (gVisor)** | All 7 services configured with `runtime: runsc`. User-space kernel interposes on syscalls to reduce host kernel attack surface. | `docker-compose.yml` — `runtime: ${DOCKER_RUNTIME:-runsc}`. | **CONFIGURED** — see note below |
| **Seccomp Syscall Filtering** | Default-deny profiles; only required syscalls allowed per service. `ptrace`, `mount`, `keyctl`, `bpf` blocked. | `policies/seccomp/*.json` via `security_opt`; `defaultAction: SCMP_ACT_ERRNO`. | **VERIFIED** — `test_seccomp_enforcement.py` (ptrace returns EPERM) |
| **Least-Privilege Containment** | Non-root UID 10001, `read_only: true` rootfs, 64 MB tmpfs `/tmp`, `cap_drop: ALL`, `no-new-privileges`. | Applied across all 7 Dockerfiles and `docker-compose.yml`. | **VERIFIED** — config confirmed |
| **Egress Control** | model-service has no direct internet. All outbound goes through egress-proxy, which allowlists only `api.groq.com:443`. Non-CONNECT and other-host requests return HTTP 403/405. | `egress-proxy/main.py` L113–125; `docker-compose.yml` model-net `internal: true`. | **VERIFIED** — `test_canary_and_sessions.py` egress unit test |
| **Output Sanitization** | Model responses stripped of reasoning tags, stack traces, URLs, markdown images, system-prompt patterns before leaving model-service. | `model-service/sanitizer.py`; applied at `model-service/main.py` L204. | **VERIFIED** — `test_canary_and_sessions.py` output filter unit tests |
| **Secret Redaction** | `GROQ_API_KEY` never appears in logs. `SecretRedactingFormatter` applied to every log record. | `model-service/main.py` L14–23. | **VERIFIED** — log inspection in test suite |

### 1c. Evaluation Objectives

| Objective | Mechanism | Evidence | Status |
| :--- | :--- | :--- | :---: |
| **Groq API Integration** | Real LLM inference via `llama-3.1-8b-instant` / configurable `GROQ_MODEL`. Multi-turn conversation history within a test. | `model-service/main.py` L110–214. | **VERIFIED** — `test_canary_and_sessions.py` live API tests |
| **Commit-Reveal Integrity** | SHA-256 hashes chained into append-only audit ledger before model call. On conclude, gateway recomputes and verifies against chain. Tamper detected as `"verified": false`. | `audit/main.py` L79–190; `gateway/main.py` L489–573. | **VERIFIED** — `test_commit_reveal_and_defense.py` tamper detection test |
| **Session Isolation / Zero Cross-Test Carryover** | Canary secret submitted in Test 1, session purged on conclude, queried in Test 2 — model has no recollection. Cross-tenant test asserts Tenant A secrets not visible to Tenant B. | `model-service/main.py` L217–233; `test_canary_and_sessions.py`. | **VERIFIED** — canary + cross-tenant tests pass |
| **Timing Side-Channel Padding** | `RESPONSE_PADDING_MS` pads response time to a fixed minimum bucket. Measured Δp50 between Blue idle and Blue busy compressed from +13.65 ms (unpadded) to −4.57 ms (padded at 100 ms). | `gateway/main.py` L282–291; `docs/benchmark.md` §4. | **MEASURED** — see `docs/benchmark.md` |
| **Gateway Overhead** | Full mediation pipeline (audit × 2, defense-runner × 2, model, storage) adds measured p50 overhead of +317.96 ms vs. direct model call. | `docs/benchmark.md` §2. | **MEASURED** — N=60 prompts |
| **Judge Adjudication Dashboard** | Projector-readable dashboard served through gateway (`/judge`) with judge role auth. Never reachable from tenant networks (enforced via subnet IP filter + sender check). Displays live audit chain, interactive **Verify Integrity** button, test session lifecycle, and blocked/denied attempt telemetry. Tenants cannot see monitoring data. | `gateway/judge.html`; `gateway/main.py` L580–770; `tests/test_judge_dashboard.py`. | **VERIFIED** — 10 unit & access control tests pass |
| **Cross-Tenant Compute Isolation** | CPU-pinned cpusets prevent memory exhaustion and kernel lockups. Scheduling latency inflation observed (~2× p50) when all containers share a single physical core. Full isolation requires distinct physical cores. | `docker-compose.yml` cpuset config; `docs/benchmark.md` §3. | **VERIFIED** — benchmark shows partial isolation; multi-core host required for full enforcement |
---

## 2. Network Topology & Microservices

### 2a. Container Network Topology
```
+----------------------------------------------------------------------------------------------------+
|                                             DOCKER HOST                                            |
|                                                                                                    |
|  [ JUDGE / PROJECTOR ]                                                                             |
|            │  (Host Port 8000: /judge, X-Role: judge)                                              |
|            ▼                                                                                       |
|  [ gateway-net: external ]                                                                         |
|            │                                                                                       |
|  +---------v------------------------------------------------------------------------------------+  |
|  |                                          GATEWAY                                             |  |
|  |  (FastAPI Security Hub: Lifecycle Controller, Hash Committer, Role & IP Partitioning Engine) |  |
|  +----+------------------+-------------------+--------------------+------------------------+----+  |
|       │                  │                   │                    │                        │       |
|   [ red-net ]       [ blue-net ]      [ defense-net ]        [ model-net ]            [ audit-net ]|
| (internal: true)  (internal: true)   (internal: true)      (internal: true)         (internal: true)|
|       │                  │                   │                    │                        │       |
|  +----v------+     +-----v------+     +------v---------+   +------v---------+       +--------v----+  |
|  | red-team  |     | blue-team  |     | defense-runner |   | model-service  |       |    audit    |  |
|  | (Client & |     | (Defense & |     | (Declarative   |   | (Groq Adapter, |       | (Append-Only|  |
|  | Harness)  |     | Telemetry) |     | Rule Engine)   |   | Ephemeral RAM) |       | Hash Chain) |  |
|  +-----------+     +------------+     +----------------+   +------+---------+       +-------------+  |
|                                                                   │ (HTTP CONNECT)                 |
|                                                            +------v---------+                      |
|                                                            |  egress-proxy  |                      |
|                                                            | (api.groq.com) |                      |
|                                                            +------+---------+                      |
+-------------------------------------------------------------------|--------------------------------+
                                                                    │ [ egress-net: external ]
                                                                    ▼
                                                          [ api.groq.com:443 ]
```

### 2b. Test Lifecycle & Request Mediation Sequence
```
[POST /tests] ──> STATE: created (Submissions forbidden; Blue sees state only)
                        │
                        ▼ [POST /tests/{test_id}/start]
                  STATE: running
                        │
    ┌───────────────────┴────────────────────────────────────────────────────────┐
    │ RED SUBMISSION MEDIATION PIPELINE:                                         │
    │ 1. Red submits prompt ──> Sequestered in red_payloads volume               │
    │ 2. Gateway hashes prompt (SHA-256) ──> Committed to audit ledger           │
    │ 3. Gateway queries defense-runner (isolated on defense-net):               │
    │    ├── IF BLOCKED  ──> Generic message returned + Timing Padding applied   │
    │    └── IF ALLOWED  ──> Forwarded to model-service with session_id          │
    │ 4. model-service calls Groq Cloud via egress-proxy (api.groq.com:443 only) │
    │ 5. model-service sanitizer strips reasoning tags, stack traces, URLs       │
    │ 6. Gateway queries defense-runner on model output (response policy)        │
    │ 7. Gateway hashes final reply (SHA-256) ──> Committed to audit ledger      │
    │ 8. Response padded to RESPONSE_PADDING_MS floor ──> Returned to Red        │
    └───────────────────┬────────────────────────────────────────────────────────┘
                        │
                        ▼ [POST /tests/{test_id}/conclude]
                  STATE: concluded
                        │
    ┌───────────────────┴────────────────────────────────────────────────────────┐
    │ CONCLUSION & AUDIT REVEAL:                                                 │
    │ 1. DELETE /sessions/{test_id} drops conversation history from RAM          │
    │ 2. Gateway recomputes hashes from red_payloads & calls audit verifier      │
    │ 3. Payloads & responses released to blue_releases as read-only (0444)      │
    │ 4. Blue team can now inspect revealed submissions and verifier status      │
    └────────────────────────────────────────────────────────────────────────────┘
```

### 2c. Network Isolation Rules
- **`gateway-net`** (`internal: false`): External host access to Gateway API and Judge Dashboard (`/judge`).
- **`red-net`** (`internal: true`): Joined by `red-team` and `gateway`. Subnet `172.28.2.0/24`.
- **`blue-net`** (`internal: true`): Joined by `blue-team` and `gateway`. Subnet `172.28.3.0/24`.
- **`defense-net`** (`internal: true`): Joined by `defense-runner` and `gateway`. Subnet `172.28.5.0/24`.
- **`model-net`** (`internal: true`): Joined by `model-service`, `egress-proxy`, and `gateway`. Subnet `172.28.4.0/24`.
- **`egress-net`** (`internal: false`): Joined exclusively by `egress-proxy` to forward HTTPS traffic to `api.groq.com:443`.
- **`audit-net`** (`internal: true`): Joined by `audit` and `gateway`. Subnet `172.28.6.0/24`.
- **Firewall Guarantee**: No tenant container shares any network segment with any other tenant. Gateway rejects all tenant subnet IPs from reaching `/judge` or `/logs`.

---

## 3. Directory Layout

```
bayora-poc/
├── .env.example                     # Environment template (includes GROQ_API_KEY)
├── .gitignore                       # Git exclusion of .env and runtime artifacts
├── DECISIONS.md                     # Architecture Decision Records (ADRs 001–008)
├── docker-compose.yml               # Hardened multi-tenant compose file (runsc, seccomp, non-root)
├── pytest.ini                       # Test configuration
├── README.md                        # Documentation
├── docs/
│   ├── demo-script.md               # Live demo script (≤4 min) with exact commands & projector setup
│   ├── threat-model.md              # First-draft threat model (controls, limitations, future work)
│   ├── benchmark.md                 # Measured latency, stress, and timing oracle results
│   ├── benchmark.py                 # Benchmark runner (N=60 prompts, stress test, oracle analysis)
│   ├── model-service-architecture.md# Groq API integration, output filtering, zero-context guarantee
│   ├── gvisor-setup.md              # Linux host guide for runsc installation and daemon registration
│   ├── oracle-attack-analysis.md    # Analysis of unpreventable side-channel oracle inference
│   └── verify-isolation.sh          # Isolation verification bash script
├── scripts/
│   ├── demo-reset.sh                # One-command demo reset (Linux/macOS/WSL2)
│   └── demo-reset.ps1               # One-command demo reset (Windows PowerShell)
├── egress-proxy/                    # Isolated forward proxy allowing only api.groq.com:443
│   ├── Dockerfile
│   └── main.py
├── policies/
│   ├── certs/                       # Directory for mTLS certificates (.gitkeep)
│   └── seccomp/                     # Role-tailored seccomp profiles (default-deny)
│       ├── egress-proxy.json
│       ├── gateway.json
│       ├── red-team.json
│       ├── blue-team.json
│       ├── model-service.json
│       ├── audit.json
│       └── defense-runner.json
├── gateway/                         # Gateway FastAPI service (lifecycle, routing, audit, verifier)
│   ├── Dockerfile
│   ├── judge.html                   # Projector-optimized Judge Adjudication & Audit Dashboard
│   ├── main.py                      # Security Gateway (IP firewall, mediation pipeline, judge API)
│   └── requirements.txt
├── red-team/                        # Red-team test client & harness
├── blue-team/                       # Blue-team defense uploader & telemetry observer
├── model-service/                   # Groq API adapter (ephemeral sessions, output sanitizer)
│   ├── main.py
│   └── sanitizer.py                 # Multi-layer output filter (reasoning tags, URLs, stack traces)
├── audit/                           # SHA-256 cryptographic append-only audit ledger
├── defense-runner/                  # Isolated, no-network declarative defense engine
└── tests/
    ├── test_commit_reveal_and_defense.py  # Commit-reveal lifecycle, volume isolation, tamper tests
    ├── test_canary_and_sessions.py        # Canary / session isolation / output filter / egress tests
    ├── test_judge_dashboard.py            # Judge dashboard role auth, IP firewall & verifier tests
    ├── test_integration.py                # Docker Compose integration test suite
    └── test_seccomp_enforcement.py        # Seccomp profile integrity & blocked syscall test
```

---

## 4. How to Verify

### One-command live demo reset
```bash
bash scripts/demo-reset.sh        # Linux / macOS / WSL2
```
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\demo-reset.ps1   # Windows PowerShell
```
Then follow [`docs/demo-script.md`](docs/demo-script.md) step-by-step.

### Run all tests (requires stack running)
```powershell
python -m pytest -v -s
```

### Run commit-reveal lifecycle & defense tests
```powershell
python -m pytest -v -s tests/test_commit_reveal_and_defense.py
```

### Run canary, session isolation & output filter tests
```powershell
python -m pytest -v -s tests/test_canary_and_sessions.py
```

### Run judge dashboard & security isolation tests
```powershell
python -m pytest -v -s tests/test_judge_dashboard.py
```

### Accessing the Judge Dashboard (Projector Mode)
Open in any browser:
```
http://localhost:8000/judge?token=bayora-judge-2026
```
*(Or pass `X-Role: judge` header. Tenant subnets `172.28.2.0/24` and `172.28.3.0/24` are unconditionally blocked).*

### Run seccomp & isolation tests locally
```powershell
python -m pytest -v -s tests/test_seccomp_enforcement.py
```

### Run performance benchmarks (N=60 prompts, stress, timing oracle)
```powershell
python docs/benchmark.py
```
Results written to `docs/benchmark.md`.

### Run full isolation verification on Linux with gVisor
```bash
chmod +x docs/verify-isolation.sh
./docs/verify-isolation.sh
```

---

## 5. Key Design Decisions

| Decision | Rationale |
|---|---|
| Declarative rules only in defense-runner | No arbitrary code execution — Blue uploads JSON patterns; defense-runner uses `re.escape()` substring matching only |
| SHA-256 commit before model call | Payload cannot be altered post-submission; recompute-and-compare on conclude detects any tampering |
| Ephemeral RAM sessions, never on disk | Crash = automatic purge; no reconciliation path needed for isolation guarantee |
| Egress proxy (allowlist, not denylist) | Explicit `api.groq.com:443` allow; every other destination denied by default |
| Coarse verdict only from defense-runner | `allow`/`block`/`sanitize` — rule names and patterns never cross the trust boundary |
| Response-time padding | Closes the timing side-channel between Blue-idle and Blue-busy at the cost of a fixed latency floor |
| Judge dashboard network partitioning | Adjudicator UI and telemetry served through gateway (`/judge`), strictly blocked from tenant subnets via IP filtering |

