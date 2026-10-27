import asyncio
import hashlib
import json
import os
import time
import uuid
from typing import Dict, List, Literal, Optional, Tuple
import httpx
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI(title="Bayora Gateway Service", version="0.2.0")

JUDGE_TOKEN = os.getenv("JUDGE_TOKEN", "bayora-judge-2026")

# Service URLs
MODEL_SERVICE_URL = os.getenv("MODEL_SERVICE_URL", "http://model-service:8000").rstrip("/")
DEFENSE_RUNNER_URL = os.getenv("DEFENSE_RUNNER_URL", "http://defense-runner:8000").rstrip("/")
AUDIT_SERVICE_URL = os.getenv("AUDIT_SERVICE_URL", "http://audit:8000").rstrip("/")

# Storage Directories
RED_PAYLOADS_DIR = os.getenv("RED_PAYLOADS_DIR", "/data/red_payloads")
BLUE_LOGIC_DIR = os.getenv("BLUE_LOGIC_DIR", "/data/blue_logic")
BLUE_RELEASES_DIR = os.getenv("BLUE_RELEASES_DIR", "/data/blue_releases")

os.makedirs(RED_PAYLOADS_DIR, exist_ok=True)
os.makedirs(BLUE_LOGIC_DIR, exist_ok=True)
os.makedirs(BLUE_RELEASES_DIR, exist_ok=True)

# In-memory test sessions: test_id -> test metadata
tests_db: Dict[str, dict] = {}

# In-memory call log: list of (sender, endpoint, timestamp)
call_logs: List[Tuple[str, str, float]] = []

# In-memory blocked and denied attempt events
blocked_events: List[dict] = []


def is_tenant_network(ip_or_host: Optional[str]) -> bool:
    if not ip_or_host:
        return False
    # Subnets: 172.28.2.0/24 (red-net), 172.28.3.0/24 (blue-net), 172.28.4.0/24 (model-net), 172.28.5.0/24 (defense-net)
    tenant_prefixes = ("172.28.2.", "172.28.3.", "172.28.4.", "172.28.5.")
    return any(ip_or_host.startswith(prefix) for prefix in tenant_prefixes)


def record_blocked_event(
    event_type: str,
    sender: str,
    endpoint: str,
    test_id: Optional[str] = None,
    target: Optional[str] = None,
    reason: Optional[str] = None,
    verdict: str = "BLOCKED",
):
    event = {
        "event_id": f"evt-{uuid.uuid4().hex[:8]}",
        "timestamp": time.time(),
        "event_type": event_type,
        "sender": sender,
        "endpoint": endpoint,
        "test_id": test_id,
        "target": target,
        "reason": reason or "Policy violation",
        "verdict": verdict,
    }
    blocked_events.append(event)
    if len(blocked_events) > 500:
        blocked_events.pop(0)
    return event


@app.middleware("http")
async def call_logger_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    sender = (
        request.headers.get("x-sender")
        or client_ip
    )
    endpoint = request.url.path
    timestamp = time.time()
    call_logs.append((sender, endpoint, timestamp))

    # Tenant networks or tenant senders MUST NOT access judge dashboard or monitoring
    if endpoint.startswith("/judge") or endpoint == "/logs":
        if is_tenant_network(client_ip) or sender in ("red-team", "blue-team"):
            record_blocked_event(
                event_type="unauthorized_monitoring_access",
                sender=sender,
                endpoint=endpoint,
                reason="Tenant attempted access to judge/monitoring telemetry",
                verdict="DENIED",
            )
            return Response(
                content=json.dumps({"detail": "Access forbidden: judge monitoring data is not accessible from tenant networks"}),
                status_code=status.HTTP_403_FORBIDDEN,
                media_type="application/json",
            )

    # Strict access controls between tenant endpoints
    # Red team cannot access Blue defense logic or blue endpoints
    if endpoint.startswith("/blue/") or endpoint == "/blue/defense":
        if sender == "red-team" or client_ip.startswith("172.28.2."):
            record_blocked_event(
                event_type="cross_tenant_access",
                sender=sender,
                endpoint=endpoint,
                reason="Red team attempted access to blue endpoints",
                verdict="DENIED",
            )
            return Response(
                content=json.dumps({"detail": "Access forbidden: red-team cannot access blue endpoints"}),
                status_code=status.HTTP_403_FORBIDDEN,
                media_type="application/json",
            )

    response = await call_next(request)
    return response


# ==============================================================================
# PYDANTIC SCHEMAS
# ==============================================================================

class TestCreateResponse(BaseModel):
    test_id: str
    state: str


class StatusResponse(BaseModel):
    state: str


class DefenseRule(BaseModel):
    name: Optional[str] = "rule"
    target: Literal["prompt", "response", "all"] = "all"
    action: Literal["allow", "block", "sanitize"] = "block"
    patterns: List[str] = Field(default_factory=list, description="Declarative pattern tokens")
    threshold: int = Field(1, ge=1, description="Threshold of matches to trigger rule")
    replacement: Optional[str] = "[REDACTED]"


class DefenseUploadRequest(BaseModel):
    test_id: Optional[str] = None
    default_action: Literal["allow", "block"] = "allow"
    rules: List[DefenseRule] = Field(default_factory=list)


class RedSubmitRequest(BaseModel):
    test_id: str = Field(..., description="Target test session ID")
    prompt: str = Field(..., description="Prompt payload")


class RedSubmitResponse(BaseModel):
    reply: str


# ==============================================================================
# SYSTEM & LIFECYCLE ENDPOINTS
# ==============================================================================

@app.get("/health", status_code=status.HTTP_200_OK)
async def health():
    return {"status": "ok"}


# ==============================================================================
# BENCHMARK PASSTHROUGH ENDPOINTS (FOR EMPIRICAL EVALUATION)
# ==============================================================================

@app.post("/bench/direct-infer")
async def bench_direct_infer(req: Request):
    """
    Direct model stub bypass strictly for benchmarking baseline latency.
    Forwards directly to model-service without defense-runner or audit chain.
    """
    body = await req.json()
    resp = await http_post_with_retry(f"{MODEL_SERVICE_URL}/infer", body, timeout=15.0)
    return resp.json()


@app.get("/bench/blue/health")
async def bench_blue_health():
    """Direct health probe to blue-team container for latency benchmarking."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get("http://blue-team:8000/health")
            return resp.json()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(e))


@app.post("/tests", response_model=TestCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_test():
    test_id = f"test-{uuid.uuid4().hex[:8]}"
    tests_db[test_id] = {
        "test_id": test_id,
        "state": "created",
        "created_at": time.time(),
        "submissions": [],
        "verified": None,
    }
    return TestCreateResponse(test_id=test_id, state="created")


@app.post("/tests/{test_id}/start")
async def start_test(test_id: str):
    if test_id not in tests_db:
        raise HTTPException(status_code=404, detail="Test not found")

    current_state = tests_db[test_id]["state"]
    if current_state != "created":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot start test in state: {current_state}. Must be 'created'.",
        )

    tests_db[test_id]["state"] = "running"
    tests_db[test_id]["started_at"] = time.time()
    return {"test_id": test_id, "state": "running"}


@app.get("/tests/{test_id}/status", response_model=StatusResponse)
async def get_test_status(test_id: str):
    """Returns state ONLY while running or created."""
    if test_id not in tests_db:
        raise HTTPException(status_code=404, detail="Test not found")

    return StatusResponse(state=tests_db[test_id]["state"])


async def http_post_with_retry(
    url: str,
    json_data: dict,
    timeout: float = 10.0,
    max_retries: int = 5,
    backoff: float = 0.5,
) -> httpx.Response:
    """Helper to query downstream internal services with retry on connection/timeout."""
    last_exc = None
    for attempt in range(max_retries):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, json=json_data)
                resp.raise_for_status()
                return resp
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
            last_exc = exc
            if attempt < max_retries - 1:
                await asyncio.sleep(backoff * (attempt + 1))
        except Exception as exc:
            raise exc
    raise last_exc


# ==============================================================================
# BLUE TEAM DEFENSIVE LOGIC & STATUS
# ==============================================================================

@app.post("/blue/defense", status_code=status.HTTP_200_OK)
async def upload_defense(req: DefenseUploadRequest):
    """
    Blue uploads declarative defensive logic.
    Stored in blue_logic as declarative JSON.
    Zero arbitrary code execution.
    """
    key = req.test_id or "__global__"
    filename = f"{key}.json"
    filepath = os.path.join(BLUE_LOGIC_DIR, filename)

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(req.model_dump(), f, indent=2)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to store defensive logic: {str(e)}",
        )

    # Sync declarative rules with defense-runner
    try:
        await http_post_with_retry(
            f"{DEFENSE_RUNNER_URL}/sync_rules",
            req.model_dump(),
            timeout=5.0,
            max_retries=3,
        )
    except Exception:
        # Defense runner will also load from disk
        pass

    return {
        "status": "stored",
        "key": key,
        "rules_count": len(req.rules),
    }


@app.get("/blue/tests/{test_id}/status", response_model=StatusResponse)
async def get_blue_test_status(test_id: str):
    """While a test is 'running', Blue's status endpoint returns state ONLY."""
    if test_id not in tests_db:
        raise HTTPException(status_code=404, detail="Test not found")

    return StatusResponse(state=tests_db[test_id]["state"])


@app.get("/blue/tests/{test_id}/results")
async def get_blue_test_results(test_id: str):
    """
    Blue can only access payloads and responses AFTER the test has concluded.
    While 'running' or 'created', access is strictly forbidden.
    """
    if test_id not in tests_db:
        raise HTTPException(status_code=404, detail="Test not found")

    current_state = tests_db[test_id]["state"]
    if current_state != "concluded":
        record_blocked_event(
            event_type="premature_payload_access",
            sender="blue-team",
            endpoint=f"/blue/tests/{test_id}/results",
            test_id=test_id,
            reason=f"Blue attempted to read payloads while test state is '{current_state}'. Payloads are sequestered.",
            verdict="DENIED",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Payloads are sequestered while test state is '{current_state}'. State only is available.",
        )

    release_file = os.path.join(BLUE_RELEASES_DIR, test_id, "released_payloads.json")
    if os.path.exists(release_file):
        try:
            with open(release_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to read release data: {str(e)}")

    raise HTTPException(status_code=404, detail="Release data not found")


# ==============================================================================
# RED TEAM SUBMISSION & EVALUATION
# ==============================================================================

@app.post("/red/submit", response_model=RedSubmitResponse)
async def red_submit(req: RedSubmitRequest, request: Request):
    start_time = time.time()

    async def apply_padding():
        pad_header = request.headers.get("x-timing-padding")
        try:
            target_ms = float(pad_header) if pad_header is not None else float(os.getenv("RESPONSE_PADDING_MS", "0"))
        except (TypeError, ValueError):
            target_ms = 0.0
        if target_ms > 0:
            elapsed_ms = (time.time() - start_time) * 1000.0
            if elapsed_ms < target_ms:
                await asyncio.sleep((target_ms - elapsed_ms) / 1000.0)

    test_id = req.test_id
    if test_id not in tests_db:
        raise HTTPException(status_code=404, detail="Test not found")

    current_state = tests_db[test_id]["state"]
    if current_state != "running":
        record_blocked_event(
            event_type="invalid_state_submission",
            sender="red-team",
            endpoint="/red/submit",
            test_id=test_id,
            reason=f"Submissions only allowed while test is in 'running' state. Current state: '{current_state}'.",
            verdict="DENIED",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Submissions only allowed while test is in 'running' state. Current state: '{current_state}'.",
        )

    submission_id = f"sub-{uuid.uuid4().hex[:12]}"
    prompt_text = req.prompt
    timestamp = time.time()

    # 1. Write payload to red's store (red_payloads)
    test_red_dir = os.path.join(RED_PAYLOADS_DIR, test_id)
    os.makedirs(test_red_dir, exist_ok=True)
    payload_file = os.path.join(test_red_dir, f"{submission_id}_payload.json")

    payload_record = {
        "test_id": test_id,
        "submission_id": submission_id,
        "prompt": prompt_text,
        "timestamp": timestamp,
    }
    with open(payload_file, "w", encoding="utf-8") as f:
        json.dump(payload_record, f, indent=2)

    # 2. Log ONLY prompt hash in audit chain (never send payload to audit or blue)
    prompt_hash = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
    try:
        await http_post_with_retry(
            f"{AUDIT_SERVICE_URL}/log",
            {
                "test_id": test_id,
                "session_id": test_id,
                "submission_id": submission_id,
                "entry_type": "payload_commit",
                "payload_hash": prompt_hash,
            },
            timeout=10.0,
            max_retries=5,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to log payload hash to audit ledger: {str(e)}",
        )

    # 3. Call defense-runner on red prompt BEFORE sending to model
    prompt_to_model = prompt_text
    try:
        defense_resp = await http_post_with_retry(
            f"{DEFENSE_RUNNER_URL}/evaluate",
            {
                "test_id": test_id,
                "target": "prompt",
                "text": prompt_text,
            },
            timeout=10.0,
            max_retries=5,
        )
        verdict_data = defense_resp.json()
        verdict = verdict_data.get("verdict")

        if verdict == "block":
            record_blocked_event(
                event_type="prompt_blocked",
                sender="red-team",
                endpoint="/red/submit",
                test_id=test_id,
                target="prompt",
                reason="Red prompt matched declarative defense policy block rule",
                verdict="BLOCKED",
            )
            # Red sees ONLY a generic "blocked" message, NEVER the rule that fired
            await apply_padding()
            return RedSubmitResponse(reply="Blocked by defense policy")
        elif verdict == "sanitize":
            prompt_to_model = verdict_data.get("sanitized_text", prompt_text)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to query defense-runner: {str(e)}",
        )

    # 4. Forward prompt to model-service /infer with session_id
    try:
        model_resp = await http_post_with_retry(
            f"{MODEL_SERVICE_URL}/infer",
            {
                "prompt": prompt_to_model,
                "session_id": test_id,
            },
            timeout=30.0,
            max_retries=3,
        )
        model_reply = model_resp.json().get("reply", "")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Upstream model rate limit reached. Please retry shortly.",
            )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Model service error (HTTP {exc.response.status_code}): {exc.response.text}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to communicate with model-service: {str(e)}",
        )

    # 5. Call defense-runner on model response BEFORE returning to red
    final_reply = model_reply
    try:
        defense_resp = await http_post_with_retry(
            f"{DEFENSE_RUNNER_URL}/evaluate",
            {
                "test_id": test_id,
                "target": "response",
                "text": model_reply,
            },
            timeout=10.0,
            max_retries=5,
        )
        verdict_data = defense_resp.json()
        verdict = verdict_data.get("verdict")

        if verdict == "block":
            record_blocked_event(
                event_type="response_blocked",
                sender="red-team",
                endpoint="/red/submit",
                test_id=test_id,
                target="response",
                reason="Model response matched declarative defense policy block rule",
                verdict="BLOCKED",
            )
            # Red sees ONLY a generic "blocked" message, NEVER the rule that fired
            await apply_padding()
            return RedSubmitResponse(reply="Blocked: response policy violation")
        elif verdict == "sanitize":
            final_reply = verdict_data.get("sanitized_text", model_reply)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to query defense-runner on model response: {str(e)}",
        )

    # 6. Log model response hash in audit chain with session_id
    response_hash = hashlib.sha256(final_reply.encode("utf-8")).hexdigest()
    try:
        await http_post_with_retry(
            f"{AUDIT_SERVICE_URL}/log",
            {
                "test_id": test_id,
                "session_id": test_id,
                "submission_id": submission_id,
                "entry_type": "response_commit",
                "payload_hash": response_hash,
            },
            timeout=10.0,
            max_retries=5,
        )
    except Exception:
        pass

    # 7. Write response to red's store
    response_file = os.path.join(test_red_dir, f"{submission_id}_response.json")
    with open(response_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "test_id": test_id,
                "submission_id": submission_id,
                "response": final_reply,
                "timestamp": time.time(),
            },
            f,
            indent=2,
        )

    tests_db[test_id]["submissions"].append({
        "submission_id": submission_id,
        "prompt_hash": prompt_hash,
        "response_hash": response_hash,
    })

    await apply_padding()
    return RedSubmitResponse(reply=final_reply)


# ==============================================================================
# CONCLUSION & HASH RE-VERIFICATION
# ==============================================================================

@app.post("/tests/{test_id}/conclude")
async def conclude_test(test_id: str):
    if test_id not in tests_db:
        raise HTTPException(status_code=404, detail="Test not found")

    current_state = tests_db[test_id]["state"]
    if current_state != "running":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot conclude test in state: {current_state}. Must be 'running'.",
        )

    tests_db[test_id]["state"] = "concluded"
    tests_db[test_id]["concluded_at"] = time.time()

    # 1. Read all payloads and responses from red_payloads
    test_red_dir = os.path.join(RED_PAYLOADS_DIR, test_id)
    items_to_verify = []
    revealed_items = []

    if os.path.exists(test_red_dir):
        files = sorted(os.listdir(test_red_dir))
        for fname in files:
            fpath = os.path.join(test_red_dir, fname)
            if fname.endswith("_payload.json"):
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    prompt_text = data.get("prompt", "")
                    sub_id = data.get("submission_id", "")
                    recomputed_prompt_hash = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
                    items_to_verify.append({
                        "submission_id": sub_id,
                        "entry_type": "payload_commit",
                        "recomputed_hash": recomputed_prompt_hash,
                    })
                    revealed_items.append({
                        "submission_id": sub_id,
                        "prompt": prompt_text,
                        "prompt_hash": recomputed_prompt_hash,
                    })

            elif fname.endswith("_response.json"):
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    resp_text = data.get("response", "")
                    sub_id = data.get("submission_id", "")
                    recomputed_resp_hash = hashlib.sha256(resp_text.encode("utf-8")).hexdigest()
                    items_to_verify.append({
                        "submission_id": sub_id,
                        "entry_type": "response_commit",
                        "recomputed_hash": recomputed_resp_hash,
                    })
                    # Match with revealed items
                    for item in revealed_items:
                        if item["submission_id"] == sub_id:
                            item["response"] = resp_text
                            item["response_hash"] = recomputed_resp_hash

    # 2. Verifier recomputes their hashes against the audit chain
    verification_passed = False
    verification_details = {}

    try:
        audit_verify_resp = await http_post_with_retry(
            f"{AUDIT_SERVICE_URL}/verify",
            {
                "test_id": test_id,
                "items": items_to_verify,
            },
            timeout=10.0,
            max_retries=5,
        )
        verification_details = audit_verify_resp.json()
        verification_passed = verification_details.get("verified", False)
    except Exception as e:
        verification_details = {"error": f"Failed to contact audit verifier: {str(e)}"}

    tests_db[test_id]["verified"] = verification_passed

    # 3. Release payloads and responses to blue (read-only)
    test_release_dir = os.path.join(BLUE_RELEASES_DIR, test_id)
    os.makedirs(test_release_dir, exist_ok=True)
    release_path = os.path.join(test_release_dir, "released_payloads.json")

    release_payload = {
        "test_id": test_id,
        "state": "concluded",
        "verified": verification_passed,
        "verification_details": verification_details,
        "submissions_count": len(revealed_items),
        "submissions": revealed_items,
    }

    with open(release_path, "w", encoding="utf-8") as f:
        json.dump(release_payload, f, indent=2)

    # Make file read-only on filesystem
    try:
        os.chmod(release_path, 0o444)
    except Exception:
        pass

    # 4. Destroy model session to guarantee no memory carries over between tests or tenants
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.delete(f"{MODEL_SERVICE_URL}/sessions/{test_id}")
    except Exception:
        pass

    return {
        "test_id": test_id,
        "state": "concluded",
        "verified": verification_passed,
        "verification_details": verification_details,
        "submissions_count": len(revealed_items),
    }


def verify_judge_credentials(request: Request):
    """Enforces judge-only role authentication and verifies request is not from tenant networks."""
    client_ip = request.client.host if request.client else "unknown"
    sender = request.headers.get("x-sender") or client_ip

    if is_tenant_network(client_ip) or sender in ("red-team", "blue-team"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: judge monitoring data is not accessible from tenant networks",
        )

    role = request.headers.get("x-role", "").lower()
    auth_header = request.headers.get("authorization", "")
    bearer_token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""
    query_token = request.query_params.get("token", "")

    if role == "judge" or bearer_token == JUDGE_TOKEN or query_token == JUDGE_TOKEN:
        return True

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: valid judge role or token required",
    )


@app.get("/logs")
async def get_call_logs(request: Request):
    verify_judge_credentials(request)
    return [{"sender": sender, "endpoint": endpoint, "timestamp": ts} for sender, endpoint, ts in call_logs]


# ==============================================================================
# JUDGE DASHBOARD & MONITORING ENDPOINTS (JUDGE ROLE ONLY)
# ==============================================================================

@app.get("/judge", response_class=HTMLResponse)
async def get_judge_dashboard(request: Request):
    """
    Serves the projector-optimized Judge Dashboard.
    Strictly forbidden from tenant networks.
    """
    client_ip = request.client.host if request.client else "unknown"
    sender = request.headers.get("x-sender") or client_ip

    if is_tenant_network(client_ip) or sender in ("red-team", "blue-team"):
        record_blocked_event(
            event_type="unauthorized_monitoring_access",
            sender=sender,
            endpoint="/judge",
            reason="Tenant network attempted access to judge dashboard HTML",
            verdict="DENIED",
        )
        return HTMLResponse(
            content="<h1>403 Forbidden: Judge dashboard is not accessible from tenant networks</h1>",
            status_code=status.HTTP_403_FORBIDDEN,
        )

    judge_html_path = os.path.join(os.path.dirname(__file__), "judge.html")
    if os.path.exists(judge_html_path):
        with open(judge_html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())

    return HTMLResponse(content="<h1>Judge dashboard template missing</h1>", status_code=500)


@app.get("/judge/api/overview")
async def get_judge_overview(request: Request):
    """
    Returns aggregated telemetry for the judge dashboard:
    - Status of each test
    - Full cryptographic audit chain
    - Denied or blocked attempt events
    """
    verify_judge_credentials(request)

    audit_entries = []
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{AUDIT_SERVICE_URL}/chain")
            if resp.status_code == 200:
                audit_entries = resp.json().get("entries", [])
    except Exception:
        pass

    tests_list = list(tests_db.values())
    active_count = sum(1 for t in tests_list if t.get("state") == "running")

    # Latest verification status across concluded tests
    concluded_tests = [t for t in tests_list if t.get("state") == "concluded"]
    last_verified = None
    if concluded_tests:
        last_verified = all(t.get("verified") is True for t in concluded_tests)

    return {
        "tests": tests_list,
        "audit_chain": audit_entries,
        "blocked_events": blocked_events,
        "summary": {
            "total_tests": len(tests_list),
            "active_tests": active_count,
            "chain_length": len(audit_entries),
            "blocked_count": len(blocked_events),
            "last_verified": last_verified,
        },
    }


@app.post("/judge/api/verify")
async def judge_verify_integrity(request: Request):
    """
    Invokes the cryptographic verifier against the entire audit chain
    and candidate payloads/responses from all test stores.
    """
    verify_judge_credentials(request)

    items_to_verify = []
    if os.path.exists(RED_PAYLOADS_DIR):
        try:
            for test_dir_name in os.listdir(RED_PAYLOADS_DIR):
                test_dir = os.path.join(RED_PAYLOADS_DIR, test_dir_name)
                if not os.path.isdir(test_dir):
                    continue
                for fname in sorted(os.listdir(test_dir)):
                    fpath = os.path.join(test_dir, fname)
                    if fname.endswith("_payload.json"):
                        try:
                            with open(fpath, "r", encoding="utf-8") as f:
                                data = json.load(f)
                                prompt_text = data.get("prompt", "")
                                items_to_verify.append({
                                    "submission_id": data.get("submission_id", ""),
                                    "entry_type": "payload_commit",
                                    "recomputed_hash": hashlib.sha256(prompt_text.encode("utf-8")).hexdigest(),
                                })
                        except Exception:
                            pass
                    elif fname.endswith("_response.json"):
                        try:
                            with open(fpath, "r", encoding="utf-8") as f:
                                data = json.load(f)
                                resp_text = data.get("response", "")
                                items_to_verify.append({
                                    "submission_id": data.get("submission_id", ""),
                                    "entry_type": "response_commit",
                                    "recomputed_hash": hashlib.sha256(resp_text.encode("utf-8")).hexdigest(),
                                })
                        except Exception:
                            pass
        except Exception:
            pass

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{AUDIT_SERVICE_URL}/verify",
                json={
                    "test_id": "__all__",
                    "items": items_to_verify,
                },
            )
            verify_result = resp.json()

            # Get current chain length
            chain_resp = await client.get(f"{AUDIT_SERVICE_URL}/chain")
            chain_len = chain_resp.json().get("chain_length", 0) if chain_resp.status_code == 200 else len(items_to_verify)
            verify_result["chain_length"] = chain_len
            return verify_result
    except Exception as e:
        return {
            "verified": False,
            "chain_intact": False,
            "chain_length": 0,
            "error": f"Failed to contact audit verifier service: {str(e)}",
        }


@app.get("/judge/api/blocked-events")
async def get_judge_blocked_events(request: Request):
    """Returns real-time list of denied and blocked attempt events."""
    verify_judge_credentials(request)
    return {"blocked_events": blocked_events}

