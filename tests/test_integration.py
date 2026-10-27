import subprocess
import time
import pytest
import httpx

GATEWAY_HOST_URL = "http://localhost:8000"


@pytest.fixture(scope="module", autouse=True)
def docker_environment():
    """Brings up docker compose services before tests and tears down after."""
    print("\n[+] Ensuring clean slate before starting containers...")
    subprocess.run(
        ["docker", "compose", "down", "-v", "--remove-orphans"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    time.sleep(3.0)

    print("\n[+] Starting docker compose services (gateway, model-service, red-team, blue-team, defense-runner, audit)...")
    build_cmd = [
        "docker", "compose", "up", "-d", "--build",
        "gateway", "model-service", "egress-proxy", "red-team", "blue-team", "defense-runner", "audit"
    ]

    res = subprocess.run(
        build_cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert res.returncode == 0, f"docker compose up failed:\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}"

    # Wait for gateway to become healthy
    deadline = time.time() + 90.0
    gateway_ready = False
    last_status = None
    while time.time() < deadline:
        try:
            r = httpx.get(f"{GATEWAY_HOST_URL}/health", timeout=5.0)
            if r.status_code == 200:
                gateway_ready = True
                break
            last_status = f"HTTP {r.status_code}: {r.text}"
        except Exception as e:
            last_status = f"Conn err: {e}"
        time.sleep(1.0)

    if not gateway_ready:
        ps_info = subprocess.run(["docker", "compose", "ps"], capture_output=True, text=True).stdout
        gw_logs = subprocess.run(["docker", "compose", "logs", "gateway"], capture_output=True, text=True).stdout
        assert gateway_ready, (
            f"Gateway failed to become healthy within 90s. Last status: {last_status}\n"
            f"[PS]:\n{ps_info}\n[LOGS]:\n{gw_logs}"
        )

    # Wait for downstream services to be reachable from gateway
    deadline = time.time() + 60.0
    downstream_ready = False
    probe_py = (
        "import urllib.request\n"
        "try:\n"
        "    urllib.request.urlopen('http://defense-runner:8000/health', timeout=3)\n"
        "    urllib.request.urlopen('http://audit:8000/health', timeout=3)\n"
        "    urllib.request.urlopen('http://model-service:8000/health', timeout=3)\n"
        "    print('ALL_READY')\n"
        "except Exception:\n"
        "    exit(1)\n"
    )
    while time.time() < deadline:
        probe = subprocess.run(
            ["docker", "compose", "exec", "-T", "gateway", "python", "-c", probe_py],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if "ALL_READY" in probe.stdout:
            downstream_ready = True
            break
        time.sleep(1.5)

    assert downstream_ready, "Downstream services (defense-runner, audit, model-service) failed to become reachable."
    time.sleep(1.0)
    print("[+] Gateway and all downstream services are healthy and reachable.")

    yield

    print("\n[+] Tearing down docker compose services...")
    subprocess.run(
        ["docker", "compose", "down", "-v", "--remove-orphans"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_b_submit_before_start_rejected():
    """
    Asserts (b): A payload submission before starting the test is rejected.
    """
    with httpx.Client(base_url=GATEWAY_HOST_URL, timeout=30.0) as client:
        # 1. Create a test
        create_resp = client.post("/tests")
        assert create_resp.status_code == 201, f"Expected 201 Created, got: {create_resp.status_code}"
        data = create_resp.json()
        test_id = data["test_id"]
        assert data["state"] == "created"

        # 2. Verify status endpoint reports 'created'
        status_resp = client.get(f"/tests/{test_id}/status")
        assert status_resp.status_code == 200
        assert status_resp.json()["state"] == "created"

        # 3. Attempt to submit payload while in 'created' state -> MUST be rejected (400)
        sub_resp = client.post(
            "/red/submit",
            json={"test_id": test_id, "prompt": "Pre-start prompt attempt"},
        )
        assert sub_resp.status_code == 400, (
            f"Expected 400 Bad Request for submission before start, got: {sub_resp.status_code} ({sub_resp.text})"
        )
        assert "running" in sub_resp.json().get("detail", "").lower()


def test_a_replies_come_back_from_red_team_script():
    """
    Asserts (a): Running the red-team script sends prompts, and replies come back from model-service.
    """
    # Execute the red-team script inside the running red-team container
    exec_cmd = ["docker", "compose", "exec", "-T", "red-team", "python", "client.py"]
    res = subprocess.run(
        exec_cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert res.returncode == 0, f"red-team script failed:\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}"

    output = res.stdout
    print(f"\n[red-team output]:\n{output}")

    # Assert that replies come back with the expected model-service format
    assert "MODEL RESPONSE: Explain adversarial robustness in language models." in output, (
        f"Missing expected response for prompt 1 in output: {output}"
    )
    assert "MODEL RESPONSE: Test boundary validation under pressure." in output, (
        f"Missing expected response for prompt 2 in output: {output}"
    )


def test_c_red_team_cannot_reach_model_service_directly():
    """
    Asserts (c): red-team cannot reach model-service directly.
    A direct HTTP request from inside the red-team container fails because
    red-team is on red-net and model-service is on model-net with no shared route.
    """
    probe_py = (
        "import urllib.request\n"
        "try:\n"
        "    urllib.request.urlopen('http://model-service:8000/health', timeout=2)\n"
        "    print('UNEXPECTED_SUCCESS')\n"
        "except Exception as e:\n"
        "    print(f'EXPECTED_FAILURE: {type(e).__name__}: {e}')\n"
        "    exit(42)\n"
    )

    exec_cmd = ["docker", "compose", "exec", "-T", "red-team", "python", "-c", probe_py]
    res = subprocess.run(
        exec_cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    print(f"\n[Isolation probe result]: code={res.returncode}, output={res.stdout + res.stderr}")

    # Exit code must be 42 (our failure trigger), and output must NOT say UNEXPECTED_SUCCESS
    assert res.returncode == 42, (
        f"Expected direct connection to fail with exit code 42, but got: {res.returncode}\n"
        f"STDOUT: {res.stdout}\nSTDERR: {res.stderr}"
    )
    assert "EXPECTED_FAILURE" in res.stdout
    assert "UNEXPECTED_SUCCESS" not in res.stdout


def test_gateway_call_logs_and_lifecycle():
    """
    Verifies that the gateway logs all requests with (sender, endpoint, timestamp)
    and transitions tests cleanly through conclude.
    """
    with httpx.Client(base_url=GATEWAY_HOST_URL, timeout=30.0) as client:
        # Create, start, and conclude a test
        c_resp = client.post("/tests")
        tid = c_resp.json()["test_id"]
        client.post(f"/tests/{tid}/start")
        client.post(f"/tests/{tid}/conclude")

        status_resp = client.get(f"/tests/{tid}/status")
        assert status_resp.json()["state"] == "concluded"

        # Attempt to submit after conclude -> must be rejected
        late_sub = client.post("/red/submit", json={"test_id": tid, "prompt": "Late prompt"})
        assert late_sub.status_code == 400

        # Query call logs
        logs_resp = client.get("/logs")
        assert logs_resp.status_code == 200
        logs = logs_resp.json()
        assert len(logs) > 0
        endpoints_called = [l["endpoint"] for l in logs]
        assert "/tests" in endpoints_called
        assert f"/tests/{tid}/start" in endpoints_called
        assert f"/tests/{tid}/conclude" in endpoints_called
