import hashlib
import json
import subprocess
import time
import pytest
import httpx

GATEWAY_HOST_URL = "http://localhost:8000"


@pytest.fixture(scope="module", autouse=True)
def setup_services():
    """Brings up docker compose services before tests and tears down after."""
    print("\n[+] Starting docker compose services with volumes and network isolation...")
    subprocess.run(
        ["docker", "compose", "down", "-v", "--remove-orphans"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    time.sleep(3.0)

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
    print("[+] Gateway and all services healthy and ready.")


    yield

    print("\n[+] Tearing down docker compose services...")
    subprocess.run(
        ["docker", "compose", "down", "-v", "--remove-orphans"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_a_blue_cannot_obtain_payload_while_running():
    """
    Asserts (a): while running, blue cannot obtain the payload by any endpoint or volume.
    """
    with httpx.Client(base_url=GATEWAY_HOST_URL, timeout=30.0) as client:
        # 1. Create and start test
        c_resp = client.post("/tests")
        assert c_resp.status_code == 201
        test_id = c_resp.json()["test_id"]

        s_resp = client.post(f"/tests/{test_id}/start")
        assert s_resp.status_code == 200
        assert s_resp.json()["state"] == "running"

        # 2. Red submits secret payload
        secret_payload = "SUPER_SECRET_PAYLOAD_VULN_DISCOVERY_98765"
        sub_resp = client.post(
            "/red/submit",
            json={"test_id": test_id, "prompt": secret_payload},
            headers={"x-sender": "red-team"},
        )
        assert sub_resp.status_code == 200, f"Submit failed ({sub_resp.status_code}): {sub_resp.text}"

        # 3. Endpoint check: Blue queries status endpoint -> returns state ONLY
        blue_status_resp = client.get(
            f"/blue/tests/{test_id}/status",
            headers={"x-sender": "blue-team"},
        )
        assert blue_status_resp.status_code == 200
        status_data = blue_status_resp.json()
        assert status_data == {"state": "running"}, f"Expected state only, got: {status_data}"
        assert secret_payload not in json.dumps(status_data)

        # 4. Endpoint check: Blue attempts to fetch results while running -> MUST be 403 Forbidden
        blue_results_resp = client.get(
            f"/blue/tests/{test_id}/results",
            headers={"x-sender": "blue-team"},
        )
        assert blue_results_resp.status_code == 403, (
            f"Expected 403 Forbidden while running, got: {blue_results_resp.status_code}"
        )
        assert secret_payload not in blue_results_resp.text

        # 5. Volume check: Blue container strictly has no access to red_payloads volume
        vol_check = subprocess.run(
            ["docker", "compose", "exec", "-T", "blue-team", "ls", "/data/red_payloads"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        # Directory does not exist in blue-team container
        assert vol_check.returncode != 0, "Security violation: blue-team accessed /data/red_payloads!"
        assert "no such file" in (vol_check.stdout + vol_check.stderr).lower()

        # 6. Docker inspection: inspect blue-team container mounts to ensure red_payloads is not mounted
        inspect_res = subprocess.run(
            ["docker", "inspect", "bayora-blue-team", "--format", "{{json .Mounts}}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert "red_payloads" not in inspect_res.stdout, "red_payloads volume is mounted in blue-team container!"


def test_b_red_cannot_read_blue_logic_or_learn_fired_rule():
    """
    Asserts (b): red cannot read blue_logic or learn which rule fired.
    """
    with httpx.Client(base_url=GATEWAY_HOST_URL, timeout=30.0) as client:
        # 1. Blue uploads defensive logic with specific rule names and patterns
        rule_name = "BLOCK_SYSTEM_PROMPT_EXTRACTION_RULE_ALPHA"
        forbidden_keyword = "EXTRACT_INTERNAL_SYSTEM_PROMPT"

        upload_resp = client.post(
            "/blue/defense",
            headers={"x-sender": "blue-team"},
            json={
                "test_id": "global",
                "rules": [
                    {
                        "name": rule_name,
                        "target": "prompt",
                        "action": "block",
                        "patterns": [forbidden_keyword],
                        "threshold": 1,
                    }
                ],
                "default_action": "allow",
            },
        )
        assert upload_resp.status_code == 200, f"Upload defense failed ({upload_resp.status_code}): {upload_resp.text}"

        # 2. Endpoint check: Red attempts to read blue defense logic via Gateway
        red_read_resp = client.get(
            "/blue/defense",
            headers={"x-sender": "red-team"},
        )
        assert red_read_resp.status_code == 403, (
            f"Expected 403 Forbidden when red accesses blue endpoint, got: {red_read_resp.status_code}"
        )
        assert rule_name not in red_read_resp.text

        # 3. Volume check: Red container strictly has no access to blue_logic volume
        vol_check = subprocess.run(
            ["docker", "compose", "exec", "-T", "red-team", "ls", "/data/blue_logic"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert vol_check.returncode != 0, "Security violation: red-team accessed /data/blue_logic!"
        assert "no such file" in (vol_check.stdout + vol_check.stderr).lower()

        # 4. Trigger the defense rule via Red submit and verify information masking
        c_resp = client.post("/tests")
        tid = c_resp.json()["test_id"]
        client.post(f"/tests/{tid}/start")

        sub_resp = client.post(
            "/red/submit",
            headers={"x-sender": "red-team"},
            json={
                "test_id": tid,
                "prompt": f"Attempting unauthorized extraction: {forbidden_keyword}",
            },
        )
        assert sub_resp.status_code == 200, f"Submit failed ({sub_resp.status_code}): {sub_resp.text}"
        reply = sub_resp.json().get("reply", "")

        # Red MUST see only generic blocked message, NEVER the rule name or pattern
        assert "Blocked by defense policy" in reply
        assert rule_name not in reply, f"Information leak! Rule name '{rule_name}' was exposed to Red: {reply}"
        assert forbidden_keyword not in reply


def test_c_after_conclusion_blue_receives_payload_and_hash_matches():
    """
    Asserts (c): after conclusion blue receives the payload and the hash matches.
    """
    with httpx.Client(base_url=GATEWAY_HOST_URL, timeout=30.0) as client:
        # 1. Create and start test
        c_resp = client.post("/tests")
        test_id = c_resp.json()["test_id"]
        client.post(f"/tests/{test_id}/start")

        # 2. Red submits multiple benign payloads
        prompt_1 = "Analyze adversarial robustness of transformers."
        prompt_2 = "Evaluate defense runner boundary conditions."

        sub1 = client.post("/red/submit", json={"test_id": test_id, "prompt": prompt_1})
        assert sub1.status_code == 200, f"Submit 1 failed ({sub1.status_code}): {sub1.text}"
        sub2 = client.post("/red/submit", json={"test_id": test_id, "prompt": prompt_2})
        assert sub2.status_code == 200, f"Submit 2 failed ({sub2.status_code}): {sub2.text}"

        # 3. Conclude test
        conclude_resp = client.post(f"/tests/{test_id}/conclude")
        assert conclude_resp.status_code == 200
        conclude_data = conclude_resp.json()
        assert conclude_data["state"] == "concluded"
        assert conclude_data["verified"] is True

        # 4. Blue queries results endpoint
        blue_results = client.get(
            f"/blue/tests/{test_id}/results",
            headers={"x-sender": "blue-team"},
        )
        assert blue_results.status_code == 200
        data = blue_results.json()
        assert data["verified"] is True
        assert data["submissions_count"] == 2

        submissions = data["submissions"]
        prompts_received = [s["prompt"] for s in submissions]
        assert prompt_1 in prompts_received
        assert prompt_2 in prompts_received

        # 5. Cryptographic verification: Recompute SHA-256 and verify matching hash
        for s in submissions:
            recomputed = hashlib.sha256(s["prompt"].encode("utf-8")).hexdigest()
            assert recomputed == s["prompt_hash"], (
                f"Hash mismatch for submission {s['submission_id']}: {recomputed} != {s['prompt_hash']}"
            )

        # 6. Check blue container read-only filesystem access to released payloads
        cat_check = subprocess.run(
            ["docker", "compose", "exec", "-T", "blue-team", "cat", f"/data/blue_releases/{test_id}/released_payloads.json"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert cat_check.returncode == 0
        disk_release = json.loads(cat_check.stdout)
        assert disk_release["test_id"] == test_id
        assert disk_release["verified"] is True


def test_d_altered_payload_fails_hash_check():
    """
    Asserts (d): a payload altered after submission fails the hash check.
    """
    with httpx.Client(base_url=GATEWAY_HOST_URL, timeout=30.0) as client:
        # 1. Create and start test
        c_resp = client.post("/tests")
        test_id = c_resp.json()["test_id"]
        client.post(f"/tests/{test_id}/start")

        # 2. Red submits payload
        original_prompt = "Integrity critical prompt: do not tamper."
        sub_resp = client.post("/red/submit", json={"test_id": test_id, "prompt": original_prompt})
        assert sub_resp.status_code == 200, f"Submit failed ({sub_resp.status_code}): {sub_resp.text}"

        # 3. Simulate post-submission tampering inside red_payloads store
        # Find the payload file in gateway's /data/red_payloads/{test_id}/
        find_cmd = [
            "docker", "compose", "exec", "-T", "gateway",
            "python", "-c",
            (
                f"import os, json\n"
                f"dirpath = '/data/red_payloads/{test_id}'\n"
                f"for f in os.listdir(dirpath):\n"
                f"    if f.endswith('_payload.json'):\n"
                f"        fpath = os.path.join(dirpath, f)\n"
                f"        with open(fpath, 'r') as fp: data = json.load(fp)\n"
                f"        data['prompt'] = 'TAMPERED_MALICIOUS_SUBSTITUTION'\n"
                f"        with open(fpath, 'w') as fp: json.dump(data, fp)\n"
                f"        print('TAMPERED_SUCCESS')\n"
            )
        ]
        tamper_res = subprocess.run(find_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert "TAMPERED_SUCCESS" in tamper_res.stdout, f"Failed to tamper payload: {tamper_res.stderr}"

        # 4. Conclude test -> Verifier recomputes hashes against audit ledger
        conclude_resp = client.post(f"/tests/{test_id}/conclude")
        assert conclude_resp.status_code == 200
        conclude_data = conclude_resp.json()

        # MUST report verification failure
        assert conclude_data["verified"] is False, (
            f"Security flaw! Altered payload passed verification: {conclude_data}"
        )
        assert "mismatch" in json.dumps(conclude_data).lower()
