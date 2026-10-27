import hashlib
import json
import os
import sys
import time
import pytest
from fastapi.testclient import TestClient

# Ensure gateway and audit modules are importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "gateway")))

from main import app, tests_db, call_logs, blocked_events, JUDGE_TOKEN


@pytest.fixture(autouse=True)
def clean_state():
    """Resets in-memory state before each test."""
    tests_db.clear()
    call_logs.clear()
    blocked_events.clear()
    yield
    tests_db.clear()
    call_logs.clear()
    blocked_events.clear()


@pytest.fixture
def client():
    return TestClient(app)


# ==============================================================================
# 1. JUDGE DASHBOARD SERVED THROUGH GATEWAY & JUDGE ROLE AUTH
# ==============================================================================

def test_judge_dashboard_html_served_to_judge(client):
    """Asserts that GET /judge serves the projector-optimized dashboard UI."""
    resp = client.get("/judge", headers={"x-role": "judge"})
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    html = resp.text
    assert "Bayora Adjudication Console" in html
    assert "Verify Integrity" in html
    assert "Cryptographic Audit Chain" in html
    assert "Test Sessions Lifecycle" in html
    assert "Denied & Blocked Attempt Events" in html


def test_judge_api_overview_requires_auth(client):
    """Asserts that GET /judge/api/overview rejects unauthenticated requests."""
    resp = client.get("/judge/api/overview")
    assert resp.status_code == 401
    assert "unauthorized" in resp.json().get("detail", "").lower()


def test_judge_api_overview_accessible_with_token(client):
    """Asserts that GET /judge/api/overview succeeds with valid judge token."""
    resp = client.get(f"/judge/api/overview?token={JUDGE_TOKEN}")
    assert resp.status_code == 200
    data = resp.json()
    assert "tests" in data
    assert "audit_chain" in data
    assert "blocked_events" in data
    assert "summary" in data


# ==============================================================================
# 2. TENANTS STRICTLY FORBIDDEN FROM JUDGE DASHBOARD & MONITORING DATA
# ==============================================================================

def test_tenants_forbidden_from_judge_dashboard_by_sender(client):
    """Asserts that red-team and blue-team senders are rejected with 403 Forbidden."""
    for tenant_sender in ("red-team", "blue-team"):
        resp = client.get("/judge", headers={"x-sender": tenant_sender})
        assert resp.status_code == 403, f"Expected 403 for {tenant_sender}, got {resp.status_code}"
        assert "forbidden" in resp.text.lower()

        resp_api = client.get("/judge/api/overview", headers={"x-sender": tenant_sender, "x-role": "judge"})
        assert resp_api.status_code == 403, f"Expected 403 for {tenant_sender} API call, got {resp_api.status_code}"


def test_tenants_forbidden_from_monitoring_logs(client):
    """Asserts that tenants cannot access the /logs endpoint."""
    for tenant_sender in ("red-team", "blue-team"):
        resp = client.get("/logs", headers={"x-sender": tenant_sender})
        assert resp.status_code == 403

    # Unauthenticated external caller cannot view logs either
    resp_anon = client.get("/logs")
    assert resp_anon.status_code == 401

    # Judge can view logs
    resp_judge = client.get("/logs", headers={"x-role": "judge"})
    assert resp_judge.status_code == 200


def test_tenant_network_ip_rejected_even_if_spoofing_judge_role():
    """
    Simulates a request arriving from a tenant network subnet (e.g. 172.28.2.3 or 172.28.3.3).
    Asserts that even if the tenant sends 'x-role: judge' and the correct token,
    the gateway rejects them with 403 Forbidden at the network layer.
    """
    tenant_client = TestClient(app, client=("172.28.2.3", 54321))
    resp = tenant_client.get(
        f"/judge/api/overview?token={JUDGE_TOKEN}",
        headers={"x-role": "judge"},
    )
    assert resp.status_code == 403
    assert "tenant networks" in resp.json().get("detail", "").lower()

    # Blue network simulation
    blue_client = TestClient(app, client=("172.28.3.3", 54322))
    resp_blue = blue_client.get(
        "/judge",
        headers={"x-role": "judge"},
    )
    assert resp_blue.status_code == 403
    assert "tenant networks" in resp_blue.text.lower()


# ==============================================================================
# 3. TRACKING OF DENIED AND BLOCKED ATTEMPT EVENTS
# ==============================================================================

def test_blocked_events_tracked_on_cross_tenant_access(client):
    """Asserts that cross-tenant access attempts are recorded in blocked_events."""
    resp = client.post(
        "/blue/defense",
        json={"rules": []},
        headers={"x-sender": "red-team"},
    )
    assert resp.status_code == 403

    events_resp = client.get("/judge/api/blocked-events", headers={"x-role": "judge"})
    assert events_resp.status_code == 200
    events = events_resp.json()["blocked_events"]
    assert len(events) >= 1
    cross_evt = next((e for e in events if e["event_type"] == "cross_tenant_access"), None)
    assert cross_evt is not None
    assert cross_evt["sender"] == "red-team"
    assert cross_evt["verdict"] == "DENIED"


def test_blocked_events_tracked_on_unauthorized_monitoring_access(client):
    """Asserts that tenant attempts to access monitoring are recorded in blocked_events."""
    resp = client.get("/judge", headers={"x-sender": "blue-team"})
    assert resp.status_code == 403

    events_resp = client.get("/judge/api/blocked-events", headers={"x-role": "judge"})
    assert events_resp.status_code == 200
    events = events_resp.json()["blocked_events"]
    mon_evt = next((e for e in events if e["event_type"] == "unauthorized_monitoring_access"), None)
    assert mon_evt is not None
    assert mon_evt["sender"] == "blue-team"
    assert mon_evt["verdict"] == "DENIED"


def test_invalid_state_submission_tracked(client):
    """Asserts that attempting to submit payload before test start is logged in blocked_events."""
    create_resp = client.post("/tests")
    assert create_resp.status_code == 201
    test_id = create_resp.json()["test_id"]

    sub_resp = client.post("/red/submit", json={"test_id": test_id, "prompt": "premature prompt"})
    assert sub_resp.status_code == 400

    events_resp = client.get("/judge/api/blocked-events", headers={"x-role": "judge"})
    events = events_resp.json()["blocked_events"]
    inv_evt = next((e for e in events if e["event_type"] == "invalid_state_submission"), None)
    assert inv_evt is not None
    assert inv_evt["test_id"] == test_id
    assert inv_evt["verdict"] == "DENIED"


# ==============================================================================
# 4. AUDIT CHAIN & VERIFY INTEGRITY ENDPOINT
# ==============================================================================

def test_judge_verify_integrity_endpoint(client, monkeypatch):
    """
    Asserts that POST /judge/api/verify executes the verifier and returns
    chain status, block count, and tamper detection.
    """
    # Mock audit service responses
    async def mock_post(url, *args, **kwargs):
        class MockResp:
            status_code = 200
            def json(self):
                return {
                    "verified": True,
                    "chain_intact": True,
                    "matched_items": 2,
                }
        return MockResp()

    async def mock_get(url, *args, **kwargs):
        class MockResp:
            status_code = 200
            def json(self):
                return {
                    "chain_length": 5,
                    "entries": [
                        {
                            "index": 0,
                            "test_id": "test-1",
                            "submission_id": "sub-1",
                            "entry_type": "payload_commit",
                            "payload_hash": "a" * 64,
                            "prev_hash": "0" * 64,
                            "entry_hash": "b" * 64,
                            "timestamp": time.time(),
                        }
                    ]
                }
        return MockResp()

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get)

    verify_resp = client.post("/judge/api/verify", headers={"x-role": "judge"})
    assert verify_resp.status_code == 200
    res = verify_resp.json()
    assert res["verified"] is True
    assert res["chain_intact"] is True
    assert res["chain_length"] == 5

    # Check that overview reflects the audit chain
    overview_resp = client.get("/judge/api/overview", headers={"x-role": "judge"})
    assert overview_resp.status_code == 200
    overview = overview_resp.json()
    assert overview["summary"]["chain_length"] == 1
    assert len(overview["audit_chain"]) == 1
