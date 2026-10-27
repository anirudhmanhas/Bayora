import os
import sys
import httpx

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://gateway:8000").rstrip("/")


def run_red_team_script(gateway_url: str = GATEWAY_URL) -> list[str]:
    print(f"[Red Team] Connecting to gateway at {gateway_url}...")

    with httpx.Client(base_url=gateway_url, timeout=30.0, headers={"x-sender": "red-team"}) as client:
        # 1. Create a test
        create_resp = client.post("/tests")
        create_resp.raise_for_status()
        test_info = create_resp.json()
        test_id = test_info["test_id"]
        print(f"[Red Team] Created test: {test_id} (state: {test_info.get('state')})")

        # 2. Start the test
        start_resp = client.post(f"/tests/{test_id}/start")
        start_resp.raise_for_status()
        print(f"[Red Team] Started test: {test_id} (state: {start_resp.json().get('state')})")

        # 3. Send two prompts
        prompts = [
            "Explain adversarial robustness in language models.",
            "Test boundary validation under pressure.",
        ]
        replies = []
        for prompt in prompts:
            print(f"[Red Team] Submitting prompt: '{prompt}'")
            sub_resp = client.post("/red/submit", json={"test_id": test_id, "prompt": prompt})
            sub_resp.raise_for_status()
            reply = sub_resp.json().get("reply", "")
            print(f"[Red Team] Received reply: '{reply}'")
            replies.append(reply)

        return replies


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else GATEWAY_URL
    run_red_team_script(url)
