import os
import httpx
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

app = FastAPI(title="Bayora Blue Team Service", version="0.2.0")

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://gateway:8000").rstrip("/")
BLUE_RELEASES_DIR = os.getenv("BLUE_RELEASES_DIR", "/data/blue_releases")


@app.get("/health", status_code=status.HTTP_200_OK)
def health():
    return {"status": "ok"}


@app.get("/status/{test_id}")
async def check_status(test_id: str):
    """Blue queries test status from Gateway."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=5.0, headers={"x-sender": "blue-team"}) as client:
        resp = await client.get(f"/blue/tests/{test_id}/status")
        return resp.json()


@app.post("/defense")
async def upload_defense_to_gateway(rules: dict):
    """Blue uploads declarative rules to Gateway."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=5.0, headers={"x-sender": "blue-team"}) as client:
        resp = await client.post("/blue/defense", json=rules)
        return resp.json()


@app.get("/results/{test_id}")
async def fetch_results(test_id: str):
    """Blue queries results after conclusion."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=5.0, headers={"x-sender": "blue-team"}) as client:
        resp = await client.get(f"/blue/tests/{test_id}/results")
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        return resp.json()
