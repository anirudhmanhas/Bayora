import os
import sys
from fastapi import FastAPI, status

try:
    from .client import run_red_team_script
except ImportError:
    from client import run_red_team_script

app = FastAPI(title="Bayora Red Team Service", version="0.1.0")


@app.get("/health", status_code=status.HTTP_200_OK)
async def health():
    return {"status": "ok"}


@app.post("/run")
async def trigger_script():
    replies = run_red_team_script()
    return {"status": "completed", "replies": replies}



if __name__ == "__main__":
    gateway_url = sys.argv[1] if len(sys.argv) > 1 else os.getenv("GATEWAY_URL", "http://gateway:8000")
    run_red_team_script(gateway_url)
