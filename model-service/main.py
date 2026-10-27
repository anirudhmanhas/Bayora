import asyncio
import logging
import os
import sys
import time
from typing import Dict, List, Optional
import httpx
from fastapi import FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from sanitizer import sanitize_model_output, SecretRedactingFormatter


LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b").strip()
GROQ_API_URL = os.getenv("GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions").strip()
PROXY_URL = os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY") or None

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(
    SecretRedactingFormatter(
        fmt="%(asctime)s [%(levelname)s] [model-service] %(message)s",
        secret=GROQ_API_KEY,
    )
)
logger = logging.getLogger("model-service")
logger.setLevel(LOG_LEVEL)
logger.handlers = [handler]
logger.propagate = False

app = FastAPI(title="Bayora Model Service (Groq API)", version="0.3.0")

# In-memory session store: session_id -> list of {"role": "...", "content": "..."}
# Ephemeral: destroyed completely on test conclusion
sessions: Dict[str, List[Dict[str, str]]] = {}
session_metadata: Dict[str, dict] = {}


class InferRequest(BaseModel):
    prompt: str = Field(..., description="User prompt payload")
    session_id: Optional[str] = Field(None, description="Unique test session identifier")
    test_id: Optional[str] = Field(None, description="Alternative test identifier")


class InferResponse(BaseModel):
    reply: str
    session_id: str
    model: str
    filtered_types: List[str] = Field(default_factory=list)


@app.get("/health", status_code=status.HTTP_200_OK)
async def health():
    return {
        "status": "ok",
        "service": "model-service",
        "model": GROQ_MODEL,
        "api_key_configured": bool(GROQ_API_KEY),
        "proxy_configured": bool(PROXY_URL),
        "active_sessions": len(sessions),
    }


@app.post("/infer", response_model=InferResponse)
async def infer(req: InferRequest):
    session_id = (req.session_id or req.test_id or "default-session").strip()
    prompt = req.prompt

    # 1. Retrieve or create isolated conversation session
    if session_id not in sessions:
        sessions[session_id] = []
        session_metadata[session_id] = {
            "created_at": time.time(),
            "last_active": time.time(),
            "turn_count": 0,
        }

    # Append new user prompt to the active session history
    sessions[session_id].append({"role": "user", "content": prompt})
    session_metadata[session_id]["last_active"] = time.time()
    session_metadata[session_id]["turn_count"] += 1

    # 2. Check if API key is provided
    if not GROQ_API_KEY:
        # Fallback only when no key is configured (e.g. offline dry runs)
        logger.warning("GROQ_API_KEY is not set. Using ephemeral offline stub response.")
        mock_raw = f"MOCK MODEL [{GROQ_MODEL}] response to: {prompt}"
        sanitized_reply, telemetry = sanitize_model_output(mock_raw)
        sessions[session_id].append({"role": "assistant", "content": sanitized_reply})
        return InferResponse(
            reply=sanitized_reply,
            session_id=session_id,
            model=f"mock-{GROQ_MODEL}",
            filtered_types=telemetry.get("stripped_types", []),
        )

    # 3. Call Groq API through egress-proxy
    messages_payload = list(sessions[session_id])
    request_body = {
        "model": GROQ_MODEL,
        "messages": messages_payload,
        "temperature": 0.6,
        "max_tokens": 1024,
    }

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
        "User-Agent": "Bayora-Model-Service/0.3.0",
    }

    client_kwargs = {
        "timeout": httpx.Timeout(25.0, connect=10.0),
        "trust_env": True,
    }
    if PROXY_URL:
        client_kwargs["proxy"] = PROXY_URL

    raw_reply = ""
    try:
        async with httpx.AsyncClient(**client_kwargs) as client:
            resp = await client.post(
                GROQ_API_URL,
                json=request_body,
                headers=headers,
            )

            # Clean rate limit & status code handling
            if resp.status_code == 429:
                retry_after = resp.headers.get("retry-after", "a few seconds")
                logger.warning(f"Groq API rate limit reached (HTTP 429). Retry-after: {retry_after}")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Model provider rate limit reached. Please retry after {retry_after}.",
                )

            if resp.status_code == 401:
                logger.error("Groq API authentication failed (HTTP 401). Verify GROQ_API_KEY.")
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Model provider authentication failed. Contact platform administrator.",
                )

            if resp.status_code >= 500:
                logger.error(f"Groq API upstream server error: HTTP {resp.status_code}")
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Model provider upstream server error (HTTP {resp.status_code}).",
                )

            resp.raise_for_status()
            data = resp.json()

            choices = data.get("choices", [])
            if not choices:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Model provider returned empty choices list.",
                )

            raw_reply = choices[0].get("message", {}).get("content", "")

    except httpx.TimeoutException as exc:
        logger.error(f"Groq API request timed out: {exc}")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Model provider request timed out.",
        )
    except httpx.ConnectError as exc:
        logger.error(f"Failed to connect to Groq API via proxy: {exc}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to connect to model provider via egress proxy.",
        )
    except httpx.HTTPStatusError as exc:
        logger.error(f"Groq API HTTP error: HTTP {exc.response.status_code} - {exc.response.text}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Groq API error (HTTP {exc.response.status_code})",
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Unexpected error communicating with Groq API: {type(exc).__name__}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Error communicating with model provider: {type(exc).__name__}",
        )

    # 4. Filter model output before returning (strip reasoning tags, URLs, images, stack traces, system leaks)
    sanitized_reply, telemetry = sanitize_model_output(raw_reply)

    # Store sanitized reply in conversation history
    sessions[session_id].append({"role": "assistant", "content": sanitized_reply})

    return InferResponse(
        reply=sanitized_reply,
        session_id=session_id,
        model=GROQ_MODEL,
        filtered_types=telemetry.get("stripped_types", []),
    )


@app.delete("/sessions/{session_id}", status_code=status.HTTP_200_OK)
@app.post("/sessions/{session_id}/delete", status_code=status.HTTP_200_OK)
async def delete_session(session_id: str):
    """
    Purges model session memory.
    Called when a test concludes or session lifecycle ends.
    Guarantees no conversation history carries over to future tests or tenants.
    """
    had_session = session_id in sessions
    sessions.pop(session_id, None)
    session_metadata.pop(session_id, None)
    logger.info(f"Deleted model session '{session_id}' (existed={had_session})")
    return {
        "status": "deleted",
        "session_id": session_id,
        "existed": had_session,
    }


@app.get("/sessions/{session_id}/status")
async def get_session_status(session_id: str):
    """Diagnostic endpoint to inspect active turns in a session."""
    if session_id not in sessions:
        return {"session_id": session_id, "active": False, "turns": 0}
    return {
        "session_id": session_id,
        "active": True,
        "turns": len(sessions[session_id]),
        "metadata": session_metadata.get(session_id, {}),
    }
