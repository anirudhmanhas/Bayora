import hashlib
import json
import os
import time
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(title="Bayora Audit Ledger Service", version="0.2.0")

AUDIT_STORE_DIR = os.getenv("AUDIT_STORE_DIR", "/data/audit")
GENESIS_HASH = "0" * 64

# In-memory chain of blocks
chain: List[Dict] = []


def _persist_chain():
    try:
        os.makedirs(AUDIT_STORE_DIR, exist_ok=True)
        with open(os.path.join(AUDIT_STORE_DIR, "audit_chain.json"), "w", encoding="utf-8") as f:
            json.dump(chain, f, indent=2)
    except Exception:
        pass


def _load_chain():
    global chain
    path = os.path.join(AUDIT_STORE_DIR, "audit_chain.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                chain = json.load(f)
        except Exception:
            chain = []


_load_chain()


class LogRequest(BaseModel):
    test_id: str = Field(..., description="Test session identifier")
    submission_id: str = Field(..., description="Unique submission ID")
    entry_type: str = Field("payload_commit", description="Type of entry (payload_commit, response_commit)")
    payload_hash: str = Field(..., description="SHA-256 hash of the payload or response")
    session_id: Optional[str] = Field(None, description="Model session identifier")


class VerifyItem(BaseModel):
    submission_id: str
    entry_type: str = "payload_commit"
    recomputed_hash: str


class VerifyRequest(BaseModel):
    test_id: str
    items: List[VerifyItem]


def compute_entry_hash(
    index: int,
    test_id: str,
    submission_id: str,
    entry_type: str,
    payload_hash: str,
    prev_hash: str,
    timestamp: float,
    session_id: str = "",
) -> str:
    canonical = f"{index}|{test_id}|{submission_id}|{entry_type}|{payload_hash}|{prev_hash}|{timestamp:.6f}|{session_id}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@app.get("/health", status_code=status.HTTP_200_OK)
async def health():
    return {"status": "ok", "chain_length": len(chain)}


@app.post("/log", status_code=status.HTTP_201_CREATED)
async def log_entry(req: LogRequest):
    index = len(chain)
    prev_hash = chain[-1]["entry_hash"] if chain else GENESIS_HASH
    timestamp = time.time()
    effective_session_id = req.session_id or req.test_id

    entry_hash = compute_entry_hash(
        index=index,
        test_id=req.test_id,
        submission_id=req.submission_id,
        entry_type=req.entry_type,
        payload_hash=req.payload_hash,
        prev_hash=prev_hash,
        timestamp=timestamp,
        session_id=effective_session_id,
    )

    entry = {
        "index": index,
        "test_id": req.test_id,
        "session_id": effective_session_id,
        "submission_id": req.submission_id,
        "entry_type": req.entry_type,
        "payload_hash": req.payload_hash,
        "prev_hash": prev_hash,
        "timestamp": timestamp,
        "entry_hash": entry_hash,
    }

    chain.append(entry)
    _persist_chain()

    return {"status": "logged", "entry": entry}


@app.get("/chain/{test_id}")
async def get_chain_for_test(test_id: str):
    test_entries = [entry for entry in chain if entry["test_id"] == test_id]
    return {"test_id": test_id, "entries": test_entries, "total_chain_length": len(chain)}


@app.get("/chain")
async def get_full_chain():
    return {"chain_length": len(chain), "entries": chain}


@app.post("/verify")
async def verify_integrity(req: VerifyRequest):
    # 1. Verify cryptographic integrity of the entire hash chain
    expected_prev = GENESIS_HASH
    for block in chain:
        if block["prev_hash"] != expected_prev:
            return {
                "verified": False,
                "chain_intact": False,
                "error": f"Broken chain at index {block['index']}: prev_hash mismatch",
            }
        recomputed_block_hash = compute_entry_hash(
            index=block["index"],
            test_id=block["test_id"],
            submission_id=block["submission_id"],
            entry_type=block["entry_type"],
            payload_hash=block["payload_hash"],
            prev_hash=block["prev_hash"],
            timestamp=block["timestamp"],
            session_id=block.get("session_id", ""),
        )
        if block["entry_hash"] != recomputed_block_hash:
            return {
                "verified": False,
                "chain_intact": False,
                "error": f"Corrupted block at index {block['index']}: entry_hash mismatch",
            }
        expected_prev = block["entry_hash"]

    # 2. Check candidate recomputed hashes against logged hashes for this test (or all tests if __all__)
    test_entries = {
        (entry["submission_id"], entry["entry_type"]): entry["payload_hash"]
        for entry in chain
        if (req.test_id in ("__all__", "*", "") or entry["test_id"] == req.test_id)
    }

    mismatches = []
    missing = []
    for item in req.items:
        key = (item.submission_id, item.entry_type)
        if key not in test_entries:
            missing.append(f"{item.submission_id}:{item.entry_type}")
        elif test_entries[key] != item.recomputed_hash:
            mismatches.append({
                "submission_id": item.submission_id,
                "entry_type": item.entry_type,
                "expected_audit_hash": test_entries[key],
                "actual_recomputed_hash": item.recomputed_hash,
            })

    if mismatches or missing:
        return {
            "verified": False,
            "chain_intact": True,
            "mismatches": mismatches,
            "missing": missing,
            "error": "Hash mismatch detected between candidate data and audit chain",
        }

    return {
        "verified": True,
        "chain_intact": True,
        "matched_items": len(req.items),
    }
