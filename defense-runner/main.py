import json
import os
import re
from typing import Dict, List, Literal, Optional
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(title="Bayora Defense Runner Service", version="0.2.0")

BLUE_LOGIC_DIR = os.getenv("BLUE_LOGIC_DIR", "/data/blue_logic")

# In-memory rule cache: test_id -> rules dict
# Key "__global__" is used for global rules
rules_cache: Dict[str, Dict] = {}


def _load_rules_from_disk():
    global rules_cache
    if not os.path.exists(BLUE_LOGIC_DIR):
        return

    try:
        for fname in os.listdir(BLUE_LOGIC_DIR):
            if fname.endswith(".json"):
                fpath = os.path.join(BLUE_LOGIC_DIR, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        test_id = data.get("test_id") or os.path.splitext(fname)[0]
                        rules_cache[test_id] = data
                except Exception:
                    pass
    except Exception:
        pass


_load_rules_from_disk()


class DefenseRule(BaseModel):
    name: Optional[str] = "rule"
    target: Literal["prompt", "response", "all"] = "all"
    action: Literal["allow", "block", "sanitize"] = "block"
    patterns: List[str] = Field(default_factory=list, description="Declarative pattern tokens or regexes")
    threshold: int = Field(1, ge=1, description="Number of pattern matches required to trigger rule")
    replacement: Optional[str] = "[REDACTED]"


class DefenseConfig(BaseModel):
    test_id: Optional[str] = None
    default_action: Literal["allow", "block"] = "allow"
    rules: List[DefenseRule] = Field(default_factory=list)


class EvaluateRequest(BaseModel):
    test_id: Optional[str] = None
    target: Literal["prompt", "response"] = "prompt"
    text: str = Field(..., description="Prompt or model response text to evaluate")


class EvaluateResponse(BaseModel):
    verdict: Literal["allow", "block", "sanitize"]
    sanitized_text: Optional[str] = None


@app.get("/health", status_code=status.HTTP_200_OK)
async def health():
    return {"status": "ok", "cached_rule_sets": len(rules_cache)}


@app.post("/reload", status_code=status.HTTP_200_OK)
async def reload_rules():
    """Reloads declarative rules from blue_logic storage."""
    _load_rules_from_disk()
    return {"status": "reloaded", "cached_rule_sets": len(rules_cache)}


@app.post("/sync_rules", status_code=status.HTTP_200_OK)
async def sync_rules(config: DefenseConfig):
    """Allows gateway to update rule cache directly in memory."""
    key = config.test_id or "__global__"
    rules_cache[key] = config.model_dump()
    return {"status": "synced", "key": key, "rules_count": len(config.rules)}


def _get_applicable_rules(test_id: Optional[str]) -> List[DefenseRule]:
    # Refresh disk state in case a new file was written
    _load_rules_from_disk()

    rules_data: List[dict] = []
    if test_id and test_id in rules_cache:
        rules_data.extend(rules_cache[test_id].get("rules", []))
    if "__global__" in rules_cache:
        rules_data.extend(rules_cache["__global__"].get("rules", []))
    if "global" in rules_cache:
        rules_data.extend(rules_cache["global"].get("rules", []))

    parsed: List[DefenseRule] = []
    for r in rules_data:
        try:
            parsed.append(DefenseRule(**r))
        except Exception:
            pass
    return parsed


@app.post("/evaluate", response_model=EvaluateResponse)
async def evaluate(req: EvaluateRequest):
    rules = _get_applicable_rules(req.test_id)
    current_text = req.text
    sanitized = False

    for rule in rules:
        if rule.target not in (req.target, "all"):
            continue

        # Count pattern hits declaratively
        matches_count = 0
        matching_spans = []

        for pat in rule.patterns:
            if not pat:
                continue
            # Safe regex search or case-insensitive substring
            try:
                found = list(re.finditer(re.escape(pat), current_text, flags=re.IGNORECASE))
                if found:
                    matches_count += len(found)
                    matching_spans.extend(found)
            except Exception:
                # Fallback to simple substring
                if pat.lower() in current_text.lower():
                    matches_count += 1

        if matches_count >= rule.threshold:
            if rule.action == "block":
                # Returns ONLY the coarse verdict, never the rule name or pattern
                return EvaluateResponse(verdict="block", sanitized_text=None)

            if rule.action == "sanitize":
                replacement = rule.replacement or "[REDACTED]"
                for pat in rule.patterns:
                    try:
                        current_text = re.sub(re.escape(pat), replacement, current_text, flags=re.IGNORECASE)
                        sanitized = True
                    except Exception:
                        pass

    if sanitized:
        return EvaluateResponse(verdict="sanitize", sanitized_text=current_text)

    return EvaluateResponse(verdict="allow", sanitized_text=None)
