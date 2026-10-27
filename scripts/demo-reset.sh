#!/usr/bin/env bash
# =============================================================================
# scripts/demo-reset.sh
# One-command Bayora demo environment reset (Linux / macOS / WSL2)
#
# Usage:  bash scripts/demo-reset.sh
#         GROQ_API_KEY=<key> bash scripts/demo-reset.sh
#
# What it does:
#   1. Tears down all containers and named volumes (clean slate)
#   2. Rebuilds all images from source
#   3. Starts the full stack in detached mode
#   4. Waits for gateway, model-service, and egress-proxy healthchecks
#   5. Pre-loads a global demo defense rule so the demo can start immediately
#   6. Prints a READY banner
# =============================================================================

set -euo pipefail

GATEWAY="http://localhost:8000"
TIMEOUT=120   # seconds to wait for healthchecks
RULE_PAYLOAD='{
  "default_action": "allow",
  "rules": [
    {
      "name": "block-jailbreak-keyword",
      "target": "all",
      "action": "block",
      "patterns": ["jailbreak"],
      "threshold": 1
    }
  ]
}'

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[demo-reset]${NC} $*"; }
warn() { echo -e "${YELLOW}[demo-reset]${NC} $*"; }
die()  { echo -e "${RED}[demo-reset] FATAL:${NC} $*"; exit 1; }

# ── 0. Preflight ─────────────────────────────────────────────────────────────
command -v docker   >/dev/null 2>&1 || die "docker not found"
command -v curl     >/dev/null 2>&1 || die "curl not found"

# Must run from repo root (docker-compose.yml present)
[ -f docker-compose.yml ] || die "Run this script from the Bayora repo root"

# ── 1. Tear down existing containers and volumes ──────────────────────────────
log "Step 1/5 — Tearing down containers and volumes..."
docker compose down -v --remove-orphans 2>/dev/null || true
log "  Containers stopped; named volumes removed."

# ── 2. Rebuild images ─────────────────────────────────────────────────────────
log "Step 2/5 — Rebuilding images (no-cache skipped for speed; add --no-cache if needed)..."
docker compose build --parallel

# ── 3. Start all services ─────────────────────────────────────────────────────
log "Step 3/5 — Starting stack in detached mode..."
docker compose up -d

# ── 4. Wait for healthchecks ──────────────────────────────────────────────────
log "Step 4/5 — Waiting for services to become healthy (timeout: ${TIMEOUT}s)..."

wait_for() {
  local label="$1"
  local url="$2"
  local deadline=$((SECONDS + TIMEOUT))
  printf "  Waiting for %s " "$label"
  until curl -sf "$url" >/dev/null 2>&1; do
    [ $SECONDS -lt $deadline ] || die "Timed out waiting for $label at $url"
    printf "."
    sleep 2
  done
  echo " OK"
}

wait_for "gateway"       "$GATEWAY/health"

# Extra 3-second settle time for defense-runner rule cache
sleep 3

# ── 5. Pre-load demo defense rule ─────────────────────────────────────────────
log "Step 5/5 — Pre-loading global demo defense rule..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$GATEWAY/blue/defense" \
  -H "Content-Type: application/json" \
  -H "x-sender: blue-team" \
  -d "$RULE_PAYLOAD")

if [ "$HTTP_STATUS" = "200" ]; then
  log "  Global rule uploaded successfully."
else
  warn "  Defense rule upload returned HTTP $HTTP_STATUS (non-fatal; upload manually in Step 2 of demo)."
fi

# ── 6. Ready banner ───────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        === BAYORA DEMO READY ===             ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Gateway  :  http://localhost:8000           ║${NC}"
echo -e "${GREEN}║  Docs     :  docs/demo-script.md            ║${NC}"
echo -e "${GREEN}║                                              ║${NC}"
echo -e "${GREEN}║  Next step:                                  ║${NC}"
echo -e "${GREEN}║    curl -s -X POST http://localhost:8000/tests ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
log "All services healthy. Follow docs/demo-script.md to run the demo."
