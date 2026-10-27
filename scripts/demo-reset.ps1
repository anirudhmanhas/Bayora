# =============================================================================
# scripts/demo-reset.ps1
# One-command Bayora demo environment reset (Windows PowerShell)
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\scripts\demo-reset.ps1
#   $env:GROQ_API_KEY = "gsk_..."; powershell -ExecutionPolicy Bypass -File .\scripts\demo-reset.ps1
#
# What it does:
#   1. Tears down all containers and named volumes (clean slate)
#   2. Rebuilds all images from source
#   3. Starts the full stack in detached mode
#   4. Waits for gateway healthcheck
#   5. Pre-loads a global demo defense rule
#   6. Prints a READY banner
# =============================================================================

# In PowerShell, keep Continue so native commands writing to stderr (like Docker progress) do not halt execution
$ErrorActionPreference = "Continue"

$GATEWAY   = "http://localhost:8000"
$TIMEOUT_S = 120

$RULE_PAYLOAD = @{
    default_action = "allow"
    rules = @(
        @{
            name      = "block-jailbreak-keyword"
            target    = "all"
            action    = "block"
            patterns  = @("jailbreak")
            threshold = 1
        }
    )
} | ConvertTo-Json -Depth 5

function Write-Step($msg) { Write-Host "[demo-reset] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[demo-reset] $msg" -ForegroundColor Yellow }
function Fail($msg)        { Write-Host "[demo-reset] FATAL: $msg" -ForegroundColor Red; exit 1 }

# --- 0. Preflight ---
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Fail "docker not found in PATH" }
if (-not (Test-Path "docker-compose.yml")) { Fail "Run this script from the Bayora repo root" }

# --- 1. Tear down containers + volumes ---
Write-Step "Step 1/5 - Tearing down containers and volumes..."
& docker compose down -v --remove-orphans
if ($LASTEXITCODE -ne 0) {
    Write-Warn "docker compose down returned non-zero (non-fatal, continuing)..."
} else {
    Write-Step "  Containers stopped; named volumes removed."
}

# --- 2. Rebuild images ---
Write-Step "Step 2/5 - Rebuilding images..."
& docker compose build --parallel
if ($LASTEXITCODE -ne 0) { Fail "Docker build failed" }

# --- 3. Start all services ---
Write-Step "Step 3/5 - Starting stack in detached mode..."
& docker compose up -d
if ($LASTEXITCODE -ne 0) { Fail "Docker compose up failed" }

# --- 4. Wait for gateway healthcheck ---
Write-Step "Step 4/5 - Waiting for gateway to become healthy (timeout: ${TIMEOUT_S}s)..."
$deadline = [DateTime]::Now.AddSeconds($TIMEOUT_S)
$ready = $false
Write-Host -NoNewline "  Polling "
while ([DateTime]::Now -lt $deadline) {
    try {
        $resp = Invoke-WebRequest -Uri "$GATEWAY/health" -UseBasicParsing -TimeoutSec 3 -ErrorAction SilentlyContinue
        if ($resp -and $resp.StatusCode -eq 200) { $ready = $true; break }
    } catch { }
    Write-Host -NoNewline "."
    Start-Sleep -Seconds 2
}
Write-Host " OK"
if (-not $ready) { Fail "Gateway did not become healthy within ${TIMEOUT_S}s" }

# Extra settle time for defense-runner rule cache
Start-Sleep -Seconds 3

# --- 5. Pre-load demo defense rule ---
Write-Step "Step 5/5 - Pre-loading global demo defense rule..."
try {
    $uploadParams = @{
        Uri             = "$GATEWAY/blue/defense"
        Method          = "Post"
        ContentType     = "application/json"
        Headers         = @{ "x-sender" = "blue-team" }
        Body            = $RULE_PAYLOAD
        UseBasicParsing = $true
        ErrorAction     = "Stop"
    }
    $uploadResp = Invoke-WebRequest @uploadParams
    Write-Step "  Global rule uploaded (HTTP $($uploadResp.StatusCode))."
} catch {
    Write-Warn "  Defense rule upload failed (non-fatal; upload manually in Step 2 of demo)."
    Write-Warn "  Error: $_"
}

# --- 6. Ready banner ---
Write-Host ""
Write-Host "+----------------------------------------------+" -ForegroundColor Green
Write-Host "|          === BAYORA DEMO READY ===           |" -ForegroundColor Green
Write-Host "+----------------------------------------------+" -ForegroundColor Green
Write-Host "|  Gateway  :  http://localhost:8000           |" -ForegroundColor Green
Write-Host "|  Docs     :  docs/demo-script.md             |" -ForegroundColor Green
Write-Host "|                                              |" -ForegroundColor Green
Write-Host "|  Next step (PowerShell):                     |" -ForegroundColor Green
Write-Host "|    Invoke-RestMethod -Method Post            |" -ForegroundColor Green
Write-Host "|      http://localhost:8000/tests             |" -ForegroundColor Green
Write-Host "+----------------------------------------------+" -ForegroundColor Green
Write-Host ""
Write-Step "All services healthy. Follow docs/demo-script.md to run the demo."
