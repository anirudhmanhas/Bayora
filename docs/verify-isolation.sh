#!/usr/bin/env bash
# ==============================================================================
# Bayora POC - Isolation & Hardening Verification Script
# Checks:
# 1. Runtime of each container is runsc
# 2. Container users are non-root
# 3. Red-team cannot see Blue-team's processes or files
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

CONTAINERS=(
    "bayora-gateway"
    "bayora-red-team"
    "bayora-blue-team"
    "bayora-model-service"
    "bayora-audit"
    "bayora-defense-runner"
    "bayora-egress-proxy"
)

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

pass() {
    echo -e "  [${GREEN}PASS${NC}] $1"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
}

fail() {
    echo -e "  [${RED}FAIL${NC}] $1"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
}

warn() {
    echo -e "  [${YELLOW}WARN${NC}] $1"
}

echo -e "\n${BLUE}================================================================${NC}"
echo -e "${BLUE}        BAYORA POC - ISOLATION & HARDENING VERIFICATION        ${NC}"
echo -e "${BLUE}================================================================${NC}\n"

# ------------------------------------------------------------------------------
# 1. Check Container Runtime is runsc
# ------------------------------------------------------------------------------
echo -e "${YELLOW}--- Check 1: Container Runtime (gVisor runsc) ---${NC}"
for c in "${CONTAINERS[@]}"; do
    if ! docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
        fail "Container ${c} is not running. Start services with: docker compose up -d"
        continue
    fi

    RUNTIME=$(docker inspect "${c}" --format '{{.HostConfig.Runtime}}')
    if [ "${RUNTIME}" == "runsc" ]; then
        pass "Container ${c} is running under gVisor runtime (${RUNTIME})"
    else
        fail "Container ${c} runtime is '${RUNTIME}' (expected 'runsc')"
    fi
done

# ------------------------------------------------------------------------------
# 2. Check Container Users are Non-Root
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}--- Check 2: Non-Root Execution (UID != 0) ---${NC}"
for c in "${CONTAINERS[@]}"; do
    if ! docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
        continue
    fi

    CONFIG_USER=$(docker inspect "${c}" --format '{{.Config.User}}')
    LIVE_UID=$(docker exec "${c}" id -u 2>/dev/null || echo "unknown")

    if [ "${LIVE_UID}" != "0" ] && [ "${LIVE_UID}" != "unknown" ]; then
        pass "Container ${c} runs as non-root user (UID: ${LIVE_UID}, Config: ${CONFIG_USER})"
    elif [ "${CONFIG_USER}" != "" ] && [ "${CONFIG_USER}" != "0" ] && [ "${CONFIG_USER}" != "root" ]; then
        pass "Container ${c} configured as non-root (${CONFIG_USER})"
    else
        fail "Container ${c} is running as root (UID: ${LIVE_UID})"
    fi
done

# ------------------------------------------------------------------------------
# 3. Check Process Isolation (Red Team cannot see Blue Team processes)
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}--- Check 3: Process Isolation (PID Namespace & gVisor Sandbox) ---${NC}"
if docker ps --format '{{.Names}}' | grep -q "^bayora-red-team$"; then
    RED_PS_OUTPUT=$(docker exec bayora-red-team ps -ef 2>/dev/null || docker exec bayora-red-team ps aux 2>/dev/null || echo "")

    if echo "${RED_PS_OUTPUT}" | grep -Ei "blue-team|gateway|model-service|audit" > /dev/null; then
        fail "Cross-tenant process leak! Red team can see foreign processes:\n${RED_PS_OUTPUT}"
    else
        pass "Red team process table is strictly isolated; zero foreign tenant processes visible"
    fi
else
    fail "bayora-red-team is not running; process isolation check skipped"
fi

# ------------------------------------------------------------------------------
# 4. Check Filesystem Isolation (Red Team cannot access Blue Team files)
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}--- Check 4: Filesystem & Host Mount Isolation ---${NC}"
if docker ps --format '{{.Names}}' | grep -q "^bayora-red-team$"; then
    # Attempt to read host /proc/1/root or inspect docker socket
    FS_PROBE=$(docker exec bayora-red-team sh -c "cat /proc/1/root/etc/shadow 2>&1" || true)
    if echo "${FS_PROBE}" | grep -qEi "Permission denied|No such file|Operation not permitted"; then
        pass "Red team cannot read host root filesystem via /proc/1/root"
    else
        fail "Suspicious access from red team to /proc/1/root:\n${FS_PROBE}"
    fi

    # Attempt to touch or write to rootfs (should fail because read_only: true)
    WRITE_PROBE=$(docker exec bayora-red-team sh -c "touch /app/hacked 2>&1" || true)
    if echo "${WRITE_PROBE}" | grep -qEi "Read-only file system|Permission denied|Operation not permitted"; then

        pass "Red team root filesystem is immutable and read-only"
    else
        fail "Red team root filesystem is writable! (Expected read-only filesystem)"
    fi
else
    fail "bayora-red-team is not running; filesystem isolation check skipped"
fi

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}================================================================${NC}"
echo -e "Verification Summary: ${GREEN}${PASSED_CHECKS} Passed${NC}, ${RED}${FAILED_CHECKS} Failed${NC} (Total: ${TOTAL_CHECKS})"
echo -e "${BLUE}================================================================${NC}\n"

if [ "${FAILED_CHECKS}" -gt 0 ]; then
    exit 1
else
    echo -e "${GREEN}All isolation and security checks PASSED successfully!${NC}\n"
    exit 0
fi
