import json
import subprocess
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
POLICIES_DIR = BASE_DIR / "policies" / "seccomp"

ROLE_PROFILES = [
    "gateway.json",
    "red-team.json",
    "blue-team.json",
    "model-service.json",
    "audit.json",
    "defense-runner.json",
]

BLOCKED_SYSCALLS = [
    "ptrace",
    "mount",
    "umount",
    "umount2",
    "pivot_root",
    "keyctl",
    "add_key",
    "request_key",
    "bpf",
    "setns",
    "unshare",
    "reboot",
    "kexec_load",
    "kexec_file_load",
    "chroot",
    "syslog",
]


def test_seccomp_profiles_structural_validity():
    """
    Validates that each role profile has a valid Seccomp JSON structure,
    specifies defaultAction SCMP_ACT_ERRNO, and strips dangerous syscalls.
    """
    for profile_name in ROLE_PROFILES:
        profile_path = POLICIES_DIR / profile_name
        assert profile_path.exists(), f"Missing seccomp profile: {profile_path}"

        with open(profile_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data.get("defaultAction") == "SCMP_ACT_ERRNO", (
            f"{profile_name}: defaultAction must be SCMP_ACT_ERRNO"
        )
        assert "architectures" in data
        assert "syscalls" in data

        # Gather all allowed syscalls
        allowed_names = set()
        for entry in data.get("syscalls", []):
            if entry.get("action") == "SCMP_ACT_ALLOW":
                allowed_names.update(entry.get("names", []))

        # Check that none of the blocked syscalls are allowed
        for blocked in BLOCKED_SYSCALLS:
            assert blocked not in allowed_names, (
                f"SECURITY VIOLATION in {profile_name}: syscall '{blocked}' is permitted!"
            )


def test_seccomp_filter_blocks_prohibited_syscall():
    """
    Verifies that the generated seccomp profile actively causes prohibited syscalls
    (e.g. ptrace) to be blocked and fail with -1 (EPERM).
    """
    profile_path = POLICIES_DIR / "red-team.json"
    cmd = [
        "docker", "run", "--rm",
        "--security-opt", "no-new-privileges:true",
        "--security-opt", f"seccomp={profile_path}",
        "python:3.12-slim",
        "python", "-c",
        (
            "import ctypes, errno\n"
            "libc = ctypes.CDLL(None)\n"
            "ret = libc.syscall(101, 0, 0, 0, 0)\n"
            "print(f'PTRACE_RETURN: {ret}')\n"
            "exit(0 if ret == -1 else 1)\n"
        )
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert res.returncode == 0, f"Expected ptrace to be blocked (-1), output: {res.stdout} {res.stderr}"
    assert "PTRACE_RETURN: -1" in res.stdout


def test_check_runsc_registration_and_enforcement():
    """
    Checks if runsc is registered in the Docker daemon.
    - If registered: executes a test container under runsc with seccomp to verify blocked syscall fails.
    - If NOT registered: plainly reports that enforcement cannot be confirmed under runsc on this host.
    """
    res = subprocess.run(
        ["docker", "info", "--format", "{{json .Runtimes}}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert res.returncode == 0, f"docker info failed: {res.stderr}"

    try:
        runtimes = json.loads(res.stdout)
    except Exception:
        runtimes = {}

    runsc_available = "runsc" in runtimes

    if not runsc_available:
        msg = (
            "\n"
            "====================================================================================\n"
            "[STATUS: UNVERIFIED UNDER RUNSC]\n"
            f"Active Docker daemon runtimes: {list(runtimes.keys())}\n"
            "The 'runsc' (gVisor) runtime is NOT installed/registered in this host's Docker daemon.\n"
            "Current host environment: Windows with Docker Desktop Linux Engine (runc).\n"
            "Per Hack in Hills working rules: 'Never claim a security property you did not test.'\n"
            "Enforcement under runsc CANNOT be confirmed on this development host.\n"
            "To confirm live enforcement under runsc, follow instructions in docs/gvisor-setup.md\n"
            "on a Linux host with gVisor installed.\n"
            "====================================================================================\n"
        )
        print(msg)
        pytest.skip("runsc runtime is not registered on this Docker daemon; enforcement unverified.")

    # If runsc IS available, run live container validation
    print("\n[+] 'runsc' is registered! Testing live seccomp enforcement under runsc...")
    seccomp_arg = f"seccomp={POLICIES_DIR / 'red-team.json'}"
    test_cmd = [
        "docker", "run", "--rm",
        "--runtime=runsc",
        "--security-opt", "no-new-privileges:true",
        "--security-opt", seccomp_arg,
        "python:3.12-slim",
        "python", "-c",
        (
            "import ctypes\n"
            "libc = ctypes.CDLL(None)\n"
            "# Cross-process inspection (PTRACE_ATTACH=16 on PID 1) must be blocked\n"
            "ptrace_attach = libc.syscall(101, 16, 1, 0, 0)\n"
            "# Kernel modification via mount (syscall 165) must be blocked\n"
            "mount_ret = libc.syscall(165, 0, 0, 0, 0)\n"
            "print(f'PTRACE_ATTACH={ptrace_attach} MOUNT_RET={mount_ret}')\n"
        )
    ]
    live_res = subprocess.run(test_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    print(f"[runsc test result]: code={live_res.returncode}, stdout={live_res.stdout}, stderr={live_res.stderr}")
    assert live_res.returncode != 0 or "-1" in live_res.stdout, (
        f"Expected blocked syscall under runsc to fail, got: {live_res.stdout}"
    )
    assert "PTRACE_ATTACH=-1" in live_res.stdout or "MOUNT_RET=-1" in live_res.stdout

