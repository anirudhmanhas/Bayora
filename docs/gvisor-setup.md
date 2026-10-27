# gVisor (runsc) Host Setup Guide & Isolation Architecture
> **Bayora POC: Secure Adversarial AI Testing Infrastructure**
> Target Platform: Linux (Ubuntu 22.04+ / Debian 12+) with Docker Engine

---

## 1. Overview of gVisor (`runsc`)

gVisor is an application kernel written in Go that implements a substantial portion of the Linux system call interface. It operates between containerized applications and the host Linux kernel, running as an OCI-compliant runtime named `runsc`.

### Security Boundary
In standard Docker containers (`runc`), container processes share the host Linux kernel directly, separated only by Linux namespaces, cgroups, and seccomp filters. A kernel vulnerability (e.g. privilege escalation via a flawed syscall handler or driver) compromises the entire host and all tenants.

Under gVisor (`runsc`):
- Every container runs inside its own **Sentry** (the user-space kernel).
- The Sentry intercepts application system calls and emulates them in user space.
- Only a minimal, heavily restricted set of host system calls (via **Gofer**) are ever sent to the real host kernel.
- Seccomp filters are applied on the Sentry itself, drastically reducing the attack surface.

---

## 2. Installation on a Linux Host

Follow these steps on your Linux host machine to install `runsc` and register it with the Docker daemon.

### Step 1: Install Dependencies
```bash
sudo apt-get update && sudo apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg
```

### Step 2: Add the gVisor GPG Key and APT Repository
```bash
# Add gVisor public signing key
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg

# Add the official repository to apt sources
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | \
    sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
```

### Step 3: Install `runsc`
```bash
sudo apt-get update && sudo apt-get install -y runsc
```

### Step 4: Verify Binary Installation
```bash
runsc --version
```

---

## 3. Register `runsc` in Docker Daemon Configuration

Docker must be configured to recognize `runsc` as a valid runtime.

### Step 1: Automatic Registration (Recommended)
You can run the built-in installer:
```bash
sudo runsc install
```
This automatically updates `/etc/docker/daemon.json` and configures the `runsc` runtime.

### Step 2: Manual Registration
Alternatively, edit or create `/etc/docker/daemon.json` with network passthrough enabled for Docker bridge networking compatibility:
```json
{
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc",
      "runtimeArgs": [
        "--network=host"
      ]
    }
  }
}
```

If you already have existing runtimes (e.g., `nvidia`), add `runsc` alongside them:
```json
{
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc",
      "runtimeArgs": [
        "--network=host"
      ]
    },
    "nvidia": {
      "path": "nvidia-container-runtime"
    }
  }
}
```

### Step 3: Restart Docker Daemon
```bash
sudo systemctl daemon-reload
sudo systemctl restart docker
```

### Step 4: Verify Docker Registration
Run:
```bash
docker info --format '{{json .Runtimes}}'
```
You should see `"runsc"` present in the output:
```json
{"runc":{"path":"runc"},"runsc":{"path":"/usr/bin/runsc"}}
```

Test running a gVisor sandboxed container:
```bash
docker run --rm --runtime=runsc alpine uname -a
```
The output should report Linux with a gVisor-specific banner (e.g. `#1 SMP Thu Jan 1 00:00:00 UTC 1970`).

---

## 4. Current Verification Status on Development Host

> [!IMPORTANT]
> **Honest Verification Notice**:
> The development environment used for building this codebase is running on a **Windows host with Docker Desktop Linux Engine** using default runtimes (`runc`, `nvidia`).
> 
> Because the host does not have `runsc` installed or registered in `/etc/docker/daemon.json`, **enforcement of seccomp profiles specifically under the `runsc` runtime could not be verified on this Windows development machine**.
>
> All seccomp profiles, read-only root filesystems, capability dropping, and `docker-compose.yml` configurations have been syntactically and structurally verified. To verify live execution under gVisor, deploy this project to a Linux host configured with `runsc` following the steps above and execute `./docs/verify-isolation.sh`.
