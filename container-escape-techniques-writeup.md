# Container Escape Techniques: From Theory to Detection

## Overview

This writeup summarizes research on container escape techniques in cloud environments. I reviewed the findings of Unit 42 researchers Yosef Yaakov and Bar Ben-Michael (July 2024) and translated them into actionable pentesting notes and detection guidance.

**Research source:** Unit 42 — Container Breakouts: Escape Techniques in Cloud Environments  
**Date:** 2026-06-23  
**Focus:** Cloud security, container escape, detection engineering

---

## What is a container?

Containers run application processes in an isolated user space while sharing the host kernel. Isolation is achieved via Linux namespaces, capabilities, cgroups, seccomp, and LSMs.

**Key difference from VMs:** no full OS virtualization, lighter weight, but weaker isolation.

---

## Why container escapes matter

Many internet-facing containers run with elevated privileges. An attacker who lands a low-privilege shell in a container will attempt escape via misconfigurations or known vulnerabilities. Successful escapes often represent a pivoting point in the attack chain.

Historical reference: CVE-2019-5736 (runC vulnerability) allowed attackers to gain root-level code execution on the host.

---

## Escape techniques reviewed

### 1. cgroup release_agent (User-Mode Helper)

**Concept:** Abuse `call_usermodehelper` via cgroup `release_agent` to execute a program as root on the host when the cgroup is emptied.

**Prerequisites:**
- Root inside container
- Writable cgroup mount

**Steps (high-level):**
- Create cgroup and set `notify_on_release`
- Point `release_agent` to attacker binary
- Empty cgroup by writing to `cgroup.procs`

**Detection:** Monitor `release_agent` writes and `call_usermodehelper()` calls. Cortex XDR demonstrated detection of this via deepce.sh activity.

**Impact:** Full host code execution as root.

---

### 2. SUID Bit on Shared File

**Concept:** If a container shares a directory with the host and runs in the same user namespace, a SUID binary created inside is executable as root on the host.

**Prerequisites:**
- Shared volume
- Same user namespace
- Host access to execute the binary

**Detection:** Monitor file creation, `chmod` adding SUID, and host execution of SUID files by non-root users.

**Impact:** Host privilege escalation without full container escape.

---

### 3. Runtime Socket Mount

**Concept:** If the container runtime socket (`/var/run/docker.sock` or equivalent) is mounted inside the container, an attacker can use it to create a new privileged container with host filesystem access.

**Example curl flow:**
- `curl --unix-socket /var/run/docker.sock http://localhost/containers/create`
- Start the malicious container

**Detection:** Unix socket access inside container, creation of new containers from inside, anomalous Docker API calls.

**Impact:** Full host compromise via privileged sibling container.

---

### 4. Kubernetes Log Mount

**Concept:** Pods with `/var/log` mounted from host can abuse kubelet’s symlink handling to read arbitrary host files.

**Prerequisites:**
- `/var/log` host mount
- Service account / kubectl with log read access

**Steps:**
- Create symlink in /var/log pointing to `/` or sensitive directory
- Use `kubectl logs` to read through symlink

**Detection:** K8s API log read requests with abnormal paths; host-side symlink changes.

**Impact:** Arbitrary host file read as root.

---

### 5. Sensitive Mount

**Concept:** If sensitive host directories (`/etc`, `/proc`, etc.) are bind-mounted into a container, the attacker can read or modify host files directly.

**Prerequisites:**
- Misconfigured volume mounts

**Detection:** Convert container paths to host paths; alert on access to sensitive files from container context.

**Impact:** Host file read/write, depending on mount type.

---

## Detection Engineering Perspective

Unit 42 emphasizes layered detection:

1. **Syscall / kernel activity:** `call_usermodehelper`, `chmod`, file writes to sensitive paths
2. **Container runtime API:** unusual Docker/containerd requests from inside containers
3. **Kubernetes audit logs:** log reads with non-standard paths
4. **File integrity monitoring:** `release_agent`, symlink creation, SUID creation
5. **EDR causality chains:** parent-child process relationships showing container → host abuse

---

## Mitigation Recommendations

- Drop all capabilities by default
- Read-only root filesystem
- `no_new_privs: true`
- Seccomp profiles limiting syscalls
- Do not mount runtime sockets
- Do not mount host `/var/log`, `/etc`, or `/proc`
- Use AppArmor/SELinux
- Runtime: use minimal, non-root images
- Cloud: enable Prisma Cloud / Cortex XDR agent coverage

---

## Personal Takeaways

1. I will add container escape detection logic to my SOC automation playbooks.
2. In future pentests involving containers, I will check:
   - Capabilities (`cap_sys_admin`, `cap_sys_ptrace`, `cap_sys_chroot`)
   - Mounted sockets
   - Writable cgroup and release_agent
   - Sensitive host mounts
   - Shared volumes with suid bits
3. This research directly applies to cloud/K8s pentesting exams and bug bounty programs (e.g., Kubernetes escapes, Docker misconfigurations).

---

*Writeup prepared for portfolio review and interview discussion.*
