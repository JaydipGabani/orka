# Local Docker Runner

This is the local Docker execution backend for the supplied-patch verification
POC. Source preparation, CLI supervision, and persistence are separate components.
It does not dispatch production Tasks or Kubernetes workloads.

## Caller API

Existing signatures remain unchanged:

```go
func ResolveImage(ctx context.Context, image, platform string) (Environment, error)
func (runner DockerRunner) ResolveImage(ctx context.Context, image, platform string) (Environment, error)
func (runner DockerRunner) RunCheck(ctx context.Context, manifest Manifest, binding Binding, side string, check Check, sourceDir, checksDir string) (ExecutionEvidence, error)
```

New configuration and API:

```go
DockerRunner{
    LauncherPath:   trustedAbsoluteExecutablePath,
    LauncherDigest: "sha256:<64 lowercase hex characters>",
}

func (runner DockerRunner) FreezeEnvironment(environment Environment) (Environment, error)
const DockerRunnerPolicyVersion = "local-docker-v3-socket-activation"
```

`ResolveImage` now freezes the offline policy automatically. To use local services:

1. Resolve an already-installed digest-pinned image with `runner.ResolveImage`.
2. Set `environment.Profile = LocalServices` and its frozen `Services`.
3. Call `runner.FreezeEnvironment(environment)` and use the returned environment.
4. Finish and freeze the manifest, then compute its digest and independent binding.
5. Call `RunCheck` with the same trusted launcher configuration and staged inputs.

`FreezeEnvironment` clones the dependency map, preserves other dependency entries,
and sets these reserved identities inside the manifest:

| Key | Value |
| --- | --- |
| `orka.local-runner.policy` | `local-docker-v3-socket-activation` |
| `orka.local-runner.seccomp` | SHA-256 of the exact generated seccomp profile |
| `orka.local-runner.launcher` | Trusted executable SHA-256; local-services only |

`RunCheck` rejects absent/stale policy identities, launcher mismatches, or a profile
change without refreezing. New executions require a newly frozen manifest. Existing
stored manifests, observations, and seals retain their recorded policy identities;
do not rewrite old evidence as v3 results. This is a versioned runner-policy binding,
not remote attestation of the host or Docker daemon.

The CLI requires `--network-launcher` and `--network-launcher-sha256`
for `local-services`. Treat both as trusted operator configuration, not project or
manifest-controlled command options. The digest uses the `sha256:...` format.
Call `FreezeEnvironment` before computing the manifest digest. Store APIs are unchanged.

## Required Preparation

- Native Linux Docker on the requested `linux/amd64` or `linux/arm64` platform,
  through a trusted local Unix socket; no QEMU fallback or remote daemon.
- Kernel Linux 6.7 or newer, enabled Landlock LSM with ABI >= 4 and TCP network
  restrictions. Kernel version alone is insufficient. Host and container policies
  must permit `landlock_create_ruleset`, `landlock_add_rule`, and
  `landlock_restrict_self`.
- Docker seccomp support, recognition of those Landlock syscall names, cgroup CPU,
  memory/swap and PID limits, init support, and the pinned image already installed.
- IPv6 dual-stack support, including IPv6 loopback in the owned network namespace.
  Fixture activation requires an `AF_INET6` socket with `IPV6_V6ONLY=0`; there is
  no IPv4-only or unconfined fallback.
- Permission to install an inherited seccomp BPF filter using
  `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)` under no-new-privileges.
- A trusted native **static, non-PIE ELF** launcher compiled from
  `launcher/landlock.c`, independently pinned by SHA-256. It must be a regular
  executable, not a symlink, at most 8 MiB, and outside both staged input trees.
  Its path must be absolute and canonical, without commas or control characters.
- The tool image needs `/usr/bin/env`, the interpreters/tools used by the frozen
  checks, and all dependencies preinstalled. Fixtures must consume the inherited
  TCP listening descriptor described below, close/drain it on SIGTERM, and exit zero.

These prerequisites were exercised on Linux `6.17.0-1022-azure`, Landlock ABI 7,
Docker `28.2.2`, native `linux/amd64`. Native arm64 is implemented but was not live
tested here. No fallback permits unrestricted loopback when preparation is missing.

Build the helper from the trusted runner checkout, never from the project being
verified. The following uses the locally available pinned Go/gcc image, without
network access, elevated capabilities, or new dependencies:

```sh
mkdir -p bin
docker run --rm --pull never --network none --read-only \
  --user "$(id -u):$(id -g)" --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --memory 512m --pids-limit 128 \
  --tmpfs /tmp:rw,nosuid,nodev,size=67108864 \
  --mount "type=bind,src=$PWD/internal/patchverification/launcher,dst=/input,readonly" \
  --mount "type=bind,src=$PWD/bin,dst=/output" \
  --entrypoint /usr/bin/gcc \
  golang@sha256:116489021a0d8ca3facf79f84ee69052cff88733547150a644d45c5eaa91dc43 \
  -static -O2 -Wall -Wextra -Werror \
  -o /output/network-launcher /input/landlock.c
sha256sum bin/network-launcher
```

Pin the resulting digest through the trusted operator configuration. Computing a
digest of an arbitrary project-supplied executable does not establish trust. No
compiled binary is part of this change; live tests build into temporary directories.

## Enforced Network Contract

Every local-service run uses an owned Docker `--network none` anchor. Offline
checks each use their own network-none namespace without an anchor. These have
only loopback, no bridge, published port, host networking, or egress. A trusted launcher must install
Landlock and its inherited bind/listen deny filter successfully and emit its
private readiness marker before any fixture
starts. All workload processes run as UID/GID 65532, with all capabilities dropped,
no-new-privileges, a read-only root, bounded writable tmpfs, and a default-deny
seccomp profile. The actual Docker command, seccomp JSON, no-new-privileges, mounts,
image identity, capability restrictions, and resource configuration are inspected.

| Process | Inherited listener | New bind/listen | TCP connect |
| --- | --- | --- | --- |
| Trusted namespace anchor | None | Denied | None |
| Each fixture | Exactly its own declared port | Denied | None |
| Check and all descendants | None | Denied | Declared service ports only |

There may be at most eight distinct service ports, each in 1024-65535. Each fixture
launcher accepts exactly one `--bind-tcp` port and `--connect-tcp -`; multi-port
fixture requests are rejected. The subject uses `--bind-tcp -` and may connect only
to declared ports. A client's implicit ephemeral source port on `connect` is
supported, but every subsequent `bind` and `listen` syscall is denied, including
implicit listening endpoints and explicit port 0. IPv4, IPv6, and IPv4-mapped IPv6
use the same kernel-enforced policy. A declared
destination port does not grant external connectivity because the namespace has
no external interface or route.

After closing all inherited non-stdio descriptors, the trusted static launcher
opens, binds, and listens on one dual-stack `AF_INET6` socket at `::` for a fixture.
It alone sets `ORKA_LISTEN_FD=3`, then installs the irreversible inherited seccomp
filter before `execv`. The fixture must adopt descriptor 3 without calling `bind`
or `listen`, mark it close-on-exec after adoption, and keep it out of unrelated
subprocesses. No subject or anchor receives a listener or this environment value.
Readiness output does not grant listening authority; the descriptor is already
bound to the exact declared port by the launcher.

Seccomp permits Internet sockets only for `SOCK_STREAM` with protocol 0 or TCP,
including NONBLOCK/CLOEXEC flags. UDP, raw sockets, SCTP, packet/netlink sockets,
independent Unix sockets (including abstract sockets), and socket-family bypasses
are denied. Local Unix `socketpair` is restricted to `SOCK_STREAM`, with
NONBLOCK/CLOEXEC flags allowed; datagram and sequenced-packet pairs are denied.
`MSG_FASTOPEN` is denied on `sendto`, `sendmsg`, and `sendmmsg`, since these flags
can initiate connections without Landlock's connect hook. Ordinary sends remain
available on permitted connected sockets.
The offline profile is unchanged: no Internet sockets, ordinary Unix IPC allowed.
Namespace creation/join, io_uring, ptrace and other existing bypass exclusions stay
denied. No capabilities, privileged mode, firewall installation, or host networking
are required.

External DNS is not available. Docker's resolver is loopback-only; TCP port 53 is
undeclared and UDP cannot be created. Local hosts-file lookups such as `localhost`
are not external DNS. Fixtures should use numeric loopback addresses.

Landlock and seccomp restrictions survive fork/exec and cannot be widened by
invoking the launcher again or stacking an allow-all filter. Re-exec closes the
inherited listener; attempting to activate another listener fails closed. A
no-listener re-exec cannot regain the descriptor. Unavailable confinement exits
125 before executing a script; missing dual-stack activation has an explicit
prerequisite diagnostic, never an unconfined execution.

## Frozen Inputs and Evidence

Every `manifest.Files` entry must match its staged file's actual size, SHA-256,
and executable bit, including helpers and non-executable data. `FrozenFile` has an
`Executable bool` field serialized as `executable,omitempty`. Source freezing
records the actual mode bit for every file; restaging uses exactly `0555` for
executables and `0444` otherwise, not just the top-level command's mode. Mode-only
changes alter the manifest digest and mismatched staged modes are rejected.
Omitted false preserves historical JSON canonicalization and hashes. File content,
including a shebang or test prose, does not confer executable or check authority.
Missing/extra files, symlinks, special files, and
undeclared directories are rejected. Executable commands must name declared files
under `/checks`. Both inputs must be separate canonical directories outside Git
worktrees, with no Git metadata or special files.

After validation, the runner stages checks from the deep-copied manifest bytes and
the verified launcher bytes in its own temporary tree. It mounts those snapshots
read-only, not the caller's original check or launcher files. Changes to the caller
paths after validation cannot replace executed bytes. Fixture containers have no
source mount and no shared writable filesystem/PID namespace with the subject.

**Source preparation is still a caller trust boundary.** The parent must verify
each source tar's `ArchiveDigest` and corresponding `Tree` against the frozen
manifest, safely extract it outside Git worktrees, and keep that private staged
source immutable until `RunCheck` returns. Enforce archive traversal, link, special
file and resource limits in the parent source preparer. The runner neither hashes
a live repository nor re-derives Git tree/archive identities from `sourceDir`.
Supplying an arbitrary directory with a claimed tree hash is not verified source
acquisition. The trusted host, Docker daemon, operator-selected helper, tool image,
and independent manifest/binding authority remain outside the hostile-project
boundary. Frozen files do not automatically become independent checks if selected
by the project being evaluated.

Subject stdout/stderr remain explicitly project-controlled reproduction evidence.
Fixture stdout is captured separately and cannot be replaced by subject output.
Any nonempty fixture stderr makes the result `SetupError`; it is never copied into
the blob map or the error text. Truncation remains an unusable result. Each retained
blob has an existing subject or service-stdout identity accepted by the store.

## Validation

Focused commands, from this runner worktree:

```sh
go test -race ./internal/patchverification -count=1
go vet ./internal/patchverification
ORKA_PATCH_VERIFY_DOCKER_TEST=1 go test -race ./internal/patchverification -run '^TestDockerLive' -count=1 -v
```

The live suite covers HTTP comparisons; declared/undeclared ports and per-fixture
roles; IPv4/IPv6/mapped IPv6; UDP/raw/SCTP/abstract sockets; external traffic on an
allowed port; TCP/UDP DNS denial; namespace/io_uring and re-exec attempts; stdout and
staged-file spoofing; unsupported confinement; service stderr/blob accounting;
readiness, shutdown, output limits, timeouts, cancellation; and offline Go/C builds.
Additional regressions cover implicit listeners in both roles; all three Fast Open
send variants over IPv4/IPv6; datagram socketpair disconnect/rebind; single-port
activation and missing IPv6; descriptor clearing on re-exec; and directly executable,
read-only external helpers. The unsafe syscall cases were reproduced inside owned
network-none containers before the fix and return `EPERM` under v3.
Tests assert removal of every owned runner and auxiliary container.

Native arm64 still requires live validation. Previous v2 matrix records are not
v3 evidence; rerun the matrix using a rebuilt trusted launcher and a newly frozen
manifest. Direct Go commands provide compile and runtime validation for worktrees
not indexed by the editor language service.
