# Local report-validation and patch-verification fixtures

These are caller-controlled demonstrations. The CLI scripts here use
`executionBackend: local-docker`; their Task objects are local projections,
not Kubernetes workloads. The default CLI uses the real integrated source
preparer and Docker observer. There is no mock-success CLI mode.

The separate [Kubernetes conformance driver](../../scripts/patch_verification_kube_conformance.py)
reuses these fixtures through the authenticated API, actual Orka Tasks and
Jobs. See [Kubernetes and AKS operation](../../website/docs/operations/patch-verification.md).
The checks use private `$TMPDIR` paths so both backends can run the same scripts.

The problem is an order quantity accepted outside 1 through 100. Every request
has a healthy normal case (5) and two problem variations (-1 and 101). Go uses
`go test`, C compiles a separate trusted test driver with `gcc`, and HTTP checks
the client plus independently captured service requests. All use the same CLI,
manifest, source preparation, runner, evaluator, and persistence workflow.

The additional `config` project models a configuration manager, tests effective
policy after install/reconcile/restart and retained-state upgrade, and captures
requests at the independent HTTP fixture. It is a process model, not proof about
a real controller or cluster. Explicitly requiring those environments produces
an action-appropriate Unable result without executing workloads.

| Patch | Expected conclusion |
| --- | --- |
| fixed | Verified for these checks |
| notfixed | Not fixed |
| partial | Partially fixed |
| regression | Introduces a regression |
| temporary (config only) | Partially fixed: installation override is undone by reconciliation/restart |

Requirements: Linux, Git, util-linux `/usr/bin/prlimit`, Bash, jq, native Docker,
the repository's Go toolchain, and this preinstalled image:
`golang@sha256:116489021a0d8ca3facf79f84ee69052cff88733547150a644d45c5eaa91dc43`.
No script downloads executables or dependencies. Set `PATCHVERIFY_PLATFORM` only
to the native `linux/amd64` or `linux/arm64` platform supported by that image.
The two-action 58-scenario matrix passed on amd64 with the v3 socket-activation profile.
Earlier v2 records remain separate; never reinterpret them as v3 evidence.
Arm64 has not been live-tested.

From the checkout root:

```sh
go build -o bin/patchverify ./cmd/patchverify
request=$(bash examples/patch-verification/demo.sh go fixed)
db_dir=$(mktemp -d /tmp/patchverify-evidence.XXXXXX)
go run ./cmd/patchverify start --request "$request" --db "$db_dir/evidence.db"
```

The generator copies only the small fixture source into a new `/tmp` repository,
disables user Git configuration and hooks, creates an original fixture commit,
checks the selected patch, and emits the request path. Relative paths in that
request resolve against its directory. Nothing is committed to this checkout.
Requests and fixture repositories are preserved for inspection; delete them
explicitly after their runs finish. Put the evidence DB in a separate directory.

Use `c`, `http`, or `config` instead of `go`, and any patch in the table. An optional third
argument `commit` applies the patch and creates a second disposable commit, then
puts both exact SHAs in the request. The default `patch` mode binds the original
SHA and patch file. No symbolic revision is passed to `start`.

```sh
request=$(bash examples/patch-verification/demo.sh c partial commit)
go run ./cmd/patchverify start --request "$request" --db "$db_dir/evidence.db"
```

### Validate without a patch

The fourth generator argument selects the action. Report-only generation does
not read/apply a patch or create a patched commit:

```sh
request=$(bash examples/patch-verification/demo.sh go fixed patch validate-report)
bin/patchverify start --request "$request" --db "$db_dir/evidence.db"
```

Reports finish as Reproduced, Not reproduced under these conditions, or Unable
to validate. Non-reproduction does not prove the report is wrong. When a patch
arrives, submit `action: verify-patch`, an `earlierValidation` run ID, one patch
input, and `declaredChanges` to the same private DB. Saved checks/setup are restored,
all original checks run again, and the earlier result stays unchanged. See the
[linked example](../../docs/design/patch-verification-poc.md#reproduction).

New verification requests explicitly declare source/configuration/dependency/
deployment/permission changes. `requiredEnvironment` names process/local-service
needs or unsupported cluster/controller/external-service/test-identity needs.
Local file ownership and permissions authorize access; production principal-based
link authorization remains part of the planned API integration.

### HTTP confinement

HTTP uses `local-services`, one fixture on TCP 18080, and no external network.
It requires enabled Landlock TCP ABI >= 4 (Linux 6.7+ is necessary but not
sufficient), Docker seccomp support including inherited BPF via `prctl`, IPv6
dual-stack loopback support, and an operator-trusted static non-PIE native
launcher. Build the runner helper from the trusted checkout,
never from the project under test:

```sh
mkdir -p bin
docker run --rm --pull never --network none --read-only \
  --user "$(id -u):$(id -g)" --cap-drop ALL \
  --security-opt no-new-privileges=true --memory 512m --pids-limit 128 \
  --tmpfs /tmp:rw,nosuid,nodev,size=67108864 \
  --mount "type=bind,src=$PWD/internal/patchverification/launcher,dst=/input,readonly" \
  --mount "type=bind,src=$PWD/bin,dst=/output" --entrypoint /usr/bin/gcc \
  golang@sha256:116489021a0d8ca3facf79f84ee69052cff88733547150a644d45c5eaa91dc43 \
  -static -O2 -Wall -Wextra -Werror -o /output/network-launcher /input/landlock.c
launcher_digest="sha256:$(sha256sum bin/network-launcher | cut -d ' ' -f 1)"
request=$(bash examples/patch-verification/demo.sh http fixed)
go run ./cmd/patchverify start --request "$request" --db "$db_dir/evidence.db" \
  --network-launcher "$PWD/bin/network-launcher" \
  --network-launcher-sha256 "$launcher_digest"
```

Pin that digest from the trusted build. Hashing an arbitrary supplied binary is
not a trust decision. Before executing the service, the launcher opens exactly one
dual-stack TCP listener on 18080 and provides `ORKA_LISTEN_FD=3`. The supplied
service adopts that descriptor; it never binds or listens itself. Its shell wrapper
keeps the descriptor out of compiler subprocesses. Both fixture and client are
then unable to bind or create additional listeners, and all Fast Open send variants
are denied. Fixtures cannot initiate outbound connections; clients may connect
only to declared ports. Datagram Unix socketpairs are unavailable in this profile.
There is no legacy-bind or IPv4-only fallback.

The service emits `ready` after adopting the socket, `reserve` for each request,
and closes the listener with exit zero on SIGTERM. Healthy rejected quantities
must not contact it. Subjects never inherit the service descriptor.
Missing confinement, setup failures, service stderr, or truncation are Unable.

### Iteration and evidence

Each generated request and each `start` is a new run, even for unchanged inputs.
Use the early run ID with `get`, `evidence`, `cancel`, and `recover` as described in
the [design plan](../../docs/design/patch-verification-poc.md). Keep the original
run for comparison; do not overwrite unfavorable evidence with later results.

Go/C drivers report bounded `healthy` or `broken` observations. They are trusted
demo adapters, not a generic attestation mechanism: arbitrary project code can
lie through output or process behavior. Frozen HTTP service effects are stronger
observations for this example but still cover only the specified cases.
Frozen checks preserve each helper's actual executable bit and are restaged
read-only. Script-like prose does not become executable or independent attestation.

### Full matrix

After building the CLI and trusted launcher, run:

```sh
matrix=$(mktemp -d /tmp/patchverify-matrix.XXXXXX)
bash examples/patch-verification/verify.sh go "$matrix"
bash examples/patch-verification/verify.sh c "$matrix"
bash examples/patch-verification/verify.sh http "$matrix"
bash examples/patch-verification/verify.sh config "$matrix"
bash examples/patch-verification/validate.sh go "$matrix"
bash examples/patch-verification/validate.sh c "$matrix"
bash examples/patch-verification/validate.sh http "$matrix"
bash examples/patch-verification/validate.sh config "$matrix"
```

The harness asserts direct patch/commit outcomes, report reproduction and
non-reproduction, named unsupported-environment results, and linked verification
without access to the earlier live checks. Quantity checks have three observations
per report and six per comparison; configuration has five and ten. The temporary
configuration override and missed state migration retain specific unfixed cases.
Earlier evidence is compared byte-for-byte after links. Databases and JSON records
remain in the chosen directory for inspection.
