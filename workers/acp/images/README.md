# Immutable ACP runtime images

These definitions build separate Codex, Claude, and GitHub Copilot ACP runtime
images. The build context must be the repository root so each image can compile
`cmd/orka-acp-runtime` and verify its duplicated supply-chain values against
`internal/acp/pins.go`.

The final images intentionally:

- run the Orka supervisor as root so it can create private session trees and
  launch each ACP child under a unique, non-reused UID/GID;
- contain no provider, controller, SCM, Git, or MCP credential;
- remove npm, npx, Corepack, and Yarn from the runtime image;
- contain no `git`, `ssh`, `curl`, or `wget` client;
- use `/sessions` as the writable session root and otherwise support a
  read-only root filesystem;
- rely on the supervisor's empty child-environment allowlist and provider
  update-disable controls;
- support only `linux/amd64` and `linux/arm64`.

Runtime credentials must be mounted as files and referenced through the
`ORKA_ACP_*_TOKEN_FILE` settings. Do not pass secrets as Docker build arguments,
labels, or environment defaults.

## Frozen inputs

Base images are immutable multi-platform manifest-list references:

| Input | Immutable reference |
| --- | --- |
| Dockerfile frontend | `docker/dockerfile:1.7.1@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e` |
| Go builder | `golang:1.26.2-bookworm@sha256:47ce5636e9936b2c5cbf708925578ef386b4f8872aec74a67bd13a627d242b19` |
| Node builder/runtime | `node:22.22.0-bookworm-slim@sha256:dd9d21971ec4395903fa6143c2b9267d048ae01ca6d3ea96f16cb30df6187d94` |

Codex inputs:

| Input | Pin |
| --- | --- |
| Codex ACP source | commit `307d81018f7cc0c3141ddf71c7532d38310e2cfb`; codeload archive SHA-256 `4d3cc46a901bdd4abf112e703e734078e09a172ecd535aa3e556318a051a7c39` |
| Codex ACP release | `1.1.7`; npm tar SHA-256 `642920240baa0b6b1951fb2c56b9ff11689648019499615f941000d95d127301` |
| Orka Codex ACP external-sandbox patch | `workers/acp/images/codex/patch-agent-mode.mjs`; SHA-256 `4b1fc39dc7ac0d6aa404030a3433f46c8b9c67e8e8223efca490a6ab8bf4287a` |
| Patched Codex ACP `dist/index.js` | SHA-256 `bcfb6a2772a7de2d027e977d9bc9db5fa210a462de1af7ab061361be4410cc75` |
| Codex CLI | `0.145.0`; source commit `25af12f7e61572b0bc18ddb1008be543b91519b0` |
| Codex CLI `linux/amd64` | npm tar SHA-256 `11239480f8e3efd1430f23bbe91c1a397856b8bbe6185ccbaee2382d25e03df2` |
| Codex CLI `linux/arm64` | npm tar SHA-256 `b78c57e172b2f18e5969ae26183253cd3cdd9abb3b424a8f7334f4b5530c2b27` |

Claude inputs:

| Input | Pin |
| --- | --- |
| Claude Agent ACP source | commit `c19bddcf7914259d6c15103a2d1580c7371e1d16`; codeload archive SHA-256 `e927898fd1b9d32a9a070c4217a89ba793c2baa1b03a4ffb509b13236333cf36` |
| Claude Agent ACP release | `0.61.0`; npm tar SHA-256 `bb410d53e2d13591da5ebcaf09ae055d166ffefb27b7172988650cd62ef4ebd3` |
| Claude Agent SDK | `0.3.217`; npm tar SHA-256 `20363761b29724950b749ecbc5186c46e29f2a0330554ca309a9e7ff8d6e5799` |
| Claude Code | `2.1.217`, carried by the SDK native package |
| Claude native `linux/amd64` | npm tar SHA-256 `8d2ccffbdf63aef1436a30b0fd32ef0eac663c3465318b181138471a68f02b92` |
| Claude native `linux/arm64` | npm tar SHA-256 `51080502df2942d2092c4a5b7122eda518041fbe954027a1e128ede3cb337563` |

GitHub Copilot inputs:

| Input | Pin |
| --- | --- |
| Copilot CLI | `1.0.77`; source commit `aee1edd29ef0f2058425bf399bcc9e5002a2b8f2` |
| Copilot CLI `linux/amd64` | official `copilot-linux-x64.tar.gz`; SHA-256 `c6414f99c5b29b049a3b0929ba824f0ff0ae88b85eb52559be45631b96b00f4c` |
| Copilot CLI `linux/arm64` | official `copilot-linux-arm64.tar.gz`; SHA-256 `5bcf01b30bd74ce415cc93acb404885e0bc396cde037ca68efe2b8ec84f91e5a` |
| Copilot CLI license | `LICENSE.md` at the pinned source commit; SHA-256 `1fbd0dcc55c66738b1b591632132c927de20c8443dff1d55b4851e378883e402` |

Copilot CLI `1.0.77` is newer than the `1.0.76-0` boundary that fixed
credentialless custom-provider session creation in ACP mode. Orka therefore
keeps the real upstream credential behind its provider proxy and starts
Copilot ACP sessions without GitHub login or an ACP authentication exchange.

Codex and Claude adapters are compiled from exact GitHub source archives after
frozen `package-lock.json` installs with `npm ci --ignore-scripts`. Their
unmodified adapter outputs must first byte-match separately checksum-verified
published npm releases. The Codex build then applies the checksum-pinned Orka
mode patch, rebuilds, and verifies the exact patched bundle digest. That mode
selects Codex's `externalSandbox` policy with restricted network so the
RuntimeSession and Pod security boundary is authoritative without nested
namespaces.

The Copilot image instead installs the unmodified official per-architecture
release executable. Its tar asset is checksum-verified, must contain exactly one
`copilot` entry, and is never downloaded at runtime. All final images perform no
package installation or network download.

## Build with the remote builder

Use the repository root as the final argument:

```bash
docker buildx build \
  --builder remote-vm \
  --platform linux/amd64,linux/arm64 \
  --file workers/acp/images/codex/Dockerfile \
  --tag docker.io/sozercan/orka-acp-codex:1.1.7-codex-0.145.0 \
  --provenance=mode=max \
  --sbom=true \
  --push \
  .
```

```bash
docker buildx build \
  --builder remote-vm \
  --platform linux/amd64,linux/arm64 \
  --file workers/acp/images/claude/Dockerfile \
  --tag docker.io/sozercan/orka-acp-claude:0.61.0-sdk-0.3.217 \
  --provenance=mode=max \
  --sbom=true \
  --push \
  .
```

```bash
docker buildx build \
  --builder remote-vm \
  --platform linux/amd64,linux/arm64 \
  --file workers/acp/images/copilot/Dockerfile \
  --tag docker.io/sozercan/orka-acp-copilot:1.0.77 \
  --provenance=mode=max \
  --sbom=true \
  --push \
  .
```

For a non-publishing verification build, replace `--push` and `--tag` with:

```bash
--output=type=cacheonly
```

After publishing, record the returned multi-platform image digest and sign that
immutable digest rather than a mutable tag.

## Runtime contract

Each image defaults only `ORKA_ACP_PROVIDER`. Deployment configuration must
supply the model, runtime-pool and controller fence, profile digests, workspace
intent, credential role/scope, and absolute Secret-mounted token-file paths.
Mount a writable volume at `/sessions`; do not rely on the image layer for
session durability. Kubernetes packaging must also enforce the read-only root
filesystem, no service-account token, default-deny egress, and only the
explicit supervisor capabilities needed for UID/GID and process management.

The images omit an SCM client on purpose. Clone and publication belong to the
separate clean-room Workspace/Publisher identity, not the ACP runtime process
tree.

## Licensing caveat

Orka's license and notice, adapter licenses, and provider license/notice files
are retained under `/usr/share/licenses` in the final images.

Codex ACP and the pinned Codex source are Apache-2.0. Claude Agent ACP is
Apache-2.0, but the Claude Agent SDK and bundled native Claude Code executable
are proprietary Anthropic artifacts whose package license says use is subject
to Anthropic's legal agreements. GitHub Copilot CLI is distributed unmodified
under the GitHub Copilot CLI License included in the image and in the repository
`NOTICE.md`. Building these Dockerfiles does not independently grant service or
provider access. Obtain legal approval for the intended distribution and
service model before pushing or sharing the Claude or Copilot images.
