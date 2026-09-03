---
description: "Install Orka on a Kubernetes cluster and run your first agent task."
---

# Getting started

Orka runs AI agents on Kubernetes. You describe work as a **Task**, and Orka runs it in
a Pod, keeps a durable record of what happened, and gives you the result over a REST API,
a CLI, or a built-in web dashboard.

The point is that the API keys stay in the cluster. Developers get a ServiceAccount token,
not an LLM key, and the platform team decides which models and providers are allowed.

## Mental model

Three custom resources cover most of what you will do:

| Resource | What it is |
| --- | --- |
| **Provider** | An LLM backend — Anthropic, OpenAI, or Azure OpenAI — plus the Secret holding its API key. |
| **Agent** | A reusable configuration: which Provider and model to use, a system prompt, which tools it may call. |
| **Task** | One unit of work. This is the thing you create to make something happen. |

A Task points at an Agent; an Agent points at a Provider.

There are three kinds of Task, and the difference matters because they run in different places:

- **`type: ai`** — Orka's own AI worker. It runs in a per-Task Kubernetes Job, calls the
  model, and can use built-in tools like web search and code execution.
- **`type: agent`** — a real coding-agent CLI (Codex, Claude Code, GitHub Copilot CLI, or
  OpenCode) running inside Orka. See [What ACP means](#what-acp-means) below.
- **`type: container`** — an arbitrary container command. No model involved. Useful for
  build and test steps that an agent needs done. See
  [Container tasks](guides/container-tasks.md) for the filesystem rules, which trip
  most people up the first time.

[Architecture](concepts/architecture.md) has the full component picture.

### What ACP means

ACP is the **Agent Client Protocol** — a JSON-RPC protocol that coding-agent CLIs speak
over stdin/stdout, so a program can drive them instead of a human typing at a terminal.
It is an external open protocol, not an Orka invention:
see [agentclientprotocol.com](https://agentclientprotocol.com).

Orka uses it to run agent CLIs as a service. Rather than starting a fresh container per
request, Orka keeps a pool of long-lived agent processes (a **RuntimePool**) and talks to
them over ACP. That is why `type: agent` Tasks start faster than a container would, and
why the docs talk about pools and sessions rather than Jobs.

Terms like *fence*, *epoch*, and *fail closed* show up throughout these docs.
The [Glossary](reference/glossary.md) defines all of them in one place.

## Prerequisites

- A Kubernetes cluster and a `kubectl` that can reach it. For a laptop,
  [kind](https://kind.sigs.k8s.io/) or [minikube](https://minikube.sigs.k8s.io/) is fine.
- An API key for at least one LLM provider (Anthropic, OpenAI, or Azure OpenAI).

That is all you need for the released install below. Running `type: agent` coding-agent
Tasks needs more — see [Installing from source](#option-b-current-main-from-source).

For building Orka yourself, see [Development](development/development.md) for the
toolchain versions.

## Install

There are two versions of Orka, and it is worth being clear about which one you are getting.

| | Latest release (v0.1.3) | `main` |
| --- | --- | --- |
| Install | One command, no clone | Build the images yourself |
| `type: ai` and `type: container` Tasks | Yes | Yes |
| Chat, gateways, repository monitors, security scanning | Yes | Yes |
| `type: agent` coding agents (ACP) | **No** | Yes |
| Harness modes, RuntimePools, workspace providers | **No** | Yes |

Most of these docs describe `main`. The v0.1.3 release predates the coding-agent work
entirely, so any page that mentions ACP, RuntimePools, or harness modes does not apply
to it. See [Release status](reference/release-status.md) for the full breakdown.

### Option A: latest release, one command

```bash
kubectl apply -f https://raw.githubusercontent.com/orka-agents/orka/v0.1.3/deploy/orka.yaml
```

That creates the `orka-system` namespace, the CRDs, RBAC, and the controller. Wait for it:

```bash
kubectl -n orka-system rollout status deploy/orka-controller-manager
```

Or with Helm:

```bash
helm repo add orka https://orka-agents.github.io/orka/charts
helm repo update
helm install orka orka/orka --version 0.1.3 \
  --namespace orka-system --create-namespace
```

Check [the tag list](https://github.com/orka-agents/orka/tags) for a newer version before
pinning to v0.1.3. The project publishes tags and chart artifacts; it does not currently
create GitHub Release entries, so the tags are the list to watch.

Then skip to [Your first task](#your-first-task).

### Option B: current `main`, from source

No container images are published from `main` — the release workflow only runs on `v*`
tags — so this path builds them locally. It is the right path if you want coding-agent
Tasks or you are developing Orka itself.

You will need, in addition to the prerequisites above:

- Go, Bun, and Docker — see [Development](development/development.md#prerequisites) for versions
- A **provider proxy**. Built-in coding agents never receive an LLM API key directly;
  all their model traffic goes through an authenticated proxy in front of
  [Vekil](operations/provider-proxy.md). Set that up first — the chart refuses to
  install without it.
- A TLS certificate for the admission webhooks, and a 32-byte encryption key for
  execution snapshots.

```bash
git clone https://github.com/orka-agents/orka.git
cd orka
make docker-build-all      # builds controller, workers, publisher, and the four agent runtimes
```

Load or push those images, then note the digests. The chart requires
`repository@sha256:...` references and rejects mutable tags, so that agent runtimes cannot
silently change under a running pool.

Claim a namespace for the install. The label is not optional — the controller checks it at
startup and exits if it is missing or does not match:

```bash
kubectl create -f - <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: orka-system
  labels:
    orka.ai/controller-mode: harness-v2
EOF
```

Create the two required Secrets. The snapshot key encrypts stored agent execution records;
keep it somewhere safe, because rotating it makes existing snapshots unreadable:

```bash
kubectl -n orka-system create secret generic orka-agent-snapshot-key \
  --from-literal=key="$(openssl rand -base64 32)"
```

Now the webhook certificate. The chart serves admission on the Service
`orka-webhook.orka-system.svc`, so the certificate has to name exactly that — a
certificate for any other name is rejected by the API server at admission time, not at
install time. For local evaluation a self-signed certificate is fine; use your own CA or
[cert-manager](https://cert-manager.io/) for anything real.

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout /tmp/webhook.key -out /tmp/webhook.crt \
  -subj "/CN=orka-webhook.orka-system.svc" \
  -addext "subjectAltName=DNS:orka-webhook.orka-system.svc,DNS:orka-webhook.orka-system.svc.cluster.local"

kubectl -n orka-system create secret generic orka-webhook-tls \
  --type=kubernetes.io/tls \
  --from-file=tls.crt=/tmp/webhook.crt \
  --from-file=tls.key=/tmp/webhook.key \
  --from-file=ca.crt=/tmp/webhook.crt
```

:::note[Why `ca.crt` is the certificate again]
The certificate is self-signed, so it is its own issuer. The chart reads `ca.crt` to build
the `caBundle` the API server uses to trust the webhook. With a real CA, `ca.crt` is that
CA's certificate instead.
:::

Install the chart. Use `manifest_staging/charts/orka` — that is the chart that matches
`main`. The `charts/orka` directory at the repo root is the snapshot of the last release
and is a generation behind:

```bash
WEBHOOK_CA_BUNDLE="$(kubectl -n orka-system get secret orka-webhook-tls -o jsonpath='{.data.ca\.crt}')"

helm install orka ./manifest_staging/charts/orka \
  --namespace orka-system \
  --set controller.mode=harness-v2 \
  --set controller.watchNamespace=orka-system \
  --set controller.image.repository=ghcr.io/orka-agents/orka \
  --set controller.image.digest=sha256:<controller-digest> \
  --set publisher.image.repository=ghcr.io/orka-agents/orka/workspace-publisher \
  --set publisher.image.digest=sha256:<publisher-digest> \
  --set controller.acpRuntime.codexImage=ghcr.io/orka-agents/orka/acp-codex-runtime@sha256:<digest> \
  --set controller.acpRuntime.claudeImage=ghcr.io/orka-agents/orka/acp-claude-runtime@sha256:<digest> \
  --set controller.acpRuntime.copilotImage=ghcr.io/orka-agents/orka/acp-copilot-runtime@sha256:<digest> \
  --set controller.acpRuntime.opencodeImage=ghcr.io/orka-agents/orka/acp-opencode-runtime@sha256:<digest> \
  --set-string controller.agentExecutionSnapshot.existingSecret=orka-agent-snapshot-key \
  --set-string controller.agentExecutionSnapshot.key=key \
  --set-string webhooks.tls.existingSecret=orka-webhook-tls \
  --set-string webhooks.caBundle="${WEBHOOK_CA_BUNDLE}" \
  --set providerProxy.enabled=true
```

You can leave out the four `acpRuntime` image lines. Any runtime you do not configure is
simply unavailable, and Tasks that ask for it fail with a clear error rather than falling
back to something else.

If Helm refuses to render, that is deliberate — the chart checks its inputs up front
rather than installing something broken. [Troubleshooting](operations/troubleshooting.md)
lists the guards and what each one wants.

:::info[Kustomize instead of Helm]
`make deploy` and the `config/acp-production` overlay install the same thing. Use that
overlay rather than `config/default`; it adds the network policy that stops model traffic
from bypassing the provider proxy. `make deploy` also creates the artifact, publisher, and
proxy Secrets for you.
:::

### Two installs on one cluster

Controller mode is fixed for the life of an install and cannot be changed by upgrading.
To run the older `harness-v1` contract alongside `harness-v2`, install it as a separate
release in a separate namespace. Tasks never move between them.
See [Harness modes](operations/harness-modes.md).

### Upgrades

Helm does not update CRDs on `helm upgrade` — that is a Helm behavior, not an Orka one.
Apply the CRDs from the target chart yourself first, every time.
[Upgrading](operations/upgrading.md) has the procedure.

## Give yourself an API client

The REST API authenticates with Kubernetes ServiceAccount tokens. The Helm chart creates
an `orka-client` ServiceAccount with the right permissions. If you installed with
Kustomize, create one yourself — [Upgrading and access](operations/troubleshooting.md#i-get-403-from-the-api)
shows the roles it needs.

```bash
kubectl port-forward -n orka-system svc/orka 8080:8080
export ORKA_TOKEN="$(kubectl -n orka-system create token orka-client)"
```

:::warning[Namespace matters]
Almost every command on this page needs `-n orka-system`. Orka watches exactly one
namespace, and resources created elsewhere are silently ignored — no error, they just
never run. `kubectl create token orka-client` fails the same way without it.
:::

## Your first task

### 1. Create a Provider

```bash
kubectl -n orka-system create secret generic anthropic-secret \
  --from-literal=api-key=your-api-key

kubectl apply -f - <<'EOF'
apiVersion: core.orka.ai/v1alpha1
kind: Provider
metadata:
  name: anthropic
  namespace: orka-system
spec:
  type: anthropic
  secretRef:
    name: anthropic-secret
    key: api-key
  defaultModel: claude-sonnet-4-20250514
EOF
```

### 2. Create an Agent

```bash
kubectl apply -f - <<'EOF'
apiVersion: core.orka.ai/v1alpha1
kind: Agent
metadata:
  name: assistant
  namespace: orka-system
spec:
  providerRef:
    name: anthropic
  model:
    temperature: 0.7
  systemPrompt:
    inline: "You are a helpful assistant."
EOF
```

### 3. Run a Task

```bash
kubectl apply -f - <<'EOF'
apiVersion: core.orka.ai/v1alpha1
kind: Task
metadata:
  name: hello-task
  namespace: orka-system
spec:
  type: ai
  agentRef:
    name: assistant
  prompt: "What is Kubernetes?"
EOF
```

### 4. Read the result

```bash
kubectl -n orka-system get task hello-task

curl -H "Authorization: Bearer ${ORKA_TOKEN}" \
  http://localhost:8080/api/v1/tasks/hello-task/result
```

If the Task never leaves `Pending`, see
[Troubleshooting](operations/troubleshooting.md#my-task-stays-pending).

### 5. Collect artifacts

Files a Task writes are retrievable once it finishes:

```bash
curl -H "Authorization: Bearer ${ORKA_TOKEN}" \
  http://localhost:8080/api/v1/tasks/hello-task/artifacts

orka task artifacts hello-task
orka task download hello-task output.json -o ./output.json
```

## Running a coding agent

This section needs an [Option B](#option-b-current-main-from-source) install.

A `type: agent` Task runs a real coding-agent CLI against a git repository. Orka clones the
repo, hands the agent a working copy, and records everything it does.

### 1. Check the provider proxy is up

Built-in agent runtimes never see a provider Secret. They get a token for Orka's proxy and
a specific model they are allowed to use; the real API key stays with
[Vekil](operations/provider-proxy.md). Confirm the `provider-auth-proxy` Deployment is
Ready before submitting agent Tasks.

### 2. Create an Agent with a runtime

```bash
kubectl apply -f - <<'EOF'
apiVersion: core.orka.ai/v1alpha1
kind: Agent
metadata:
  name: claude-agent
  namespace: orka-system
spec:
  model:
    name: claude-sonnet-4-20250514
  runtime:
    type: claude
    contractVersion: orka.harness.v2
    defaultMaxTurns: 50
    defaultAllowBash: true
    defaultAllowedTools: [Read, Write, Edit, Bash]
EOF
```

Two runtime-specific notes:

- **Codex** needs `defaultAllowBash: true`. The upstream Codex CLI has no reliable way to
  disable its shell, so Orka fails fast rather than pretending the restriction holds.
- **OpenCode** uses `provider/model` names such as `openai/gpt-5.4`, and requires
  `model.contextWindow` and `model.maxTokens`. Orka pins both into the pool so compaction
  limits do not shift when a catalog updates.

### 3. Run it

```bash
kubectl apply -f - <<'EOF'
apiVersion: core.orka.ai/v1alpha1
kind: Task
metadata:
  name: code-review
  namespace: orka-system
spec:
  type: agent
  agentRef:
    name: claude-agent
  prompt: "Review this repo for security issues. Do not modify files."
  workspace:
    intent: read
    gitRepo: "https://github.com/example/repo.git"
    branch: main
    # For a private repo. Only the clean-room publisher resolves this Secret —
    # the agent process never sees the credential.
    # readCredentialRef:
    #   name: repository-read
  agentRuntime:
    maxTurns: 20
EOF
```

### 4. Watch it

```bash
kubectl -n orka-system get task code-review
kubectl -n orka-system get runtimepools
orka task status code-review
```

[Agent runtimes](concepts/agent-runtimes.md) has the full configuration reference.

## Stronger isolation

If your cluster has `RuntimeClass` objects such as `gvisor` or `kata-qemu`, `ai` and
`container` Tasks can run through them via `spec.execution`. Set a default on the Agent and
override per Task. Coding-agent Tasks use RuntimePool resource profiles instead.
See [Configuration](reference/configuration.md#execution) and
[Security](concepts/security.md#execution-workloads).

## The dashboard

```bash
kubectl port-forward -n orka-system svc/orka 8080:8080
open http://localhost:8080
```

The UI ships inside the controller binary — there is nothing extra to deploy.
See [Web dashboard](guides/ui.md).

## The CLI

```bash
make build-cli
./bin/orka login                                  # reads your kubeconfig, opens a browser
./bin/orka login --server https://orka.example.com
./bin/orka login --token <token>
```

It can pull a token from a bearer token, a token file, exec-based auth (GKE, AWS IAM), or
an OIDC provider. Full command list: [CLI reference](reference/cli.md).

## Next steps

**Learn the pieces**

- [Glossary](reference/glossary.md) — every term these docs assume
- [Architecture](concepts/architecture.md) — how a Task becomes a Pod
- [Configuration](reference/configuration.md) — Helm values and controller flags
- [Security](concepts/security.md) — hardening, auth, and tenancy

**Do something with it**

- [Interactive chat](guides/chat.md) — talk to an orchestrator that creates Tasks for you
- [Container tasks](guides/container-tasks.md) — build and test steps that actually work
- [Multi-agent coordination](reference/multi-agent-coordination.md) — one agent delegating to several
- [Repository monitors](guides/repository-monitors.md) — automatic PR review queues
- [Scheduled tasks](guides/scheduled-tasks.md) — cron-driven agents

**Connect your own tools**

- [OpenAI-compatible API](reference/openai-compat.md) — Continue, Cursor, and similar
- [Anthropic-compatible API](reference/anthropic-compat.md) — Claude Code and similar
- [REST API](reference/api-reference.md)

**When it breaks**

- [Troubleshooting](operations/troubleshooting.md)
- [Operations runbook](operations/runbook.md)
