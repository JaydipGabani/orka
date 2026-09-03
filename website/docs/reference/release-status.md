---
slug: /release-status
description: "What is in the latest tagged release versus what these docs describe."
---

# Release status

**These docs describe `main`.** The newest tagged release, **v0.1.3**, is older than a
large part of what is written here.

That gap is deliberate — `main` is where the current work lands — but it means you can
follow a page here exactly and get "unknown field" or "no matches for kind" from a v0.1.3
cluster. This page tells you which one you are on and what the difference is.

## Which one am I running?

```bash
kubectl -n orka-system get deploy orka -o jsonpath='{.spec.template.spec.containers[0].image}'
kubectl get crd -l app.kubernetes.io/name=orka --no-headers | wc -l
```

| CRDs | You have |
| --- | --- |
| 17 | v0.1.3 |
| 26 | a build from `main` |
| 12 | a stale `charts/orka/` snapshot from the repo root — see the warning below |

## What v0.1.3 does not have

The whole agent-runtime layer landed after v0.1.3 was cut. Missing there:

| | v0.1.3 | `main` |
| --- | --- | --- |
| Container tasks (`type: container`) | Yes | Yes |
| Native AI tasks (`type: ai`) | Yes | Yes |
| Chat and compatibility APIs | Yes | Yes |
| Repository monitors, scans, gateways | Yes | Yes |
| Coding agents over [ACP](glossary.md#running-coding-agents) (`type: agent`) | **No** | Yes |
| `RuntimePool` / `RuntimeSession` | **No** | Yes |
| `PromptAttempt`, `ControllerEpoch`, `Publication`, `BranchClaim`, `ExternalEffect` | **No** | Yes |
| `RuntimeProviderConfig`, `RuntimeWorkspaceProfile`, `RuntimeSessionControl` | **No** | Yes |
| [Harness modes](../operations/harness-modes.md) (`orka.ai/controller-mode`) | **No** | Yes |
| `--watch-namespace` | Optional; empty watches the whole cluster | **Required** |

Nine CRDs are new on `main`. If a page here mentions a `RuntimePool`, a supervisor, a
prompt attempt, or clean-room publication, it does not apply to v0.1.3.

## Installing v0.1.3

One command, no clone:

```bash
kubectl apply -f https://raw.githubusercontent.com/orka-agents/orka/v0.1.3/deploy/orka.yaml
```

Or with Helm:

```bash
helm repo add orka https://orka-agents.github.io/orka/charts
helm repo update
helm install orka orka/orka --namespace orka-system --create-namespace
```

Both are published by the release workflow, which runs only on a `v*` tag.

## Installing `main`

There is no published image for `main` — the release workflow is the only thing that
builds and pushes images, and it is tag-triggered. To run current features you build the
images yourself. [Getting started](../getting-started.md) has the full path.

:::warning[Do not install from `charts/orka/` or `deploy/orka.yaml` at the repo root]
Those are *promoted release snapshots*, refreshed only during release preparation. On
`main` today they hold a 12-CRD chart that is behind both v0.1.3 and `main`. It installs
without error and gives you a controller that crashes on startup.

Build from `manifest_staging/charts/orka/` instead — that is the chart regenerated from
current source by `make manifests`.
:::

## Version support

Orka is pre-1.0.

- CRD schemas may change between minor releases. Read the release notes before upgrading,
  and follow [Upgrading](../operations/upgrading.md) — Helm will not update CRDs for you.
- Only the latest release gets fixes. There are no patch backports to older tags.
- No release is supported for production use yet.

Release notes and assets: [github.com/orka-agents/orka/releases](https://github.com/orka-agents/orka/releases).
