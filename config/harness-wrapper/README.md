# Harness wrapper authentication Secret

The canonical Kustomize installer intentionally does **not** commit or generate
the shared bearer token. Before applying `deploy/orka.yaml` directly, create the
required Secret in `orka-system` without printing the token:

```bash
set -euo pipefail

kubectl create namespace orka-system --dry-run=client -o yaml | kubectl apply -f -
if ! kubectl -n orka-system get secret harness-wrapper-auth >/dev/null 2>&1; then
  openssl rand -hex 32 | \
    kubectl -n orka-system create secret generic harness-wrapper-auth \
      --from-file=token=/dev/stdin
fi

kubectl apply -f deploy/orka.yaml
```

`make deploy` performs the same preflight and creates the Secret only when it is
absent. Helm installs use the chart-managed Secret or
`workers.harnessWrapper.auth.existingSecret` instead.

## Coexistence controller wiring

The dual controller drives harness v1 turns through this wrapper when it runs
with `--agent-execution-ownership=coexistence` and the following environment
is present on the controller Deployment (the historical names):

```yaml
env:
  - name: ORKA_HARNESS_WRAPPER_ENDPOINT
    value: http://agent-harness-wrapper:8080
  - name: ORKA_HARNESS_WRAPPER_BEARER_TOKEN_FILE
    value: /var/run/orka/harness-wrapper/token
```

with the `harness-wrapper-auth` Secret mounted read-only at
`/var/run/orka/harness-wrapper`. The controller's drain protocol uses the
wrapper's bearer-authenticated `/v1/admin/close-admission` and
`/v1/admin/unsettled-turns` endpoints backed by the durable ledger PVC.
