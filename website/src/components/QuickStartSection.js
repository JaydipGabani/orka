import React from 'react';
import CodeBlock from '@theme/CodeBlock';
import Link from '@docusaurus/Link';

export default function QuickStartSection() {
  return (
    <section className="landing-section quickstart-section">
      <h2 className="section-title">Quick start</h2>
      <p className="section-subtitle">
        Install the latest release with one command, add an LLM key, and start
        creating tasks.
      </p>
      <div className="quickstart-grid">
        <div className="quickstart-card">
          <h3>Install the controller</h3>
          <p>
            CRDs, RBAC, controller, and the built-in dashboard. The manifest
            mounts a harness-wrapper-auth Secret without creating it, so make
            the namespace and that Secret first.
          </p>
          <CodeBlock language="bash">{`kubectl create namespace orka-system
kubectl -n orka-system create secret generic harness-wrapper-auth \\
  --from-literal=token="$(openssl rand -hex 32)"

kubectl apply -f https://raw.githubusercontent.com/orka-agents/orka/v0.1.3/deploy/orka.yaml

kubectl -n orka-system rollout status deploy/orka-controller-manager`}</CodeBlock>
        </div>
        <div className="quickstart-card">
          <h3>Add a provider &amp; open the dashboard</h3>
          <p>
            Store an LLM key as a Kubernetes Secret, register a Provider, then
            open the dashboard or point any OpenAI-compatible client at it.
          </p>
          <CodeBlock language="bash">{`kubectl -n orka-system create secret generic anthropic-secret \\
  --from-literal=api-key=your-api-key

kubectl port-forward -n orka-system svc/orka-api 8080:8080
# open http://localhost:8080`}</CodeBlock>
        </div>
      </div>
      <p className="section-subtitle">
        Running coding agents such as Codex or Claude Code on the ACP runtime path
        needs a build from{' '}
        <code>main</code> — see{' '}
        <Link to="/docs/getting-started">Getting started</Link> and{' '}
        <Link to="/docs/release-status">Release status</Link>.
      </p>
    </section>
  );
}
