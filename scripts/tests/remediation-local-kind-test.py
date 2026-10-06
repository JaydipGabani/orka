#!/usr/bin/env python3
"""Offline fixtures only: never connect to Docker, Kubernetes, registries, or models."""

import sys

sys.dont_write_bytecode = True

import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest import mock
import uuid


REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("remediation_local_kind", REPO / "scripts/remediation_local_kind.py")
bootstrap = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bootstrap
SPEC.loader.exec_module(bootstrap)
SENTINEL = "SYNTHETIC_PRIVATE_BYTES_DO_NOT_PRINT"


def uid(value):
    return str(uuid.UUID(int=value))


def image(name):
    return "localhost:5000/" + name + "@sha256:" + "a" * 64


def kubeconfig(context):
    return {"apiVersion": "v1", "kind": "Config", "current-context": context,
            "contexts": [{"name": context, "context": {"cluster": "fixture", "user": "fixture"}}],
            "clusters": [{"name": "fixture", "cluster": {"server": "https://127.0.0.1:6443",
                                                        "certificate-authority-data": "fixture-ca"}}],
            "users": [{"name": "fixture", "user": {"client-certificate-data": "fixture-client",
                                                  "client-key-data": SENTINEL}}]}


def obj(kind, name, identity, namespace="", lab_id="b" * 32):
    result = {"kind": kind, "metadata": bootstrap.metadata(name, lab_id, namespace or None)}
    result["metadata"]["uid"] = identity
    return result


class KindctlDerivationTests(unittest.TestCase):
    def derive(self, root, tag):
        result = subprocess.run(
            ["bash", "-c",
             'source "$1"\nkindctl_normalize_tag "$3"\nkindctl_derive_name_for_root_tag "$2" "$3"\n',
             "kindctl-derive-test", str(REPO / ".agents/skills/kindctl/bin/kindctl"), str(root), tag],
            cwd=REPO, capture_output=True, text=True, check=True, timeout=10,
        )
        return result.stdout.splitlines()

    def test_accepted_tags_match_actual_kindctl_derivation(self):
        for root in (REPO / "bin/derive-checkout", REPO / "bin/Repeated--Name_ABC", REPO / ("long-name-" * 9)):
            for tag in ("control", "new-subject", "a", "a-b2-c3-d4-e5-f6"):
                with self.subTest(root=root.name, tag=tag):
                    normalized, derived = self.derive(root, tag)
                    self.assertEqual(normalized, tag)
                    self.assertEqual(bootstrap.kind_name(root, tag), derived)

    def test_actual_kindctl_aliases_are_rejected_before_name_derivation(self):
        root = REPO / "bin/derive-checkout"
        for alias in ("new--subject", "control---lab"):
            normalized, derived = self.derive(root, alias)
            self.assertNotEqual(normalized, alias)
            self.assertEqual(derived, self.derive(root, normalized)[1])
            with self.subTest(alias=alias), self.assertRaises(bootstrap.Failure):
                bootstrap.kind_name(root, alias)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.base = REPO / "bin/remediation-local-kind-tests" / uuid.uuid4().hex
        self.base.mkdir(parents=True, mode=0o700)
        self.addCleanup(lambda: shutil.rmtree(self.base))
        self.worktree = self.base / "checkout"
        self.worktree.mkdir(mode=0o700)
        self.private = self.base / "private"
        self.private.mkdir(mode=0o700)
        self.store = self.base / "kind-store"
        self.store.mkdir(mode=0o700)
        environment = mock.patch.dict(os.environ, {"KINDCTL_STORE": str(self.store)})
        environment.start()
        self.addCleanup(environment.stop)
        # Test artifacts stay in this checkout's ignored bin/, never system temp.
        checkout = mock.patch.object(bootstrap, "inside_checkout", side_effect=lambda p:
                                     any(parent != REPO and (parent / ".git").exists() for parent in (p, *p.parents)))
        checkout.start()
        self.addCleanup(checkout.stop)
        self.source = self.private / "approved-policy.json"
        self.catalog = self.private / "catalog"
        self.catalog.mkdir(mode=0o700)
        self.catalog_file = self.catalog / "revision/recipe.yml"
        self.write(self.catalog_file, SENTINEL.encode())
        self.policy = {
            "policies": [{
                "version": 1, "name": "approved", "namespace": "control", "proposalBackend": "copilot-acp-v1",
                "maxCandidates": 3, "maxModelCalls": 8, "maxDurationSeconds": 3600,
                "allowRestrictedModel": True, "allowTestChanges": False, "requirePlanApproval": True,
                "copilot": {"image": image("copilot"), "identityReferences": [{"name": "approved-reference"}],
                            "proxyEndpoint": "http://model-proxy.gateway.svc:8080", "proxyNamespace": "gateway",
                            "runtimeNamespace": "runtime"},
                "repositories": ["keda"], "adapters": [{
                    "name": "keda", "kind": "dalec-keda-events", "repositories": ["keda"], "configuration": {
                        "capability": "keda-event-publishing-v2", "clusterUID": uid(1),
                        "kubeconfig": "/private/old/lab.kubeconfig", "context": "kind-old",
                        "probeImage": image("probe"), "requiredCapabilities": ["keda-event-publishing-v2"],
                        "requiredRequirements": ["approved-isolation"],
                        "controller": {
                            "enableEventPublishing": True, "DedicatedClusterApproved": True, "Bindings": [],
                            "ClusterIdentity": bootstrap.cluster_identity(uid(1)),
                            "APIServer": {"CIDR": "192.0.2.1/32", "Port": 6443},
                            "DNS": {"CIDR": "", "Port": 0}, "ObserverImage": image("observer"),
                            "Template": {"Source": {"Repository": "https://github.com/kedacore/keda", "Commit": "1" * 40},
                                         "ClusterWatchRole": {"name": "remediation-keda-watch", "uid": uid(2),
                                                              "resource": {"Group": "rbac.authorization.k8s.io",
                                                                           "Version": "v1", "Resource": "clusterroles"}}},
                        },
                        "buildEnvironment": {
                            "BuildKit": None, "ImageBindings": None, "AllowedGVKs": None,
                            "Isolation": {"ProbeImage": image("probe")}, "SyntheticScope": "controller-events",
                            "Kubernetes": {"Kubeconfig": "/private/old/lab.kubeconfig", "Context": "kind-old",
                                           "ObserverCIDRs": ["192.0.2.0/24"]},
                            "OutputRoot": "/private/old/output", "TemporaryRoot": "/private/old/scratch",
                            "Limits": {"MaxNamespaces": 4, "MaxActiveRuns": 1, "BuildTimeout": 1800000000000},
                            "BuildJobs": {
                                "Namespace": "remediation-builds", "WorkerImage": image("build-worker"),
                                "BuildKitAddress": "tcp://buildkit.remediation-builds.svc:1234",
                                "OutputRepository": "localhost:5000/approved-output", "WorkerArg": "",
                                "WorkerContext": "approved-worker", "Args": {}, "Limits": {"cpu": "2", "memory": "2Gi"},
                                "RegistrySecretName": "old-registry",
                                "TLS": {"caSecretName": "old-ca", "clientSecretName": "old-client",
                                        "serverName": "buildkit.remediation-builds.svc"},
                            },
                            "Repositories": [{
                                "ID": "keda", "RecipeRoot": str(self.catalog), "SourceRoot": "",
                                "Recipes": [{"ID": "approved-recipe", "CatalogDirectory": "revision", "Path": "recipe.yml",
                                             "Commit": "2" * 40, "Files": {"recipe.yml": "sha256:" + bootstrap.sha(SENTINEL.encode())},
                                             "FrontendImage": image("frontend"), "WorkerImage": image("worker"),
                                             "OriginalImage": image("original")}],
                            }],
                        },
                    },
                }],
            }],
        }
        self.config = {
            "version": 1,
            "control": {"tag": "control", "clusterUID": uid(10),
                        "controller": {"namespace": "control", "name": "controller", "uid": uid(11)},
                        "gateway": {"namespace": "gateway", "name": "model-proxy", "uid": uid(12)}},
            "subject": {"tag": "new-subject", "privateRoot": str(self.private / "new-subject"),
                        "podCIDR": "10.250.0.0/16", "serviceCIDR": "10.251.0.0/16"},
            "approved": {"policyFile": str(self.source), "policySHA256": "", "catalogRoot": str(self.catalog),
                         "crdsFile": str(self.private / "crds.json"), "crdsSHA256": "", "newPolicyName": "new-approved-policy"},
            "registry": {"container": "fixture-registry", "containerID": "c" * 64, "networkID": "d" * 64, "port": 5000,
                         "caFile": str(self.private / "registry-ca.crt"), "caSHA256": "",
                         "authFile": str(self.private / "registry-auth.json")},
            "ciliumChartFile": str(self.private / "cilium.tgz"), "buildkitPort": 1235,
        }
        self.bundle = {"apiVersion": "v1", "kind": "List", "items": [
            {"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition", "metadata": {"name": n},
             "spec": {"group": group, "names": {"plural": plural, "kind": kind}, "scope": scope,
                      "versions": [{"name": "v1alpha1", "served": True, "storage": True,
                                    "schema": {"openAPIV3Schema": {"type": "object"}}}]}}
            for n, (group, plural, kind, scope) in bootstrap.CRDS.items()
        ]}
        self.write_json(Path(self.config["approved"]["crdsFile"]), self.bundle)
        self.config["approved"]["crdsSHA256"] = bootstrap.sha(Path(self.config["approved"]["crdsFile"]).read_bytes())
        public_ca = b"-----BEGIN CERTIFICATE-----\nc3ludGhldGljLWZpeHR1cmU=\n-----END CERTIFICATE-----\n"
        self.write(Path(self.config["registry"]["caFile"]), public_ca)
        self.config["registry"]["caSHA256"] = bootstrap.sha(public_ca)
        self.auth = {"auths": {"localhost:5000": {"auth": base64.b64encode(("operator:" + SENTINEL).encode()).decode()}}}
        self.write_json(Path(self.config["registry"]["authFile"]), self.auth)
        self.write(Path(self.config["ciliumChartFile"]), b"synthetic-pinned-chart")
        chart = mock.patch.object(bootstrap, "CILIUM_CHART_SHA256", bootstrap.sha(b"synthetic-pinned-chart"))
        chart.start()
        self.addCleanup(chart.stop)
        self.config_file = self.private / "bootstrap.json"
        self.persist()
        no_process = mock.patch.object(bootstrap.subprocess, "run", side_effect=AssertionError("unexpected real subprocess"))
        no_process.start()
        self.addCleanup(no_process.stop)
        for operation in ("socket", "create_connection"):
            no_network = mock.patch.object(bootstrap.socket, operation, side_effect=AssertionError("unexpected real network"))
            no_network.start()
            self.addCleanup(no_network.stop)

    def write(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(data)
        path.chmod(0o600)

    def write_json(self, path, value):
        self.write(path, bootstrap.wire(value))

    def persist(self):
        self.write_json(self.source, self.policy)
        self.config["approved"]["policySHA256"] = bootstrap.sha(self.source.read_bytes())
        self.write_json(self.config_file, self.config)

    def load(self, **kwargs):
        return bootstrap.load_inputs(self.config_file, worktree=self.worktree, store=self.store, **kwargs)

    @property
    def adapter(self):
        return self.policy["policies"][0]["adapters"][0]["configuration"]

    def cli(self, *args):
        load = bootstrap.load_inputs
        output = io.StringIO()
        with mock.patch.object(bootstrap, "load_inputs", side_effect=lambda f, **kw: load(f, self.worktree, store=self.store, **kw)):
            with contextlib.redirect_stdout(output):
                status = bootstrap.main([*args, "--config", str(self.config_file)])
        self.assertNotIn(SENTINEL, output.getvalue())
        return status, json.loads(output.getvalue())

    def state(self, inputs):
        return {"owner": bootstrap.OWNER, "labID": "b" * 32, "planDigest": inputs.plan_digest, "phase": "needs-verification",
                "clusterUID": uid(20), "roleUID": uid(21), "nodeAddress": "192.0.2.20", "registryAddress": "192.0.2.30",
                "podCIDR": "10.250.0.0/24", "objects": [], "probes": [],
                "secrets": {"ca": "new-ca", "client": "new-client", "registry": "new-registry"}}


class InputTests(Fixture):
    def test_control_and_subject_tags_reject_kindctl_dash_aliases_offline(self):
        for target in ("control", "subject"):
            previous = self.config[target]["tag"]
            self.config[target]["tag"] = "new--subject"
            self.persist()
            with self.subTest(target=target), self.assertRaises(bootstrap.Failure):
                self.load()
            self.config[target]["tag"] = previous
            self.persist()

    def test_invalid_tagged_runtime_references_are_rejected_offline(self):
        for reference in ("team/probe:tag:extra", "team/probe:", "team//probe", "Team/probe", "team/probe/-"):
            self.adapter["probeImage"] = image(reference)
            self.adapter["buildEnvironment"]["Isolation"]["ProbeImage"] = self.adapter["probeImage"]
            self.persist()
            with self.subTest(reference=reference), self.assertRaises(bootstrap.Failure):
                self.load()

    def test_public_template_is_not_an_approval(self):
        template = (REPO / "examples/report-remediation/local-kind-operator.example.json").read_bytes()
        self.write(self.config_file, template)
        status, result = self.cli("plan")
        self.assertEqual(status, 1)
        self.assertEqual(result["stage"], "offline-input-validation")

    def test_plan_and_validate_are_process_and_write_free(self):
        before = {str(p): p.read_bytes() for p in self.base.rglob("*") if p.is_file()}
        with mock.patch.object(bootstrap, "Runner", side_effect=AssertionError("runner used in offline mode")):
            for mode in ("plan", "validate"):
                status, result = self.cli(mode, "--approve-privileged-buildkit")
                self.assertEqual(status, 0)
                self.assertFalse(result["onlineChecksPerformed"])
                self.assertEqual(result["catalogFiles"], 1)
                self.assertNotIn(str(self.private), json.dumps(result))
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.base.rglob("*") if p.is_file()})
        self.assertFalse(Path(self.config["subject"]["privateRoot"]).exists())

    def test_all_apply_approvals_precede_runner_or_root_creation(self):
        inputs = self.load()
        flags = [
            ([], "exact-plan-approval-required"),
            (["--approve-plan", inputs.plan_digest], "existing-control-approval-required"),
            (["--approve-plan", inputs.plan_digest, "--approve-existing-control", uid(10)], "privileged-buildkit-approval-required"),
        ]
        with mock.patch.object(bootstrap, "Runner", side_effect=AssertionError("approval bypass")):
            for options, code in flags:
                status, result = self.cli("apply", *options)
                self.assertEqual(status, 1)
                self.assertEqual(result["code"], code)
        self.assertFalse(inputs.root.exists())

    def test_duplicate_json_keys_and_bad_arguments_are_redacted(self):
        self.write(self.config_file, b'{"version":1,"version":2}')
        self.assertEqual(self.cli("plan")[1]["code"], "duplicate-json-key")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = bootstrap.main(["plan", "--unknown=" + SENTINEL])
        self.assertEqual(status, 1)
        self.assertNotIn(SENTINEL, output.getvalue())

    def test_tag_store_root_and_hook_collisions_are_rejected(self):
        cases = ("same-tag", "normalized-alias", "tracked-tag", "scoped-file", "existing-root", "root-in-checkout", "setup-hook")
        for case in cases:
            with self.subTest(case=case):
                old = copy.deepcopy(self.config)
                additions = []
                if case == "same-tag":
                    self.config["subject"]["tag"] = "control"
                elif case == "normalized-alias":
                    self.config["subject"]["tag"] = "New_Subject"
                elif case == "tracked-tag":
                    path = self.store / "registry.json"
                    self.write_json(path, {"clusters": {bootstrap.kind_name(self.worktree, "new-subject"): {}}})
                    additions.append(path)
                elif case == "scoped-file":
                    path = self.store / (bootstrap.kind_name(self.worktree, "new-subject") + ".kubeconfig")
                    self.write(path, b"unrelated")
                    additions.append(path)
                elif case == "existing-root":
                    path = Path(self.config["subject"]["privateRoot"])
                    path.mkdir(mode=0o700)
                    additions.append(path)
                elif case == "root-in-checkout":
                    self.config["subject"]["privateRoot"] = str(self.worktree / "private")
                else:
                    path = self.worktree / ".kind/setup.sh"
                    self.write(path, b"exit 0\n")
                    additions.append(path)
                self.persist()
                with self.assertRaises(bootstrap.Failure):
                    self.load()
                for path in additions:
                    path.rmdir() if path.is_dir() else path.unlink()
                self.config = old
                self.persist()

    def test_unsupported_or_missing_approval_inputs_do_not_fallback(self):
        mutations = [
            lambda: self.policy["policies"][0]["adapters"][0].update(kind="arbitrary-adapter"),
            lambda: self.adapter.update(capability="http"),
            lambda: self.adapter["controller"].update(enableEventPublishing=False),
            lambda: self.adapter["controller"].update(Bindings=[{}]),
            lambda: self.adapter["buildEnvironment"].update(BuildKit={"Address": "unapproved"}),
            lambda: self.adapter["buildEnvironment"]["Repositories"][0].update(Recipes=[]),
            lambda: self.adapter["buildEnvironment"]["Repositories"][0]["Recipes"][0].update(Files={}),
            lambda: self.adapter["buildEnvironment"]["BuildJobs"].update(OutputRepository="other.invalid/output"),
        ]
        for mutate in mutations:
            old = copy.deepcopy(self.policy)
            mutate()
            self.persist()
            with self.assertRaises(bootstrap.Failure):
                self.load()
            self.policy = old
            self.persist()

    def test_only_exact_approved_catalog_files_are_read(self):
        unapproved = self.catalog / "not-approved.txt"
        self.write(unapproved, b"unrelated-private-input")
        actual_open = os.open
        calls = []

        def record(path, *args, **kwargs):
            calls.append(str(path))
            return actual_open(path, *args, **kwargs)

        with mock.patch.object(bootstrap.os, "open", side_effect=record):
            inputs = self.load()
        self.assertEqual(inputs.catalog, {"revision/recipe.yml": SENTINEL.encode()})
        self.assertNotIn(str(unapproved), calls)
        self.assertNotIn(SENTINEL, json.dumps(inputs.summary()))

    def test_catalog_digest_path_and_symlink_checks(self):
        self.write(self.catalog_file, b"changed")
        with self.assertRaisesRegex(bootstrap.Failure, "approved-input-digest-mismatch"):
            self.load()
        self.write(self.catalog_file, SENTINEL.encode())
        recipe = self.adapter["buildEnvironment"]["Repositories"][0]["Recipes"][0]
        recipe["CatalogDirectory"] = "../outside"
        self.persist()
        with self.assertRaisesRegex(bootstrap.Failure, "invalid-catalog-path"):
            self.load()
        recipe["CatalogDirectory"] = "revision"
        self.persist()
        self.catalog_file.unlink()
        self.catalog_file.symlink_to(self.source)
        with self.assertRaisesRegex(bootstrap.Failure, "symlink"):
            self.load()

    def test_mount_option_injection_and_overlapping_cidrs_are_rejected(self):
        for key, value in (("privateRoot", str(self.private / "new,readonly,dst=unapproved")),
                           ("serviceCIDR", "10.250.0.0/16")):
            old = self.config["subject"][key]
            self.config["subject"][key] = value
            self.persist()
            with self.assertRaises(bootstrap.Failure):
                self.load()
            self.config["subject"][key] = old
            self.persist()

    def test_private_root_in_another_checkout_is_rejected(self):
        other = self.private / "other-checkout"
        other.mkdir(mode=0o700)
        (other / ".git").mkdir()
        self.config["subject"]["privateRoot"] = str(other / "private-lab")
        self.persist()
        with self.assertRaisesRegex(bootstrap.Failure, "private-root-overlaps-checkout"):
            self.load()

    def test_credential_permissions_and_auth_scope_are_fail_closed(self):
        auth_file = Path(self.config["registry"]["authFile"])
        auth_file.chmod(0o644)
        with self.assertRaisesRegex(bootstrap.Failure, "private-file-permissions"):
            self.load()
        auth_file.chmod(0o600)
        for data in ({"auths": self.auth["auths"], "credsStore": "unapproved"},
                     {"auths": {**self.auth["auths"], "other.invalid": {"auth": "anything"}}},
                     {"auths": {"localhost:5000": {"identitytoken": SENTINEL}}}):
            self.write_json(auth_file, data)
            with self.assertRaises(bootstrap.Failure):
                self.load()

    def test_registry_ca_never_accepts_private_key_material(self):
        path = Path(self.config["registry"]["caFile"])
        data = path.read_bytes() + b"-----BEGIN PRIVATE KEY-----\n" + SENTINEL.encode() + b"\n-----END PRIVATE KEY-----\n"
        self.write(path, data)
        self.config["registry"]["caSHA256"] = bootstrap.sha(data)
        self.persist()
        with self.assertRaisesRegex(bootstrap.Failure, "registry-ca-must-contain-only-certificates"):
            self.load()

    def test_crd_bundle_rejects_other_objects_metadata_and_webhooks(self):
        for mutate in (
            lambda b: b["items"][0].update(kind="ClusterRole"),
            lambda b: b["items"][0]["metadata"].update(uid=uid(99)),
            lambda b: b["items"][0]["spec"].update(conversion={"strategy": "Webhook"}),
        ):
            bundle = copy.deepcopy(self.bundle)
            mutate(bundle)
            data = bootstrap.wire(bundle)
            self.write(Path(self.config["approved"]["crdsFile"]), data)
            self.config["approved"]["crdsSHA256"] = bootstrap.sha(data)
            self.persist()
            with self.assertRaises(bootstrap.Failure):
                self.load()

    def test_source_budget_changes_invalidate_plan_but_are_never_rewritten(self):
        before = self.load().plan_digest
        self.policy["policies"][0]["maxCandidates"] = 2
        self.persist()
        self.assertNotEqual(before, self.load().plan_digest)
        self.assertEqual(self.load().policy["policies"][0]["maxCandidates"], 2)

    def test_kindctl_store_is_frozen_in_plan_and_commands(self):
        before = self.load()
        other = self.base / "other-store"
        other.mkdir(mode=0o700)
        after = bootstrap.load_inputs(self.config_file, self.worktree, store=other)
        self.assertNotEqual(before.plan_digest, after.plan_digest)
        with mock.patch.dict(os.environ, {"KINDCTL_STORE": str(other)}):
            with mock.patch.object(bootstrap.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"{}", b"")) as run:
                bootstrap.Runner(before).kube(["get", "namespace", "kube-system"])
        self.assertEqual(run.call_args.kwargs["env"]["KINDCTL_STORE"], str(self.store))

    def test_scoped_kubeconfig_rejects_exec_proxy_insecure_and_wrong_context(self):
        for mutate in (
            lambda c: c["users"][0]["user"].update(exec={"command": SENTINEL}),
            lambda c: c["clusters"][0]["cluster"].update({"proxy-url": "http://unapproved"}),
            lambda c: c["clusters"][0]["cluster"].update({"insecure-skip-tls-verify": True}),
            lambda c: c.update({"current-context": "other"}),
            lambda c: c["contexts"][0]["context"].update(user="other"),
        ):
            value = kubeconfig("kind-approved")
            mutate(value)
            with self.assertRaises(bootstrap.Failure):
                bootstrap.checked_kubeconfig(value, "kind-approved")


class ConstructionTests(Fixture):
    def test_crd_defaulting_never_hides_schema_or_scope_changes(self):
        spec = self.bundle["items"][0]["spec"]
        defaulted = bootstrap.crd_spec(spec)
        self.assertEqual(defaulted, bootstrap.crd_spec(defaulted))
        changed = copy.deepcopy(defaulted)
        changed["versions"][0]["schema"]["openAPIV3Schema"]["additionalProperties"] = True
        self.assertNotEqual(bootstrap.crd_spec(changed), defaulted)
        changed = copy.deepcopy(defaulted)
        changed["scope"] = "Cluster"
        self.assertNotEqual(bootstrap.crd_spec(changed), defaulted)

    def test_kind_config_pins_node_state_cni_and_pid_limit(self):
        inputs = self.load()
        config = bootstrap.kind_config(inputs)
        self.assertTrue(config["networking"]["disableDefaultCNI"])
        node = config["nodes"][0]
        self.assertEqual(node["image"], bootstrap.NODE_IMAGE)
        self.assertIn("podPidsLimit: 512", node["kubeadmConfigPatches"][0])
        mounts = node["extraMounts"]
        self.assertTrue(all(m["hostPath"].startswith(str(inputs.root) + "/") for m in mounts))
        self.assertTrue(next(m for m in mounts if m["containerPath"] == "/etc/containerd/certs.d")["readOnly"])
        self.assertEqual(bootstrap.cilium_values()["policyCIDRMatchMode"], ["nodes"])

    def test_buildkit_command_has_private_state_bounds_pins_and_no_credentials(self):
        inputs = self.load()
        command = bootstrap.buildkit_command(inputs, "c" * 64, "b" * 32)
        for flag, value in (("--network", "container:" + "c" * 64), ("--memory", "8g"), ("--memory-swap", "8g"),
                            ("--cpus", "4"), ("--pids-limit", "2048")):
            self.assertEqual(command[command.index(flag) + 1], value)
        self.assertIn(bootstrap.BUILDKIT_IMAGE, command)
        self.assertIn("tcp://0.0.0.0:1235", command)
        self.assertNotIn(SENTINEL, " ".join(command))
        mounts = [command[i + 1] for i, part in enumerate(command) if part == "--mount"]
        self.assertEqual(len(mounts), 6)
        self.assertTrue(all("src=" + str(inputs.root) + "/" in m for m in mounts))
        self.assertEqual(sum(m.endswith(",readonly") for m in mounts), 5)
        for forbidden in ("docker.sock", "ca.key", "client.key", "--allow-insecure-entitlement", "--tls-skip-verify"):
            self.assertNotIn(forbidden, " ".join(command))

    def test_compiled_rbac_and_only_immutable_secret_shapes(self):
        inputs = self.load()
        inputs.root.mkdir(mode=0o700)
        for file in ("ca.crt", "client.crt", "client.key"):
            bootstrap.write_new(inputs.root, "lab/tls/" + file, SENTINEL.encode())
        bootstrap.write_new(inputs.root, "lab/registry-auth.json", bootstrap.wire(self.auth))
        resources = list(bootstrap.build_resources(inputs, self.state(inputs)))
        roles = [r for r in resources if r["kind"] == "ClusterRole"]
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0]["rules"], bootstrap.WATCH_RULES)
        self.assertNotIn("aggregationRule", roles[0])
        self.assertFalse(any(r["kind"].endswith("Binding") for r in resources))
        secrets_ = [r for r in resources if r["kind"] == "Secret"]
        self.assertEqual([r["type"] for r in secrets_], ["Opaque", "kubernetes.io/tls", "kubernetes.io/dockerconfigjson"])
        self.assertTrue(all(r["immutable"] for r in secrets_))
        network = next(r for r in resources if r["kind"] == "NetworkPolicy")
        self.assertEqual(network["spec"]["policyTypes"], ["Ingress", "Egress"])
        self.assertNotIn("ingress", network["spec"])
        self.assertEqual(network["spec"]["egress"][0]["ports"], [{"protocol": "TCP", "port": 1235}])

    def test_verification_rejects_same_uid_rbac_network_and_secret_drift(self):
        inputs = self.load()
        inputs.root.mkdir(mode=0o700)
        for file in ("ca.crt", "client.crt", "client.key"):
            bootstrap.write_new(inputs.root, "lab/tls/" + file, SENTINEL.encode())
        bootstrap.write_new(inputs.root, "lab/registry-auth.json", bootstrap.wire(self.auth))
        state = self.state(inputs)
        resources = list(bootstrap.build_resources(inputs, state))
        cases = [
            ("ClusterRole", lambda r: r["rules"][0]["verbs"].append("delete")),
            ("ClusterRole", lambda r: r.update(aggregationRule={"clusterRoleSelectors": [{}]})),
            ("NetworkPolicy", lambda r: r["spec"]["egress"].append({})),
            ("NetworkPolicy", lambda r: r["spec"].update(ingress=[{}])),
            ("Secret", lambda r: r.update(immutable=False)),
            ("Secret", lambda r: r["data"].update(unapproved=base64.b64encode(SENTINEL.encode()).decode())),
            ("Service", lambda r: r["spec"].update(selector={"unapproved": "target"})),
            ("EndpointSlice", lambda r: r["endpoints"][0]["addresses"].append("192.0.2.99")),
        ]
        for kind, mutate in cases:
            with self.subTest(kind=kind):
                desired = next(r for r in resources if r["kind"] == kind)
                actual = copy.deepcopy(desired)
                actual["metadata"]["uid"] = state["roleUID"] if kind == "ClusterRole" else uid(60)
                if kind == "Service":
                    actual["spec"]["type"] = "ClusterIP"
                identity = bootstrap.object_id(actual)
                bootstrap.check_resource(state, identity, actual, desired)
                mutate(actual)
                with self.assertRaises(bootstrap.Failure):
                    bootstrap.check_resource(state, identity, actual, desired)

    def test_policy_clone_changes_only_lab_bindings(self):
        inputs = self.load()
        original = copy.deepcopy(inputs.policy)
        cloned = bootstrap.clone_policy(inputs, self.state(inputs), kubeconfig("kind-new"))
        p = cloned["policies"][0]
        c = p["adapters"][0]["configuration"]
        old = original["policies"][0]
        for key in ("copilot", "maxCandidates", "maxModelCalls", "maxDurationSeconds",
                    "allowRestrictedModel", "allowTestChanges", "requirePlanApproval", "proposalBackend", "namespace"):
            self.assertEqual(p[key], old[key])
        for key in ("capability", "probeImage", "requiredCapabilities", "requiredRequirements"):
            self.assertEqual(c[key], self.adapter[key])
        old_build = self.adapter["buildEnvironment"]
        new_build = c["buildEnvironment"]
        for key in ("Limits", "Isolation", "SyntheticScope"):
            self.assertEqual(new_build[key], old_build[key])
        for key in ("WorkerImage", "OutputRepository", "WorkerArg", "WorkerContext", "Args", "Limits"):
            self.assertEqual(new_build["BuildJobs"][key], old_build["BuildJobs"][key])
        self.assertEqual(new_build["Repositories"][0]["Recipes"], old_build["Repositories"][0]["Recipes"])
        self.assertEqual(c["controller"]["Template"]["Source"], self.adapter["controller"]["Template"]["Source"])
        self.assertEqual(c["controller"]["ClusterIdentity"], bootstrap.cluster_identity(uid(20)))
        self.assertEqual(inputs.policy, original)

    def test_runner_always_uses_scoped_kindctl_and_captures_output(self):
        runner = bootstrap.Runner(self.load())
        with mock.patch.object(bootstrap.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"{}", b"")) as run:
            runner.kube(["get", "namespace", "kube-system", "-o", "json"], control=True)
            runner.kube(["create", "-f", "-", "-o", "json"], data=SENTINEL.encode())
        first, second = run.call_args_list
        self.assertEqual(first.args[0][:4], [str(runner.kindctl), "kubectl", "--tag", "control"])
        self.assertEqual(second.args[0][:4], [str(runner.kindctl), "kubectl", "--tag", "new-subject"])
        self.assertNotIn(SENTINEL, " ".join(second.args[0]))
        self.assertEqual(second.kwargs["input"], SENTINEL.encode())
        self.assertNotIn("KUBECONFIG", second.kwargs["env"])
        self.assertEqual(second.kwargs["stdout"], subprocess.PIPE)
        self.assertEqual(second.kwargs["stderr"], subprocess.PIPE)
        self.assertFalse(second.kwargs.get("shell", False))

    def test_subprocess_failure_never_reflects_output_or_input(self):
        inputs = self.load()
        with mock.patch.object(bootstrap.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, SENTINEL.encode(), SENTINEL.encode())):
            with self.assertRaisesRegex(bootstrap.Failure, "^command-failed$"):
                bootstrap.Runner(inputs).kube(["create", "-f", "-"], data=SENTINEL.encode())

    def test_existing_ownership_receipt_is_not_overwritten(self):
        inputs = self.load()
        inputs.root.mkdir(mode=0o700)
        state = self.state(inputs)
        bootstrap.save_state(inputs, state)
        before = (inputs.root / "ownership.json").read_bytes()
        changed = {**state, "labID": "e" * 32}
        with self.assertRaisesRegex(bootstrap.Failure, "state-owner-mismatch"):
            bootstrap.save_state(inputs, changed)
        self.assertEqual((inputs.root / "ownership.json").read_bytes(), before)


class ProbeTests(Fixture):
    def test_probe_workloads_are_credential_free_or_buildkit_only(self):
        spec = bootstrap.pod_spec(image("probe"), ["/orka-remediation-network-probe"], ["serve", "--nonce", "b" * 64])
        pod = {**obj("Pod", "probe", uid(40), "probe-ns"), "spec": spec,
               "status": {"containerStatuses": [{"imageID": image("probe"), "state": {"terminated": {"exitCode": 0}}}]}}
        bootstrap.verify_pod(pod, image("probe"))
        for mutate in (
            lambda p: p["spec"].update(automountServiceAccountToken=True),
            lambda p: p["spec"].update(hostPID=True),
            lambda p: p["spec"].update(volumes=[{"name": "operator", "secret": {"secretName": "operator-kubeconfig"}}]),
            lambda p: p["spec"]["containers"][0]["securityContext"].update(allowPrivilegeEscalation=True),
            lambda p: p["status"]["containerStatuses"][0].update(imageID=image("probe").replace("a" * 64, "f" * 64)),
        ):
            changed = copy.deepcopy(pod)
            mutate(changed)
            with self.assertRaises(bootstrap.Failure):
                bootstrap.verify_pod(changed, image("probe"))

    def test_connection_refusal_is_not_an_isolation_pass(self):
        inputs = self.load()
        probes = bootstrap.Probes(inputs, mock.Mock(), self.state(inputs))
        spec = bootstrap.pod_spec(image("probe"), ["/orka-remediation-network-probe"], [])
        pod = {**obj("Pod", "denied", uid(40), "probe-ns"), "spec": spec, "status": {"phase": "Succeeded",
               "containerStatuses": [{"imageID": image("probe"), "state": {"terminated": {"exitCode": 0,
                "message": json.dumps({"reachable": False, "nonceMatched": False, "failureClass": "connection-refused"})}}}]}}
        with mock.patch.object(probes, "create", return_value=pod), mock.patch.object(probes, "wait", return_value=pod):
            with self.assertRaisesRegex(bootstrap.Failure, "network-probe-not-conclusive"):
                probes.network("probe-ns", "denied", "b" * 64, "192.0.2.10:8080", blocked=True)

    def test_cleanup_uses_exact_uid_preconditions_and_never_deletes_build_namespace(self):
        inputs = self.load()
        inputs.root.mkdir(mode=0o700)
        state = self.state(inputs)
        namespace = obj("Namespace", "owned-probe", uid(41))
        state["probes"] = [bootstrap.object_id(namespace)]
        bootstrap.save_state(inputs, state)
        runner = mock.Mock()
        runner.get.side_effect = [obj("Namespace", "kube-system", uid(20)), namespace]
        runner.kube.side_effect = [b"{}", b""]
        bootstrap.Probes(inputs, runner, state).cleanup()
        deletion = runner.kube.call_args_list[0]
        self.assertEqual(deletion.args[0], ["delete", "--raw", "/api/v1/namespaces/owned-probe", "-f", "-"])
        self.assertEqual(json.loads(deletion.kwargs["data"])["preconditions"], {"uid": uid(41)})
        self.assertEqual(state["probes"], [])
        self.assertNotIn("remediation-builds", json.dumps(runner.kube.call_args_list[0].args))

    def test_cleanup_refuses_changed_cluster_or_object_without_deletion(self):
        inputs = self.load()
        for cluster_changed in (True, False):
            state = self.state(inputs)
            state["probes"] = [bootstrap.object_id(obj("Namespace", "owned-probe", uid(41)))]
            runner = mock.Mock()
            runner.get.side_effect = ([obj("Namespace", "kube-system", uid(99))] if cluster_changed else
                                      [obj("Namespace", "kube-system", uid(20)), obj("Namespace", "owned-probe", uid(99))])
            with self.assertRaises(bootstrap.Failure):
                bootstrap.Probes(inputs, runner, state).cleanup()
            runner.kube.assert_not_called()

    def test_active_verification_lock_is_not_adopted(self):
        inputs = self.load()
        inputs.root.mkdir(mode=0o700)
        bootstrap.write_new(inputs.root, "verification.lock", b"existing-operation")
        with self.assertRaises(FileExistsError):
            bootstrap.verify(inputs, mock.Mock())
        self.assertEqual((inputs.root / "verification.lock").read_bytes(), b"existing-operation")


class RegistryChecksTests(Fixture):
    media_types = (
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    )

    def registry(self, inputs, required_media, wrong_digest=False):
        requests = []
        pins = {}
        config = inputs.adapter
        for value in (config["probeImage"], config["controller"]["ObserverImage"],
                      config["buildEnvironment"]["BuildJobs"]["WorkerImage"]):
            path, pin = value[len(inputs.authority) + 1:].split("@")
            repository = path.rsplit(":", 1)[0] if ":" in path else path
            pins["/v2/" + repository + "/manifests/" + pin] = pin

        class HTTPS:
            def __init__(self, *args, **kwargs):
                pass

            def request(self, method, path, headers):
                self.path, self.headers = path, headers
                requests.append((method, path, headers))

            def getresponse(self):
                authenticated = "Authorization" in self.headers
                accepted = {v.strip() for v in self.headers["Accept"].split(",")}
                if self.path == "/v2/":
                    status = 200 if authenticated else 401
                    pin = None
                elif self.path not in pins:
                    status, pin = 404, None
                else:
                    status = 200 if authenticated and required_media in accepted else 406
                    pin = "sha256:" + "f" * 64 if wrong_digest else pins[self.path]
                return mock.Mock(status=status, getheader=lambda key: pin if key == "Docker-Content-Digest" else None)

            def close(self):
                pass

        context = mock.MagicMock()
        context.wrap_socket.return_value = mock.MagicMock()
        with mock.patch.object(bootstrap.ssl, "create_default_context", return_value=context) as tls:
            with mock.patch.object(bootstrap.socket, "create_connection", return_value=mock.MagicMock()):
                with mock.patch.object(bootstrap.http.client, "HTTPSConnection", HTTPS):
                    bootstrap.registry_connectivity(inputs, "192.0.2.30", inputs.auth)
        tls.assert_called_once_with(cadata=inputs.ca.decode("ascii"))
        self.assertEqual(context.wrap_socket.call_args_list[0].kwargs["server_hostname"], "localhost")
        self.assertEqual(context.wrap_socket.call_args_list[1].kwargs["server_hostname"], "fixture-registry")
        self.assertTrue(all(method == "HEAD" for method, _, _ in requests))
        self.assertNotIn("Authorization", requests[0][2])
        return requests

    def test_registry_negotiates_all_four_immutable_manifest_types(self):
        inputs = self.load()
        for required in self.media_types:
            with self.subTest(media_type=required):
                requests = self.registry(inputs, required)
                for _, _, headers in requests:
                    self.assertEqual({s.strip() for s in headers["Accept"].split(",")}, set(self.media_types))

    def test_registry_tagged_digest_reads_repository_by_digest_not_tag_path(self):
        self.adapter["probeImage"] = image("team/probe:release-v1")
        self.adapter["buildEnvironment"]["Isolation"]["ProbeImage"] = self.adapter["probeImage"]
        self.adapter["controller"]["ObserverImage"] = image("team/observer:Release_1")
        self.adapter["buildEnvironment"]["BuildJobs"]["WorkerImage"] = image("build-worker:v2")
        self.persist()
        requests = self.registry(self.load(), self.media_types[0])
        manifests = [path for _, path, _ in requests if path != "/v2/"]
        self.assertEqual(manifests, ["/v2/" + repo + "/manifests/sha256:" + "a" * 64
                                    for repo in ("team/probe", "team/observer", "build-worker")])

    def test_registry_success_without_exact_digest_is_rejected(self):
        with self.assertRaisesRegex(bootstrap.Failure, "approved-runtime-image-unavailable"):
            self.registry(self.load(), self.media_types[0], wrong_digest=True)


class DaemonChecksTests(Fixture):
    def daemon(self, inputs, state):
        mounts = (
            ("lab/buildkit", "/var/lib/buildkit", True),
            ("lab/buildkitd.toml", "/etc/buildkit/buildkitd.toml", False),
            ("lab/registry-ca.crt", "/registry-trust/ca.crt", False),
            ("lab/tls/ca.crt", "/tls/ca.crt", False),
            ("lab/tls/server.crt", "/tls/server.crt", False),
            ("lab/tls/server.key", "/tls/server.key", False),
        )
        return {
            "Id": state["daemonID"], "Name": "/" + inputs.daemon_name, "Image": "sha256:" + "f" * 64,
            "State": {"Running": True}, "Config": {"Labels": {"remediation.orka.ai/lab": state["labID"]}},
            "HostConfig": {"Memory": 8 * 1024**3, "MemorySwap": 8 * 1024**3, "NanoCpus": 4 * 10**9,
                           "PidsLimit": 2048, "NetworkMode": "container:" + inputs.config["registry"]["containerID"]},
            "Mounts": [{"Source": str(inputs.root / src), "Destination": dst, "RW": writable} for src, dst, writable in mounts],
        }

    def check(self, inputs, state, daemon, rejection="TLSV13_ALERT_CERTIFICATE_REQUIRED"):
        runner = mock.Mock()
        runner.run.side_effect = [bootstrap.wire([daemon]), bootstrap.wire([{"Id": "sha256:" + "f" * 64}])]
        context = mock.MagicMock()
        if rejection:
            error = bootstrap.ssl.SSLError("synthetic rejection")
            error.reason = rejection
            context.wrap_socket.side_effect = error
        with mock.patch.object(bootstrap.ssl, "create_default_context", return_value=context):
            with mock.patch.object(bootstrap.socket, "create_connection", return_value=mock.MagicMock()):
                bootstrap.daemon_checks(inputs, runner, state)
        self.assertEqual(runner.run.call_args_list, [
            mock.call(["docker", "inspect", "--type", "container", state["daemonID"]]),
            mock.call(["docker", "image", "inspect", bootstrap.BUILDKIT_IMAGE]),
        ])
        context.wrap_socket.assert_called_once()
        self.assertEqual(context.wrap_socket.call_args.kwargs["server_hostname"], bootstrap.BUILD_SERVER)

    def test_daemon_requires_exact_bounds_mounts_identity_and_certificate_rejection(self):
        inputs = self.load()
        state = {**self.state(inputs), "daemonID": "e" * 64}
        daemon = self.daemon(inputs, state)
        self.check(inputs, state, daemon)
        for mutate in (
            lambda d: d.update(Id="a" * 64),
            lambda d: d.update(Image="sha256:" + "b" * 64),
            lambda d: d["HostConfig"].update(Memory=16 * 1024**3),
            lambda d: d["HostConfig"].update(PidsLimit=-1),
            lambda d: d["HostConfig"].update(NetworkMode="host"),
            lambda d: d["Mounts"][1].update(RW=True),
            lambda d: d["Mounts"][0].update(Source="/private/unowned/state"),
        ):
            changed = copy.deepcopy(daemon)
            mutate(changed)
            with self.assertRaises(bootstrap.Failure):
                self.check(inputs, state, changed)
        for reason in (None, "CERTIFICATE_VERIFY_FAILED"):
            with self.subTest(reason=reason), self.assertRaises(bootstrap.Failure):
                self.check(inputs, state, daemon, rejection=reason)


class FakeRunner:
    """Record only in-memory calls; no command or network is delegated."""

    def __init__(self, inputs):
        self.inputs = inputs
        self.kindctl = inputs.worktree / ".agents/skills/kindctl/bin/kindctl"
        self.calls = []
        self.creates = []
        self.counter = 100
        self.wrong_control = False
        self.existing_subject = False
        self.reject_create = False

    def run(self, args, data=None, timeout=120):
        args = list(map(str, args))
        self.calls.append((args, data))
        if args == ["kind", "get", "clusters"]:
            return (self.inputs.subject_name if self.existing_subject else "unrelated-control").encode()
        if args[:3] == ["docker", "ps", "-a"]:
            return b""
        if args[:4] == ["docker", "inspect", "--type", "container"]:
            return bootstrap.wire([{
                "Id": "c" * 64, "Name": "/fixture-registry", "State": {"Running": True},
                "NetworkSettings": {"Networks": {"kind": {"NetworkID": "d" * 64, "IPAddress": "10.249.0.2"}}},
            }])
        if args[:3] == ["docker", "network", "inspect"]:
            return bootstrap.wire([{"Id": "d" * 64, "Name": "kind", "IPAM": {"Config": [{"Subnet": "10.249.0.0/16"}]}}])
        if args[:3] == ["docker", "run", "-d"]:
            return ("e" * 64 + "\n").encode()
        if args[:2] in ([str(self.kindctl), "create"], [str(self.kindctl), "exec"]):
            return b""
        raise AssertionError("unexpected fake command shape")

    def kube(self, args, control=False, data=None, timeout=120):
        args = list(map(str, args))
        self.calls.append((["kindctl-kube", "control" if control else "subject", *args], data))
        if args[:2] == ["config", "view"]:
            tag = self.inputs.config["control" if control else "subject"]["tag"]
            return bootstrap.wire(kubeconfig("kind-" + bootstrap.kind_name(self.inputs.worktree, tag)))
        if args[:2] == ["get", "nodes"]:
            if control:
                return bootstrap.wire({"items": [{"spec": {"podCIDRs": ["10.248.0.0/24"]}}]})
            node = obj("Node", self.inputs.subject_name + "-control-plane", uid(22))
            node.update(spec={"podCIDR": "10.250.0.0/24"},
                        status={"addresses": [{"type": "InternalIP", "address": "10.249.0.4"}]})
            return bootstrap.wire({"items": [node]})
        if args[:1] == ["wait"]:
            return b""
        if args == ["create", "-f", "-", "-o", "json"]:
            if self.reject_create:
                raise bootstrap.Failure("command-failed")
            resource = json.loads(data)
            resource["metadata"]["uid"] = uid(self.counter)
            self.counter += 1
            self.creates.append(resource)
            return bootstrap.wire(resource)
        raise AssertionError("unexpected fake Kubernetes command shape")

    def get(self, kind, name_, namespace=None, control=False):
        self.calls.append((["get", "control" if control else "subject", kind, name_, namespace or ""], None))
        if kind == "namespace" and name_ == "kube-system":
            return obj("Namespace", name_, uid((99 if self.wrong_control else 10) if control else 20))
        if control and kind == "deployment":
            return obj("Deployment", name_, uid(11), namespace)
        if control and kind == "service":
            return obj("Service", name_, uid(12), namespace)
        raise AssertionError("unexpected fake identity read")


class ApplyCommandTests(Fixture):
    def test_unverifiable_phases_never_rewrite_owned_receipts(self):
        inputs = self.load()
        inputs.root.mkdir(mode=0o700)
        path = inputs.root / "ownership.json"
        for phase in ("preparing", "incomplete", "unknown"):
            state = {**self.state(inputs), "phase": phase}
            bootstrap.save_state(inputs, state)
            before = path.read_bytes()
            runner = mock.Mock()
            with mock.patch.object(bootstrap, "save_state", wraps=bootstrap.save_state) as save:
                with self.subTest(phase=phase), self.assertRaisesRegex(bootstrap.Failure, "incomplete-or-conflicting-ownership"):
                    bootstrap.verify(inputs, runner)
                save.assert_not_called()
            self.assertEqual(path.read_bytes(), before)
            self.assertFalse(runner.mock_calls)
            self.assertFalse((inputs.root / "verification.lock").exists())

    def test_stale_preparing_verify_preserves_concurrent_apply_identity_acknowledgements(self):
        inputs = self.load()
        inputs.root.mkdir(mode=0o700)
        preparing = {**self.state(inputs), "phase": "preparing"}
        preparing.pop("clusterUID")
        bootstrap.save_state(inputs, preparing)
        acknowledged = {**preparing, "daemonID": "e" * 64, "clusterUID": uid(20)}
        path = inputs.root / "ownership.json"
        read = bootstrap.read_file
        interleaved = False

        def capture_then_acknowledge(filename, *args, **kwargs):
            nonlocal interleaved
            snapshot = read(filename, *args, **kwargs)
            if Path(filename) == path and not interleaved:
                interleaved = True
                # Apply can acknowledge resources while verify holds only its own lock.
                self.assertTrue((inputs.root / "verification.lock").exists())
                bootstrap.save_state(inputs, acknowledged)
            return snapshot

        runner = mock.Mock()
        with mock.patch.object(bootstrap, "read_file", side_effect=capture_then_acknowledge):
            with self.assertRaisesRegex(bootstrap.Failure, "incomplete-or-conflicting-ownership"):
                bootstrap.verify(inputs, runner)
        self.assertTrue(interleaved)
        self.assertEqual(json.loads(path.read_bytes()), acknowledged)
        self.assertFalse(runner.mock_calls)
        self.assertFalse((inputs.root / "ownership.next.json").exists())
        self.assertFalse((inputs.root / "verification.lock").exists())

    def test_preparing_verify_does_not_collide_with_apply_staged_receipt(self):
        inputs = self.load()
        inputs.root.mkdir(mode=0o700)
        preparing = {**self.state(inputs), "phase": "preparing"}
        bootstrap.save_state(inputs, preparing)
        path = inputs.root / "ownership.json"
        before = path.read_bytes()
        pending = bootstrap.wire({**preparing, "daemonID": "e" * 64})
        bootstrap.write_new(inputs.root, "ownership.next.json", pending)
        with self.assertRaisesRegex(bootstrap.Failure, "incomplete-or-conflicting-ownership"):
            bootstrap.verify(inputs, mock.Mock())
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual((inputs.root / "ownership.next.json").read_bytes(), pending)
        self.assertFalse((inputs.root / "verification.lock").exists())

    def test_changed_staged_policy_clears_ready_receipt_before_hash_failure(self):
        inputs = self.load()
        inputs.root.mkdir(mode=0o700)
        bootstrap.write_new(inputs.root, "operator-data/policy.json", b"edited-after-ready")
        state = {**self.state(inputs), "phase": "ready", "validation": {"old": True},
                 "policySHA256": bootstrap.sha(b"approved-original")}
        bootstrap.save_state(inputs, state)
        runner = mock.Mock()
        with self.assertRaisesRegex(bootstrap.Failure, "staged-policy-changed"):
            bootstrap.verify(inputs, runner)
        stored = json.loads((inputs.root / "ownership.json").read_bytes())
        self.assertEqual(stored["phase"], "needs-verification")
        self.assertNotIn("validation", stored)
        self.assertEqual(stored["policySHA256"], state["policySHA256"])
        self.assertFalse((inputs.root / "verification.lock").exists())
        self.assertFalse(runner.mock_calls)

    def test_owned_missing_policy_or_leftover_probes_cannot_retain_ready(self):
        inputs = self.load()
        inputs.root.mkdir(mode=0o700)
        for pending in ([], [bootstrap.object_id(obj("Namespace", "leftover", uid(99)))]):
            state = {**self.state(inputs), "phase": "ready", "validation": {"old": True},
                     "policySHA256": bootstrap.sha(b"missing-policy"), "probes": pending}
            bootstrap.save_state(inputs, state)
            with self.assertRaises((bootstrap.Failure, FileNotFoundError)):
                bootstrap.verify(inputs, mock.Mock())
            stored = json.loads((inputs.root / "ownership.json").read_bytes())
            self.assertEqual(stored["phase"], "needs-verification")
            self.assertNotIn("validation", stored)
            self.assertEqual(stored["probes"], pending)

    def test_invalid_owner_plan_or_lab_identity_never_rewrites_receipt(self):
        inputs = self.load()
        inputs.root.mkdir(mode=0o700)
        path = inputs.root / "ownership.json"
        for key, value in (("owner", "unrelated-tool"), ("planDigest", "f" * 64), ("labID", "invalid")):
            state = {**self.state(inputs), "phase": "ready", "validation": {"old": True}, key: value}
            self.write_json(path, state)
            before = path.read_bytes()
            with self.assertRaisesRegex(bootstrap.Failure, "incomplete-or-conflicting-ownership"):
                bootstrap.verify(inputs, mock.Mock())
            self.assertEqual(path.read_bytes(), before)

    def fake_tls(self, inputs, runner, address):
        for name_ in ("ca.crt", "ca.key", "client.crt", "client.key", "server.crt", "server.key"):
            bootstrap.write_new(inputs.root, "lab/tls/" + name_, SENTINEL.encode())

    def test_apply_uses_create_only_pinned_scoped_commands(self):
        inputs = self.load()
        runner = FakeRunner(inputs)
        probe = mock.MagicMock()
        probe.__enter__.return_value.connect_ex.return_value = bootstrap.errno.ECONNREFUSED
        old_umask = os.umask(0o077)
        try:
            with mock.patch.object(bootstrap, "registry_connectivity"), mock.patch.object(bootstrap, "create_tls", self.fake_tls):
                with mock.patch.object(bootstrap.socket, "socket", return_value=probe):
                    with mock.patch.object(bootstrap, "verify", return_value={"status": "fixture-verified"}) as verify:
                        result = bootstrap.apply(inputs, runner)
        finally:
            os.umask(old_umask)
        self.assertEqual(result["status"], "fixture-verified")
        commands = [args for args, _ in runner.calls]
        create = next(c for c in commands if c[:2] == [str(runner.kindctl), "create"])
        self.assertEqual(create, [str(runner.kindctl), "create", "--tag", "new-subject", "--config", str(inputs.root / "lab/kind.json")])
        self.assertNotIn("--k8s-version", create)
        helm = next(c for c in commands if c[:2] == [str(runner.kindctl), "exec"])
        self.assertEqual(helm[2:8], ["--tag", "new-subject", "--", "helm", "install", "cilium"])
        self.assertTrue(all("apply" not in c and "replace" not in c and "delete" not in c for c in commands))
        self.assertEqual(len(runner.creates), 14)
        self.assertTrue(all(c[1] == "subject" for c in commands if c[:1] == ["kindctl-kube"] and "create" in c))
        self.assertNotIn(SENTINEL, json.dumps(commands))
        staged = inputs.root / "operator-data/lab.kubeconfig"
        self.assertEqual(staged.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(staged.read_bytes())["clusters"][0]["cluster"]["server"], "https://10.249.0.4:6443")
        state = json.loads((inputs.root / "ownership.json").read_bytes())
        self.assertEqual(state["phase"], "needs-verification")
        self.assertEqual(len(state["objects"]), 14)
        self.assertEqual(state["daemonID"], "e" * 64)
        self.assertEqual((inputs.root / "operator-data/catalog/revision/recipe.yml").read_bytes(), SENTINEL.encode())
        self.assertNotIn(SENTINEL, (inputs.root / "ownership.json").read_text())
        self.assertTrue(all(s["immutable"] for s in runner.creates if s["kind"] == "Secret"))
        verify.assert_called_once()

    def test_control_identity_or_existing_cluster_failure_precedes_mutation(self):
        for field in ("wrong_control", "existing_subject"):
            inputs = self.load()
            runner = FakeRunner(inputs)
            setattr(runner, field, True)
            with mock.patch.object(bootstrap, "prepare_files") as files:
                with self.assertRaises(bootstrap.Failure):
                    bootstrap.apply(inputs, runner)
            files.assert_not_called()
            self.assertFalse(inputs.root.exists())
            self.assertFalse(runner.creates)

    def test_create_conflict_preserves_receipt_without_adoption_or_deletion(self):
        inputs = self.load()
        runner = FakeRunner(inputs)
        runner.reject_create = True
        probe = mock.MagicMock()
        probe.__enter__.return_value.connect_ex.return_value = bootstrap.errno.ECONNREFUSED
        with mock.patch.object(bootstrap, "registry_connectivity"), mock.patch.object(bootstrap, "create_tls", self.fake_tls):
            with mock.patch.object(bootstrap.socket, "socket", return_value=probe):
                with self.assertRaisesRegex(bootstrap.Failure, "command-failed"):
                    bootstrap.apply(inputs, runner)
        state = json.loads((inputs.root / "ownership.json").read_bytes())
        self.assertEqual(state["phase"], "preparing")
        self.assertEqual(state["clusterUID"], uid(20))
        self.assertFalse(state["objects"])
        self.assertFalse((inputs.root / "operator-data/policy.json").exists())
        self.assertTrue(all("delete" not in c and "apply" not in c and "replace" not in c for c, _ in runner.calls))

    def test_failed_reverification_invalidates_previous_readiness(self):
        inputs = self.load()
        inputs.root.mkdir(mode=0o700)
        bootstrap.write_new(inputs.root, "operator-data/policy.json", b"fixture-policy")
        state = {**self.state(inputs), "phase": "ready", "validation": {"old": True},
                 "policySHA256": bootstrap.sha(b"fixture-policy")}
        bootstrap.save_state(inputs, state)
        runner = FakeRunner(inputs)
        runner.wrong_control = True
        with self.assertRaisesRegex(bootstrap.Failure, "control-cluster-identity-changed"):
            bootstrap.verify(inputs, runner)
        stored = json.loads((inputs.root / "ownership.json").read_bytes())
        self.assertEqual(stored["phase"], "needs-verification")
        self.assertNotIn("validation", stored)
        self.assertFalse((inputs.root / "verification.lock").exists())


if __name__ == "__main__":
    unittest.main()
