#!/usr/bin/env python3
"""Stage an approved remediation policy in a fresh, local-only Kind subject lab."""

import sys

sys.dont_write_bytecode = True

import argparse
import base64
import copy
from dataclasses import dataclass
import errno
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import socket
import ssl
import stat
import subprocess
import time
from urllib.parse import urlsplit


WORKTREE = Path(__file__).resolve().parents[1]
OWNER = "orka-remediation-local-kind/v1"
NODE_IMAGE = "kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a"
BUILDKIT_IMAGE = "mcr.microsoft.com/oss/v2/moby/buildkit@sha256:1ecb6f4906eb57f47e53ad9fa500c80959574a6c6326aad281f225cb9b5c1693"
CILIUM_CHART_SHA256 = "39b62a72f0892dd16548bd08ee97d5db2e975f7c1f57155578a144186e22992f"
CILIUM_IMAGE = "quay.io/cilium/cilium:v1.18.2@sha256:858f807ea4e20e85e3ea3240a762e1f4b29f1cb5bbd0463b8aa77e7b097c0667"
BUILD_NAMESPACE = "remediation-builds"
BUILD_SERVER = "buildkit.remediation-builds.svc"
HEX = re.compile(r"^[0-9a-f]{64}$")
UID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
IMAGE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[0-9a-f]{64}$")
REGISTRY_MEDIA_TYPES = (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)
CRDS = {
    "scaledobjects.keda.sh": ("keda.sh", "scaledobjects", "ScaledObject", "Namespaced"),
    "scaledjobs.keda.sh": ("keda.sh", "scaledjobs", "ScaledJob", "Namespaced"),
    "triggerauthentications.keda.sh": ("keda.sh", "triggerauthentications", "TriggerAuthentication", "Namespaced"),
    "clustertriggerauthentications.keda.sh": ("keda.sh", "clustertriggerauthentications", "ClusterTriggerAuthentication", "Cluster"),
    "cloudeventsources.eventing.keda.sh": ("eventing.keda.sh", "cloudeventsources", "CloudEventSource", "Namespaced"),
    "clustercloudeventsources.eventing.keda.sh": ("eventing.keda.sh", "clustercloudeventsources", "ClusterCloudEventSource", "Cluster"),
}
WATCH_RULES = [
    {"apiGroups": ["keda.sh"], "resources": ["clustertriggerauthentications"], "verbs": ["get", "list", "watch"]},
    {"apiGroups": ["eventing.keda.sh"], "resources": ["clustercloudeventsources"], "verbs": ["get", "list", "watch"]},
]


class Failure(Exception):
    """Only fixed, content-free error codes may cross the CLI boundary."""


def require(condition, code):
    if not condition:
        raise Failure(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def wire(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def decode(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate-json-key")
            result[key] = value
        return result

    try:
        return json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise Failure("invalid-json") from None


def shape(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys), "unsupported-input-shape")


def name(value, maximum=63):
    require(isinstance(value, str) and len(value) <= maximum and NAME.fullmatch(value), "invalid-resource-name")
    return value


def kind_tag(value):
    name(value, 16)
    require("--" not in value, "noncanonical-kindctl-tag")
    return value


def absolute(value):
    require(isinstance(value, str), "invalid-private-path")
    require("," not in value and all(ord(c) >= 32 and ord(c) != 127 for c in value), "invalid-private-path")
    path = Path(value)
    require(path.is_absolute() and str(path) == value and ".." not in path.parts, "invalid-private-path")
    require(not any(path.is_relative_to(p) for p in (Path("/tmp"), Path("/var/tmp"))), "persistent-private-path-required")
    require(not any(p.is_symlink() for p in (path, *path.parents)), "symlink-input-or-output")
    return path


def read_file(value, maximum=2 << 20, private=True):
    path = absolute(str(value))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, "input-file-type-or-size")
        if private:
            require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0, "private-file-permissions")
        data = handle.read(maximum + 1)
        require(len(data) <= maximum, "input-file-size")
        return data


def pinned_file(value, pin, maximum=2 << 20, private=True):
    require(isinstance(pin, str) and HEX.fullmatch(pin), "invalid-input-digest")
    data = read_file(value, maximum, private)
    require(sha(data) == pin, "approved-input-digest-mismatch")
    return data


def relative(value):
    require(isinstance(value, str) and "\\" not in value, "invalid-catalog-path")
    path = PurePosixPath(value)
    require(value and not path.is_absolute() and str(path) == value and
            all(part not in ("", ".", "..") for part in path.parts), "invalid-catalog-path")
    return Path(value)


def inside_checkout(path):
    return any((parent / ".git").exists() for parent in (path, *path.parents))


def kind_name(worktree, tag):
    # Mirror kindctl's nonmutating name derivation; apply also checks its actual context.
    kind_tag(tag)
    suffix = "-" + sha(str(worktree).encode())[:6] + "-" + tag
    base = re.sub(r"[^a-z0-9-]+", "-", worktree.name.lower())
    base = re.sub("-+", "-", base).strip("-")[:min(40, 50 - len(suffix))] or "repo"
    return base + suffix


def cluster_identity(uid):
    # Exact Go struct field order used by controllerlab.ClusterIdentity.
    return sha(wire({"Domain": "orka.controllerlab.cluster.v1", "UID": uid}))


def registry_auth(data, authority):
    obj = decode(data)
    shape(obj, ("auths",))
    shape(obj["auths"], (authority,))
    entry = obj["auths"][authority]
    shape(entry, ("auth",))
    try:
        credential = base64.b64decode(entry["auth"], validate=True)
    except (ValueError, TypeError):
        raise Failure("invalid-registry-auth") from None
    user, separator, password = credential.partition(b":")
    require(separator and user and password and len(credential) <= 8192 and
            not any(c < 32 or c == 127 for c in credential), "invalid-registry-auth")
    return entry["auth"]


def registry_reference(image, authority):
    require(isinstance(image, str) and IMAGE.fullmatch(image) and image.startswith(authority + "/"),
            "subject-runtime-registry-not-supported")
    reference, pin = image[len(authority) + 1:].split("@")
    repository, tagged, tag = reference.partition(":")
    require(not tagged or re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag),
            "invalid-subject-runtime-image-reference")
    component = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
    require(len(repository) <= 255 and re.fullmatch(component + r"(?:/" + component + r")*", repository),
            "invalid-subject-runtime-image-reference")
    return repository, pin


@dataclass
class Inputs:
    config: dict
    policy: dict
    catalog: dict
    crds: list
    ca: bytes
    auth: bytes
    chart: bytes
    root: Path
    worktree: Path
    store: Path
    plan_digest: str

    @property
    def adapter(self):
        return self.policy["policies"][0]["adapters"][0]["configuration"]

    @property
    def subject_name(self):
        return kind_name(self.worktree, self.config["subject"]["tag"])

    @property
    def daemon_name(self):
        return "orka-remediation-buildkit-" + sha(self.subject_name.encode())[:16]

    @property
    def authority(self):
        return "localhost:" + str(self.config["registry"]["port"])

    def summary(self):
        return {"status": "offline-validated", "planDigest": self.plan_digest,
                "sourcePolicySHA256": self.config["approved"]["policySHA256"],
                "catalogBindingSHA256": digest({k: sha(v) for k, v in self.catalog.items()}),
                "catalogFiles": len(self.catalog), "onlineChecksPerformed": False,
                "requiresExistingControlApproval": True, "requiresPrivilegedBuildkitApproval": True}


def load_inputs(filename, worktree=WORKTREE, fresh=True, store=None):
    config = decode(read_file(filename))
    shape(config, ("version", "control", "subject", "approved", "registry", "ciliumChartFile", "buildkitPort"))
    require(type(config["version"]) is int and config["version"] == 1, "unsupported-input-version")
    control, subject, approved, registry = (config[k] for k in ("control", "subject", "approved", "registry"))
    shape(control, ("tag", "clusterUID", "controller", "gateway"))
    for key in ("controller", "gateway"):
        shape(control[key], ("namespace", "name", "uid"))
        name(control[key]["namespace"])
        name(control[key]["name"])
        require(isinstance(control[key]["uid"], str) and UID.fullmatch(control[key]["uid"]), "invalid-control-identity")
    require(isinstance(control["clusterUID"], str) and UID.fullmatch(control["clusterUID"]), "invalid-control-identity")
    shape(subject, ("tag", "privateRoot", "podCIDR", "serviceCIDR"))
    kind_tag(control["tag"])
    kind_tag(subject["tag"])
    require(control["tag"] != subject["tag"], "control-subject-tag-collision")
    shape(approved, ("policyFile", "policySHA256", "catalogRoot", "crdsFile", "crdsSHA256", "newPolicyName"))
    name(approved["newPolicyName"])
    shape(registry, ("container", "containerID", "networkID", "port", "caFile", "caSHA256", "authFile"))
    name(registry["container"])
    require(all(isinstance(registry[k], str) and HEX.fullmatch(registry[k]) for k in ("containerID", "networkID")),
            "registry-identity-required")
    for port in (registry["port"], config["buildkitPort"]):
        require(type(port) is int and 1024 <= port <= 65535, "invalid-local-port")
    require(registry["port"] != config["buildkitPort"], "registry-buildkit-port-collision")
    pod_net = ipaddress.ip_network(subject["podCIDR"], strict=True)
    service_net = ipaddress.ip_network(subject["serviceCIDR"], strict=True)
    require(pod_net.version == 4 and service_net.version == 4 and pod_net.is_private and service_net.is_private and
            16 <= pod_net.prefixlen <= 24 and 16 <= service_net.prefixlen <= 24 and not pod_net.overlaps(service_net),
            "unsupported-or-overlapping-cidrs")
    root = absolute(subject["privateRoot"])
    worktree = worktree.resolve()
    require(not root.is_relative_to(worktree) and not worktree.is_relative_to(root) and not inside_checkout(root),
            "private-root-overlaps-checkout")
    require(root.parent.is_dir() and root.parent.stat().st_uid == os.getuid() and
            root.parent.stat().st_mode & 0o077 == 0, "private-parent-required")
    require(not (worktree / ".kind/setup.sh").exists(), "kindctl-setup-hook-not-supported")
    store = absolute(str(store or os.environ.get("KINDCTL_STORE", Path.home() / ".kube/kind")))
    if fresh:
        require(not root.exists(), "private-root-already-exists")
        subject_name = kind_name(worktree, subject["tag"])
        require(not (store / (subject_name + ".kubeconfig")).exists(), "subject-kubeconfig-already-exists")
        if (store / "registry.json").exists():
            registry_state = decode(read_file(store / "registry.json"))
            require(subject_name not in registry_state.get("clusters", {}), "subject-tag-already-tracked")
    else:
        require(root.is_dir() and root.stat().st_uid == os.getuid() and root.stat().st_mode & 0o077 == 0,
                "private-root-ownership")
    policy = decode(pinned_file(approved["policyFile"], approved["policySHA256"]))
    shape(policy, ("policies",))
    require(isinstance(policy["policies"], list) and len(policy["policies"]) == 1, "one-approved-policy-required")
    p = policy["policies"][0]
    require(type(p["version"]) is int and p["version"] == 1 and p["proposalBackend"] == "copilot-acp-v1" and
            len(p["adapters"]) == 1 and p["adapters"][0]["kind"] == "dalec-keda-events", "unsupported-approved-adapter")
    require(p["name"] != approved["newPolicyName"], "new-policy-name-required")
    for key in ("maxCandidates", "maxModelCalls", "maxDurationSeconds"):
        require(type(p[key]) is int and p[key] > 0, "approved-budgets-required")
    for key in ("allowRestrictedModel", "allowTestChanges", "requirePlanApproval"):
        require(type(p[key]) is bool, "approved-security-decisions-required")
    c = p["adapters"][0]["configuration"]
    b = c["buildEnvironment"]
    require(c["capability"] == "keda-event-publishing-v2" and c["controller"]["enableEventPublishing"] is True and
            c["controller"]["DedicatedClusterApproved"] is True and not c["controller"]["Bindings"],
            "approved-keda-publishing-capability-required")
    require(UID.fullmatch(c["clusterUID"]) and
            c["controller"]["ClusterIdentity"] == cluster_identity(c["clusterUID"]), "approved-cluster-binding-invalid")
    name(c["controller"]["Template"]["ClusterWatchRole"]["name"])
    require(c["controller"]["Template"]["ClusterWatchRole"]["resource"] ==
            {"Group": "rbac.authorization.k8s.io", "Version": "v1", "Resource": "clusterroles"} and
            UID.fullmatch(c["controller"]["Template"]["ClusterWatchRole"]["uid"]), "approved-watch-role-binding-invalid")
    require(b["BuildKit"] is None and b["BuildJobs"] and b["Kubernetes"] and b["Isolation"] and
            b["BuildJobs"]["Namespace"] == BUILD_NAMESPACE and not b["ImageBindings"] and
            b["Limits"]["MaxNamespaces"] in (0, 4), "unsupported-build-boundary")
    shape(b["BuildJobs"]["TLS"], ("caSecretName", "clientSecretName", "serverName"))
    for key in ("caSecretName", "clientSecretName"):
        name(b["BuildJobs"]["TLS"][key])
    name(b["BuildJobs"]["RegistrySecretName"])
    require(bool(b["BuildJobs"]["WorkerArg"]) != bool(b["BuildJobs"]["WorkerContext"]), "approved-worker-selector-required")
    require(c["probeImage"] == b["Isolation"]["ProbeImage"], "probe-pin-mismatch")
    authority = "localhost:" + str(registry["port"])
    require(b["BuildJobs"]["OutputRepository"].startswith(authority + "/"), "approved-output-registry-not-supported")
    gateway = control["gateway"]
    proxy = urlsplit(p["copilot"]["proxyEndpoint"])
    require(proxy.scheme in ("http", "https") and not proxy.username and not proxy.password and
            not proxy.query and not proxy.fragment and
            proxy.hostname in (gateway["name"] + "." + gateway["namespace"] + ".svc",
                               gateway["name"] + "." + gateway["namespace"] + ".svc.cluster.local") and
            p["copilot"]["proxyNamespace"] == gateway["namespace"], "approved-control-gateway-mismatch")
    for image in (c["probeImage"], c["controller"]["ObserverImage"], b["BuildJobs"]["WorkerImage"], p["copilot"]["image"]):
        require(isinstance(image, str) and IMAGE.fullmatch(image), "approved-image-pin-required")
    for image in (c["probeImage"], c["controller"]["ObserverImage"], b["BuildJobs"]["WorkerImage"]):
        registry_reference(image, authority)
    require(len(b["Repositories"]) == 1, "one-approved-catalog-required")
    repository = b["Repositories"][0]
    catalog_root = absolute(approved["catalogRoot"])
    require(repository["RecipeRoot"] == str(catalog_root) and not repository["SourceRoot"] and repository["Recipes"],
            "approved-catalog-root-required")
    catalog = {}
    total = 0
    for recipe in repository["Recipes"]:
        catalog_directory = recipe.get("CatalogDirectory", "")
        require(isinstance(catalog_directory, str), "invalid-catalog-path")
        directory = relative(catalog_directory) if catalog_directory else Path()
        recipe_path = relative(recipe["Path"])
        require(isinstance(recipe["Files"], dict) and 1 <= len(recipe["Files"]) <= 512 and
                str(recipe_path) in recipe["Files"], "approved-recipe-files-required")
        for key in ("FrontendImage", "WorkerImage", "OriginalImage"):
            require(IMAGE.fullmatch(recipe[key]), "approved-recipe-image-pin-required")
        for path, pin in recipe["Files"].items():
            rel = directory / relative(path)
            require(isinstance(pin, str) and pin.startswith("sha256:"), "approved-catalog-digest-required")
            data = pinned_file(catalog_root / rel, pin[7:], 8 << 20)
            require(str(rel) not in catalog or catalog[str(rel)] == data, "conflicting-catalog-file")
            if str(rel) not in catalog:
                total += len(data)
            require(total <= 16 << 20, "catalog-size-limit")
            catalog[str(rel)] = data
    bundle = decode(pinned_file(approved["crdsFile"], approved["crdsSHA256"], 32 << 20))
    shape(bundle, ("apiVersion", "kind", "items"))
    require(bundle["apiVersion"] == "v1" and bundle["kind"] == "List" and len(bundle["items"]) == len(CRDS),
            "approved-crd-bundle-required")
    seen = set()
    for crd in bundle["items"]:
        shape(crd, ("apiVersion", "kind", "metadata", "spec"))
        shape(crd["metadata"], ("name",))
        n, spec = crd["metadata"]["name"], crd["spec"]
        require(crd["apiVersion"] == "apiextensions.k8s.io/v1" and crd["kind"] == "CustomResourceDefinition" and
                n in CRDS and n not in seen, "unapproved-crd-resource")
        seen.add(n)
        require((spec["group"], spec["names"]["plural"], spec["names"]["kind"], spec["scope"]) == CRDS[n] and
                spec.get("conversion", {}).get("strategy", "None") == "None" and
                any(v["name"] == "v1alpha1" and v["served"] for v in spec["versions"]), "unsupported-crd-contract")
    ca = pinned_file(registry["caFile"], registry["caSHA256"], private=False)
    require(re.fullmatch(rb"(?:\s*-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*)+", ca),
            "registry-ca-must-contain-only-certificates")
    auth = read_file(registry["authFile"], 64 << 10)
    registry_auth(auth, authority)
    chart = pinned_file(config["ciliumChartFile"], CILIUM_CHART_SHA256, 32 << 20, private=False)
    plan_digest = digest({"version": 1, "config": config, "worktree": str(worktree), "kindctlStore": str(store),
                          "catalog": {k: sha(v) for k, v in catalog.items()},
                          "nodeImage": NODE_IMAGE, "buildkitImage": BUILDKIT_IMAGE, "ciliumImage": CILIUM_IMAGE,
                          "ciliumChartSHA256": CILIUM_CHART_SHA256, "watchRules": WATCH_RULES})
    return Inputs(config, policy, catalog, bundle["items"], ca, auth, chart, root, worktree, store, plan_digest)


class Runner:
    def __init__(self, inputs):
        self.inputs = inputs
        self.kindctl = inputs.worktree / ".agents/skills/kindctl/bin/kindctl"

    def run(self, args, data=None, timeout=120):
        env = dict(os.environ)
        env.pop("KUBECONFIG", None)
        env["KINDCTL_STORE"] = str(self.inputs.store)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run([str(a) for a in args], input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, cwd=self.inputs.worktree, env=env, timeout=timeout)
        require(result.returncode == 0, "command-failed")
        require(len(result.stdout) <= 40 << 20, "command-output-limit")
        return result.stdout

    def kube(self, args, control=False, data=None, timeout=120):
        tag = self.inputs.config["control" if control else "subject"]["tag"]
        return self.run([self.kindctl, "kubectl", "--tag", tag, *args], data, timeout)

    def get(self, kind, name_, namespace=None, control=False):
        return decode(self.kube((["-n", namespace] if namespace else []) + ["get", kind, name_, "-o", "json"],
                                control=control))


def object_id(obj):
    m = obj["metadata"]
    require(UID.fullmatch(m["uid"]) and not m.get("deletionTimestamp"), "resource-identity-unavailable")
    return {"kind": obj["kind"], "name": m["name"], "namespace": m.get("namespace", ""), "uid": m["uid"]}


def labels(lab_id):
    return {"app.kubernetes.io/managed-by": "orka-remediation-local-kind", "remediation.orka.ai/lab": lab_id}


def metadata(name_, lab_id, namespace=None):
    result = {"name": name_, "labels": labels(lab_id)}
    if namespace:
        result["namespace"] = namespace
    return result


def write_new(root, rel, data):
    path = root / relative(rel)
    require(not any(p.is_symlink() for p in (path, *path.parents)), "output-symlink")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def save_state(inputs, state):
    require(state["owner"] == OWNER and state["planDigest"] == inputs.plan_digest, "state-owner-mismatch")
    path = inputs.root / "ownership.json"
    if path.exists():
        previous = decode(read_file(path))
        require(previous["owner"] == OWNER and previous["labID"] == state["labID"] and
                previous["planDigest"] == state["planDigest"], "state-owner-mismatch")
    write_new(inputs.root, "ownership.next.json", wire(state) + b"\n")
    os.replace(inputs.root / "ownership.next.json", path)


def kind_config(inputs):
    root = inputs.root
    return {
        "kind": "Cluster", "apiVersion": "kind.x-k8s.io/v1alpha4",
        "networking": {"disableDefaultCNI": True, "podSubnet": inputs.config["subject"]["podCIDR"],
                       "serviceSubnet": inputs.config["subject"]["serviceCIDR"]},
        "containerdConfigPatches": ['[plugins."io.containerd.cri.v1.images".registry]\nconfig_path = "/etc/containerd/certs.d"\n'],
        "nodes": [{"role": "control-plane", "image": NODE_IMAGE,
                   "kubeadmConfigPatches": ["kind: KubeletConfiguration\npodPidsLimit: 512\n"],
                   "extraMounts": [
                       {"hostPath": str(root / "lab/containerd"), "containerPath": "/var/lib/containerd"},
                       {"hostPath": str(root / "lab/storage"), "containerPath": "/var/local-path-provisioner"},
                       {"hostPath": str(root / "lab/registry-hosts"), "containerPath": "/etc/containerd/certs.d", "readOnly": True},
                   ]}],
    }


def cilium_values():
    return {"ipam": {"mode": "kubernetes"}, "kubeProxyReplacement": False, "routingMode": "tunnel",
            "operator": {"replicas": 1}, "policyCIDRMatchMode": ["nodes"],
            "image": {"repository": "quay.io/cilium/cilium", "tag": "v1.18.2",
                      "digest": CILIUM_IMAGE.split("@")[1], "useDigest": True}}


def buildkit_command(inputs, registry_id, lab_id):
    root = inputs.root
    args = ["docker", "run", "-d", "--name", inputs.daemon_name, "--network", "container:" + registry_id,
            "--privileged", "--memory", "8g", "--memory-swap", "8g", "--cpus", "4", "--pids-limit", "2048",
            "--restart", "unless-stopped", "--log-opt", "max-size=10m", "--log-opt", "max-file=3",
            "--label", "remediation.orka.ai/lab=" + lab_id, "--env", "TMPDIR=/var/lib/buildkit/scratch"]
    for source, target, ro in (
        ("lab/buildkit", "/var/lib/buildkit", False), ("lab/buildkitd.toml", "/etc/buildkit/buildkitd.toml", True),
        ("lab/registry-ca.crt", "/registry-trust/ca.crt", True), ("lab/tls/ca.crt", "/tls/ca.crt", True),
        ("lab/tls/server.crt", "/tls/server.crt", True), ("lab/tls/server.key", "/tls/server.key", True),
    ):
        args += ["--mount", "type=bind,src=" + str(root / source) + ",dst=" + target + (",readonly" if ro else "")]
    return args + [BUILDKIT_IMAGE, "--config", "/etc/buildkit/buildkitd.toml",
                   "--addr", "unix:///run/buildkit/buildkitd.sock", "--addr", "tcp://0.0.0.0:" + str(inputs.config["buildkitPort"]),
                   "--tlscacert", "/tls/ca.crt", "--tlscert", "/tls/server.crt", "--tlskey", "/tls/server.key"]


def checked_kubeconfig(value, context):
    require(value.get("current-context") == context and
            all(len(value.get(k, [])) == 1 for k in ("contexts", "clusters", "users")), "scoped-kubeconfig-context")
    selected, cluster, user = value["contexts"][0], value["clusters"][0], value["users"][0]
    require(selected["name"] == context and selected["context"]["cluster"] == cluster["name"] and
            selected["context"]["user"] == user["name"], "scoped-kubeconfig-binding")
    require(set(user["user"]) == {"client-certificate-data", "client-key-data"} and
            all(user["user"].values()) and cluster["cluster"].get("certificate-authority-data") and
            not cluster["cluster"].get("insecure-skip-tls-verify") and not cluster["cluster"].get("proxy-url"),
            "unsafe-kubeconfig-authentication")
    endpoint = urlsplit(cluster["cluster"]["server"])
    require(endpoint.scheme == "https" and endpoint.hostname and not endpoint.username and not endpoint.password and
            not endpoint.query and not endpoint.fragment and endpoint.path in ("", "/"), "unsafe-kubeconfig-endpoint")
    return value


def check_control(inputs, runner):
    control = inputs.config["control"]
    view = decode(runner.kube(["config", "view", "--raw", "--minify", "-o", "json"], control=True))
    checked_kubeconfig(view, "kind-" + kind_name(inputs.worktree, control["tag"]))
    cluster = object_id(runner.get("namespace", "kube-system", control=True))
    require(cluster["uid"] == control["clusterUID"], "control-cluster-identity-changed")
    for key, kind in (("controller", "deployment"), ("gateway", "service")):
        expected = control[key]
        actual = object_id(runner.get(kind, expected["name"], expected["namespace"], control=True))
        require(actual["uid"] == expected["uid"], "control-resource-identity-changed")
    nodes = decode(runner.kube(["get", "nodes", "-o", "json"], control=True))
    networks = [ipaddress.ip_network(inputs.config["subject"][k]) for k in ("podCIDR", "serviceCIDR")]
    for node in nodes["items"]:
        for cidr in node.get("spec", {}).get("podCIDRs", []):
            require(not any(n.overlaps(ipaddress.ip_network(cidr)) for n in networks), "subject-control-cidr-overlap")


def check_registry(inputs, runner):
    expected = inputs.config["registry"]
    values = decode(runner.run(["docker", "inspect", "--type", "container", expected["containerID"]]))
    require(len(values) == 1, "registry-container-unavailable")
    value = values[0]
    require(value["Id"] == expected["containerID"] and value["Name"] == "/" + expected["container"] and
            value["State"]["Running"], "registry-container-identity-changed")
    network = value["NetworkSettings"]["Networks"].get("kind", {})
    require(network.get("NetworkID") == expected["networkID"], "registry-network-identity-changed")
    address = ipaddress.ip_address(network["IPAddress"])
    require(address.version == 4 and address.is_private and not address.is_loopback, "registry-address-invalid")
    topology = decode(runner.run(["docker", "network", "inspect", expected["networkID"]]))
    require(len(topology) == 1 and topology[0]["Id"] == expected["networkID"] and topology[0]["Name"] == "kind",
            "registry-network-identity-changed")
    for entry in topology[0]["IPAM"]["Config"]:
        subnet = ipaddress.ip_network(entry["Subnet"])
        for key in ("podCIDR", "serviceCIDR"):
            require(not subnet.overlaps(ipaddress.ip_network(inputs.config["subject"][key])), "subject-docker-cidr-overlap")
    return str(address)


def registry_connectivity(inputs, address, auth):
    context = ssl.create_default_context(cadata=inputs.ca.decode("ascii"))
    authorization = registry_auth(auth, inputs.authority)
    registry = inputs.config["registry"]
    # Both names are needed: BuildKit uses localhost, Kind pulls through Docker DNS.
    for hostname in ("localhost", registry["container"]):
        with socket.create_connection((address, registry["port"]), timeout=5) as plain:
            with context.wrap_socket(plain, server_hostname=hostname):
                pass

    def head(path, authenticated):
        connection = http.client.HTTPSConnection("localhost", registry["port"], context=context, timeout=5)
        connection.sock = context.wrap_socket(socket.create_connection((address, registry["port"]), timeout=5),
                                              server_hostname="localhost")
        try:
            headers = {"Accept": ", ".join(REGISTRY_MEDIA_TYPES)}
            if authenticated:
                headers["Authorization"] = "Basic " + authorization
            connection.request("HEAD", path, headers=headers)
            response = connection.getresponse()
            return response.status, response.getheader("Docker-Content-Digest")
        finally:
            connection.close()

    require(head("/v2/", False)[0] == 401 and head("/v2/", True)[0] == 200, "registry-authentication-check-failed")
    c = inputs.adapter
    for image in (c["probeImage"], c["controller"]["ObserverImage"], c["buildEnvironment"]["BuildJobs"]["WorkerImage"]):
        repository, pin = registry_reference(image, inputs.authority)
        require(head("/v2/" + repository + "/manifests/" + pin, True) == (200, pin), "approved-runtime-image-unavailable")


def create_tls(inputs, runner, address):
    root = inputs.root
    tls = root / "lab/tls"
    runner.run(["openssl", "req", "-new", "-newkey", "rsa:3072", "-nodes", "-x509", "-sha256", "-days", "14",
                "-subj", "/CN=orka-local-subject-buildkit-ca", "-keyout", tls / "ca.key", "-out", tls / "ca.crt"])
    for kind, usage in (("server", "serverAuth"), ("client", "clientAuth")):
        ext = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        ext += "extendedKeyUsage=" + usage + "\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"
        if kind == "server":
            ext += "subjectAltName=DNS:" + BUILD_SERVER + ",DNS:" + BUILD_SERVER + ".cluster.local,DNS:localhost,IP:127.0.0.1,IP:" + address + "\n"
        write_new(root, "lab/tls/" + kind + ".ext", ext.encode())
        runner.run(["openssl", "req", "-new", "-newkey", "rsa:3072", "-nodes", "-sha256",
                    "-subj", "/CN=orka-local-subject-buildkit-" + kind,
                    "-keyout", tls / (kind + ".key"), "-out", tls / (kind + ".csr")])
        runner.run(["openssl", "x509", "-req", "-sha256", "-days", "7", "-in", tls / (kind + ".csr"),
                    "-CA", tls / "ca.crt", "-CAkey", tls / "ca.key", "-CAcreateserial",
                    "-extfile", tls / (kind + ".ext"), "-out", tls / (kind + ".crt")])
        runner.run(["openssl", "verify", "-CAfile", tls / "ca.crt", "-purpose", "ssl" + kind, tls / (kind + ".crt")])
    for path in tls.iterdir():
        os.chmod(path, 0o600)
    for path in ("server.csr", "client.csr", "server.ext", "client.ext", "ca.srl"):
        (tls / path).unlink(missing_ok=True)


def prepare_files(inputs, runner, address):
    root = inputs.root
    for directory in ("lab/containerd", "lab/storage", "lab/registry-hosts", "lab/tls", "lab/buildkit/scratch",
                      "operator-data/output", "operator-data/scratch"):
        (root / directory).mkdir(parents=True, mode=0o700)
    write_new(root, "lab/registry-ca.crt", inputs.ca)
    write_new(root, "lab/registry-auth.json", inputs.auth)
    authority = inputs.authority
    registry = inputs.config["registry"]
    host = "https://" + registry["container"] + ":" + str(registry["port"])
    hosts = 'server = ' + json.dumps("https://" + authority) + '\n[host.' + json.dumps(host) + ']\n'
    hosts += 'capabilities = ["pull", "resolve"]\nca = [' + json.dumps("/etc/containerd/certs.d/" + authority + "/ca.crt") + ']\n'
    hosts += '[host.' + json.dumps(host) + '.header]\nauthorization = [' + json.dumps("Basic " + registry_auth(inputs.auth, authority)) + ']\n'
    write_new(root, "lab/registry-hosts/" + authority + "/ca.crt", inputs.ca)
    write_new(root, "lab/registry-hosts/" + authority + "/hosts.toml", hosts.encode())
    config = '[worker.oci]\nmax-parallelism = 2\ngc = true\n[registry.' + json.dumps(authority) + ']\n'
    config += 'http = false\ninsecure = false\nca = ["/registry-trust/ca.crt"]\n'
    write_new(root, "lab/buildkitd.toml", config.encode())
    write_new(root, "lab/kind.json", wire(kind_config(inputs)))
    write_new(root, "lab/cilium-values.json", wire(cilium_values()))
    write_new(root, "lab/cilium.tgz", inputs.chart)
    create_tls(inputs, runner, address)


def build_resources(inputs, state):
    lab_id = state["labID"]
    port, address = inputs.config["buildkitPort"], state["registryAddress"]
    yield {"apiVersion": "v1", "kind": "Namespace", "metadata": metadata(BUILD_NAMESPACE, lab_id)}
    role = inputs.adapter["controller"]["Template"]["ClusterWatchRole"]["name"]
    yield {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
           "metadata": metadata(role, lab_id), "rules": copy.deepcopy(WATCH_RULES)}
    for crd in inputs.crds:
        yield {**copy.deepcopy(crd), "metadata": metadata(crd["metadata"]["name"], lab_id)}
    for key, kind, files in (
        ("ca", "Opaque", {"ca.crt": "ca.crt"}),
        ("client", "kubernetes.io/tls", {"tls.crt": "client.crt", "tls.key": "client.key"}),
        ("registry", "kubernetes.io/dockerconfigjson", {".dockerconfigjson": None}),
    ):
        data = {k: base64.b64encode(read_file(inputs.root / "lab/tls" / f) if f else
                                  read_file(inputs.root / "lab/registry-auth.json")).decode() for k, f in files.items()}
        yield {"apiVersion": "v1", "kind": "Secret", "metadata": metadata(state["secrets"][key], lab_id, BUILD_NAMESPACE),
               "immutable": True, "type": kind, "data": data}
    yield {"apiVersion": "v1", "kind": "Service", "metadata": metadata("buildkit", lab_id, BUILD_NAMESPACE),
           "spec": {"ports": [{"name": "buildkit", "protocol": "TCP", "port": port, "targetPort": port}]}}
    m = metadata("buildkit-operator-endpoint", lab_id, BUILD_NAMESPACE)
    m["labels"].update({"kubernetes.io/service-name": "buildkit", "endpointslice.kubernetes.io/managed-by": "orka-remediation-local-kind"})
    yield {"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice", "metadata": m, "addressType": "IPv4",
           "ports": [{"name": "buildkit", "port": port, "protocol": "TCP"}],
           "endpoints": [{"addresses": [address], "conditions": {"ready": True}}]}
    yield {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
           "metadata": metadata("build-client-boundary", lab_id, BUILD_NAMESPACE),
           "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"], "egress": [
               {"to": [{"ipBlock": {"cidr": address + "/32"}}], "ports": [{"protocol": "TCP", "port": port}]},
               {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                        "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
                "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},
           ]}}


def clone_policy(inputs, state, kubeconfig):
    result = copy.deepcopy(inputs.policy)
    p = result["policies"][0]
    p["name"] = inputs.config["approved"]["newPolicyName"]
    c = p["adapters"][0]["configuration"]
    c["clusterUID"] = state["clusterUID"]
    c["controller"]["ClusterIdentity"] = cluster_identity(state["clusterUID"])
    c["controller"]["Template"]["ClusterWatchRole"]["uid"] = state["roleUID"]
    c["controller"]["APIServer"].update({"CIDR": state["nodeAddress"] + "/32", "Port": 6443})
    c["kubeconfig"] = str(inputs.root / "operator-data/lab.kubeconfig")
    c["context"] = kubeconfig["current-context"]
    b = c["buildEnvironment"]
    b["Kubernetes"].update({"Kubeconfig": c["kubeconfig"], "Context": c["context"], "ObserverCIDRs": [state["podCIDR"]]})
    b["Repositories"][0]["RecipeRoot"] = str(inputs.root / "operator-data/catalog")
    b["OutputRoot"] = str(inputs.root / "operator-data/output")
    b["TemporaryRoot"] = str(inputs.root / "operator-data/scratch")
    b["BuildJobs"]["BuildKitAddress"] = "tcp://" + BUILD_SERVER + ":" + str(inputs.config["buildkitPort"])
    b["BuildJobs"]["TLS"].update({"caSecretName": state["secrets"]["ca"], "clientSecretName": state["secrets"]["client"],
                                 "serverName": BUILD_SERVER})
    b["BuildJobs"]["RegistrySecretName"] = state["secrets"]["registry"]
    return result


def apply(inputs, runner):
    check_control(inputs, runner)
    require(inputs.subject_name not in runner.run(["kind", "get", "clusters"]).decode().split(), "subject-cluster-already-exists")
    for selector in ("name=^/" + inputs.daemon_name + "$", "label=io.x-k8s.kind.cluster=" + inputs.subject_name):
        require(not runner.run(["docker", "ps", "-a", "-q", "--filter", selector]).strip(), "subject-docker-resource-already-exists")
    address = check_registry(inputs, runner)
    registry_connectivity(inputs, address, inputs.auth)
    with socket.socket() as probe:
        probe.settimeout(3)
        require(probe.connect_ex((address, inputs.config["buildkitPort"])) == errno.ECONNREFUSED, "buildkit-port-not-provably-unused")
    require(not (inputs.worktree / ".kind/setup.sh").exists(), "kindctl-setup-hook-not-supported")
    os.mkdir(inputs.root, 0o700)
    lab_id = secrets.token_hex(16)
    state = {"owner": OWNER, "labID": lab_id, "planDigest": inputs.plan_digest, "phase": "preparing",
             "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "registryAddress": address, "objects": [], "probes": [],
             "secrets": {key: "remediation-build-" + key + "-" + lab_id[:12] for key in ("ca", "client", "registry")}}
    save_state(inputs, state)
    prepare_files(inputs, runner, address)
    daemon = runner.run(buildkit_command(inputs, inputs.config["registry"]["containerID"], lab_id)).decode().strip()
    require(HEX.fullmatch(daemon), "buildkit-create-acknowledgement-invalid")
    state["daemonID"] = daemon
    save_state(inputs, state)
    runner.run([runner.kindctl, "create", "--tag", inputs.config["subject"]["tag"], "--config", inputs.root / "lab/kind.json"],
               timeout=600)
    state["clusterUID"] = object_id(runner.get("namespace", "kube-system"))["uid"]
    save_state(inputs, state)
    runner.run([runner.kindctl, "exec", "--tag", inputs.config["subject"]["tag"], "--", "helm", "install",
                "cilium", inputs.root / "lab/cilium.tgz", "--namespace", "kube-system",
                "--values", inputs.root / "lab/cilium-values.json", "--wait", "--timeout", "180s"], timeout=240)
    runner.kube(["wait", "--for=condition=Ready", "nodes", "--all", "--timeout=120s"], timeout=150)
    nodes = decode(runner.kube(["get", "nodes", "-o", "json"]))["items"]
    require(len(nodes) == 1, "one-subject-node-required")
    node = nodes[0]
    state["node"] = object_id(node)
    state["nodeAddress"] = next(a["address"] for a in node["status"]["addresses"] if a["type"] == "InternalIP")
    require(ipaddress.ip_address(state["nodeAddress"]).version == 4, "subject-node-address-invalid")
    state["podCIDR"] = node["spec"]["podCIDR"]
    require(ipaddress.ip_network(state["podCIDR"]).subnet_of(ipaddress.ip_network(inputs.config["subject"]["podCIDR"])),
            "subject-pod-cidr-mismatch")
    save_state(inputs, state)
    for resource in build_resources(inputs, state):
        check_subject(runner, state)
        actual = decode(runner.kube(["create", "-f", "-", "-o", "json"], data=wire(resource)))
        identity = object_id(actual)
        require(actual["metadata"].get("labels", {}).get("remediation.orka.ai/lab") == lab_id, "created-resource-owner-mismatch")
        state["objects"].append(identity)
        if identity["kind"] == "ClusterRole":
            state["roleUID"] = identity["uid"]
        save_state(inputs, state)
        if identity["kind"] == "CustomResourceDefinition":
            runner.kube(["wait", "--for=condition=Established", "crd/" + identity["name"], "--timeout=60s"])
    view = decode(runner.kube(["config", "view", "--raw", "--minify", "-o", "json"]))
    checked_kubeconfig(view, "kind-" + inputs.subject_name)
    view["clusters"][0]["cluster"]["server"] = "https://" + state["nodeAddress"] + ":6443"
    write_new(inputs.root, "operator-data/lab.kubeconfig", wire(view) + b"\n")
    for path, data in inputs.catalog.items():
        write_new(inputs.root, "operator-data/catalog/" + path, data)
    policy = wire(clone_policy(inputs, state, view)) + b"\n"
    write_new(inputs.root, "operator-data/policy.json", policy)
    state.update({"policySHA256": sha(policy), "phase": "needs-verification"})
    save_state(inputs, state)
    return verify(inputs, runner, state)


def check_subject(runner, state):
    require(object_id(runner.get("namespace", "kube-system"))["uid"] == state["clusterUID"],
            "subject-cluster-identity-changed")


def crd_spec(spec):
    value = copy.deepcopy(spec)
    value.setdefault("conversion", {"strategy": "None"})
    value.setdefault("preserveUnknownFields", False)
    value["names"].setdefault("singular", value["names"]["kind"].lower())
    value["names"].setdefault("listKind", value["names"]["kind"] + "List")
    return value


def check_resource(state, identity, actual, expected):
    require(object_id(actual) == identity and
            identity["namespace"] == expected["metadata"].get("namespace", "") and
            actual["metadata"].get("labels", {}).get("remediation.orka.ai/lab") == state["labID"],
            "subject-resource-ownership-changed")
    kind = identity["kind"]
    if kind == "ClusterRole":
        require(actual["rules"] == WATCH_RULES and not actual.get("aggregationRule") and identity["uid"] == state["roleUID"],
                "compiled-watch-role-changed")
    elif kind == "CustomResourceDefinition":
        require(crd_spec(actual["spec"]) == crd_spec(expected["spec"]) and
                any(c["type"] == "Established" and c["status"] == "True" for c in actual["status"]["conditions"]),
                "approved-crd-schema-changed")
    elif kind == "Secret":
        require(actual.get("immutable") is True and actual["type"] == expected["type"] and
                actual["data"] == expected["data"], "build-secret-contract-changed")
    elif kind == "NetworkPolicy":
        desired, observed = copy.deepcopy(expected["spec"]), copy.deepcopy(actual["spec"])
        desired.setdefault("ingress", [])
        observed.setdefault("ingress", [])
        require(observed == desired, "build-network-policy-changed")
    elif kind == "Service":
        require(actual["spec"]["ports"] == expected["spec"]["ports"] and not actual["spec"].get("selector") and
                actual["spec"].get("type") == "ClusterIP" and not actual["spec"].get("externalIPs"), "build-service-changed")
    elif kind == "EndpointSlice":
        require(all(actual[k] == expected[k] for k in ("ports", "endpoints", "addressType")) and
                actual["metadata"]["labels"].get("kubernetes.io/service-name") == "buildkit", "build-service-endpoints-changed")


def pod_spec(image, command, args, lifetime=45):
    return {
        "restartPolicy": "Never", "activeDeadlineSeconds": lifetime, "terminationGracePeriodSeconds": 1,
        "automountServiceAccountToken": False, "enableServiceLinks": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "probe", "image": image, "imagePullPolicy": "IfNotPresent", "command": command, "args": args,
                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                        "resources": {"requests": {"cpu": "50m", "memory": "32Mi", "ephemeral-storage": "8Mi"},
                                      "limits": {"cpu": "100m", "memory": "64Mi", "ephemeral-storage": "8Mi"}},
                        "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File"}],
    }


def verify_pod(pod, image, secret_names=()):
    spec = pod["spec"]
    require(spec.get("automountServiceAccountToken") is False and not spec.get("initContainers") and
            not any(spec.get(k) for k in ("hostNetwork", "hostPID", "hostIPC")), "probe-pod-boundary-changed")
    context = spec.get("securityContext", {})
    require(context.get("runAsNonRoot") is True and context.get("runAsUser") == 65532 and
            context.get("seccompProfile", {}).get("type") == "RuntimeDefault", "probe-pod-security-changed")
    require(len(spec["containers"]) == 1, "probe-pod-container-count")
    container = spec["containers"][0]
    context = container.get("securityContext", {})
    require(container["image"] == image and context.get("allowPrivilegeEscalation") is False and
            context.get("readOnlyRootFilesystem") is True and context.get("capabilities", {}).get("drop") == ["ALL"],
            "probe-container-security-changed")
    require(all(v.get("secret", {}).get("secretName") in secret_names for v in spec.get("volumes", [])),
            "unapproved-probe-volume")
    statuses = pod["status"].get("containerStatuses", [])
    require(len(statuses) == 1 and statuses[0].get("imageID", "").endswith(image.split("@")[1]), "probe-runtime-image-mismatch")
    return statuses[0]


class Probes:
    def __init__(self, inputs, runner, state):
        self.inputs, self.runner, self.state = inputs, runner, state

    def create(self, obj):
        check_subject(self.runner, self.state)
        actual = decode(self.runner.kube(["create", "-f", "-", "-o", "json"], data=wire(obj)))
        identity = object_id(actual)
        require(actual["metadata"].get("labels", {}).get("remediation.orka.ai/lab") == self.state["labID"],
                "probe-owner-changed")
        self.state["probes"].append(identity)
        save_state(self.inputs, self.state)
        return actual

    def wait(self, pod, completed=True):
        identity = object_id(pod)
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline:
            actual = self.runner.get("pod", identity["name"], identity["namespace"])
            require(object_id(actual) == identity, "probe-pod-identity-changed")
            phase = actual["status"].get("phase")
            if phase in ("Succeeded", "Failed") or (not completed and phase == "Running"):
                return actual
            time.sleep(0.5)
        raise Failure("probe-timeout")

    def buildkit(self):
        image = self.inputs.adapter["buildEnvironment"]["BuildJobs"]["WorkerImage"]
        spec = pod_spec(image, ["/usr/bin/buildctl"], [
            "--addr", "tcp://" + BUILD_SERVER + ":" + str(self.inputs.config["buildkitPort"]),
            "--tlscacert", "/buildkit-ca/ca.crt", "--tlscert", "/builder-client/tls.crt",
            "--tlskey", "/builder-client/tls.key", "--tlsservername", BUILD_SERVER, "debug", "workers",
        ], lifetime=60)
        spec["volumes"] = [
            {"name": "ca", "secret": {"secretName": self.state["secrets"]["ca"], "defaultMode": 0o440,
                                     "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
            {"name": "client", "secret": {"secretName": self.state["secrets"]["client"], "defaultMode": 0o440,
                                         "items": [{"key": "tls.crt", "path": "tls.crt"}, {"key": "tls.key", "path": "tls.key"}]}},
        ]
        spec["containers"][0]["volumeMounts"] = [
            {"name": "ca", "mountPath": "/buildkit-ca", "readOnly": True},
            {"name": "client", "mountPath": "/builder-client", "readOnly": True},
        ]
        pod = self.wait(self.create({"apiVersion": "v1", "kind": "Pod",
                                    "metadata": metadata("buildkit-probe-" + self.state["labID"][:12], self.state["labID"], BUILD_NAMESPACE),
                                    "spec": spec}))
        status = verify_pod(pod, image, (self.state["secrets"]["ca"], self.state["secrets"]["client"]))
        require(status.get("state", {}).get("terminated", {}).get("exitCode") == 0 and pod["status"]["phase"] == "Succeeded",
                "buildkit-service-mutual-tls-failed")
        return {**object_id(pod), "imageID": status["imageID"], "exitCode": 0}

    def network(self, namespace, name_, nonce, target=None, blocked=False):
        image = self.inputs.adapter["probeImage"]
        args = ["connect" if target else "serve", "--nonce", nonce]
        if target:
            args += ["--target", target, "--expect", "blocked" if blocked else "reachable"]
        pod = self.wait(self.create({"apiVersion": "v1", "kind": "Pod",
                                    "metadata": metadata(name_, self.state["labID"], namespace),
                                    "spec": pod_spec(image, ["/orka-remediation-network-probe"], args, lifetime=75 if not target else 30)}),
                        completed=bool(target))
        status = verify_pod(pod, image)
        if not target:
            require(pod["status"]["phase"] == "Running", "network-canary-not-running")
            return pod
        terminated = status.get("state", {}).get("terminated", {})
        require(terminated.get("exitCode") == 0, "network-probe-failed")
        result = decode(terminated.get("message", "").encode())
        expected = {"reachable": not blocked, "nonceMatched": not blocked, "failureClass": "dial-timeout" if blocked else "none"}
        require(result == expected, "network-probe-not-conclusive")
        return {**object_id(pod), "imageID": status["imageID"], "result": result}

    def isolation(self):
        suffix = self.state["labID"][:12]
        control, subject = "remediation-probe-" + suffix + "-control", "remediation-probe-" + suffix + "-subject"
        for namespace in (control, subject):
            self.create({"apiVersion": "v1", "kind": "Namespace", "metadata": metadata(namespace, self.state["labID"])})
        nonce = secrets.token_hex(32)
        server = self.network(control, "egress-canary", nonce)
        target = server["status"]["podIP"] + ":8080"
        before = self.network(control, "egress-positive-before", nonce, target)
        policy = self.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                              "metadata": metadata("deny-all", self.state["labID"], subject),
                              "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}})
        time.sleep(2)
        blocked = self.network(subject, "egress-blocked", nonce, target, blocked=True)
        after = self.network(control, "egress-positive-after", nonce, target)
        require(object_id(self.runner.get("pod", "egress-canary", control)) == object_id(server), "network-canary-replaced")
        egress = {"canary": object_id(server), "policyUID": policy["metadata"]["uid"],
                  "positiveBefore": before, "denied": blocked, "positiveAfter": after}
        nonce = secrets.token_hex(32)
        server = self.network(subject, "ingress-canary", nonce)
        target = server["status"]["podIP"] + ":8080"
        blocked = self.network(control, "ingress-blocked", nonce, target, blocked=True)
        self.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                     "metadata": metadata("allow-control", self.state["labID"], subject),
                     "spec": {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": [{
                         "from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": control}}}],
                         "ports": [{"protocol": "TCP", "port": 8080}]}]}})
        time.sleep(2)
        positive = self.network(control, "ingress-positive", nonce, target)
        require(object_id(self.runner.get("pod", "ingress-canary", subject)) == object_id(server), "network-canary-replaced")
        return {"egress": egress, "ingress": {"canary": object_id(server), "denied": blocked, "positive": positive}}

    def cleanup(self):
        targets = [r for r in self.state["probes"] if r["kind"] == "Namespace" or
                   (r["kind"] == "Pod" and r["namespace"] == BUILD_NAMESPACE)]
        for identity in targets:
            check_subject(self.runner, self.state)
            actual = self.runner.get(identity["kind"], identity["name"], identity["namespace"] or None)
            require(object_id(actual) == identity and
                    actual["metadata"].get("labels", {}).get("remediation.orka.ai/lab") == self.state["labID"],
                    "probe-cleanup-ownership-changed")
            path = ("/api/v1/namespaces/" + identity["name"] if identity["kind"] == "Namespace" else
                    "/api/v1/namespaces/" + identity["namespace"] + "/pods/" + identity["name"])
            options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": identity["uid"]},
                       "propagationPolicy": "Foreground"}
            self.runner.kube(["delete", "--raw", path, "-f", "-"], data=wire(options))
            deadline = time.monotonic() + 75
            while time.monotonic() < deadline:
                args = (["-n", identity["namespace"]] if identity["namespace"] else [])
                raw = self.runner.kube(args + ["get", identity["kind"], identity["name"], "--ignore-not-found", "-o", "json"])
                if not raw.strip():
                    break
                require(decode(raw)["metadata"]["uid"] == identity["uid"], "probe-cleanup-identity-replaced")
                time.sleep(0.5)
            else:
                raise Failure("probe-cleanup-incomplete")
        self.state["probes"] = []
        save_state(self.inputs, self.state)


def daemon_checks(inputs, runner, state):
    daemon = decode(runner.run(["docker", "inspect", "--type", "container", state["daemonID"]]))[0]
    expected_image = decode(runner.run(["docker", "image", "inspect", BUILDKIT_IMAGE]))[0]["Id"]
    h = daemon["HostConfig"]
    require(daemon["Id"] == state["daemonID"] and daemon["Image"] == expected_image and daemon["State"]["Running"] and
            daemon["Name"] == "/" + inputs.daemon_name and
            daemon["Config"]["Labels"].get("remediation.orka.ai/lab") == state["labID"], "buildkit-identity-changed")
    require(h["Memory"] == 8 * 1024**3 and h["MemorySwap"] == 8 * 1024**3 and h["NanoCpus"] == 4 * 10**9 and
            h["PidsLimit"] == 2048 and h["NetworkMode"] == "container:" + inputs.config["registry"]["containerID"],
            "buildkit-boundary-changed")
    expected_mounts = {
        "/var/lib/buildkit": ("lab/buildkit", True), "/etc/buildkit/buildkitd.toml": ("lab/buildkitd.toml", False),
        "/registry-trust/ca.crt": ("lab/registry-ca.crt", False), "/tls/ca.crt": ("lab/tls/ca.crt", False),
        "/tls/server.crt": ("lab/tls/server.crt", False), "/tls/server.key": ("lab/tls/server.key", False),
    }
    require(len(daemon["Mounts"]) == len(expected_mounts), "buildkit-mounts-changed")
    for mount in daemon["Mounts"]:
        require(mount["Destination"] in expected_mounts, "buildkit-mounts-changed")
        source, writable = expected_mounts[mount["Destination"]]
        require(mount["Source"] == str(inputs.root / source) and mount["RW"] == writable, "buildkit-mounts-changed")
    context = ssl.create_default_context(cafile=str(inputs.root / "lab/tls/ca.crt"))
    with socket.create_connection((state["registryAddress"], inputs.config["buildkitPort"]), timeout=5) as plain:
        try:
            with context.wrap_socket(plain, server_hostname=BUILD_SERVER) as connection:
                connection.settimeout(5)
                connection.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
                connection.recv(32)
        except ssl.SSLError as error:
            require(error.reason in ("TLSV13_ALERT_CERTIFICATE_REQUIRED", "SSLV3_ALERT_HANDSHAKE_FAILURE"),
                    "buildkit-tls-rejection-inconclusive")
        else:
            raise Failure("buildkit-client-certificate-not-required")


def verify_owned(inputs, runner, state):
    require(state["owner"] == OWNER and state["planDigest"] == inputs.plan_digest and
            isinstance(state.get("labID"), str) and re.fullmatch(r"[0-9a-f]{32}", state["labID"]),
            "incomplete-or-conflicting-ownership")
    require(state.get("phase") in ("needs-verification", "ready"), "incomplete-or-conflicting-ownership")
    state["phase"] = "needs-verification"
    state.pop("validation", None)
    save_state(inputs, state)
    require(not state["probes"], "incomplete-or-conflicting-ownership")
    require(sha(read_file(inputs.root / "operator-data/policy.json")) == state["policySHA256"], "staged-policy-changed")
    check_control(inputs, runner)
    check_subject(runner, state)
    require(check_registry(inputs, runner) == state["registryAddress"], "registry-address-changed")
    registry_connectivity(inputs, state["registryAddress"], read_file(inputs.root / "lab/registry-auth.json"))
    daemon_checks(inputs, runner, state)
    node = runner.get("node", state["node"]["name"])
    require(object_id(node) == state["node"], "subject-node-identity-changed")
    node_container = decode(runner.run(["docker", "inspect", "--type", "container", state["node"]["name"]]))[0]
    node_image = decode(runner.run(["docker", "image", "inspect", NODE_IMAGE]))[0]["Id"]
    require(node_container["Config"]["Labels"].get("io.x-k8s.kind.cluster") == inputs.subject_name and
            node_container["Image"] == node_image, "subject-node-image-changed")
    if state.get("nodeContainerID"):
        require(node_container["Id"] == state["nodeContainerID"], "subject-node-container-changed")
    state["nodeContainerID"] = node_container["Id"]
    configz = decode(runner.kube(["get", "--raw", "/api/v1/nodes/" + state["node"]["name"] + "/proxy/configz"]))
    require(configz["kubeletconfig"]["podPidsLimit"] == 512, "subject-pid-limit-changed")
    cilium = runner.get("daemonset", "cilium", "kube-system")
    require(cilium["spec"]["template"]["spec"]["containers"][0]["image"] == CILIUM_IMAGE, "cilium-image-changed")
    cidrs = runner.get("ciliumnode", state["node"]["name"])["spec"]["ipam"]["podCIDRs"]
    require(cidrs == [state["podCIDR"]], "cilium-pod-cidr-mismatch")
    desired = {(o["kind"], o["metadata"]["name"]): o for o in build_resources(inputs, state)}
    require(len(state["objects"]) == len(desired) and
            {(o["kind"], o["name"]) for o in state["objects"]} == set(desired), "subject-resource-inventory-changed")
    for identity in state["objects"]:
        actual = runner.get(identity["kind"], identity["name"], identity["namespace"] or None)
        check_resource(state, identity, actual, desired[(identity["kind"], identity["name"])])
    for resource in ("clustertriggerauthentications.keda.sh", "clustercloudeventsources.eventing.keda.sh"):
        require(not decode(runner.kube(["get", resource, "-o", "json"]))["items"], "subject-global-keda-scope-not-empty")
    ready = runner.run([runner.kindctl, "exec", "--tag", inputs.config["subject"]["tag"], "--", "kubectl",
                        "--kubeconfig", inputs.root / "operator-data/lab.kubeconfig", "--context", "kind-" + inputs.subject_name,
                        "get", "--raw", "/readyz"])
    require(ready.strip() == b"ok", "staged-controller-api-not-ready")
    probes = Probes(inputs, runner, state)
    try:
        build = probes.buildkit()
        isolation = probes.isolation()
    finally:
        probes.cleanup()
    state.update({"phase": "ready", "validation": {"completedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "apiReadyz": True, "registryTLSAndAuth": True,
                  "buildkitMutualTLS": build, "cni": isolation, "podPidsLimit": 512, "probeCleanupComplete": True,
                  "adapterIssuedRunIsolationReceipt": False, "modelCalls": 0, "subjectBuilds": 0},
                  "remaining": ["Integrate the staged policy/catalog and private kubeconfig into the existing operator installation without replacing old policy/data.",
                                "Verify control-to-subject API and observer-Pod routing; no control routes or deployments were changed.",
                                "Run the controller's exact policy readiness/pin checks and obtain fresh per-run isolation/cleanup evidence.",
                                "Model execution, source builds, pipeline qualification, and credential rotation are separate approved operations."]})
    save_state(inputs, state)
    return {"status": "ready", "planDigest": inputs.plan_digest, "clusterUID": state["clusterUID"],
            "roleUID": state["roleUID"], "daemonID": state["daemonID"], "policySHA256": state["policySHA256"],
            "policyFile": "operator-data/policy.json", "evidenceFile": "ownership.json",
            "adapterIssuedRunIsolationReceipt": False}


def verify(inputs, runner, state=None):
    lock = inputs.root / "verification.lock"
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    identity = os.fstat(fd)
    os.close(fd)
    try:
        recorded = decode(read_file(inputs.root / "ownership.json"))
        if state is not None:
            require(recorded == state, "ownership-changed-before-verification")
        return verify_owned(inputs, runner, recorded)
    finally:
        require(lock.stat().st_ino == identity.st_ino, "verification-lock-replaced")
        lock.unlink()


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Failure("invalid-arguments")


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "validate", "apply", "verify"))
    parser.add_argument("--config", required=True, help="private, operator-completed bootstrap JSON")
    parser.add_argument("--approve-plan", help="exact digest returned by offline plan")
    parser.add_argument("--approve-existing-control", help="explicitly approved existing control cluster UID")
    parser.add_argument("--approve-privileged-buildkit", action="store_true", help="acknowledge the bounded rootful Docker build boundary")
    stage = "arguments"
    try:
        args = parser.parse_args(argv)
        stage = "offline-input-validation"
        inputs = load_inputs(args.config, fresh=args.mode != "verify")
        if args.mode in ("plan", "validate"):
            result = inputs.summary()
        else:
            require(args.approve_plan == inputs.plan_digest, "exact-plan-approval-required")
            require(args.approve_existing_control == inputs.config["control"]["clusterUID"], "existing-control-approval-required")
            require(args.approve_privileged_buildkit, "privileged-buildkit-approval-required")
            os.umask(0o077)
            stage = args.mode
            runner = Runner(inputs)
            result = apply(inputs, runner) if args.mode == "apply" else verify(inputs, runner)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Failure as error:
        print(json.dumps({"status": "blocked", "stage": stage, "code": str(error)}, sort_keys=True))
    except Exception:
        print(json.dumps({"status": "blocked", "stage": stage, "code": "input-or-operation-unavailable"}, sort_keys=True))
    return 1


if __name__ == "__main__":
    sys.exit(main())
