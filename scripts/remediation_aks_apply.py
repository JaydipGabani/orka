#!/usr/bin/env python3
"""Review-gated, fixed-footprint AKS foundation operations. No workload installer."""

import argparse
import base64
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "config/development/remediation-aks"
SPEC = importlib.util.spec_from_file_location("remediation_aks_plan", ROOT / "scripts/remediation_aks_plan.py")
plan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(plan)
require = plan.require
Failure = plan.Failure
AUTO_API = "2024-10-23"
ARM = "https://management.azure.com"
NEW_TEMPLATES = ("cleanup", "cleanup-access", "peering", "dns-link", "registry-pull")
REQUIRED_ACTIONS = {
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.Resources/subscriptions/resourceGroups/delete",
    "Microsoft.Resources/subscriptions/resourceGroups/resources/read",
    "Microsoft.Resources/deployments/read",
    "Microsoft.Resources/deployments/operations/read",
    "Microsoft.ContainerService/managedClusters/read",
    "Microsoft.ContainerService/managedClusters/delete",
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Compute/virtualMachines/instanceView/read",
    "Microsoft.Compute/virtualMachines/delete",
    "Microsoft.Authorization/permissions/read",
}
ABSENT_CODES = frozenset(("ResourceNotFound", "ResourceGroupNotFound", "NotFound", "RoleDefinitionDoesNotExist",
                         "RoleAssignmentNotFound", "ParentResourceNotFound"))
PREFLIGHT_QUEUE_ALLOWANCE_SECONDS = 600
PREFLIGHT_EXECUTION_SECONDS = 600
ACR_PULL_ROLE = "7f951dda-4ed3-4680-a7ca-43fe172d538d"
READ_ONLY_ACTIONS = {
    "group-metadata-read": {"Microsoft.Resources/subscriptions/resourceGroups/read"},
    "peering-metadata-read": {"Microsoft.Network/virtualNetworks/virtualNetworkPeerings/read"},
}


def missing_azure_response(stderr, rest):
    if rest:
        match = re.fullmatch(r"ERROR:\s*Not Found\((\{.*\})\)\s*", stderr, re.DOTALL)
        if not match:
            return False
        try:
            value = json.loads(match.group(1))
        except (ValueError, TypeError):
            return False
        if not isinstance(value, dict):
            return False
        error = value["error"] if "error" in value else value
        return isinstance(error, dict) and error.get("code") in ABSENT_CODES
    match = re.match(r"^ERROR:\s*\(([A-Za-z]+)\)", stderr)
    return bool(match and match.group(1) in ABSENT_CODES)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def utc():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def timestamp(value):
    return value.isoformat().replace("+00:00", "Z")


def source_hashes():
    files = sorted(p for p in SOURCE.iterdir() if p.is_file()) + [
        ROOT / "scripts/remediation_aks_plan.py", ROOT / "scripts/remediation_aks_apply.py"]
    return {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in files}


def public_key(path):
    data = plan.private_path(path).read_text().strip()
    parts = data.split()
    require(len(parts) in (2, 3) and parts[0] in ("ssh-ed25519", "ssh-rsa") and
            "\n" not in data and "PRIVATE" not in data, "public-ssh-key-file-required")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError:
        raise Failure("invalid-public-ssh-key") from None
    require(len(blob) >= 36 and int.from_bytes(blob[:4]) == len(parts[0]) and
            blob[4:4 + len(parts[0])] == parts[0].encode(), "invalid-public-ssh-key")
    return data


def redacted(value):
    if isinstance(value, dict):
        return {k: ("[redacted]" if k.lower() in
                    ("keydata", "adminpassword", "access_token", "authorization", "clientsecret")
                    else redacted(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redacted(v) for v in value]
    return value


def write_json(path, value):
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")
    path.chmod(0o600)


def arm_parameters(values):
    return {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
            "contentVersion": "1.0.0.0", "parameters": {k: {"value": v} for k, v in values.items()}}


def role_guids(scope):
    return {kind: str(uuid.uuid5(uuid.NAMESPACE_URL, scope["cleanupResourceGroupId"] + "/" + kind))
            for kind in ("resource-cleanup", "peering-cleanup", "group-metadata-read", "peering-metadata-read")}


def owned(resource, scope, owner, receipt, expected_id=None):
    require(isinstance(resource, dict), "owned-resource-required")
    require(resource.get("id", "").lower() ==
            (expected_id or scope["verificationResourceGroupId"]).lower(), "owned-resource-id-mismatch")
    tags = resource.get("tags") or {}
    require(all(tags.get(k) == v for k, v in {
        "orka-purpose": "isolated-remediation-verification",
        "orka-owner": owner,
        "orka-deployment": scope["verificationResourceGroupId"].split("/rg-")[-1],
        "orka-cleanup-receipt": receipt,
    }.items()), "resource-ownership-mismatch")


class Azure:
    def __init__(self, subscription, work, runner=subprocess.run):
        self.subscription = subscription
        self.work = work
        self.runner = runner
        self.serial = 0

    def cli(self, *arguments, absent=False, raw=False, timeout=900):
        command = plan.scoped_az(self.subscription, *arguments)
        try:
            result = self.runner(command, capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Failure("azure-command-unavailable-or-timed-out") from None
        if result.returncode:
            if absent and missing_azure_response(result.stderr, rest=arguments[0] == "rest"):
                return None
            raise Failure("azure-command-failed") from None
        if raw:
            return result.stdout
        if not result.stdout.strip():
            return None
        value = json.loads(result.stdout)
        plan.check_subscription_ids(value, self.subscription)
        return value

    def rest(self, method, identity, version, body=None, absent=False, text_file=None, raw=False):
        require(identity.startswith(f"/subscriptions/{self.subscription}/"), "rest-outside-subscription")
        require("?" not in identity and "#" not in identity and ".." not in identity, "invalid-rest-resource-id")
        arguments = ["rest", "--method", method, "--url", ARM + identity + "?api-version=" + version]
        if body is not None:
            plan.check_subscription_ids(body, self.subscription)
            self.serial += 1
            path = self.work / f"request-{self.serial}.json"
            write_json(path, body)
            arguments += ["--body", "@" + str(path)]
        if text_file is not None:
            arguments += ["--body", "@" + str(text_file), "--headers", "Content-Type=text/plain"]
        return self.cli(*arguments, absent=absent, raw=raw)

    def get(self, identity, version, absent=False):
        return self.rest("GET", identity, version, absent=absent)

    def deploy(self, name, template, values, group=None, preview=False, validation="Template",
               expected_parameters=None, expected_template=None):
        parameters = self.work / (name + ".parameters.json")
        write_json(parameters, arm_parameters(values))
        if expected_parameters is not None:
            require(sha(parameters.read_bytes()) == expected_parameters, "apply-parameters-not-reviewed")
        if expected_template is not None:
            require(sha(Path(template).read_bytes()) == expected_template, "apply-template-not-reviewed")
        arguments = ["deployment", "group" if group else "sub", "what-if" if preview else "create",
                     "--name", name, "--template-file", str(template), "--parameters", "@" + str(parameters)]
        arguments += ["--resource-group", group] if group else ["--location", "eastus2"]
        if preview:
            arguments += ["--validation-level", validation, "--no-pretty-print"]
        result = self.cli(*arguments, timeout=3600)
        write_json(self.work / (name + (".what-if.json" if preview else ".deployment.json")), redacted(result))
        return result


def compile_templates(work):
    result = {}
    for name in (*NEW_TEMPLATES, "main"):
        command = ["az", "bicep", "build", "--file", str(SOURCE / (name + ".bicep")), "--stdout"]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
        require(completed.returncode == 0 and not completed.stderr.strip(), "bicep-build-or-warning")
        value = json.loads(completed.stdout)
        destination = work / (name + ".arm.json")
        write_json(destination, value)
        result[name] = sha(destination.read_bytes())
    return result


def prepare(args, work, azure):
    require(not (work / "bundle.json").exists(), "fresh-bundle-directory-required")
    values = json.loads(plan.private_path(args.parameters).read_text())["parameters"]
    values = {k: v["value"] for k, v in values.items()}
    require(values["location"] == "eastus2", "unapproved-region")
    scope = plan.targets(args.subscription, values["suffix"], args.control_vnet_id, args.control_aks_id)
    account = azure.cli("account", "show", "--query",
                        "{subscription:id,tenant:tenantId,environment:environmentName}")
    require(account["subscription"] == args.subscription and account["environment"] == "AzureCloud",
            "account-scope-mismatch")
    for key in ("verificationResourceGroupId", "managedNodeResourceGroupId", "cleanupResourceGroupId"):
        require(azure.cli("group", "exists", "--name", scope[key].split("/")[-1]) is False,
                "unexpected-existing-resource-group")
    registry_name = scope["verificationRegistryId"].split("/")[-1]
    available = azure.cli("acr", "check-name", "--name", registry_name)
    require(available.get("nameAvailable") is True, "isolated-registry-name-unavailable")
    control = azure.get(scope["controlClusterId"], "2025-07-01")
    control_kubelet = kubelet_identity(control, args.subscription)
    if args.public_key_file:
        values["operatorSshPublicKey"] = public_key(args.public_key_file)
    key_ready = values["operatorSshPublicKey"].startswith(("ssh-rsa ", "ssh-ed25519 "))
    receipt = str(uuid.uuid4())
    values["cleanupReceipt"] = receipt
    hashes = source_hashes()
    values["sourceDigest"] = sha(wire(hashes))
    write_json(work / "compute-inputs.json", values)
    compiled = compile_templates(work)
    require(source_hashes() == hashes, "source-changed-during-compile")
    bundle = {"version": 1, "subscriptionId": args.subscription, "tenantId": account["tenant"],
              "scope": scope, "owner": values["owner"], "suffix": values["suffix"],
              "cleanupReceipt": receipt, "sourceHashes": hashes, "compiledHashes": compiled,
              "sourceDigest": sha(wire(hashes)), "computeInputsSha256": sha((work / "compute-inputs.json").read_bytes()),
              "publicKeyReady": key_ready, "roleGuids": role_guids(scope),
              "controlKubeletIdentity": control_kubelet}
    plan.check_subscription_ids(bundle, args.subscription)
    bootstrap = {"suffix": bundle["suffix"], "owner": bundle["owner"], "cleanupReceipt": receipt,
                 "sourceDigest": bundle["sourceDigest"], "location": "eastus2"}
    write_json(work / "bundle.json", bundle)
    preview = azure.deploy("review-cleanup-bootstrap", work / "cleanup.arm.json", bootstrap, preview=True)
    require(preview["status"] == "Succeeded", "cleanup-preview-failed")
    allowed = [scope["verificationResourceGroupId"].lower(), scope["cleanupResourceGroupId"].lower()]
    for change in preview["changes"]:
        rid = change["resourceId"].lower()
        require(change["changeType"] == "Create" and any(rid == p or rid.startswith(p + "/") for p in allowed),
                "unexpected-bootstrap-preview")
    print("Review bundle compiled; no Azure mutation. Independent review is required before bootstrap.")


def load_bundle(args, work):
    bundle = json.loads((work / "bundle.json").read_text())
    require(bundle["version"] == 1 and bundle["subscriptionId"] == args.subscription, "bundle-scope-mismatch")
    require(bundle["scope"] == plan.targets(args.subscription, bundle["suffix"],
            args.control_vnet_id, args.control_aks_id), "bundle-target-mismatch")
    require(source_hashes() == bundle["sourceHashes"], "reviewed-source-drift")
    require(args.reviewed_source_sha256 == bundle["sourceDigest"], "independent-review-digest-required")
    require(sha((work / "compute-inputs.json").read_bytes()) == bundle["computeInputsSha256"],
            "compute-input-drift")
    for name, digest in bundle["compiledHashes"].items():
        require(sha((work / (name + ".arm.json")).read_bytes()) == digest, "compiled-template-drift")
    plan.check_subscription_ids(bundle, args.subscription)
    return bundle


def save_receipt(work, receipt):
    write_json(work / "receipt.json", receipt)


def account_identity(azure, bundle, receipt):
    account = azure.get(bundle["scope"]["automationAccountId"], AUTO_API)
    owned(account, bundle["scope"], bundle["owner"], bundle["cleanupReceipt"],
          bundle["scope"]["automationAccountId"])
    identity = account["identity"]
    require(identity["type"] == "SystemAssigned" and not identity.get("userAssignedIdentities") and
            identity["tenantId"] == bundle["tenantId"], "unexpected-automation-identity")
    if "principalId" in receipt:
        require(receipt["principalId"] == identity["principalId"], "automation-principal-drift")
    return identity["principalId"]


def access(azure, bundle, receipt, node=False, peer=False):
    control = bundle["scope"]["controlVnetId"].split("/")
    values = {"suffix": bundle["suffix"], "principalId": receipt["principalId"],
              "resourceRoleGuid": bundle["roleGuids"]["resource-cleanup"],
              "peeringRoleGuid": bundle["roleGuids"]["peering-cleanup"],
              "groupMetadataRoleGuid": bundle["roleGuids"]["group-metadata-read"],
              "peerMetadataRoleGuid": bundle["roleGuids"]["peering-metadata-read"],
              "controlResourceGroup": control[4], "includeNodeGroup": node}
    deployed = azure.deploy("bounded-cleanup-access", azure.work / "cleanup-access.arm.json", values)
    outputs = deployed["properties"]["outputs"]
    assignments = receipt.setdefault("cleanupAssignments", {})
    for key, output in (("verification", "verificationAssignmentId"), ("groupsRead", "groupMetadataAssignmentId"),
                        ("nodes", "nodeAssignmentId")):
        if outputs[output]["value"]:
            assignments[key] = outputs[output]["value"]
    action_sets = {"resource-cleanup": REQUIRED_ACTIONS, "peering-cleanup": {
        "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/read",
        "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/delete"}, **READ_ONLY_ACTIONS}
    expected_scopes = {
        "resource-cleanup": [bundle["scope"]["verificationResourceGroupId"]] +
            ([bundle["scope"]["managedNodeResourceGroupId"]] if node else []),
        "peering-cleanup": ["/".join(bundle["scope"]["controlVnetId"].split("/")[:5])],
        "group-metadata-read": [f"/subscriptions/{bundle['subscriptionId']}"],
        "peering-metadata-read": ["/".join(bundle["scope"]["controlVnetId"].split("/")[:5])],
    }
    for name, expected_actions in action_sets.items():
        identity = f"/subscriptions/{bundle['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/" + bundle["roleGuids"][name]
        role = azure.get(identity, "2022-04-01")["properties"]
        require(role["type"] == "CustomRole" and role["roleName"] ==
                bundle["scope"]["verificationResourceGroupId"].split("/rg-")[-1] + "-" + name,
                "cleanup-role-drift")
        permissions = role["permissions"]
        require(len(permissions) == 1 and set(permissions[0]["actions"]) == expected_actions and
                not any(permissions[0].get(k) for k in ("notActions", "dataActions", "notDataActions")),
                "cleanup-role-permission-drift")
        require({s.lower() for s in role["assignableScopes"]} ==
                {s.lower() for s in expected_scopes[name]}, "cleanup-role-assignable-scope-drift")
    read_id, read_body = scoped_assignment(bundle, receipt, bundle["scope"]["controlVnetId"],
                                           "peering-metadata-read")
    existing = azure.get(read_id, "2022-04-01", absent=True)
    if existing is None:
        azure.rest("PUT", read_id, "2022-04-01", read_body)
        existing = azure.get(read_id, "2022-04-01")
    assignment_readback(existing, read_body, bundle["scope"]["controlVnetId"])
    assignments["peerMetadataRead"] = read_id
    group_read = azure.get(assignments["groupsRead"], "2022-04-01")
    group_role = f"/subscriptions/{bundle['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/" + bundle["roleGuids"]["group-metadata-read"]
    assignment_readback(group_read, {"properties": {"principalId": receipt["principalId"],
                                                  "roleDefinitionId": group_role}},
                        f"/subscriptions/{bundle['subscriptionId']}")
    if peer:
        identity, body = peer_assignment(bundle, receipt)
        require(azure.get(identity, "2022-04-01", absent=True) is None,
                "unexpected-existing-peering-assignment")
        azure.rest("PUT", identity, "2022-04-01", body)
        assignment_readback(azure.get(identity, "2022-04-01"), body,
                            bundle["scope"]["controlSidePeeringId"])
        receipt["peeringAssignmentId"] = identity
        assignments["peerDelete"] = identity
    receipt["nodeScopeReady"] = node
    receipt["peeringScopeReady"] = peer
    save_receipt(azure.work, receipt)


def peer_assignment(bundle, receipt):
    return scoped_assignment(bundle, receipt, bundle["scope"]["controlSidePeeringId"], "peering-cleanup")


def scoped_assignment(bundle, receipt, scope, role_name):
    role = (f"/subscriptions/{bundle['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/" +
            bundle["roleGuids"][role_name])
    identity = scope + "/providers/Microsoft.Authorization/roleAssignments/" + str(
        uuid.uuid5(uuid.NAMESPACE_URL, scope + "/" + role + "/" + receipt["principalId"]))
    return identity, {"properties": {"principalId": receipt["principalId"], "principalType": "ServicePrincipal",
                                    "roleDefinitionId": role}}


def assignment_readback(resource, body, scope):
    actual = resource["properties"]
    require(actual["principalId"] == body["properties"]["principalId"] and
            actual["roleDefinitionId"].lower() == body["properties"]["roleDefinitionId"].lower() and
            actual["scope"].lower() == scope.lower(), "cleanup-assignment-readback-mismatch")


def kubelet_identity(cluster, subscription):
    require(cluster["id"].lower().startswith(f"/subscriptions/{subscription}/"), "foreign-kubelet-cluster")
    identity = cluster["properties"]["identityProfile"]["kubeletidentity"]
    require(plan.UUID.fullmatch(identity["objectId"]) and plan.UUID.fullmatch(identity["clientId"]) and
            identity["resourceId"].lower().startswith(f"/subscriptions/{subscription}/"), "invalid-kubelet-identity")
    return {"objectId": identity["objectId"], "clientId": identity["clientId"], "resourceId": identity["resourceId"]}


def registry_pulls(azure, bundle, receipt, aks):
    scope = bundle["scope"]
    control = kubelet_identity(azure.get(scope["controlClusterId"], "2025-07-01"), bundle["subscriptionId"])
    require(control == bundle["controlKubeletIdentity"], "control-kubelet-identity-drift")
    verification = kubelet_identity(aks, bundle["subscriptionId"])
    require(verification["objectId"] != control["objectId"] and
            verification["resourceId"].lower().startswith(scope["managedNodeResourceGroupId"].lower() + "/"),
            "verification-kubelet-identity-not-isolated")
    registry = azure.get(scope["verificationRegistryId"], "2025-11-01")
    owned(registry, scope, bundle["owner"], bundle["cleanupReceipt"], scope["verificationRegistryId"])
    properties = registry["properties"]
    require(registry["sku"]["name"] == "Basic" and properties["adminUserEnabled"] is False and
            properties["anonymousPullEnabled"] is False and properties["publicNetworkAccess"] == "Enabled" and
            properties["roleAssignmentMode"] == "LegacyRegistryPermissions", "registry-boundary-drift")
    result = azure.deploy("isolated-registry-pulls", azure.work / "registry-pull.arm.json", {
        "registryName": registry["name"], "controlKubeletObjectId": control["objectId"],
        "verificationKubeletObjectId": verification["objectId"]},
        group=scope["verificationResourceGroupId"].split("/")[-1])
    assignments = {}
    role = f"/subscriptions/{bundle['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/{ACR_PULL_ROLE}"
    for name, principal in (("control", control["objectId"]), ("verification", verification["objectId"])):
        identity = result["properties"]["outputs"][name + "AssignmentId"]["value"]
        assignment_readback(azure.get(identity, "2022-04-01"), {
            "properties": {"principalId": principal, "roleDefinitionId": role}}, scope["verificationRegistryId"])
        assignments[name] = identity
    receipt["registryPullAssignments"] = assignments
    receipt["verificationKubeletIdentity"] = verification
    write_json(azure.work / "isolated-registry.json", {
        "registryId": registry["id"], "loginServer": properties["loginServer"], "sku": "Basic",
        "roleAssignmentMode": properties["roleAssignmentMode"], "adminUserEnabled": False,
        "anonymousPullEnabled": False, "kubeletIdentities": {"control": control, "verification": verification},
        "pullOnlyAssignments": assignments, "imageCopiesOrBuildCredentialsCreated": False})
    save_receipt(azure.work, receipt)

def manifest(bundle, receipt, cleanup=False):
    return {"version": 1, "subscriptionId": bundle["subscriptionId"], "tenantId": bundle["tenantId"],
            "principalId": receipt["principalId"], "suffix": bundle["suffix"], "owner": bundle["owner"],
            "cleanupReceipt": bundle["cleanupReceipt"], "controlVnetId": bundle["scope"]["controlVnetId"],
            "budgetStartUtc": receipt.get("T0", ""), "expiresAtUtc": receipt.get("deadline", ""),
            "requireNodeScope": cleanup, "requirePeeringScope": cleanup}


def preflight_job(azure, bundle, receipt):
    account = bundle["scope"]["automationAccountId"]
    job = account + "/jobs/" + str(uuid.uuid4())
    parameters = {"ManifestJson": wire(manifest(bundle, receipt)).decode(), "Mode": "Preflight"}
    azure.rest("PUT", job, AUTO_API, {"properties": {"runbook": {"name": "ExactFoundationCleanup"},
                                                  "parameters": parameters}})
    receipt["preflightJobId"] = job
    save_receipt(azure.work, receipt)
    end = time.monotonic() + PREFLIGHT_QUEUE_ALLOWANCE_SECONDS + PREFLIGHT_EXECUTION_SECONDS
    while time.monotonic() < end:
        state = azure.get(job, AUTO_API)["properties"]["status"]
        if state == "Completed":
            output = azure.rest("GET", job + "/output", AUTO_API, raw=True)
            try:
                proof = json.loads(output.strip())
            except ValueError:
                raise Failure("preflight-proof-output-invalid") from None
            require(proof == {"outcome": "preflight-succeeded", "principalMatched": True,
                              "coreDeleteAuthority": True, "postDeleteGroupRead": True,
                              "postDeletePeeringRead": True}, "preflight-proof-output-mismatch")
            receipt["preflightCompleted"] = timestamp(utc())
            save_receipt(azure.work, receipt)
            return
        require(state not in ("Failed", "Stopped", "Suspended"), "cleanup-preflight-failed")
        time.sleep(10)
    raise Failure("cleanup-preflight-timed-out")


def bootstrap(azure, bundle, receipt):
    scope = bundle["scope"]
    require(not receipt, "bootstrap-not-repeatable-without-operator-recovery")
    for key in ("verificationResourceGroupId", "managedNodeResourceGroupId", "cleanupResourceGroupId"):
        require(azure.cli("group", "exists", "--name", scope[key].split("/")[-1]) is False,
                "unexpected-existing-resource-group")
    for guid in bundle["roleGuids"].values():
        identity = f"/subscriptions/{bundle['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/{guid}"
        require(azure.get(identity, "2022-04-01", absent=True) is None, "unexpected-existing-role-definition")
    receipt.update({"phase": "bootstrap-intent", "subscriptionId": bundle["subscriptionId"],
                    "cleanupReceipt": bundle["cleanupReceipt"], "sourceDigest": bundle["sourceDigest"]})
    save_receipt(azure.work, receipt)
    status = azure.cli("provider", "show", "--namespace", "Microsoft.Automation",
                       "--query", "registrationState")
    if status != "Registered":
        azure.cli("provider", "register", "--namespace", "Microsoft.Automation", "--wait")
    values = {"suffix": bundle["suffix"], "owner": bundle["owner"], "cleanupReceipt": bundle["cleanupReceipt"],
              "sourceDigest": bundle["sourceDigest"], "location": "eastus2"}
    azure.deploy("bounded-cleanup-bootstrap", azure.work / "cleanup.arm.json", values)
    receipt["principalId"] = account_identity(azure, bundle, receipt)
    save_receipt(azure.work, receipt)
    access(azure, bundle, receipt)
    book = scope["automationAccountId"] + "/runbooks/ExactFoundationCleanup"
    azure.rest("PUT", book + "/draft/content", AUTO_API, text_file=SOURCE / "cleanup-runbook.ps1")
    azure.rest("POST", book + "/publish", AUTO_API)
    end = time.monotonic() + 180
    while time.monotonic() < end:
        if azure.get(book, AUTO_API)["properties"]["state"] == "Published":
            break
        time.sleep(5)
    else:
        raise Failure("runbook-publication-timed-out")
    content = azure.rest("GET", book + "/content", AUTO_API, raw=True)
    require(content.replace("\r\n", "\n").strip() ==
            (SOURCE / "cleanup-runbook.ps1").read_text().strip(), "published-runbook-content-mismatch")
    preflight_job(azure, bundle, receipt)
    receipt["phase"] = "bootstrap-ready"
    save_receipt(azure.work, receipt)


def schedules(azure, bundle, receipt, create=False):
    account = bundle["scope"]["automationAccountId"]
    start = dt.datetime.fromisoformat(receipt["T0"].replace("Z", "+00:00"))
    parameters = {"ManifestJson": wire(manifest(bundle, receipt, cleanup=True)).decode(), "Mode": "Cleanup"}
    for name, hours in (("PrimaryCleanup", 22), ("CatchupCleanup", 23)):
        identity = account + "/schedules/" + name
        binding = account + "/jobSchedules/" + str(uuid.uuid5(uuid.NAMESPACE_URL, account + "/" + name))
        scheduled = timestamp(start + dt.timedelta(hours=hours))
        if create:
            require(azure.get(identity, AUTO_API, absent=True) is None and
                    azure.get(binding, AUTO_API, absent=True) is None, "unexpected-existing-schedule")
            azure.rest("PUT", identity, AUTO_API, {"properties": {
                "frequency": "OneTime", "startTime": scheduled, "timeZone": "UTC",
                "description": "Exactly owned foundation cleanup; no recurrence."}, "name": name})
        if create:
            azure.rest("PUT", binding, AUTO_API, {"properties": {
                "schedule": {"name": name}, "runbook": {"name": "ExactFoundationCleanup"},
                "parameters": parameters}})
        actual = azure.get(identity, AUTO_API)["properties"]
        require(actual["frequency"] == "OneTime" and actual["isEnabled"] is True and
                dt.datetime.fromisoformat(actual["startTime"].replace("Z", "+00:00")) ==
                start + dt.timedelta(hours=hours), "schedule-readback-mismatch")
        actual_binding = azure.get(binding, AUTO_API)["properties"]
        require(actual_binding["schedule"]["name"] == name and
                actual_binding["runbook"]["name"] == "ExactFoundationCleanup" and
                actual_binding["parameters"] == parameters and not actual_binding.get("runOn"),
                "schedule-binding-readback-mismatch")


def validate_armed_preview(preview, bundle, receipt, prepared_group):
    require(preview["status"] == "Succeeded", "provider-validation-required")
    owned(prepared_group, bundle["scope"], bundle["owner"], bundle["cleanupReceipt"])
    require(prepared_group["tags"].get("orka-source-digest") == bundle["sourceDigest"],
            "prepared-source-digest-mismatch")
    expected = {
        "orka-purpose": "isolated-remediation-verification",
        "orka-owner": bundle["owner"],
        "orka-deployment": bundle["scope"]["verificationResourceGroupId"].split("/rg-")[-1],
        "orka-cleanup-receipt": bundle["cleanupReceipt"],
        "orka-source-digest": bundle["sourceDigest"],
        "orka-budget-start-utc": receipt["T0"],
        "orka-expires-at-utc": receipt["deadline"],
    }
    group = bundle["scope"]["verificationResourceGroupId"].lower()
    required = {group, bundle["scope"]["verificationClusterId"].lower(),
                bundle["scope"]["builderVirtualMachineId"].lower(), bundle["scope"]["verificationRegistryId"].lower()}
    found = set()
    for change in preview["changes"]:
        identity = change["resourceId"].lower()
        require(identity == group or identity.startswith(group + "/"), "provider-preview-outside-owned-group")
        require(identity not in found, "duplicate-provider-preview-resource")
        found.add(identity)
        if identity == group:
            require(change["changeType"] in ("Modify", "NoChange"), "prepared-group-recreation-forbidden")
            after = change.get("after") or {}
            require(after.get("tags") == expected and after.get("location", "").lower() == "eastus2",
                    "unexpected-prepared-group-change")
            before = change.get("before") or prepared_group
            require(before.get("tags") == prepared_group["tags"], "prepared-group-readback-drift")
            for delta in change.get("delta") or []:
                require(delta.get("path") == "tags" or delta.get("path", "").startswith("tags."),
                        "prepared-group-nontag-change")
        else:
            require(change["changeType"] == "Create", "existing-child-resource-forbidden")
    require(required.issubset(found), "incomplete-provider-preview")


def arm(azure, bundle, receipt):
    require(receipt.get("phase") == "bootstrap-ready" and receipt.get("preflightCompleted"),
            "successful-cleanup-preflight-required")
    require(bundle["publicKeyReady"], "real-public-ssh-key-required-before-clock")
    registry_name = bundle["scope"]["verificationRegistryId"].split("/")[-1]
    require(azure.cli("acr", "check-name", "--name", registry_name).get("nameAvailable") is True,
            "isolated-registry-name-unavailable")
    current_kubelet = kubelet_identity(azure.get(bundle["scope"]["controlClusterId"], "2025-07-01"),
                                      bundle["subscriptionId"])
    require(current_kubelet == bundle["controlKubeletIdentity"], "control-kubelet-identity-drift")
    account_identity(azure, bundle, receipt)
    group = azure.get(bundle["scope"]["verificationResourceGroupId"], "2024-03-01")
    cleanup_group = azure.get(bundle["scope"]["cleanupResourceGroupId"], "2024-03-01")
    owned(cleanup_group, bundle["scope"], bundle["owner"], bundle["cleanupReceipt"],
          bundle["scope"]["cleanupResourceGroupId"])
    require(cleanup_group["tags"].get("orka-source-digest") == bundle["sourceDigest"],
            "cleanup-group-source-drift")
    children = azure.cli("resource", "list", "--resource-group",
                         bundle["scope"]["verificationResourceGroupId"].split("/")[-1])
    require(not children, "prepared-verification-group-not-empty")
    start = utc() + dt.timedelta(minutes=10)
    receipt.update({"T0": timestamp(start), "deadline": timestamp(start + dt.timedelta(hours=24))})
    values = json.loads((azure.work / "compute-inputs.json").read_text())
    values["budgetStartUtc"] = receipt["T0"]
    preview = azure.deploy("provider-verification-preview", azure.work / "main.arm.json",
                           values, preview=True, validation="Provider")
    validate_armed_preview(preview, bundle, receipt, group)
    receipt.update({"phase": "arming-intent",
                    "applyParametersSha256": sha((azure.work / "provider-verification-preview.parameters.json").read_bytes()),
                    "applyTemplateSha256": bundle["compiledHashes"]["main"]})
    save_receipt(azure.work, receipt)
    schedules(azure, bundle, receipt, create=True)
    require(utc() < start, "arming-did-not-complete-before-clock")
    receipt["phase"] = "armed"
    receipt["armedReadbackUtc"] = timestamp(utc())
    save_receipt(azure.work, receipt)


def compute(azure, bundle, receipt):
    require(receipt.get("phase") == "armed", "armed-schedules-required")
    require(utc() < dt.datetime.fromisoformat(receipt["T0"].replace("Z", "+00:00")) +
            dt.timedelta(minutes=30), "fresh-armed-clock-required")
    schedules(azure, bundle, receipt)
    account_identity(azure, bundle, receipt)
    start = dt.datetime.fromisoformat(receipt["T0"].replace("Z", "+00:00"))
    while utc() < start:
        time.sleep(max(0, min(15, (start - utc()).total_seconds())))
    group = azure.get(bundle["scope"]["verificationResourceGroupId"], "2024-03-01")
    owned(group, bundle["scope"], bundle["owner"], bundle["cleanupReceipt"])
    for key, version in (("verificationClusterId", "2025-07-01"), ("builderVirtualMachineId", "2024-11-01")):
        require(azure.get(bundle["scope"][key], version, absent=True) is None, "unexpected-existing-compute")
    require(azure.cli("group", "exists", "--name",
            bundle["scope"]["managedNodeResourceGroupId"].split("/")[-1]) is False, "unexpected-existing-node-group")
    quota = azure.cli("vm", "list-usage", "--location", "eastus2",
                     "--query", "[?name.value=='standardDSv5Family' || name.value=='cores']")
    require(len(quota) == 2 and all(int(q["limit"]) - int(q["currentValue"]) >= 12 for q in quota),
            "approved-sku-quota-unavailable")
    parameters = azure.work / "provider-verification-preview.parameters.json"
    require(sha(parameters.read_bytes()) == receipt["applyParametersSha256"] and
            sha((azure.work / "main.arm.json").read_bytes()) == receipt["applyTemplateSha256"],
            "provider-validated-apply-input-drift")
    values = {k: v["value"] for k, v in json.loads(parameters.read_text())["parameters"].items()}
    require(values["budgetStartUtc"] == receipt["T0"] and
            values["cleanupReceipt"] == bundle["cleanupReceipt"] and
            values["sourceDigest"] == bundle["sourceDigest"], "armed-parameter-mismatch")
    receipt["phase"] = "compute-intent"
    save_receipt(azure.work, receipt)
    azure.deploy("bounded-verification-compute", azure.work / "main.arm.json", values,
                 expected_parameters=receipt["applyParametersSha256"],
                 expected_template=receipt["applyTemplateSha256"])
    require(sha((azure.work / "bounded-verification-compute.parameters.json").read_bytes()) ==
            receipt["applyParametersSha256"], "applied-parameter-digest-mismatch")
    node = azure.get(bundle["scope"]["managedNodeResourceGroupId"], "2024-03-01")
    require(node.get("managedBy", "").lower() == bundle["scope"]["verificationClusterId"].lower(),
            "node-group-owner-mismatch")
    access(azure, bundle, receipt, node=True)
    aks = azure.get(bundle["scope"]["verificationClusterId"], "2025-07-01")
    owned(aks, bundle["scope"], bundle["owner"], bundle["cleanupReceipt"],
          bundle["scope"]["verificationClusterId"])
    require(aks["properties"]["nodeResourceGroup"] ==
            bundle["scope"]["managedNodeResourceGroupId"].split("/")[-1], "node-group-mismatch")
    properties = aks["properties"]
    pools = properties["agentPoolProfiles"]
    require(len(pools) == 1 and pools[0]["count"] == 2 and pools[0]["vmSize"] == "Standard_D4s_v5" and
            pools[0].get("enableAutoScaling") is False and pools[0]["kubeletConfig"]["podMaxPids"] == 512,
            "node-pool-boundary-readback-mismatch")
    require(properties["currentKubernetesVersion"] == "1.35.8" and
            properties["networkProfile"]["networkDataplane"] == "cilium" and
            properties["networkProfile"]["networkPluginMode"] == "overlay" and
            properties["apiServerAccessProfile"]["enablePrivateCluster"] is True and
            properties["disableLocalAccounts"] is True and properties["aadProfile"]["enableAzureRBAC"] is True,
            "aks-boundary-readback-mismatch")
    vm = azure.get(bundle["scope"]["builderVirtualMachineId"], "2024-11-01")
    owned(vm, bundle["scope"], bundle["owner"], bundle["cleanupReceipt"],
          bundle["scope"]["builderVirtualMachineId"])
    require(not vm.get("identity") and vm["properties"]["hardwareProfile"]["vmSize"] == "Standard_D4s_v5",
            "builder-boundary-readback-mismatch")
    write_json(azure.work / "compute-health.json", {
        "clusterId": aks["id"], "clusterProvisioningState": properties["provisioningState"],
        "clusterPowerState": properties.get("powerState"), "version": properties["currentKubernetesVersion"],
        "poolCount": len(pools), "nodeCount": pools[0]["count"], "podMaxPids": 512,
        "builderId": vm["id"], "builderProvisioningState": vm["properties"]["provisioningState"],
        "runtimeQualification": "UNVERIFIED"})
    registry_pulls(azure, bundle, receipt, aks)
    schedules(azure, bundle, receipt)
    receipt["phase"] = "compute-ready"
    save_receipt(azure.work, receipt)


def connect(azure, bundle, receipt):
    require(receipt.get("phase") == "compute-ready", "dedicated-compute-required")
    scope = bundle["scope"]
    for own, remote, peer in (
            (scope["controlVnetId"], scope["verificationVnetId"], scope["controlSidePeeringId"]),
            (scope["verificationVnetId"], scope["controlVnetId"], scope["verificationSidePeeringId"])):
        require(azure.get(peer, "2024-05-01", absent=True) is None, "unexpected-existing-peering")
        azure.rest("PUT", peer, "2024-05-01", {"properties": {
            "remoteVirtualNetwork": {"id": remote}, "allowVirtualNetworkAccess": True,
            "allowForwardedTraffic": False, "allowGatewayTransit": False, "useRemoteGateways": False}})
        actual = azure.get(peer, "2024-05-01")["properties"]
        require(actual["remoteVirtualNetwork"]["id"].lower() == remote.lower() and
                actual["allowVirtualNetworkAccess"] is True and
                not any(actual[k] for k in ("allowForwardedTraffic", "allowGatewayTransit", "useRemoteGateways")),
                "peering-readback-mismatch")
    access(azure, bundle, receipt, node=True, peer=True)
    schedules(azure, bundle, receipt)
    group = scope["managedNodeResourceGroupId"].split("/")[-1]
    zones = azure.cli("network", "private-dns", "zone", "list", "--resource-group", group)
    require(len(zones) == 1 and zones[0]["id"].lower().startswith(scope["managedNodeResourceGroupId"].lower() + "/"),
            "private-dns-zone-not-unique")
    aks = azure.get(scope["verificationClusterId"], "2025-07-01")["properties"]
    require(aks["privateFQDN"].endswith("." + zones[0]["name"]), "private-dns-zone-origin-mismatch")
    link = zones[0]["id"] + "/virtualNetworkLinks/to-control"
    require(azure.get(link, "2024-06-01", absent=True) is None, "unexpected-existing-dns-link")
    tags = {"orka-cleanup-receipt": bundle["cleanupReceipt"], "orka-owner": bundle["owner"]}
    azure.deploy("bounded-control-dns-link", azure.work / "dns-link.arm.json",
                 {"zoneName": zones[0]["name"], "controlVnetId": scope["controlVnetId"], "ownershipTags": tags},
                 group=group)
    actual = azure.get(link, "2024-06-01")["properties"]
    require(actual["virtualNetwork"]["id"].lower() == scope["controlVnetId"].lower() and
            actual["registrationEnabled"] is False, "dns-link-readback-mismatch")
    subnet_id = scope["verificationVnetId"] + "/subnets/nodes"
    subnet = azure.get(subnet_id, "2024-05-01")["properties"]
    require(subnet["privateEndpointNetworkPolicies"] == "NetworkSecurityGroupEnabled",
            "private-endpoint-nsg-policy-not-enabled")
    endpoints = azure.cli("network", "private-endpoint", "list", "--resource-group", group,
                          "--query", "[].{id:id,subnetId:subnet.id,nics:networkInterfaces[].id}")
    require(len(endpoints) == 1 and endpoints[0]["subnetId"].lower() == subnet_id.lower() and
            len(endpoints[0]["nics"]) == 1, "private-endpoint-not-unique")
    effective = azure.cli("network", "nic", "list-effective-nsg", "--ids", endpoints[0]["nics"][0])
    expected_nsg = (scope["verificationResourceGroupId"] + "/providers/Microsoft.Network/networkSecurityGroups/" +
                    "orka-verify-" + bundle["suffix"] + "-nodes").lower()
    require(any(n["networkSecurityGroup"]["id"].lower() == expected_nsg for n in effective["value"]),
            "private-endpoint-effective-nsg-unverified")
    write_json(azure.work / "private-endpoint-policy.json", {
        "subnetId": subnet_id, "privateEndpointNetworkPolicies": subnet["privateEndpointNetworkPolicies"],
        "endpointId": endpoints[0]["id"], "effectiveNetworkSecurityGroups": effective,
        "trafficEnforcement": "UNVERIFIED_PENDING_TRUSTED_LIVE_PROBE"})
    receipt["phase"] = "private-connectivity-created"
    receipt["runtimeQualification"] = "UNVERIFIED"
    save_receipt(azure.work, receipt)


def retire(azure, bundle, receipt):
    scope = bundle["scope"]
    require(receipt.get("principalId"), "recorded-cleanup-identity-required")
    for identity, version in ((scope["verificationResourceGroupId"], "2024-03-01"),
                              (scope["managedNodeResourceGroupId"], "2024-03-01"),
                              (scope["controlSidePeeringId"], "2024-05-01")):
        require(azure.get(identity, version, absent=True) is None, "authoritative-absence-required-before-retirement")
    account_identity(azure, bundle, receipt)
    jobs = azure.get(scope["automationAccountId"] + "/jobs", AUTO_API)
    write_json(azure.work / "retired-cleanup-job-status.json", redacted(jobs))
    for name, identity in receipt.get("registryPullAssignments", {}).items():
        require(name in ("control", "verification") and identity.lower().startswith(
            scope["verificationRegistryId"].lower() + "/providers/microsoft.authorization/roleassignments/"),
            "registry-retirement-assignment-outside-scope")
        actual = azure.get(identity, "2022-04-01", absent=True)
        if actual is not None:
            principal = (bundle["controlKubeletIdentity"] if name == "control" else
                         receipt["verificationKubeletIdentity"])["objectId"]
            assignment_readback(actual, {"properties": {
                "principalId": principal, "roleDefinitionId":
                f"/subscriptions/{bundle['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/{ACR_PULL_ROLE}"}},
                scope["verificationRegistryId"])
            azure.rest("DELETE", identity, "2022-04-01")
            require(azure.get(identity, "2022-04-01", absent=True) is None,
                    "registry-assignment-retirement-unverified")
    expected = {
        "verification": (scope["verificationResourceGroupId"], "resource-cleanup"),
        "nodes": (scope["managedNodeResourceGroupId"], "resource-cleanup"),
        "groupsRead": (f"/subscriptions/{bundle['subscriptionId']}", "group-metadata-read"),
        "peerMetadataRead": (scope["controlVnetId"], "peering-metadata-read"),
        "peerDelete": (scope["controlSidePeeringId"], "peering-cleanup"),
    }
    for name, identity in receipt.get("cleanupAssignments", {}).items():
        require(name in expected, "unknown-cleanup-assignment")
        assignment_scope, role_name = expected[name]
        require(identity.lower().startswith(assignment_scope.lower() +
                "/providers/microsoft.authorization/roleassignments/"), "retirement-assignment-outside-scope")
        actual = azure.get(identity, "2022-04-01", absent=True)
        if actual is not None:
            role = (f"/subscriptions/{bundle['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/" +
                    bundle["roleGuids"][role_name])
            assignment_readback(actual, {"properties": {"principalId": receipt["principalId"],
                                                        "roleDefinitionId": role}}, assignment_scope)
            azure.rest("DELETE", identity, "2022-04-01")
            require(azure.get(identity, "2022-04-01", absent=True) is None, "assignment-retirement-unverified")
    for name, guid in bundle["roleGuids"].items():
        identity = f"/subscriptions/{bundle['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/{guid}"
        role = azure.get(identity, "2022-04-01", absent=True)
        if role is not None:
            require(role["properties"]["roleName"] ==
                    "orka-verify-" + bundle["suffix"] + "-" + name, "retirement-role-identity-mismatch")
            azure.rest("DELETE", identity, "2022-04-01")
            require(azure.get(identity, "2022-04-01", absent=True) is None, "role-retirement-unverified")
    receipt["metadataReadAuthorityRetired"] = True
    receipt["physicalAbsenceVerifiedUtc"] = timestamp(utc())
    save_receipt(azure.work, receipt)
    group = azure.get(scope["cleanupResourceGroupId"], "2024-03-01")
    owned(group, scope, bundle["owner"], bundle["cleanupReceipt"], scope["cleanupResourceGroupId"])
    azure.cli("group", "delete", "--name", scope["cleanupResourceGroupId"].split("/")[-1], "--yes")
    require(azure.cli("group", "exists", "--name", scope["cleanupResourceGroupId"].split("/")[-1]) is False,
            "cleanup-service-retirement-unverified")
    receipt["phase"] = "retired"
    save_receipt(azure.work, receipt)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("operation", choices=("plan", "bootstrap", "arm", "compute", "connect", "retire"))
    p.add_argument("--subscription", required=True)
    p.add_argument("--control-vnet-id", required=True)
    p.add_argument("--control-aks-id", required=True)
    p.add_argument("--work-dir", required=True)
    p.add_argument("--parameters")
    p.add_argument("--public-key-file")
    p.add_argument("--reviewed-source-sha256")
    return p


def main():
    args = parser().parse_args()
    os.umask(0o077)
    require(plan.UUID.fullmatch(args.subscription), "explicit-subscription-required")
    work = plan.private_path(args.work_dir)
    require(not any("quarantine" in part.lower() for part in work.parts), "quarantined-input-forbidden")
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    azure = Azure(args.subscription, work)
    if args.operation == "plan":
        require(args.parameters is not None, "private-parameters-required")
        prepare(args, work, azure)
        return
    bundle = load_bundle(args, work)
    account = azure.cli("account", "show", "--query",
                        "{subscription:id,tenant:tenantId,environment:environmentName}")
    require(account == {"subscription": args.subscription, "tenant": bundle["tenantId"],
                        "environment": "AzureCloud"}, "current-account-attestation-mismatch")
    receipt_path = work / "receipt.json"
    receipt = json.loads(receipt_path.read_text()) if receipt_path.exists() else {}
    if receipt:
        require(receipt["subscriptionId"] == args.subscription and
                receipt["cleanupReceipt"] == bundle["cleanupReceipt"] and
                receipt["sourceDigest"] == bundle["sourceDigest"], "receipt-identity-mismatch")
    actions = {"bootstrap": bootstrap, "arm": arm, "compute": compute, "connect": connect, "retire": retire}
    actions[args.operation](azure, bundle, receipt)
    print("Reviewed phase completed; receipts stored privately. No runtime qualification is implied.")


if __name__ == "__main__":
    try:
        main()
    except Failure as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError):
        print("invalid-private-input-or-azure-response", file=sys.stderr)
        sys.exit(1)
