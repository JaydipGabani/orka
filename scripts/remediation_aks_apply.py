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
from urllib.parse import urlencode

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
NEW_TEMPLATES = ("cleanup", "cleanup-access", "cleanup-recovery", "peering", "dns-link", "registry-pull")
AUTHORIZATION_MODEL = "builtin-group-cleanup-v1"
BUILTIN_ROLES = {
    "resource-cleanup": ("94877a25-7520-40c5-9c42-68e02e4758bd", "Resource Group Contributor", {
        "Microsoft.Resources/subscriptions/resourceGroups/read",
        "Microsoft.Resources/subscriptions/resourceGroups/write",
        "Microsoft.Resources/subscriptions/resourceGroups/delete",
    }),
    "group-metadata-read": ("acdd72a7-3385-48ef-bd42-f606fba81ae7", "Reader", {"*/read"}),
    "peering-cleanup": ("4d97b98b-1d4f-4787-a291-c67834d212e7", "Network Contributor", {
        "Microsoft.Authorization/*/read", "Microsoft.Insights/alertRules/*", "Microsoft.Network/*",
        "Microsoft.ResourceHealth/availabilityStatuses/read", "Microsoft.Resources/deployments/*",
        "Microsoft.Resources/subscriptions/resourceGroups/read", "Microsoft.Support/*",
    }),
}
ABSENT_CODES = frozenset(("ResourceNotFound", "ResourceGroupNotFound", "NotFound", "RoleDefinitionDoesNotExist",
                         "RoleAssignmentNotFound", "ParentResourceNotFound"))
PREFLIGHT_QUEUE_ALLOWANCE_SECONDS = 600
PREFLIGHT_EXECUTION_SECONDS = 600
ASSIGNMENT_READBACK_SECONDS = 120
ACR_PULL_ROLE = "7f951dda-4ed3-4680-a7ca-43fe172d538d"
QUALIFIED_DIAGNOSTIC = "ExactFoundationPreflightDiag542"
QUALIFIED_DIAGNOSTIC_SHA256 = "068e68640c1a982e9eecf8eaeca474cfff3c33087002d3a47c4ae6e85e7eaac9"
# These six read-only projections are created by the service, not our template:
# https://learn.microsoft.com/azure/automation/runtime-environment-overview#system-generated-runtime-environments
SYSTEM_RUNTIMES = {
    "PowerShell-5.1": ("PowerShell", "5.1"), "PowerShell-7.1": ("PowerShell", "7.1"),
    "PowerShell-7.2": ("PowerShell", "7.2"), "Python-2.7": ("Python", "2.7"),
    "Python-3.8": ("Python", "3.8"), "Python-3.10": ("Python", "3.10"),
}
PREFLIGHT_PROOF = {"outcome": "preflight-succeeded", "principalMatched": True,
                   "coreDeleteAuthority": True, "postDeleteGroupRead": True, "postDeletePeeringRead": True}


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


def builtin_role_guids():
    return {name: value[0] for name, value in BUILTIN_ROLES.items()}


def network_assignment_scopes(bundle):
    group = bundle["scope"]["verificationResourceGroupId"]
    prefix = "orka-verify-" + bundle["suffix"]
    return {
        "vnet": bundle["scope"]["verificationVnetId"],
        "nodes": group + "/providers/Microsoft.Network/networkSecurityGroups/" + prefix + "-nodes",
        "nat": group + "/providers/Microsoft.Network/natGateways/" + prefix + "-egress",
    }


def arm_guid(*values):
    return str(uuid.uuid5(uuid.UUID("11fb06fb-712d-4ddd-98c7-e71bbd588830"), "-".join(values)))


def validate_builtin_roles(azure, bundle):
    require(bundle.get("authorizationModel") == AUTHORIZATION_MODEL and
            bundle.get("roleGuids") == builtin_role_guids(), "explicit-builtin-authorization-required")
    for guid, name, actions in BUILTIN_ROLES.values():
        identity = f"/subscriptions/{bundle['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/{guid}"
        resource = azure.get(identity, "2022-04-01")
        role = resource["properties"]
        require(resource["id"].split("/")[-1].lower() == guid and
                role["type"] == "BuiltInRole" and role["roleName"] == name,
                "builtin-role-identity-drift")
        permissions = role["permissions"]
        require(len(permissions) == 1 and set(permissions[0]["actions"]) == actions and
                not any(permissions[0].get(key) for key in
                        ("notActions", "dataActions", "notDataActions", "condition", "conditionVersion")),
                "builtin-role-permission-drift")


def reject_custom_role_definitions(template):
    if isinstance(template, dict):
        require(str(template.get("type", "")).lower() != "microsoft.authorization/roledefinitions",
                "custom-role-creation-forbidden")
        for value in template.values():
            reject_custom_role_definitions(value)
    elif isinstance(template, list):
        for value in template:
            reject_custom_role_definitions(value)


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
               expected_parameters=None, expected_template=None, provider_validate=False):
        parameters = self.work / (name + ".parameters.json")
        write_json(parameters, arm_parameters(values))
        if expected_parameters is not None:
            require(sha(parameters.read_bytes()) == expected_parameters, "apply-parameters-not-reviewed")
        if expected_template is not None:
            require(sha(Path(template).read_bytes()) == expected_template, "apply-template-not-reviewed")
        arguments = ["deployment", "group" if group else "sub", "what-if" if preview else "create",
                     "--name", name, "--template-file", str(template), "--parameters", "@" + str(parameters)]
        arguments += ["--resource-group", group] if group else ["--location", "eastus2"]
        if provider_validate:
            require(not preview, "provider-create-validation-requires-create")
            validation_arguments = arguments.copy()
            validation_arguments[2] = "validate"
            checked_parameters = sha(parameters.read_bytes())
            checked_template = sha(Path(template).read_bytes())
            checked = self.cli(*validation_arguments, "--validation-level", "Provider", timeout=900)
            write_json(self.work / (name + ".provider-validation.json"), redacted(checked))
            require(not checked.get("error") and
                    checked.get("properties", {}).get("provisioningState") == "Succeeded",
                    "provider-validation-required-before-create")
            require(sha(parameters.read_bytes()) == checked_parameters and
                    sha(Path(template).read_bytes()) == checked_template,
                    "provider-validated-create-input-drift")
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
        reject_custom_role_definitions(value)
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
              "publicKeyReady": key_ready, "roleGuids": builtin_role_guids(),
              "authorizationModel": AUTHORIZATION_MODEL,
              "controlKubeletIdentity": control_kubelet}
    validate_builtin_roles(azure, bundle)
    plan.check_subscription_ids(bundle, args.subscription)
    bootstrap = {"suffix": bundle["suffix"], "owner": bundle["owner"], "cleanupReceipt": receipt,
                 "sourceDigest": bundle["sourceDigest"], "location": "eastus2"}
    write_json(work / "bundle.json", bundle)
    preview = azure.deploy("review-cleanup-bootstrap", work / "cleanup.arm.json", bootstrap,
                           preview=True, validation="Provider")
    require(preview["status"] == "Succeeded", "cleanup-preview-failed")
    allowed = [scope["verificationResourceGroupId"].lower(), scope["cleanupResourceGroupId"].lower()]
    for change in preview["changes"]:
        rid = change["resourceId"].lower()
        require(change["changeType"] == "Create" and any(rid == p or rid.startswith(p + "/") for p in allowed),
                "unexpected-bootstrap-preview")
    print("Review bundle compiled; no Azure mutation. Independent review is required before bootstrap.")


def partial_bootstrap_proof(azure, previous):
    scope = previous["scope"]
    expected_tags = {
        "orka-purpose": "isolated-remediation-verification", "orka-owner": previous["owner"],
        "orka-deployment": "orka-verify-" + previous["suffix"], "orka-cleanup-receipt": previous["cleanupReceipt"],
        "orka-source-digest": previous["sourceDigest"],
        "orka-budget-start-utc": "pending", "orka-expires-at-utc": "pending",
    }
    for key in ("verificationResourceGroupId", "cleanupResourceGroupId", "automationAccountId"):
        resource = azure.get(scope[key], AUTO_API if key == "automationAccountId" else "2024-03-01")
        owned(resource, scope, previous["owner"], previous["cleanupReceipt"], scope[key])
        require(resource["tags"] == expected_tags, "partial-bootstrap-ownership-tag-drift")
        if key == "automationAccountId":
            require(resource["properties"]["state"] == "Ok" and
                    resource["properties"]["disableLocalAuth"] is True and
                    resource["properties"]["publicNetworkAccess"] is False,
                    "partial-automation-account-boundary-drift")
    principal = account_identity(azure, previous, {})
    resources = azure.cli("resource", "list", "--resource-group", scope["cleanupResourceGroupId"].split("/")[-1])
    require({r["id"].lower() for r in resources} == {scope["automationAccountId"].lower()},
            "unexpected-partial-cleanup-resources")
    require(not azure.cli("resource", "list", "--resource-group",
                         scope["verificationResourceGroupId"].split("/")[-1]),
            "partial-verification-group-not-empty")
    require(azure.cli("group", "exists", "--name", scope["managedNodeResourceGroupId"].split("/")[-1]) is False,
            "partial-node-group-already-exists")
    for child in ("runtimeEnvironments/PowerShell74", "runbooks/ExactFoundationCleanup",
                  "schedules/PrimaryCleanup", "schedules/CatchupCleanup"):
        require(azure.get(scope["automationAccountId"] + "/" + child, AUTO_API, absent=True) is None,
                "unexpected-partial-cleanup-child")
    for guid in previous["roleGuids"].values():
        identity = f"/subscriptions/{previous['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/{guid}"
        require(azure.get(identity, "2022-04-01", absent=True) is None, "partial-role-definition-already-exists")
    query = urlencode({"api-version": "2022-04-01", "$filter": f"principalId eq '{principal}'"})
    assignments = azure.cli("rest", "--method", "GET", "--url",
        f"{ARM}/subscriptions/{previous['subscriptionId']}/providers/Microsoft.Authorization/roleAssignments?{query}")
    require(not assignments.get("nextLink") and assignments.get("value") == [],
            "partial-cleanup-identity-already-has-authority")
    operations = azure.cli("deployment", "operation", "group", "list", "--resource-group",
        scope["cleanupResourceGroupId"].split("/")[-1], "--name", "bounded-cleanup-service",
        "--query", "[].properties.statusMessage")
    require("RuntimeEnvironmentTags with value 7 cannot be greater than 3" in json.dumps(operations),
            "unsupported-partial-bootstrap-failure")
    return {"principalId": principal, "expectedTags": expected_tags, "scope": scope,
            "failure": "RuntimeEnvironmentTags7GreaterThan3", "authoringRoleAssignments": 0}


def previous_recovery_inputs(path, args):
    previous_work = plan.private_path(path)
    require(previous_work != plan.private_path(args.work_dir) and
            not any("quarantine" in part.lower() for part in previous_work.parts), "invalid-prior-recovery-workdir")
    previous = json.loads((previous_work / "bundle.json").read_text())
    receipt = json.loads((previous_work / "receipt.json").read_text())
    require(previous["subscriptionId"] == args.subscription and previous["scope"] ==
            plan.targets(args.subscription, previous["suffix"], args.control_vnet_id, args.control_aks_id),
            "prior-recovery-scope-mismatch")
    require(receipt == {"phase": "bootstrap-intent", "subscriptionId": args.subscription,
                       "cleanupReceipt": previous["cleanupReceipt"], "sourceDigest": previous["sourceDigest"]},
            "unsupported-prior-receipt-phase")
    require(sha((previous_work / "compute-inputs.json").read_bytes()) == previous["computeInputsSha256"],
            "prior-recovery-input-drift")
    for name, digest in previous["compiledHashes"].items():
        require(sha((previous_work / (name + ".arm.json")).read_bytes()) == digest, "prior-compiled-input-drift")
    return previous_work, previous


def failed_recovery_proof(path, args, previous_work, previous, partial, azure):
    failed_work = plan.private_path(path)
    require(failed_work not in (previous_work, plan.private_path(args.work_dir)) and
            not any("quarantine" in part.lower() for part in failed_work.parts), "invalid-failed-recovery-workdir")
    failed = json.loads((failed_work / "bundle.json").read_text())
    receipt = json.loads((failed_work / "receipt.json").read_text())
    link = json.loads((failed_work / "recovery-link.json").read_text())
    require(link["sha256"] == sha(wire(link["plan"])) and
            link["plan"]["kind"] == "automation-runtime-three-tag-recovery",
            "only-known-three-tag-recovery-failure-supported")
    require(all(failed[key] == previous[key] for key in (
        "subscriptionId", "tenantId", "scope", "owner", "suffix", "cleanupReceipt",
        "roleGuids", "controlKubeletIdentity", "publicKeyReady")), "failed-recovery-immutable-input-drift")
    require(link["plan"]["previousBundleSha256"] == sha((previous_work / "bundle.json").read_bytes()) and
            link["plan"]["previousReceiptSha256"] == sha((previous_work / "receipt.json").read_bytes()) and
            link["plan"]["previousSourceDigest"] == previous["sourceDigest"] and
            link["plan"]["nextSourceDigest"] == failed["sourceDigest"], "failed-recovery-origin-link-mismatch")
    require(link["plan"]["partialProof"] == partial, "failed-recovery-original-ownership-proof-mismatch")
    require(receipt == {
        "phase": "recovery-intent", "subscriptionId": previous["subscriptionId"],
        "cleanupReceipt": previous["cleanupReceipt"], "sourceDigest": failed["sourceDigest"],
        "principalId": partial["principalId"],
        "recoveryOf": {"sourceDigest": previous["sourceDigest"],
                       "receiptSha256": link["plan"]["previousReceiptSha256"],
                       "recoveryLinkSha256": link["sha256"]},
    }, "unsupported-failed-recovery-receipt")
    require(sha((failed_work / "compute-inputs.json").read_bytes()) == failed["computeInputsSha256"],
            "failed-recovery-compute-input-drift")
    for name, digest in failed["compiledHashes"].items():
        require(sha((failed_work / (name + ".arm.json")).read_bytes()) == digest, "failed-recovery-bom-drift")
    deployment_id = previous["scope"]["cleanupResourceGroupId"] + "/providers/Microsoft.Resources/deployments/bounded-cleanup-recovery"
    next_deployment_id = previous["scope"]["cleanupResourceGroupId"] + \
        "/providers/Microsoft.Resources/deployments/bounded-cleanup-zero-tags"
    zero_attempts = azure.cli("deployment", "group", "list", "--resource-group",
        previous["scope"]["cleanupResourceGroupId"].split("/")[-1],
        "--query", "[?name=='bounded-cleanup-zero-tags'].id")
    require(zero_attempts == [], "zero-tag-recovery-already-attempted")
    deployment = azure.get(deployment_id, "2024-03-01")
    require(deployment["id"].lower() == deployment_id.lower() and
            deployment["properties"]["provisioningState"] == "Failed", "failed-recovery-deployment-mismatch")
    operations = azure.cli("deployment", "operation", "group", "list", "--resource-group",
        previous["scope"]["cleanupResourceGroupId"].split("/")[-1], "--name", "bounded-cleanup-recovery",
        "--query", "[].properties")
    runtime = previous["scope"]["automationAccountId"] + "/runtimeEnvironments/PowerShell74"
    require(any(exact_runtime_key_failure(op, runtime) for op in operations),
            "exact-tag-key-limit-failure-required")
    return {"workDir": str(failed_work), "sourceDigest": failed["sourceDigest"], "deploymentId": deployment_id,
            "nextDeploymentId": next_deployment_id,
            "failure": "RuntimeEnvironmentTagKeyLength20GreaterThan16",
            "bundleSha256": sha((failed_work / "bundle.json").read_bytes()),
            "receiptSha256": sha((failed_work / "receipt.json").read_bytes()),
            "linkFileSha256": sha((failed_work / "recovery-link.json").read_bytes())}


def exact_runtime_key_failure(operation, runtime_id):
    if operation.get("provisioningState") != "Failed" or \
            (operation.get("targetResource") or {}).get("id", "").lower() != runtime_id.lower():
        return False
    status = operation.get("statusMessage")
    if isinstance(status, str):
        try:
            status = json.loads(status)
        except ValueError:
            return False
    if not isinstance(status, dict):
        return False
    error = status.get("error", status)
    return isinstance(error, dict) and error.get("code") == "BadRequest" and error.get("message") == \
        "Argument RuntimeEnvironmentTags.Key.Length with value 20 cannot be greater than 16."


def validate_recovery_preview(preview, previous, bundle):
    require(preview["status"] == "Succeeded", "recovery-provider-preview-failed")
    scope = previous["scope"]
    require(bundle["scope"] == scope, "recovery-scope-must-be-preserved")
    children = {scope["automationAccountId"].lower() + "/" + name.lower() for name in
                ("runtimeEnvironments/PowerShell74", "runbooks/ExactFoundationCleanup")}
    observed = set()
    for change in preview["changes"]:
        identity = change["resourceId"].lower()
        require(identity not in observed, "duplicate-recovery-preview-resource")
        observed.add(identity)
        if identity == scope["automationAccountId"].lower():
            require(change["changeType"] == "Ignore" and not change.get("delta"),
                    "recovery-must-not-update-existing-account")
            continue
        require(identity in children and change["changeType"] == "Create", "unexpected-recovery-create")
        after = change.get("after") or {}
        require(after.get("tags", {}) == {}, "recovery-child-tags-forbidden")
        properties = after.get("properties") or {}
        if identity.endswith("/runtimeenvironments/powershell74"):
            require(set(properties).issubset({"runtime", "defaultPackages"}) and
                    properties.get("runtime") == {"language": "PowerShell", "version": "7.4"} and
                    properties.get("defaultPackages", {}) == {}, "unexpected-recovery-runtime-properties")
        else:
            required = {"runbookType": "PowerShell", "runtimeEnvironment": "PowerShell74",
                        "logVerbose": False, "logProgress": False, "logActivityTrace": 0}
            # ARM masks the compiled empty draft object in what-if output.
            require(set(properties) == set(required) | {"draft"} and
                    all(type(properties[k]) is type(value) and properties[k] == value
                        for k, value in required.items()) and
                    properties["draft"] in ({}, "*******"), "unexpected-recovery-runbook-properties")
    require(children.issubset(observed), "recovery-preview-incomplete")


def prepare_recovery(args, work, azure):
    require(args.previous_work_dir and args.failed_recovery_work_dir and not (work / "bundle.json").exists(),
            "both-failed-attempts-and-fresh-recovery-plan-required")
    previous_work, previous = previous_recovery_inputs(args.previous_work_dir, args)
    proof = partial_bootstrap_proof(azure, previous)
    failed = failed_recovery_proof(args.failed_recovery_work_dir, args, previous_work, previous, proof, azure)
    values = json.loads((previous_work / "compute-inputs.json").read_text())
    hashes = source_hashes()
    values["sourceDigest"] = sha(wire(hashes))
    write_json(work / "compute-inputs.json", values)
    bundle = dict(previous)
    bundle.update({"sourceHashes": hashes, "sourceDigest": values["sourceDigest"],
                   "compiledHashes": compile_templates(work),
                   "computeInputsSha256": sha((work / "compute-inputs.json").read_bytes())})
    require(source_hashes() == hashes, "source-changed-during-recovery-plan")
    preview = azure.deploy("review-linked-cleanup-recovery", work / "cleanup-recovery.arm.json", {
        "prefix": "orka-verify-" + bundle["suffix"], "location": "eastus2"},
        group=bundle["scope"]["cleanupResourceGroupId"].split("/")[-1], preview=True, validation="Provider")
    validate_recovery_preview(preview, previous, bundle)
    link = {"kind": "automation-child-zero-tag-recovery", "previousWorkDir": str(previous_work),
            "previousBundleSha256": sha((previous_work / "bundle.json").read_bytes()),
            "previousReceiptSha256": sha((previous_work / "receipt.json").read_bytes()),
            "previousSourceDigest": previous["sourceDigest"], "nextSourceDigest": bundle["sourceDigest"],
            "partialProof": proof, "failedRecovery": failed}
    write_json(work / "bundle.json", bundle)
    write_json(work / "recovery-link.json", {"plan": link, "sha256": sha(wire(link))})
    print("Read-only linked recovery plan staged; separate user approval and independent review are required.")


def load_bundle(args, work):
    bundle = json.loads((work / "bundle.json").read_text())
    require(bundle["version"] == 1 and bundle["subscriptionId"] == args.subscription, "bundle-scope-mismatch")
    require(bundle["scope"] == plan.targets(args.subscription, bundle["suffix"],
            args.control_vnet_id, args.control_aks_id), "bundle-target-mismatch")
    require(source_hashes() == bundle["sourceHashes"], "reviewed-source-drift")
    require(bundle.get("authorizationModel") == AUTHORIZATION_MODEL and
            bundle["roleGuids"] == builtin_role_guids(), "explicit-builtin-authorization-required")
    require(sha(wire(bundle["sourceHashes"])) == bundle["sourceDigest"], "source-manifest-digest-mismatch")
    require(args.reviewed_source_sha256 == bundle["sourceDigest"], "independent-review-digest-required")
    require(sha((work / "compute-inputs.json").read_bytes()) == bundle["computeInputsSha256"],
            "compute-input-drift")
    for name, digest in bundle["compiledHashes"].items():
        require(sha((work / (name + ".arm.json")).read_bytes()) == digest, "compiled-template-drift")
    plan.check_subscription_ids(bundle, args.subscription)
    return bundle


def quota_blocked_inputs(args, path):
    previous_work = plan.private_path(path)
    require(previous_work != plan.private_path(args.work_dir), "new-authorization-bundle-required")
    previous = json.loads((previous_work / "bundle.json").read_text())
    receipt = json.loads((previous_work / "receipt.json").read_text())
    link = json.loads((previous_work / "recovery-link.json").read_text())
    require(previous["version"] == 1 and previous["subscriptionId"] == args.subscription and
            previous["scope"] == plan.targets(args.subscription, previous["suffix"],
                args.control_vnet_id, args.control_aks_id), "prior-authorization-scope-mismatch")
    require(not previous.get("authorizationModel") and
            previous["roleGuids"] == role_guids(previous["scope"]),
            "only-unassigned-custom-role-transition-supported")
    require(sha(wire(previous["sourceHashes"])) == previous["sourceDigest"] and
            sha((previous_work / "compute-inputs.json").read_bytes()) == previous["computeInputsSha256"],
            "prior-authorization-bundle-drift")
    for name, digest in previous["compiledHashes"].items():
        require(sha((previous_work / (name + ".arm.json")).read_bytes()) == digest, "prior-compiled-input-drift")
    require(link["sha256"] == sha(wire(link["plan"])) and
            link["plan"]["kind"] == "automation-child-zero-tag-recovery" and
            link["plan"]["nextSourceDigest"] == previous["sourceDigest"], "prior-zero-tag-link-required")
    original_work, original = previous_recovery_inputs(link["plan"]["previousWorkDir"], args)
    require(sha((original_work / "bundle.json").read_bytes()) == link["plan"]["previousBundleSha256"] and
            sha((original_work / "receipt.json").read_bytes()) == link["plan"]["previousReceiptSha256"],
            "original-receipt-link-drift")
    failed = link["plan"]["failedRecovery"]
    failed_work = plan.private_path(failed["workDir"])
    for name, key in (("bundle.json", "bundleSha256"), ("receipt.json", "receiptSha256"),
                      ("recovery-link.json", "linkFileSha256")):
        require(sha((failed_work / name).read_bytes()) == failed[key], "intermediate-receipt-link-drift")
    require(receipt == {
        "phase": "recovery-intent", "subscriptionId": previous["subscriptionId"],
        "cleanupReceipt": previous["cleanupReceipt"], "sourceDigest": previous["sourceDigest"],
        "principalId": link["plan"]["partialProof"]["principalId"],
        "recoveryOf": {"sourceDigest": original["sourceDigest"],
                       "receiptSha256": link["plan"]["previousReceiptSha256"],
                       "recoveryLinkSha256": link["sha256"], "failedRecovery": failed},
    }, "only-stopped-unassigned-recovery-supported")
    require(all(previous[key] == original[key] for key in (
        "subscriptionId", "tenantId", "scope", "owner", "suffix", "cleanupReceipt",
        "roleGuids", "controlKubeletIdentity", "publicKeyReady")), "prior-authorization-input-drift")
    return previous_work, previous, receipt, link["plan"]["partialProof"]["expectedTags"]


def granted_bootstrap_inputs(args, path):
    previous_work = plan.private_path(path)
    require(previous_work != plan.private_path(args.work_dir), "new-authorization-bundle-required")
    previous = json.loads((previous_work / "bundle.json").read_text())
    receipt = json.loads((previous_work / "receipt.json").read_text())
    record = json.loads((previous_work / "authorization-link.json").read_text())
    link = record["plan"]
    require(previous["version"] == 1 and previous["subscriptionId"] == args.subscription and
            previous["scope"] == plan.targets(args.subscription, previous["suffix"],
                args.control_vnet_id, args.control_aks_id) and
            previous.get("authorizationModel") == AUTHORIZATION_MODEL and
            previous["roleGuids"] == builtin_role_guids(), "prior-builtin-bootstrap-scope-mismatch")
    require(sha(wire(previous["sourceHashes"])) == previous["sourceDigest"] and
            sha((previous_work / "compute-inputs.json").read_bytes()) == previous["computeInputsSha256"],
            "prior-builtin-bootstrap-bundle-drift")
    for name, digest in previous["compiledHashes"].items():
        require(sha((previous_work / (name + ".arm.json")).read_bytes()) == digest, "prior-compiled-input-drift")
    require(record["sha256"] == sha(wire(link)) and link["kind"] == "builtin-authorization-transition" and
            link["authorizationModel"] == AUTHORIZATION_MODEL and
            link["nextSourceDigest"] == previous["sourceDigest"], "original-builtin-transition-required")
    original_work, original, _, _ = quota_blocked_inputs(args, link["previousWorkDir"])
    for name, key in (("bundle.json", "previousBundleSha256"), ("receipt.json", "previousReceiptSha256"),
                      ("recovery-link.json", "previousLinkSha256")):
        require(sha((original_work / name).read_bytes()) == link[key], "builtin-continuation-origin-drift")
    require(link["previousSourceDigest"] == original["sourceDigest"] and
            all(previous[key] == original[key] for key in (
                "subscriptionId", "tenantId", "scope", "owner", "suffix", "cleanupReceipt",
                "controlKubeletIdentity", "publicKeyReady")), "builtin-continuation-input-drift")
    original_values = json.loads((original_work / "compute-inputs.json").read_text())
    original_values["sourceDigest"] = previous["sourceDigest"]
    require(json.loads((previous_work / "compute-inputs.json").read_text()) == original_values,
            "builtin-continuation-compute-input-drift")
    assignments = receipt.get("cleanupAssignments")
    require(isinstance(assignments, dict) and set(assignments) == {"verification", "groupsRead"} and
            all(isinstance(value, str) and value for value in assignments.values()),
            "only-two-recorded-bootstrap-grants-supported")
    require(receipt == {
        "phase": "authorization-transition-intent", "subscriptionId": previous["subscriptionId"],
        "cleanupReceipt": previous["cleanupReceipt"], "sourceDigest": previous["sourceDigest"],
        "principalId": link["proof"]["principalId"], "authorizationModel": AUTHORIZATION_MODEL,
        "authorizationOf": {"previousSourceDigest": original["sourceDigest"],
            "previousReceiptSha256": link["previousReceiptSha256"], "authorizationLinkSha256": record["sha256"]},
        "cleanupAssignments": assignments,
    }, "only-recorded-prepublication-bootstrap-supported")
    return previous_work, previous, receipt, link["proof"]["accountTags"]


def quota_blocked_proof(azure, previous, receipt, original_tags, granted=False):
    scope = previous["scope"]
    tags = {**original_tags, "orka-source-digest": previous["sourceDigest"]}
    for key in ("verificationResourceGroupId", "cleanupResourceGroupId", "automationAccountId"):
        resource = azure.get(scope[key], AUTO_API if key == "automationAccountId" else "2024-03-01")
        owned(resource, scope, previous["owner"], previous["cleanupReceipt"], scope[key])
        require(resource["tags"] == (original_tags if key == "automationAccountId" else tags),
                "stopped-authorization-ownership-drift")
        if key == "automationAccountId":
            require(resource["properties"]["state"] == "Ok" and
                    resource["properties"]["disableLocalAuth"] is True and
                    resource["properties"]["publicNetworkAccess"] is False,
                    "stopped-automation-boundary-drift")
    require(account_identity(azure, previous, receipt) == receipt["principalId"], "stopped-principal-drift")
    if granted:
        validate_builtin_roles(azure, previous)
        expected = cleanup_assignment_scopes(previous)
        require(set(receipt["cleanupAssignments"]) == set(expected), "bootstrap-grant-set-drift")
        for key, (assignment_scope, role_name) in expected.items():
            identity = receipt["cleanupAssignments"][key]
            require(identity.lower().startswith(assignment_scope.lower() +
                    "/providers/microsoft.authorization/roleassignments/"), "bootstrap-grant-scope-drift")
            role = f"/subscriptions/{previous['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/" + \
                previous["roleGuids"][role_name]
            assignment_readback(azure.get(identity, "2022-04-01"), {"properties": {
                "principalId": receipt["principalId"], "roleDefinitionId": role}}, assignment_scope)
        audit_cleanup_assignments(azure, previous, receipt, expected, complete=True)
    else:
        require(principal_assignments(azure, previous, receipt["principalId"]) == [],
                "stopped-identity-has-existing-authority")
    require(not azure.cli("resource", "list", "--resource-group",
                         scope["verificationResourceGroupId"].split("/")[-1]),
            "stopped-verification-group-not-empty")
    require(azure.cli("group", "exists", "--name", scope["managedNodeResourceGroupId"].split("/")[-1]) is False,
            "stopped-node-group-already-exists")
    account = scope["automationAccountId"]
    runtime = azure.get(account + "/runtimeEnvironments/PowerShell74", AUTO_API)
    book = azure.get(account + "/runbooks/ExactFoundationCleanup", AUTO_API)
    require(runtime["id"].lower() == (account + "/runtimeEnvironments/PowerShell74").lower() and
            runtime.get("tags", {}) == {} and
            runtime["properties"]["runtime"] == {"language": "PowerShell", "version": "7.4"} and
            not runtime["properties"].get("defaultPackages"), "stopped-runtime-drift")
    require(book["id"].lower() == (account + "/runbooks/ExactFoundationCleanup").lower() and
            book.get("tags", {}) == {} and book["properties"]["state"] == "New" and
            book["properties"]["runbookType"] == "PowerShell" and
            book["properties"]["runtimeEnvironment"] == "PowerShell74",
            "only-unpublished-cleanup-runbook-supported")
    allowed = {account.lower(), runtime["id"].lower(), book["id"].lower()}
    resources = azure.cli("resource", "list", "--resource-group", scope["cleanupResourceGroupId"].split("/")[-1])
    require({item["id"].lower() for item in resources} <= allowed, "unexpected-stopped-cleanup-resource")
    for collection in ("jobs", "schedules", "jobSchedules"):
        items = azure.get(account + "/" + collection, AUTO_API)
        require(items.get("value") == [] and not items.get("nextLink"),
                "stopped-cleanup-has-jobs-or-schedules")
    for guid in role_guids(scope).values():
        identity = f"/subscriptions/{previous['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/{guid}"
        require(azure.get(identity, "2022-04-01", absent=True) is None, "legacy-custom-role-already-exists")
    deployment_name = "bounded-cleanup-builtin-access" if granted else "bounded-cleanup-access"
    deployment_id = f"/subscriptions/{previous['subscriptionId']}/providers/Microsoft.Resources/deployments/{deployment_name}"
    failed = azure.get(deployment_id, "2024-03-01")
    require(failed["id"].lower() == deployment_id.lower() and
            failed["properties"]["provisioningState"] == ("Succeeded" if granted else "Failed") and
            (granted or "RoleDefinitionLimitExceeded" in json.dumps(failed["properties"].get("error"))),
            "exact-role-capacity-stop-required")
    return {"principalId": receipt["principalId"], "groupTags": tags, "accountTags": original_tags,
            "failureDeploymentId": deployment_id,
            "failure": "recorded-grants-before-publication" if granted else "RoleDefinitionLimitExceeded",
            "runtimeId": runtime["id"], "unpublishedRunbookId": book["id"],
            "existingAssignments": len(receipt["cleanupAssignments"]) if granted else 0}


def prepare_builtin_resume(args, work, azure):
    require(args.previous_work_dir and not (work / "bundle.json").exists(), "fresh-builtin-resume-plan-required")
    continuation = getattr(args, "continue_granted_bootstrap", False)
    loader = granted_bootstrap_inputs if continuation else quota_blocked_inputs
    previous_work, previous, old_receipt, tags = loader(args, args.previous_work_dir)
    proof = (quota_blocked_proof(azure, previous, old_receipt, tags, granted=True) if continuation else
             quota_blocked_proof(azure, previous, old_receipt, tags))
    hashes = source_hashes()
    values = json.loads((previous_work / "compute-inputs.json").read_text())
    values["sourceDigest"] = sha(wire(hashes))
    write_json(work / "compute-inputs.json", values)
    bundle = {**previous, "authorizationModel": AUTHORIZATION_MODEL, "roleGuids": builtin_role_guids(),
              "sourceHashes": hashes, "sourceDigest": values["sourceDigest"],
              "compiledHashes": compile_templates(work),
              "computeInputsSha256": sha((work / "compute-inputs.json").read_bytes())}
    validate_builtin_roles(azure, bundle)
    require(source_hashes() == hashes, "source-changed-during-authorization-plan")
    link_file = "authorization-link.json" if continuation else "recovery-link.json"
    link = {"kind": "builtin-prepublication-continuation" if continuation else "builtin-authorization-transition",
            "authorizationModel": AUTHORIZATION_MODEL,
            "previousWorkDir": str(previous_work), "previousBundleSha256": sha((previous_work / "bundle.json").read_bytes()),
            "previousReceiptSha256": sha((previous_work / "receipt.json").read_bytes()),
            "previousLinkSha256": sha((previous_work / link_file).read_bytes()),
            "previousSourceDigest": previous["sourceDigest"], "nextSourceDigest": bundle["sourceDigest"],
            "proof": proof, "assignments": cleanup_assignment_scopes(bundle, node=True, peer=True),
            "networkAssignmentScopes": network_assignment_scopes(bundle),
            "builtinRoles": {name: {"id": guid, "name": title, "actions": sorted(actions)}
                             for name, (guid, title, actions) in BUILTIN_ROLES.items()},
            "kubernetesAuthorization": "native-rbac-after-temporary-operator-bootstrap"}
    write_json(work / "bundle.json", bundle)
    write_json(work / "authorization-link.json", {"plan": link, "sha256": sha(wire(link))})
    print("Read-only built-in authorization transition prepared; explicit review and approval are required.")


def resume_builtin_bootstrap(azure, bundle, receipt, args):
    require(not receipt and args.approved_authorization_sha256, "approved-new-authorization-receipt-required")
    record = json.loads((azure.work / "authorization-link.json").read_text())
    link = record["plan"]
    require(record["sha256"] == sha(wire(link)) == args.approved_authorization_sha256 and
            link["kind"] in ("builtin-authorization-transition", "builtin-prepublication-continuation") and
            link["authorizationModel"] == AUTHORIZATION_MODEL and
            link["nextSourceDigest"] == bundle["sourceDigest"], "approved-authorization-link-required")
    expected_roles = {name: {"id": guid, "name": title, "actions": sorted(actions)}
                      for name, (guid, title, actions) in BUILTIN_ROLES.items()}
    require(wire(link["assignments"]) == wire(cleanup_assignment_scopes(bundle, node=True, peer=True)) and
            link["networkAssignmentScopes"] == network_assignment_scopes(bundle) and
            link["builtinRoles"] == expected_roles and
            link["kubernetesAuthorization"] == "native-rbac-after-temporary-operator-bootstrap",
            "authorization-plan-does-not-match-execution")
    continuation = link["kind"] == "builtin-prepublication-continuation"
    loader = granted_bootstrap_inputs if continuation else quota_blocked_inputs
    previous_work, previous, old_receipt, tags = loader(args, link["previousWorkDir"])
    require(previous["sourceDigest"] == link["previousSourceDigest"], "authorization-origin-source-drift")
    link_file = "authorization-link.json" if continuation else "recovery-link.json"
    for name, key in (("bundle.json", "previousBundleSha256"), ("receipt.json", "previousReceiptSha256"),
                      (link_file, "previousLinkSha256")):
        require(sha((previous_work / name).read_bytes()) == link[key], "authorization-origin-record-drift")
    require(all(bundle[key] == previous[key] for key in (
        "subscriptionId", "tenantId", "scope", "owner", "suffix", "cleanupReceipt",
        "controlKubeletIdentity", "publicKeyReady")), "authorization-transition-scope-drift")
    values = json.loads((previous_work / "compute-inputs.json").read_text())
    values["sourceDigest"] = bundle["sourceDigest"]
    require(json.loads((azure.work / "compute-inputs.json").read_text()) == values,
            "authorization-transition-compute-input-drift")
    proof = (quota_blocked_proof(azure, previous, old_receipt, tags, granted=True) if continuation else
             quota_blocked_proof(azure, previous, old_receipt, tags))
    require(proof == link["proof"],
            "stopped-authorization-proof-drift")
    validate_builtin_roles(azure, bundle)
    receipt.update({"phase": "authorization-transition-intent", "subscriptionId": bundle["subscriptionId"],
                    "cleanupReceipt": bundle["cleanupReceipt"], "sourceDigest": bundle["sourceDigest"],
                    "principalId": old_receipt["principalId"], "authorizationModel": AUTHORIZATION_MODEL,
                    "authorizationOf": {"previousSourceDigest": previous["sourceDigest"],
                        "previousReceiptSha256": link["previousReceiptSha256"],
                        "authorizationLinkSha256": record["sha256"]}})
    if continuation:
        receipt["cleanupAssignments"] = dict(old_receipt["cleanupAssignments"])
    save_receipt(azure.work, receipt)
    for key in ("verificationResourceGroupId", "cleanupResourceGroupId"):
        identity = bundle["scope"][key]
        azure.cli("tag", "update", "--resource-id", identity, "--operation", "Merge",
                  "--tags", "orka-source-digest=" + bundle["sourceDigest"])
        actual = azure.get(identity, "2024-03-01")
        require(actual["tags"] == {**link["proof"]["groupTags"], "orka-source-digest": bundle["sourceDigest"]},
                "authorization-transition-tag-drift")
    finish_bootstrap(azure, bundle, receipt)


def qualified_bootstrap_inputs(args, paths):
    work = plan.private_path(args.work_dir)
    directories = {name: plan.private_path(path) for name, path in paths.items()}
    base_names = {"previous", "preflight", "diagnostic"}
    rearming = set(directories) == base_names | {"abandoned", "rollback"}
    require((set(directories) == base_names or rearming) and
            len(set(directories.values())) == len(directories) and
            all(not work.is_relative_to(path) and not path.is_relative_to(work) for path in directories.values()),
            "fresh-qualified-bootstrap-directory-required")
    filenames = {"previous": ("bundle.json", "receipt.json", "authorization-link.json"),
                 "preflight": ("plan.json", "job-request.json", "receipt.json", "safe-output.json"),
                 "diagnostic": ("receipt.json", "safe-output.json")}
    if rearming:
        filenames.update({
            "abandoned": ("bundle.json", "receipt.json", "authorization-link.json", "compute-inputs.json",
                          "provider-verification-preview.parameters.json", "provider-verification-preview.what-if.json"),
            "rollback": ("receipt.json", "failed-arming-receipt.json"),
        })
    hashes, records = {}, {}
    for name, directory in directories.items():
        hashes[name], records[name] = {}, {}
        for filename in filenames[name]:
            raw = (directory / filename).read_bytes()
            hashes[name][filename] = sha(raw)
            records[name][filename] = json.loads(raw)
    previous = records["previous"]["bundle.json"]
    old = records["previous"]["receipt.json"]
    record = records["previous"]["authorization-link.json"]
    link = record["plan"]
    require(record["sha256"] == sha(wire(link)) and link["kind"] == "builtin-prepublication-continuation" and
            link["authorizationModel"] == AUTHORIZATION_MODEL and
            link["nextSourceDigest"] == previous["sourceDigest"], "qualified-continuation-link-required")
    origin_work, origin, origin_receipt, tags = granted_bootstrap_inputs(args, link["previousWorkDir"])
    for filename, key in (("bundle.json", "previousBundleSha256"), ("receipt.json", "previousReceiptSha256"),
                          ("authorization-link.json", "previousLinkSha256")):
        require(sha((origin_work / filename).read_bytes()) == link[key], "qualified-origin-record-drift")
    require(link["previousSourceDigest"] == origin["sourceDigest"] and
            previous["version"] == 1 and previous.get("authorizationModel") == AUTHORIZATION_MODEL and
            previous["roleGuids"] == builtin_role_guids() and
            sha(wire(previous["sourceHashes"])) == previous["sourceDigest"] and
            all(previous[key] == origin[key] for key in (
                "subscriptionId", "tenantId", "scope", "suffix", "owner", "cleanupReceipt",
                "controlKubeletIdentity", "publicKeyReady")), "qualified-origin-bundle-drift")
    values = json.loads((origin_work / "compute-inputs.json").read_text())
    values["sourceDigest"] = previous["sourceDigest"]
    require(json.loads((directories["previous"] / "compute-inputs.json").read_text()) == values and
            sha((directories["previous"] / "compute-inputs.json").read_bytes()) == previous["computeInputsSha256"],
            "qualified-pending-compute-inputs-required")
    require(set(previous["compiledHashes"]) == {*NEW_TEMPLATES, "main"}, "qualified-template-set-drift")
    for name, digest in previous["compiledHashes"].items():
        require(sha((directories["previous"] / (name + ".arm.json")).read_bytes()) == digest,
                "qualified-previous-template-drift")
    account = previous["scope"]["automationAccountId"]
    failed_job = old.get("preflightJobId", "")
    require(failed_job.startswith(account + "/jobs/") and
            plan.UUID.fullmatch(failed_job.removeprefix(account + "/jobs/")), "qualified-failed-job-id-required")
    require(old == {
        "phase": "authorization-transition-intent", "subscriptionId": previous["subscriptionId"],
        "cleanupReceipt": previous["cleanupReceipt"], "sourceDigest": previous["sourceDigest"],
        "principalId": origin_receipt["principalId"], "authorizationModel": AUTHORIZATION_MODEL,
        "authorizationOf": {"previousSourceDigest": origin["sourceDigest"],
            "previousReceiptSha256": link["previousReceiptSha256"], "authorizationLinkSha256": record["sha256"]},
        "cleanupAssignments": origin_receipt["cleanupAssignments"], "nodeScopeReady": False,
        "peeringScopeReady": False, "preflightJobId": failed_job,
    }, "only-unarmed-failed-preflight-intent-supported")
    require(link["proof"]["accountTags"] == tags, "qualified-account-tag-origin-drift")
    passed = records["preflight"]["receipt.json"]
    approved = records["preflight"]["plan.json"]
    request = records["preflight"]["job-request.json"]
    diagnostic = records["diagnostic"]["receipt.json"]
    original_book = account + "/runbooks/ExactFoundationCleanup"
    diagnostic_book = account + "/runbooks/" + QUALIFIED_DIAGNOSTIC
    for evidence in (passed, diagnostic):
        require(evidence["jobId"].startswith(account + "/jobs/") and
                plan.UUID.fullmatch(evidence["jobId"].removeprefix(account + "/jobs/")) and
                evidence["jobStatus"] == "Completed" and evidence["jobPutAttempts"] == 1 and
                evidence["sourceReviewClosed"] is True, "qualified-completed-reviewed-job-required")
    require(len({failed_job, passed["jobId"], diagnostic["jobId"]}) == 3, "qualified-three-distinct-jobs-required")
    source_key = "config/development/remediation-aks/cleanup-runbook.ps1"
    require(approved["kind"] == "corrected-original-preflight-once" and
            approved["subscriptionId"] == previous["subscriptionId"] and
            approved["jobId"] == passed["jobId"] and approved["runbookId"] == original_book and
            approved["allowedJobPuts"] == 1 and approved["preflightRuntimeLimitSeconds"] == PREFLIGHT_EXECUTION_SECONDS and
            approved["noGrantsOrSchedulesOrCompute"] is True and
            approved["foundationInputs"] == passed["foundationInputs"] == hashes["previous"] and
            approved["jobRequestSha256"] == passed["requestSha256"] == hashes["preflight"]["job-request.json"] and
            passed["safeOutputSha256"] == hashes["preflight"]["safe-output.json"] and
            passed["phase"] == "corrected-preflight-passed" and
            passed["foundationReceiptsUnchanged"] is True and passed["noPermissionScheduleComputeChanges"] is True and
            passed["originalRunbookUnchanged"] is True, "qualified-corrected-preflight-evidence-mismatch")
    require(approved["currentSourceDigest"] == passed["sourceDigest"] ==
            sha(wire(approved["currentSourceHashes"])) and
            approved["originalPublishedRunbookSha256"] == passed["originalRunbookSha256"] ==
            previous["sourceHashes"][source_key] == sha((SOURCE / "cleanup-runbook.ps1").read_bytes()),
            "qualified-published-source-drift")
    current = source_hashes()
    allowed_changes = {"scripts/remediation_aks_apply.py", "config/development/remediation-aks/README.md"}
    require(set(current) == set(approved["currentSourceHashes"]) == set(previous["sourceHashes"]) and
            all(current[key] == approved["currentSourceHashes"][key] == previous["sourceHashes"][key]
                for key in current if key not in allowed_changes), "qualified-resource-source-footprint-drift")
    require(request == {"properties": {"runbook": {"name": "ExactFoundationCleanup"},
                                      "parameters": runbook_parameters(previous, old)}} and
            approved["expectedManifestDigest"] == sha(wire(manifest(previous, old))) and
            wire(records["preflight"]["safe-output.json"]) == wire(PREFLIGHT_PROOF),
            "qualified-original-preflight-proof-required")
    require(diagnostic["runbookId"] == diagnostic_book and
            diagnostic["runbookSHA256"] == QUALIFIED_DIAGNOSTIC_SHA256 and
            diagnostic["safeOutputSHA256"] == hashes["diagnostic"]["safe-output.json"] and
            diagnostic["originalRunbookUnchanged"] is True and diagnostic["foundationRecordsUnchanged"] is True and
            records["diagnostic"]["safe-output.json"].get("outcome") == "diagnostic-succeeded",
            "qualified-diagnostic-provenance-mismatch")
    if rearming:
        previous = qualified_arming_rollback_inputs(directories, records, hashes, previous, old, tags)
    return previous, old, tags, records, hashes


def qualified_arming_rollback_inputs(directories, records, hashes, previous, old, tags):
    abandoned = records["abandoned"]
    bundle, failed, record = (abandoned[name] for name in ("bundle.json", "receipt.json", "authorization-link.json"))
    link = record["plan"]
    base_paths = {name: str(directories[name]) for name in ("previous", "preflight", "diagnostic")}
    base_hashes = {name: hashes[name] for name in base_paths}
    require(record["sha256"] == sha(wire(link)) and link == qualified_bootstrap_link(
        base_paths, base_hashes, previous, bundle, link["proof"]),
        "abandoned-qualified-link-required")
    require(bundle == {**previous, "sourceHashes": bundle["sourceHashes"], "sourceDigest": bundle["sourceDigest"],
                       "computeInputsSha256": bundle["computeInputsSha256"]} and
            sha(wire(bundle["sourceHashes"])) == bundle["sourceDigest"] and
            set(bundle["sourceHashes"]) == set(previous["sourceHashes"]) and
            all(bundle["sourceHashes"][key] == previous["sourceHashes"][key] for key in previous["sourceHashes"]
                if key not in ("scripts/remediation_aks_apply.py", "config/development/remediation-aks/README.md")),
            "abandoned-qualified-bundle-drift")
    values = json.loads((directories["previous"] / "compute-inputs.json").read_text())
    values["sourceDigest"] = bundle["sourceDigest"]
    require(abandoned["compute-inputs.json"] == values and
            hashes["abandoned"]["compute-inputs.json"] == bundle["computeInputsSha256"],
            "abandoned-compute-input-drift")
    for name, digest in bundle["compiledHashes"].items():
        require(sha((directories["abandoned"] / (name + ".arm.json")).read_bytes()) == digest,
                "abandoned-compiled-template-drift")
    require(hashes["abandoned"]["receipt.json"] == hashes["rollback"]["failed-arming-receipt.json"] and
            (directories["abandoned"] / "receipt.json").read_bytes() ==
            (directories["rollback"] / "failed-arming-receipt.json").read_bytes(),
            "abandoned-arming-receipt-copy-drift")
    for name in ("T0", "deadline"):
        require(isinstance(failed.get(name), str) and re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", failed[name]), "abandoned-unarmed-clock-required")
    start = dt.datetime.fromisoformat(failed["T0"].replace("Z", "+00:00"))
    require(start.second != 0 and failed["deadline"] == timestamp(start + dt.timedelta(hours=24)),
            "only-nonminute-unarmed-clock-rollback-supported")
    passed = records["preflight"]["receipt.json"]
    expected = qualified_bootstrap_intent(bundle, previous, old, passed, base_hashes, record["sha256"])
    expected.update({"phase": "arming-intent", "preflightJobId": passed["jobId"],
        "preflightCompleted": passed["endTime"], "T0": failed["T0"], "deadline": failed["deadline"],
        "applyParametersSha256": hashes["abandoned"]["provider-verification-preview.parameters.json"],
        "applyTemplateSha256": bundle["compiledHashes"]["main"]})
    require(wire(failed) == wire(expected), "only-abandoned-unarmed-intent-supported")
    values["budgetStartUtc"] = failed["T0"]
    require(abandoned["provider-verification-preview.parameters.json"] == arm_parameters(values),
            "abandoned-arming-parameter-drift")
    prepared = {"id": bundle["scope"]["verificationResourceGroupId"], "location": "eastus2",
                "tags": {**tags, "orka-source-digest": bundle["sourceDigest"]}}
    validate_armed_preview(abandoned["provider-verification-preview.what-if.json"], bundle, failed, prepared)
    account = bundle["scope"]["automationAccountId"]
    schedule_id = account + "/schedules/PrimaryCleanup"
    binding_id = account + "/jobSchedules/" + str(uuid.uuid5(uuid.NAMESPACE_URL, account + "/PrimaryCleanup"))
    require(wire(records["rollback"]["receipt.json"]) == wire({
        "phase": "exact-partial-arming-rollback-verified", "oldSourceDigest": bundle["sourceDigest"],
        "oldReceiptSha256": hashes["abandoned"]["receipt.json"], "abandonedUnarmedT0": failed["T0"],
        "abandonedUnarmedDeadline": failed["deadline"], "scheduleId": schedule_id, "bindingId": binding_id,
        "deleted": [binding_id, schedule_id], "noComputeExisted": True,
    }), "exact-approved-unarmed-rollback-required")
    return bundle


def qualified_collection(azure, identity, version=AUTO_API):
    result = azure.get(identity, version)
    require(isinstance(result, dict) and isinstance(result.get("value"), list) and not result.get("nextLink"),
            "qualified-inventory-incomplete")
    items = result["value"]
    require(all(isinstance(item, dict) and isinstance(item.get("id"), str) for item in items) and
            len({item["id"].lower() for item in items}) == len(items), "qualified-inventory-identity-drift")
    return items


def qualified_content(azure, identity, expected):
    content = azure.rest("GET", identity + "/content", AUTO_API, raw=True).replace("\r\n", "\n")
    require(len(content) <= 65536, "qualified-published-content-too-large")
    # Automation's text upload can add one final newline. Do not normalize code.
    normalization = "none"
    if sha(content.encode()) != expected and content.endswith("\n"):
        content = content[:-1]
        normalization = "one-transport-newline"
    require(sha(content.encode()) == expected, "qualified-published-content-mismatch")
    return {"sourceSha256": expected, "normalization": normalization}


def qualified_bootstrap_proof(azure, previous, old, tags, records, group_digest=None, promoted_group_digest=None):
    scope = previous["scope"]
    account = scope["automationAccountId"]
    group_tags = {**tags, "orka-source-digest": group_digest or previous["sourceDigest"]}
    group_sources = {}
    require(tags.get("orka-budget-start-utc") == tags.get("orka-expires-at-utc") == "pending",
            "qualified-unarmed-tags-required")
    for key in ("verificationResourceGroupId", "cleanupResourceGroupId", "automationAccountId"):
        resource = azure.get(scope[key], AUTO_API if key == "automationAccountId" else "2024-03-01")
        owned(resource, scope, previous["owner"], previous["cleanupReceipt"], scope[key])
        if key == "automationAccountId":
            require(resource["tags"] == tags, "qualified-ownership-or-clock-drift")
            require(resource["properties"]["state"] == "Ok" and
                    resource["properties"]["disableLocalAuth"] is True and
                    resource["properties"]["publicNetworkAccess"] is False, "qualified-account-boundary-drift")
        else:
            permitted_tags = [group_tags]
            if promoted_group_digest is not None:
                permitted_tags.append({**group_tags, "orka-source-digest": promoted_group_digest})
            require(resource["tags"] in permitted_tags, "qualified-ownership-or-clock-drift")
            group_sources[scope[key]] = resource["tags"]["orka-source-digest"]
    require(account_identity(azure, previous, old) == old["principalId"], "qualified-principal-drift")
    validate_builtin_roles(azure, previous)
    expected_assignments = cleanup_assignment_scopes(previous)
    for key, (assignment_scope, role_name) in expected_assignments.items():
        identity = old["cleanupAssignments"][key]
        role = f"/subscriptions/{previous['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/" + \
            previous["roleGuids"][role_name]
        assignment_readback(azure.get(identity, "2022-04-01"), {"properties": {
            "principalId": old["principalId"], "roleDefinitionId": role}}, assignment_scope)
    audit_cleanup_assignments(azure, previous, old, expected_assignments, complete=True)
    require(qualified_collection(azure, scope["verificationResourceGroupId"] + "/resources", "2021-04-01") == [] and
            azure.get(scope["managedNodeResourceGroupId"], "2024-03-01", absent=True) is None,
            "qualified-empty-verification-footprint-required")
    books = {account + "/runbooks/ExactFoundationCleanup": records["preflight"]["receipt.json"]["originalRunbookSha256"],
             account + "/runbooks/" + QUALIFIED_DIAGNOSTIC: QUALIFIED_DIAGNOSTIC_SHA256}
    runtime_id = account + "/runtimeEnvironments/PowerShell74"
    resources = qualified_collection(azure, scope["cleanupResourceGroupId"] + "/resources", "2021-04-01")
    require(account.lower() in {item["id"].lower() for item in resources} and
            {item["id"].lower() for item in resources} <= {item.lower() for item in (account, runtime_id, *books)},
            "qualified-foreign-cleanup-resource")
    listed_books = qualified_collection(azure, account + "/runbooks")
    require({item["id"].lower() for item in listed_books} == {item.lower() for item in books},
            "qualified-runbook-inventory-drift")
    contents = {}
    for identity, digest in books.items():
        book = azure.get(identity, AUTO_API)
        require(book["id"].lower() == identity.lower() and not book.get("tags") and
                book["properties"]["state"] == "Published" and
                book["properties"]["runbookType"] == "PowerShell" and
                book["properties"]["runtimeEnvironment"] == "PowerShell74" and
                book["properties"].get("logVerbose") is False and book["properties"].get("logProgress") is False,
                "qualified-runbook-metadata-drift")
        contents[identity] = qualified_content(azure, identity, digest)
    runtimes = {**SYSTEM_RUNTIMES, "PowerShell74": ("PowerShell", "7.4")}
    catalogue = qualified_collection(azure, account + "/runtimeEnvironments")
    require({item["id"].lower() for item in catalogue} ==
            {(account + "/runtimeEnvironments/" + name).lower() for name in runtimes},
            "qualified-runtime-inventory-drift")
    runtime_proof = {}
    for item in catalogue:
        name = item["id"].rsplit("/", 1)[-1]
        require(name in runtimes and not item.get("tags") and
                item["properties"]["runtime"] == dict(zip(("language", "version"), runtimes[name])) and
                (name != "PowerShell74" or not item["properties"].get("defaultPackages")),
                "qualified-runtime-definition-drift")
        runtime_proof[name] = sha(wire(item["properties"]))
    for collection in ("schedules", "jobSchedules", "webhooks", "credentials", "connections", "variables",
                       "certificates", "sourceControls", "watchers", "hybridRunbookWorkerGroups",
                       "runtimeEnvironments/PowerShell74/packages"):
        require(qualified_collection(azure, account + "/" + collection) == [], "qualified-unexpected-child")
    for guid in role_guids(scope).values():
        identity = f"/subscriptions/{previous['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/{guid}"
        require(azure.get(identity, "2022-04-01", absent=True) is None, "qualified-legacy-custom-role-present")
    passed = records["preflight"]["receipt.json"]
    diagnostic = records["diagnostic"]["receipt.json"]
    expected_jobs = {old["preflightJobId"]: ("ExactFoundationCleanup", "Failed"),
                     diagnostic["jobId"]: (QUALIFIED_DIAGNOSTIC, "Completed"),
                     passed["jobId"]: ("ExactFoundationCleanup", "Completed")}
    require({item["id"].lower() for item in qualified_collection(azure, account + "/jobs")} ==
            {identity.lower() for identity in expected_jobs}, "qualified-job-inventory-drift")
    jobs = {}
    old_parameters = {"ManifestJson": wire(manifest(previous, old)).decode(), "Mode": "Preflight"}
    for identity, (book, status) in expected_jobs.items():
        job = azure.get(identity, AUTO_API)
        properties = job["properties"]
        require(job["id"].lower() == identity.lower() and job["name"] == identity.rsplit("/", 1)[-1] and
                properties["runbook"] == {"name": book} and properties["status"] == status and
                not properties.get("runOn") and isinstance(properties.get("jobId"), str) and
                plan.UUID.fullmatch(properties["jobId"]), "qualified-job-identity-or-status-drift")
        parameters = runbook_parameters(previous, old) if identity == passed["jobId"] else old_parameters
        require(properties["parameters"] == parameters, "qualified-job-parameters-drift")
        jobs[identity] = {"serviceJobId": properties["jobId"], "runbook": book, "status": status,
                          "parametersSha256": sha(wire(parameters))}
        if identity == passed["jobId"]:
            for key in ("startTime", "endTime"):
                value = properties[key]
                require(isinstance(value, str) and re.fullmatch(
                    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|\+00:00)", value) and
                    value == passed[key], "qualified-preflight-time-drift")
                jobs[identity][key] = value
            duration = dt.datetime.fromisoformat(properties["endTime"].replace("Z", "+00:00")) - \
                dt.datetime.fromisoformat(properties["startTime"].replace("Z", "+00:00"))
            require(0 <= duration.total_seconds() <= PREFLIGHT_EXECUTION_SECONDS,
                    "qualified-preflight-duration-invalid")
            decoded = {key: json.loads(value) for key, value in parameters.items()}
            require(decoded["Mode"] == "Preflight" and isinstance(decoded["ManifestJson"], str) and
                    json.loads(decoded["ManifestJson"]) == manifest(previous, old),
                    "qualified-decoded-manifest-mismatch")
            output = azure.rest("GET", identity + "/output", AUTO_API, raw=True)
            require(len(output) <= 4096 and wire(json.loads(output)) == wire(PREFLIGHT_PROOF),
                    "qualified-live-original-proof-mismatch")
        elif identity == diagnostic["jobId"]:
            output = azure.rest("GET", identity + "/output", AUTO_API, raw=True)
            require(len(output) <= 8192 and wire(json.loads(output)) ==
                    wire(records["diagnostic"]["safe-output.json"]), "qualified-diagnostic-output-drift")
    proof = {"principalId": old["principalId"], "groupTags": group_tags, "groupSourceDigests": group_sources,
             "accountTags": tags, "cleanupAssignments": old["cleanupAssignments"], "publishedContent": contents,
             "runtimeCatalogueSha256": runtime_proof, "jobs": jobs}
    if "rollback" in records:
        for identity in records["rollback"]["receipt.json"]["deleted"]:
            require(azure.get(identity, AUTO_API, absent=True) is None, "rolled-back-schedule-still-present")
        baseline = records["abandoned"]["authorization-link.json"]["plan"]["proof"]
        require(proof == {**baseline, "groupTags": group_tags, "groupSourceDigests": group_sources},
                "rolled-back-qualified-state-drift")
    return proof


def qualified_bootstrap_link(paths, hashes, previous, bundle, proof):
    return {"kind": "qualified-bootstrap-handoff", "authorizationModel": AUTHORIZATION_MODEL,
            "inputDirectories": paths, "inputHashes": hashes,
            "previousSourceDigest": previous["sourceDigest"], "nextSourceDigest": bundle["sourceDigest"],
            "compiledHashes": bundle["compiledHashes"], "computeInputsSha256": bundle["computeInputsSha256"],
            "proof": proof, "allowedTagMerges": [
                {"resourceId": bundle["scope"][key], "operation": "Merge",
                 "tags": {"orka-source-digest": bundle["sourceDigest"]}}
                for key in ("verificationResourceGroupId", "cleanupResourceGroupId")],
            "accountWrites": False, "grantWrites": False, "runbookWrites": False,
            "jobWrites": False, "scheduleWrites": False, "clockWrites": False, "computeWrites": False}


def prepare_qualified_bootstrap(args, work, azure):
    require(args.previous_work_dir and args.qualified_preflight_work_dir and args.diagnostic_work_dir and
            not (work / "bundle.json").exists() and not (work / "receipt.json").exists(),
            "fresh-qualified-bootstrap-plan-required")
    paths = {"previous": args.previous_work_dir, "preflight": args.qualified_preflight_work_dir,
             "diagnostic": args.diagnostic_work_dir}
    abandoned = getattr(args, "abandoned_arming_work_dir", None)
    rollback = getattr(args, "arming_rollback_work_dir", None)
    require(bool(abandoned) == bool(rollback), "paired-abandoned-arming-and-rollback-inputs-required")
    if abandoned:
        paths.update({"abandoned": abandoned, "rollback": rollback})
    previous, old, tags, records, hashes = qualified_bootstrap_inputs(args, paths)
    proof = qualified_bootstrap_proof(azure, previous, old, tags, records)
    current = source_hashes()
    values = json.loads((Path(paths["previous"]) / "compute-inputs.json").read_text())
    values["sourceDigest"] = sha(wire(current))
    write_json(work / "compute-inputs.json", values)
    compiled = compile_templates(work)
    require(compiled == previous["compiledHashes"], "qualified-compiled-footprint-drift")
    bundle = {**previous, "sourceHashes": current, "sourceDigest": values["sourceDigest"],
              "compiledHashes": compiled, "computeInputsSha256": sha((work / "compute-inputs.json").read_bytes())}
    require(source_hashes() == current and qualified_bootstrap_inputs(args, paths)[-1] == hashes,
            "qualified-inputs-changed-during-plan")
    link = qualified_bootstrap_link(paths, hashes, previous, bundle, proof)
    write_json(work / "bundle.json", bundle)
    write_json(work / "authorization-link.json", {"plan": link, "sha256": sha(wire(link))})
    print("Read-only qualified bootstrap handoff prepared; source review and exact-link approval are required.")


def qualified_bootstrap_intent(bundle, previous, old, passed, hashes, approval_digest):
    return {"phase": "qualified-bootstrap-intent", "subscriptionId": bundle["subscriptionId"],
        "cleanupReceipt": bundle["cleanupReceipt"], "sourceDigest": bundle["sourceDigest"],
        "principalId": old["principalId"], "authorizationModel": AUTHORIZATION_MODEL,
        "cleanupAssignments": dict(old["cleanupAssignments"]), "nodeScopeReady": False, "peeringScopeReady": False,
        "qualificationOf": {"approvalLinkSha256": approval_digest, "inputHashes": hashes,
            "previousSourceDigest": previous["sourceDigest"],
            "originalPublishedRunbookSha256": passed["originalRunbookSha256"],
            "preflightRequestSha256": passed["requestSha256"], "preflightOutputSha256": passed["safeOutputSha256"]}}


def adopt_qualified_bootstrap(azure, bundle, receipt, args):
    require(args.approved_authorization_sha256, "approved-qualified-handoff-required")
    record = json.loads((azure.work / "authorization-link.json").read_text())
    link = record["plan"]
    require(record["sha256"] == sha(wire(link)) == args.approved_authorization_sha256 and
            link["kind"] == "qualified-bootstrap-handoff", "approved-qualified-handoff-required")
    previous, old, tags, records, hashes = qualified_bootstrap_inputs(args, link["inputDirectories"])
    expected_bundle = {**previous, "sourceHashes": source_hashes(), "sourceDigest": sha(wire(source_hashes())),
                       "compiledHashes": previous["compiledHashes"], "computeInputsSha256": bundle["computeInputsSha256"]}
    require(bundle == expected_bundle, "qualified-current-bundle-drift")
    values = json.loads((Path(link["inputDirectories"]["previous"]) / "compute-inputs.json").read_text())
    values["sourceDigest"] = bundle["sourceDigest"]
    require(json.loads((azure.work / "compute-inputs.json").read_text()) == values, "qualified-compute-input-drift")
    passed = records["preflight"]["receipt.json"]
    intent = qualified_bootstrap_intent(bundle, previous, old, passed, hashes, record["sha256"])
    receipt_path = azure.work / "receipt.json"
    resuming = receipt_path.exists()
    # Use the same bytes save_receipt writes; semantic JSON equality would accept
    # edited receipts, duplicate keys or additional completion fields.
    intent_bytes = (json.dumps(intent, indent=2) + "\n").encode()
    require(not receipt_path.is_symlink() and
            ((not resuming and not receipt) or
             (resuming and receipt == intent and receipt_path.read_bytes() == intent_bytes)),
            "qualified-receipt-reentry-mismatch")
    proof = qualified_bootstrap_proof(azure, previous, old, tags, records,
                                     promoted_group_digest=bundle["sourceDigest"] if resuming else None)
    approved_proof = {**proof, "groupSourceDigests": {
        identity: previous["sourceDigest"] for identity in proof["groupSourceDigests"]}}
    require(link == qualified_bootstrap_link(link["inputDirectories"], hashes, previous, bundle, approved_proof),
            "qualified-approved-proof-drift")
    require(source_hashes() == bundle["sourceHashes"] and
            qualified_bootstrap_inputs(args, link["inputDirectories"])[-1] == hashes,
            "qualified-inputs-changed-before-adoption")
    if not resuming:
        receipt.update(intent)
        save_receipt(azure.work, receipt)
    promoted_tags = {**proof["groupTags"], "orka-source-digest": bundle["sourceDigest"]}
    for change in link["allowedTagMerges"]:
        resource = azure.get(change["resourceId"], "2024-03-01")
        owned(resource, bundle["scope"], bundle["owner"], bundle["cleanupReceipt"], change["resourceId"])
        require(resource["tags"] in (proof["groupTags"], promoted_tags), "qualified-ownership-or-clock-drift")
        if resource["tags"] == promoted_tags:
            continue
        azure.cli("tag", "update", "--resource-id", change["resourceId"], "--operation", "Merge",
                  "--tags", "orka-source-digest=" + bundle["sourceDigest"])
        resource = azure.get(change["resourceId"], "2024-03-01")
        require(resource["tags"] == promoted_tags, "qualified-tag-merge-readback-drift")
    fresh = qualified_bootstrap_proof(azure, previous, old, tags, records, group_digest=bundle["sourceDigest"])
    require(fresh == {**approved_proof, "groupTags": promoted_tags, "groupSourceDigests": {
                identity: bundle["sourceDigest"] for identity in proof["groupSourceDigests"]}} and
            qualified_bootstrap_inputs(args, link["inputDirectories"])[-1] == hashes,
            "qualified-final-proof-drift")
    receipt.update({"phase": "bootstrap-ready", "preflightJobId": passed["jobId"],
                    "preflightCompleted": passed["endTime"]})
    save_receipt(azure.work, receipt)


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
    validate_builtin_roles(azure, bundle)
    expected = cleanup_assignment_scopes(bundle, node, peer)
    audit_cleanup_assignments(azure, bundle, receipt, expected, complete=False)
    values = {"suffix": bundle["suffix"], "principalId": receipt["principalId"],
              "includeNodeGroup": node}
    deployed = azure.deploy("bounded-cleanup-builtin-access", azure.work / "cleanup-access.arm.json", values,
                            provider_validate=True)
    outputs = deployed["properties"]["outputs"]
    assignments = receipt.setdefault("cleanupAssignments", {})
    for key, output in (("verification", "verificationAssignmentId"), ("groupsRead", "groupMetadataAssignmentId"),
                        ("nodes", "nodeAssignmentId")):
        if outputs[output]["value"]:
            assignments[key] = outputs[output]["value"]
            scope, role_name = expected[key]
            role = f"/subscriptions/{bundle['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/" + bundle["roleGuids"][role_name]
            assignment_readback(azure.get(assignments[key], "2022-04-01"),
                                {"properties": {"principalId": receipt["principalId"], "roleDefinitionId": role}},
                                scope)
    save_receipt(azure.work, receipt)
    if peer:
        identity, body = peer_assignment(bundle, receipt)
        require(azure.get(identity, "2022-04-01", absent=True) is None,
                "unexpected-existing-peering-assignment")
        azure.rest("PUT", identity, "2022-04-01", body)
        assignment_readback(azure.get(identity, "2022-04-01"), body,
                            bundle["scope"]["controlSidePeeringId"])
        receipt["peeringAssignmentId"] = identity
        assignments["peerDelete"] = identity
    audit_cleanup_assignments(azure, bundle, receipt, expected, complete=True, wait_missing=True)
    receipt["nodeScopeReady"] = node
    receipt["peeringScopeReady"] = peer
    save_receipt(azure.work, receipt)


def cleanup_assignment_scopes(bundle, node=False, peer=False):
    scope = bundle["scope"]
    expected = {
        "verification": (scope["verificationResourceGroupId"], "resource-cleanup"),
        "groupsRead": (f"/subscriptions/{bundle['subscriptionId']}", "group-metadata-read"),
    }
    if node:
        expected["nodes"] = (scope["managedNodeResourceGroupId"], "resource-cleanup")
    if peer:
        expected["peerDelete"] = (scope["controlSidePeeringId"], "peering-cleanup")
    return expected


def principal_assignments(azure, bundle, principal):
    require(plan.UUID.fullmatch(principal), "invalid-cleanup-principal")
    query = urlencode({"api-version": "2022-04-01", "$filter": f"principalId eq '{principal}'"})
    result = azure.cli("rest", "--method", "GET", "--url",
        f"{ARM}/subscriptions/{bundle['subscriptionId']}/providers/Microsoft.Authorization/roleAssignments?{query}")
    require(not result.get("nextLink") and isinstance(result.get("value"), list),
            "cleanup-assignment-inventory-incomplete")
    require(all(item["properties"]["principalId"].lower() == principal.lower() for item in result["value"]),
            "cleanup-assignment-inventory-principal-mismatch")
    return result["value"]


def audit_cleanup_assignments(azure, bundle, receipt, expected, complete, wait_missing=False):
    require(not wait_missing or complete, "readback-wait-requires-complete-audit")
    allowed = {(scope.lower(), bundle["roleGuids"][name]): key for key, (scope, name) in expected.items()}
    end = time.monotonic() + ASSIGNMENT_READBACK_SECONDS
    while True:
        seen = set()
        for assignment in principal_assignments(azure, bundle, receipt["principalId"]):
            props = assignment["properties"]
            key = (props["scope"].lower(), props["roleDefinitionId"].split("/")[-1].lower())
            require(key in allowed and key not in seen, "unexpected-cleanup-assignment")
            require(not any(props.get(k) for k in ("condition", "conditionVersion", "delegatedManagedIdentityResourceId")),
                    "unexpected-conditional-cleanup-assignment")
            if complete:
                require(receipt["cleanupAssignments"].get(allowed[key], "").lower() == assignment["id"].lower(),
                        "cleanup-assignment-not-in-receipt")
            else:
                require(assignment["id"].lower() in
                        {value.lower() for value in receipt.get("cleanupAssignments", {}).values()},
                        "unrecorded-existing-cleanup-assignment")
            seen.add(key)
        if not complete or seen == set(allowed):
            return
        require(wait_missing and time.monotonic() + 2 < end, "cleanup-assignment-inventory-incomplete")
        time.sleep(2)


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
    require(not any(actual.get(key) for key in
                    ("condition", "conditionVersion", "delegatedManagedIdentityResourceId")),
            "unexpected-conditional-role-assignment")


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
        group=scope["verificationResourceGroupId"].split("/")[-1], provider_validate=True)
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
    return {"version": 2, "authorizationModel": AUTHORIZATION_MODEL,
            "subscriptionId": bundle["subscriptionId"], "tenantId": bundle["tenantId"],
            "principalId": receipt["principalId"], "suffix": bundle["suffix"], "owner": bundle["owner"],
            "cleanupReceipt": bundle["cleanupReceipt"], "controlVnetId": bundle["scope"]["controlVnetId"],
            "budgetStartUtc": receipt.get("T0", ""), "expiresAtUtc": receipt.get("deadline", ""),
            "requireNodeScope": cleanup, "requirePeeringScope": cleanup}


def runbook_parameters(bundle, receipt, cleanup=False):
    # Automation deserializes each parameter value before PowerShell binding,
    # as does Az.Automation's ProcessRunbookParameters/ConvertTo-Json path.
    values = {"ManifestJson": wire(manifest(bundle, receipt, cleanup=cleanup)).decode(),
              "Mode": "Cleanup" if cleanup else "Preflight"}
    return {name: wire(value).decode() for name, value in values.items()}


def preflight_job(azure, bundle, receipt):
    account = bundle["scope"]["automationAccountId"]
    job = account + "/jobs/" + str(uuid.uuid4())
    parameters = runbook_parameters(bundle, receipt)
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
    validate_builtin_roles(azure, bundle)
    receipt.update({"phase": "bootstrap-intent", "subscriptionId": bundle["subscriptionId"],
                    "cleanupReceipt": bundle["cleanupReceipt"], "sourceDigest": bundle["sourceDigest"]})
    save_receipt(azure.work, receipt)
    status = azure.cli("provider", "show", "--namespace", "Microsoft.Automation",
                       "--query", "registrationState")
    if status != "Registered":
        azure.cli("provider", "register", "--namespace", "Microsoft.Automation", "--wait")
    values = {"suffix": bundle["suffix"], "owner": bundle["owner"], "cleanupReceipt": bundle["cleanupReceipt"],
              "sourceDigest": bundle["sourceDigest"], "location": "eastus2"}
    azure.deploy("bounded-cleanup-bootstrap", azure.work / "cleanup.arm.json", values, provider_validate=True)
    finish_bootstrap(azure, bundle, receipt)


def finish_bootstrap(azure, bundle, receipt):
    scope = bundle["scope"]
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


def verify_network_assignments(azure, bundle, receipt, aks):
    group = bundle["scope"]["verificationResourceGroupId"]
    identity_id = group + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/orka-verify-" + \
        bundle["suffix"] + "-aks-control-plane"
    attached = aks["identity"].get("userAssignedIdentities") or {}
    require(aks["identity"]["type"] == "UserAssigned" and
            {value.lower() for value in attached} == {identity_id.lower()}, "aks-control-identity-mismatch")
    identity = azure.get(identity_id, "2023-01-31")
    owned(identity, bundle["scope"], bundle["owner"], bundle["cleanupReceipt"], identity_id)
    principal = identity["properties"]["principalId"]
    require(plan.UUID.fullmatch(principal), "invalid-aks-control-principal")
    attachment = next(iter(attached.values()))
    require(attachment.get("principalId") == principal and
            attachment.get("clientId") == identity["properties"]["clientId"],
            "aks-control-identity-instance-drift")
    role = f"/subscriptions/{bundle['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/" + \
        BUILTIN_ROLES["peering-cleanup"][0]
    assignments = {}
    for name, scope in network_assignment_scopes(bundle).items():
        assignment = scope + "/providers/Microsoft.Authorization/roleAssignments/" + arm_guid(scope, identity_id, role)
        assignment_readback(azure.get(assignment, "2022-04-01"), {"properties": {
            "principalId": principal, "roleDefinitionId": role}}, scope)
        assignments[name] = assignment
    receipt["networkAssignments"] = assignments
    receipt["aksControlPrincipalId"] = principal
    save_receipt(azure.work, receipt)


def recover_bootstrap(azure, bundle, receipt, args):
    require(not receipt and args.approved_recovery_sha256, "explicit-new-recovery-receipt-required")
    record = json.loads((azure.work / "recovery-link.json").read_text())
    link = record["plan"]
    require(record["sha256"] == sha(wire(link)) == args.approved_recovery_sha256 and
            link["kind"] == "automation-child-zero-tag-recovery" and
            link["nextSourceDigest"] == bundle["sourceDigest"], "approved-recovery-link-required")
    previous_work, previous = previous_recovery_inputs(link["previousWorkDir"], args)
    require(sha((previous_work / "bundle.json").read_bytes()) == link["previousBundleSha256"] and
            sha((previous_work / "receipt.json").read_bytes()) == link["previousReceiptSha256"] and
            previous["sourceDigest"] == link["previousSourceDigest"], "prior-recovery-receipt-drift")
    require(all(bundle[key] == previous[key] for key in (
        "subscriptionId", "tenantId", "scope", "owner", "suffix", "cleanupReceipt",
        "roleGuids", "controlKubeletIdentity", "publicKeyReady")), "recovery-immutable-input-drift")
    old_values = json.loads((previous_work / "compute-inputs.json").read_text())
    new_values = json.loads((azure.work / "compute-inputs.json").read_text())
    old_values["sourceDigest"] = bundle["sourceDigest"]
    require(new_values == old_values, "recovery-may-only-update-source-digest")
    require(partial_bootstrap_proof(azure, previous) == link["partialProof"], "partial-recovery-state-drift")
    require(failed_recovery_proof(link["failedRecovery"]["workDir"], args, previous_work, previous,
                                 link["partialProof"], azure) == link["failedRecovery"],
            "failed-recovery-link-or-platform-proof-drift")
    values = {"prefix": "orka-verify-" + bundle["suffix"], "location": "eastus2"}
    cleanup_group = bundle["scope"]["cleanupResourceGroupId"].split("/")[-1]
    preview = azure.deploy("apply-linked-cleanup-recovery", azure.work / "cleanup-recovery.arm.json", values,
                           group=cleanup_group, preview=True, validation="Provider")
    validate_recovery_preview(preview, previous, bundle)
    receipt.update({"phase": "recovery-intent", "subscriptionId": bundle["subscriptionId"],
                    "cleanupReceipt": bundle["cleanupReceipt"], "sourceDigest": bundle["sourceDigest"],
                    "principalId": link["partialProof"]["principalId"],
                    "recoveryOf": {"sourceDigest": previous["sourceDigest"],
                                   "receiptSha256": link["previousReceiptSha256"],
                                   "recoveryLinkSha256": record["sha256"],
                                   "failedRecovery": link["failedRecovery"]}})
    save_receipt(azure.work, receipt)
    azure.deploy("bounded-cleanup-zero-tags", azure.work / "cleanup-recovery.arm.json", values,
                 group=cleanup_group, provider_validate=True)
    for key in ("verificationResourceGroupId", "cleanupResourceGroupId"):
        identity = bundle["scope"][key]
        azure.cli("tag", "update", "--resource-id", identity, "--operation", "Merge",
                  "--tags", "orka-source-digest=" + bundle["sourceDigest"])
        actual = azure.get(identity, "2024-03-01")
        owned(actual, bundle["scope"], bundle["owner"], bundle["cleanupReceipt"], identity)
        require(actual["tags"] == {**link["partialProof"]["expectedTags"],
                                  "orka-source-digest": bundle["sourceDigest"]}, "recovery-tag-merge-drift")
    finish_bootstrap(azure, bundle, receipt)


def schedules(azure, bundle, receipt, create=False):
    account = bundle["scope"]["automationAccountId"]
    start = dt.datetime.fromisoformat(receipt["T0"].replace("Z", "+00:00"))
    deadline = dt.datetime.fromisoformat(receipt["deadline"].replace("Z", "+00:00"))
    require(start.utcoffset() == deadline.utcoffset() == dt.timedelta(0) and
            start.second == start.microsecond == deadline.second == deadline.microsecond == 0 and
            deadline == start + dt.timedelta(hours=24), "minute-aligned-24-hour-clock-required")
    parameters = runbook_parameters(bundle, receipt, cleanup=True)
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
    validate_builtin_roles(azure, bundle)
    audit_cleanup_assignments(azure, bundle, receipt, cleanup_assignment_scopes(bundle), complete=True)
    group = azure.get(bundle["scope"]["verificationResourceGroupId"], "2024-03-01")
    cleanup_group = azure.get(bundle["scope"]["cleanupResourceGroupId"], "2024-03-01")
    owned(cleanup_group, bundle["scope"], bundle["owner"], bundle["cleanupReceipt"],
          bundle["scope"]["cleanupResourceGroupId"])
    require(cleanup_group["tags"].get("orka-source-digest") == bundle["sourceDigest"],
            "cleanup-group-source-drift")
    children = azure.cli("resource", "list", "--resource-group",
                         bundle["scope"]["verificationResourceGroupId"].split("/")[-1])
    require(not children, "prepared-verification-group-not-empty")
    # Automation drops seconds. Eleven minutes from the UTC minute boundary
    # preserves at least ten minutes of lead time even at second 59.
    start = utc().replace(second=0, microsecond=0) + dt.timedelta(minutes=11)
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
    verify_network_assignments(azure, bundle, receipt, aks)
    receipt["kubernetesAuthorization"] = "azure-rbac-bootstrap-only"
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
    for name, identity in receipt.get("networkAssignments", {}).items():
        scopes = network_assignment_scopes(bundle)
        require(name in scopes and identity.lower().startswith(
            scopes[name].lower() + "/providers/microsoft.authorization/roleassignments/"),
            "network-retirement-assignment-outside-scope")
        actual = azure.get(identity, "2022-04-01", absent=True)
        if actual is not None:
            role = f"/subscriptions/{bundle['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/" + \
                BUILTIN_ROLES["peering-cleanup"][0]
            assignment_readback(actual, {"properties": {
                "principalId": receipt["aksControlPrincipalId"], "roleDefinitionId": role}}, scopes[name])
            azure.rest("DELETE", identity, "2022-04-01")
            require(azure.get(identity, "2022-04-01", absent=True) is None,
                    "network-assignment-retirement-unverified")
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
    require(bundle.get("authorizationModel") == AUTHORIZATION_MODEL, "explicit-builtin-authorization-required")
    expected = cleanup_assignment_scopes(bundle, node=True, peer=True)
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
    p.add_argument("operation", choices=("plan", "plan-recovery", "plan-builtin-resume", "plan-qualified-bootstrap", "bootstrap",
                                        "recover-bootstrap", "resume-builtin-bootstrap",
                                        "adopt-qualified-bootstrap",
                                        "arm", "compute", "connect", "retire"))
    p.add_argument("--subscription", required=True)
    p.add_argument("--control-vnet-id", required=True)
    p.add_argument("--control-aks-id", required=True)
    p.add_argument("--work-dir", required=True)
    p.add_argument("--parameters")
    p.add_argument("--public-key-file")
    p.add_argument("--reviewed-source-sha256")
    p.add_argument("--previous-work-dir")
    p.add_argument("--failed-recovery-work-dir")
    p.add_argument("--approved-recovery-sha256")
    p.add_argument("--approved-authorization-sha256")
    p.add_argument("--continue-granted-bootstrap", action="store_true")
    p.add_argument("--qualified-preflight-work-dir")
    p.add_argument("--diagnostic-work-dir")
    p.add_argument("--abandoned-arming-work-dir")
    p.add_argument("--arming-rollback-work-dir")
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
    if args.operation == "plan-recovery":
        prepare_recovery(args, work, azure)
        return
    if args.operation == "plan-builtin-resume":
        prepare_builtin_resume(args, work, azure)
        return
    if args.operation == "plan-qualified-bootstrap":
        prepare_qualified_bootstrap(args, work, azure)
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
    if args.operation == "recover-bootstrap":
        recover_bootstrap(azure, bundle, receipt, args)
        print("Reviewed receipt-linked cleanup recovery completed; no compute or lifetime was started.")
        return
    if args.operation == "resume-builtin-bootstrap":
        resume_builtin_bootstrap(azure, bundle, receipt, args)
        print("Reviewed built-in cleanup bootstrap completed; no compute or lifetime was started.")
        return
    if args.operation == "adopt-qualified-bootstrap":
        adopt_qualified_bootstrap(azure, bundle, receipt, args)
        print("Reviewed original preflight adopted; only two group source tags changed, with no new job or clock.")
        return
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
