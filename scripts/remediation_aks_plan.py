#!/usr/bin/env python3
"""Non-mutating AKS foundation plan, fenced to an explicit subscription."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "config/development/remediation-aks/main.bicep"
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
# Permission names such as Microsoft.Resources/subscriptions/resourceGroups/read
# are not resource IDs; only concrete subscription UUIDs select an Azure scope.
SUBSCRIPTION_ID = re.compile(r"/subscriptions/(" + UUID.pattern + r")\b", re.IGNORECASE)
SUBSCRIPTION_FLAG = re.compile(r"--subscription(?:=|\s+)([0-9a-f-]{36})", re.IGNORECASE)
CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"


class Failure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Failure(code)


def check_subscription_ids(value, subscription):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("subscription", "subscriptionId", "approvedSubscriptionId"):
                require(isinstance(item, str) and item.lower() == subscription,
                        "foreign-subscription-in-artifact")
            check_subscription_ids(key, subscription)
            check_subscription_ids(item, subscription)
    elif isinstance(value, list):
        for item in value:
            check_subscription_ids(item, subscription)
    elif isinstance(value, str):
        for found in SUBSCRIPTION_ID.findall(value):
            require(found.lower() == subscription, "foreign-subscription-in-artifact")
        for found in SUBSCRIPTION_FLAG.findall(value):
            require(found.lower() == subscription, "foreign-subscription-in-artifact")


def control_resource(value, subscription, provider, kind):
    require(isinstance(value, str), "invalid-control-resource-id")
    parts = value.split("/")
    require(len(parts) == 9 and parts[0] == "" and
            parts[1].lower() == "subscriptions" and parts[2].lower() == subscription and
            parts[3].lower() == "resourcegroups" and parts[4] and
            parts[5].lower() == "providers" and parts[6].lower() == provider.lower() and
            parts[7].lower() == kind.lower() and parts[8], "invalid-control-resource-id")
    return value


def targets(subscription, suffix, control_vnet_id, control_aks_id):
    require(isinstance(subscription, str) and UUID.fullmatch(subscription), "explicit-subscription-required")
    require(isinstance(suffix, str) and re.fullmatch(r"[a-z0-9]{6,12}", suffix), "invalid-suffix")
    control_resource(control_vnet_id, subscription, "Microsoft.Network", "virtualNetworks")
    control_resource(control_aks_id, subscription, "Microsoft.ContainerService", "managedClusters")
    prefix = "orka-verify-" + suffix
    group = f"/subscriptions/{subscription}/resourceGroups/rg-{prefix}"
    vnet = group + f"/providers/Microsoft.Network/virtualNetworks/{prefix}-vnet"
    cleanup = group + "-cleanup"
    result = {
        "subscriptionId": subscription,
        "verificationResourceGroupId": group,
        "managedNodeResourceGroupId": group + "-nodes",
        "verificationClusterId": group + f"/providers/Microsoft.ContainerService/managedClusters/{prefix}-aks",
        "builderVirtualMachineId": group + f"/providers/Microsoft.Compute/virtualMachines/{prefix}-builder",
        "verificationVnetId": vnet,
        "verificationRegistryId": group + f"/providers/Microsoft.ContainerRegistry/registries/orkaverif{suffix}",
        "cleanupResourceGroupId": cleanup,
        "automationAccountId": cleanup + f"/providers/Microsoft.Automation/automationAccounts/{prefix}-reaper",
        "controlVnetId": control_vnet_id,
        "controlClusterId": control_aks_id,
        "controlSidePeeringId": control_vnet_id + "/virtualNetworkPeerings/to-" + prefix,
        "verificationSidePeeringId": vnet + "/virtualNetworkPeerings/to-control",
        "aksContributorRoleDefinitionId":
            f"/subscriptions/{subscription}/providers/Microsoft.Authorization/roleDefinitions/{CONTRIBUTOR}",
    }
    check_subscription_ids(result, subscription)
    return result


def scoped_az(subscription, *arguments):
    require(UUID.fullmatch(subscription), "explicit-subscription-required")
    return ["az", *arguments, "--subscription", subscription, "--output", "json", "--only-show-errors"]


def validate_what_if(what_if, scope):
    check_subscription_ids(what_if, scope["subscriptionId"])
    require(what_if.get("status") == "Succeeded", "what-if-not-succeeded")
    changes = what_if.get("changes")
    require(isinstance(changes, list) and changes, "what-if-incomplete")
    group = scope["verificationResourceGroupId"].lower()
    ids = set()
    for change in changes:
        identity = change.get("resourceId", "").lower()
        require(change.get("changeType") == "Create", "what-if-not-new-only")
        require(identity == group or identity.startswith(group + "/"), "what-if-outside-new-group")
        require(identity not in ids, "duplicate-what-if-resource")
        ids.add(identity)
    for key in ("verificationResourceGroupId", "verificationClusterId", "builderVirtualMachineId", "verificationRegistryId"):
        require(scope[key].lower() in ids, "what-if-missing-required-resource")
    aks = next(c for c in changes if c["resourceId"].lower() == scope["verificationClusterId"].lower())
    require(aks["after"]["properties"]["nodeResourceGroup"] ==
            scope["managedNodeResourceGroupId"].rsplit("/", 1)[-1], "node-group-scope-mismatch")


def cli_output(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure("azure-cli-unavailable-or-timed-out") from None
    require(result.returncode == 0, "azure-cli-command-failed")
    return result.stdout


def make_plan(subscription, parameters, parameter_file, control_vnet_id, control_aks_id, call=cli_output):
    parameter_bytes = Path(parameter_file).read_bytes()
    source_bytes = {path: path.read_bytes() for path in (TEMPLATE, TEMPLATE.with_name("resources.bicep"))}
    values = parameters["parameters"]
    require(values["location"]["value"] == "eastus2", "unapproved-region")
    scope = targets(subscription, values["suffix"]["value"], control_vnet_id, control_aks_id)
    account = json.loads(call(scoped_az(
        subscription, "account", "show", "--query",
        "{subscription:id,tenant:tenantId,environment:environmentName,principal:user}")))
    # Account metadata attests the requested target; it can never select the target.
    require(account.get("subscription", "").lower() == subscription, "account-subscription-mismatch")
    require(account.get("environment") == "AzureCloud", "commercial-azure-required")
    require(isinstance(account.get("tenant"), str) and UUID.fullmatch(account["tenant"]), "invalid-tenant")
    absent = {}
    for key in ("verificationResourceGroupId", "managedNodeResourceGroupId", "cleanupResourceGroupId"):
        name = scope[key].rsplit("/", 1)[-1]
        exists = json.loads(call(scoped_az(subscription, "group", "exists", "--name", name)))
        require(exists is False, "proposed-resource-group-already-exists")
        absent[key] = True
    compiled = json.loads(call(["az", "bicep", "build", "--file", str(TEMPLATE), "--stdout"]))
    what_if = json.loads(call(scoped_az(
        subscription, "deployment", "sub", "what-if", "--location", "eastus2",
        "--name", "isolated-verification-plan", "--template-file", str(TEMPLATE),
        "--parameters", "@" + str(parameter_file), "--validation-level", "Template", "--no-pretty-print")))
    validate_what_if(what_if, scope)
    require(Path(parameter_file).read_bytes() == parameter_bytes, "parameter-file-changed-during-plan")
    require(all(path.read_bytes() == data for path, data in source_bytes.items()),
            "template-source-changed-during-plan")
    plan = {
        "approvedSubscriptionId": subscription,
        "scopeSource": "required --subscription input; never ambient Azure account/environment",
        "targets": scope,
        "accountAttestation": account,
        "resourceGroupsConfirmedAbsent": absent,
        "azureMutationsMade": False,
        "lifetimeStarted": False,
        "validationLevel": "Template",
        "providerPermissionsAndCapacityVerified": False,
        "parametersSha256": hashlib.sha256(parameter_bytes).hexdigest(),
        "templateSourceSha256": {path.name: hashlib.sha256(data).hexdigest()
                                for path, data in source_bytes.items()},
        "whatIfStatus": what_if["status"],
        "plannedResourceIds": [c["resourceId"] for c in what_if["changes"]],
    }
    check_subscription_ids(plan, subscription)
    return plan, compiled, what_if


def private_path(value):
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts and str(path) == value,
            "canonical-absolute-private-path-required")
    require(not any(path.is_relative_to(p) for p in (Path("/tmp"), Path("/var/tmp"))),
            "persistent-private-path-required")
    require(not any(p.is_symlink() for p in (path, *path.parents)), "nonsymlink-private-path-required")
    require(not any((p / ".git").exists() for p in (path, *path.parents)), "private-path-must-be-outside-git")
    return path


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--subscription", required=True)
    result.add_argument("--parameters", required=True)
    result.add_argument("--output-dir", required=True)
    result.add_argument("--control-vnet-id", required=True)
    result.add_argument("--control-aks-id", required=True)
    return result


def main():
    args = parser().parse_args()
    os.umask(0o077)
    parameters = private_path(args.parameters)
    output = private_path(args.output_dir)
    require(parameters.is_file(), "parameter-file-required")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    plan, compiled, what_if = make_plan(
        args.subscription, json.loads(parameters.read_text()), parameters,
        args.control_vnet_id, args.control_aks_id)
    artifacts = {"scoped-plan.json": plan, "foundation.arm.json": compiled, "what-if.json": what_if}
    for name, value in artifacts.items():
        destination = output / name
        require(not destination.exists() and not destination.is_symlink(), "fresh-output-files-required")
    for name, value in artifacts.items():
        with (output / name).open("x", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2)
            handle.write("\n")
    print("Explicit-subscription static plan verified; no Azure resources changed; no lifetime started.")


if __name__ == "__main__":
    try:
        main()
    except Failure as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError):
        print("invalid-plan-input-or-cli-output", file=sys.stderr)
        sys.exit(1)
