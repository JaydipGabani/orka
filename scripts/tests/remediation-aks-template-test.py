#!/usr/bin/env python3
"""Compile and inspect the ARM boundary; no Azure resource or credential access."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib
import unittest
from unittest import mock


sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "config/development/remediation-aks"
SPEC = importlib.util.spec_from_file_location("remediation_aks_plan", ROOT / "scripts/remediation_aks_plan.py")
planner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(planner)


class ExplicitSubscriptionTests(unittest.TestCase):
    approved = "11111111-1111-1111-1111-111111111111"
    ambient = "22222222-2222-2222-2222-222222222222"
    tenant = "33333333-3333-3333-3333-333333333333"

    def setUp(self):
        base = f"/subscriptions/{self.approved}/resourceGroups/control/providers/"
        self.vnet = base + "Microsoft.Network/virtualNetworks/control"
        self.aks = base + "Microsoft.ContainerService/managedClusters/control"
        self.scope = planner.targets(self.approved, "sample01", self.vnet, self.aks)
        self.calls = []
        self.account_subscription = self.approved
        self.what_if = {"status": "Succeeded", "changes": [
            {"changeType": "Create", "resourceId": self.scope[key], "after": {
                "properties": {"nodeResourceGroup": self.scope["managedNodeResourceGroupId"].rsplit("/", 1)[-1]}
            }} for key in ("verificationResourceGroupId", "verificationClusterId", "builderVirtualMachineId",
                           "verificationRegistryId")
        ]}
        self.parameters = {"parameters": {"suffix": {"value": "sample01"}, "location": {"value": "eastus2"}}}

    def call(self, command):
        self.calls.append(command)
        if command[1:3] == ["bicep", "build"]:
            return "{}"
        self.assertIn("--subscription", command)
        self.assertEqual(command[command.index("--subscription") + 1], self.approved)
        if command[1:3] == ["account", "show"]:
            return json.dumps({"subscription": self.account_subscription, "tenant": self.tenant,
                               "environment": "AzureCloud", "principal": {"type": "user"}})
        if command[1:3] == ["group", "exists"]:
            return "false"
        self.assertEqual(command[1:4], ["deployment", "sub", "what-if"])
        return json.dumps(self.what_if)

    def plan(self):
        with mock.patch.object(Path, "read_bytes", return_value=b"private-plan-fixture"):
            return planner.make_plan(self.approved, self.parameters, Path("/private/parameters.json"),
                                     self.vnet, self.aks, self.call)[0]

    def test_explicit_subscription_overrides_different_ambient_account(self):
        with mock.patch.dict(os.environ, {"AZURE_SUBSCRIPTION_ID": self.ambient}):
            result = self.plan()
        self.assertEqual(result["approvedSubscriptionId"], self.approved)
        for key, value in result["targets"].items():
            if key != "subscriptionId":
                self.assertTrue(value.startswith(f"/subscriptions/{self.approved}/"), key)
        self.assertTrue(result["targets"]["managedNodeResourceGroupId"].endswith("-nodes"))
        self.assertTrue(result["targets"]["cleanupResourceGroupId"].endswith("-cleanup"))
        self.assertEqual(len(self.calls), 6)
        self.assertFalse(result["azureMutationsMade"])
        self.assertFalse(result["providerPermissionsAndCapacityVerified"])

    def test_different_account_response_cannot_select_scope(self):
        self.account_subscription = self.ambient
        with self.assertRaisesRegex(planner.Failure, "account-subscription-mismatch"):
            self.plan()
        self.assertEqual(len(self.calls), 1)

    def test_what_if_rejects_foreign_scope_even_in_nested_identity_key(self):
        foreign = f"/subscriptions/{self.ambient}/resourceGroups/elsewhere"
        self.what_if["changes"][0]["after"]["identity"] = {"userAssignedIdentities": {foreign: {}}}
        with self.assertRaisesRegex(planner.Failure, "foreign-subscription-in-artifact"):
            self.plan()

    def test_same_subscription_existing_resource_modification_is_rejected(self):
        self.what_if["changes"][0]["changeType"] = "Modify"
        with self.assertRaisesRegex(planner.Failure, "what-if-not-new-only"):
            self.plan()

    def test_foreign_control_resource_is_rejected_before_cli(self):
        self.vnet = self.vnet.replace(self.approved, self.ambient)
        with self.assertRaisesRegex(planner.Failure, "invalid-control-resource-id"):
            self.plan()
        self.assertFalse(self.calls)

    def test_required_subscription_never_defaults_from_environment(self):
        arguments = ["--parameters", "/private/parameters.json", "--output-dir", "/private/results",
                     "--control-vnet-id", self.vnet, "--control-aks-id", self.aks]
        with mock.patch.dict(os.environ, {"AZURE_SUBSCRIPTION_ID": self.approved}), \
                mock.patch("sys.stderr"), self.assertRaises(SystemExit) as error:
            planner.parser().parse_args(arguments)
        self.assertEqual(error.exception.code, 2)

    def test_legacy_auxiliary_ids_reproduce_the_report_scope_failure(self):
        # The prior ad-hoc handoff combined a correctly scoped what-if with an
        # unscoped account response when constructing the node group and role ID.
        legacy = {"plannedResourceIds": [c["resourceId"] for c in self.what_if["changes"]],
                  "managedNodeResourceGroup": self.scope["managedNodeResourceGroupId"].replace(
                      self.approved, self.ambient)}
        with self.assertRaisesRegex(planner.Failure, "foreign-subscription-in-artifact"):
            planner.check_subscription_ids(legacy, self.approved)

    def test_cleanup_flags_cannot_target_an_ambient_subscription(self):
        with self.assertRaisesRegex(planner.Failure, "foreign-subscription-in-artifact"):
            planner.check_subscription_ids(f"az group delete --subscription {self.ambient}", self.approved)

    def test_permission_operation_names_are_not_subscription_ids(self):
        planner.check_subscription_ids({
            "permissions": [{"actions": ["Microsoft.Resources/subscriptions/resourceGroups/read",
                                         "Microsoft.Resources/subscriptions/resourceGroups/delete"]}],
            "assignableScopes": [self.scope["verificationResourceGroupId"]],
        }, self.approved)

    def test_node_group_name_must_match_the_reviewed_target(self):
        self.what_if["changes"][1]["after"]["properties"]["nodeResourceGroup"] = "another-group"
        with self.assertRaisesRegex(planner.Failure, "node-group-scope-mismatch"):
            self.plan()

    def test_nonpersistent_or_noncanonical_paths_fail_before_filesystem_access(self):
        with mock.patch.object(Path, "is_symlink", side_effect=AssertionError("must not inspect")):
            for path in ("/tmp/never-open", "/var/tmp/never-open", "/private/../elsewhere"):
                with self.subTest(path=path), self.assertRaises(planner.Failure):
                    planner.private_path(path)


class TemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(
            ["az", "bicep", "build", "--file", str(SOURCE / "main.bicep"), "--stdout"],
            check=True, capture_output=True, text=True, timeout=120,
        )
        cls.template = json.loads(result.stdout)
        nested = next(r for r in cls.template["resources"]
                      if r["type"] == "Microsoft.Resources/deployments")
        cls.resources = nested["properties"]["template"]["resources"]

    def resource(self, kind):
        matches = [r for r in self.resources if r["type"] == kind]
        self.assertEqual(len(matches), 1, kind)
        return matches[0]

    def test_fixed_compute_and_lifetime(self):
        aks = self.resource("Microsoft.ContainerService/managedClusters")
        pools = aks["properties"]["agentPoolProfiles"]
        self.assertEqual(len(pools), 1)
        self.assertEqual(pools[0]["count"], 2)
        self.assertEqual(pools[0]["vmSize"], "Standard_D4s_v5")
        self.assertIs(pools[0]["enableAutoScaling"], False)
        self.assertEqual(pools[0]["kubeletConfig"], {"podMaxPids": 512})
        self.assertEqual(pools[0]["upgradeSettings"], {"maxSurge": "1", "maxUnavailable": "0"})
        self.assertNotIn("availabilityZones", pools[0])
        vm = self.resource("Microsoft.Compute/virtualMachines")
        self.assertEqual(vm["properties"]["hardwareProfile"], {"vmSize": "Standard_D4s_v5"})
        self.assertEqual(vm["properties"]["storageProfile"]["osDisk"]["diskSizeGB"], 64)
        self.assertEqual([d["diskSizeGB"] for d in vm["properties"]["storageProfile"]["dataDisks"]], [64])
        self.assertEqual(self.template["parameters"]["location"]["allowedValues"], ["eastus2"])
        tags = self.template["variables"]["ownershipTags"]
        self.assertEqual(tags["orka-expires-at-utc"], "[dateTimeAdd(parameters('budgetStartUtc'), 'P1D')]")
        self.assertNotIn("nodeCount", self.template["parameters"])
        self.assertNotIn("vmSize", self.template["parameters"])

    def test_private_api_and_no_managed_keda(self):
        properties = self.resource("Microsoft.ContainerService/managedClusters")["properties"]
        self.assertEqual(properties["kubernetesVersion"], "1.35.8")
        self.assertEqual(properties["networkProfile"]["networkPluginMode"], "overlay")
        self.assertEqual(properties["networkProfile"]["networkDataplane"], "cilium")
        self.assertEqual(properties["networkProfile"]["outboundType"], "userAssignedNATGateway")
        self.assertTrue(properties["apiServerAccessProfile"]["enablePrivateCluster"])
        self.assertFalse(properties["apiServerAccessProfile"]["enablePrivateClusterPublicFQDN"])
        self.assertTrue(properties["apiServerAccessProfile"]["disableRunCommand"])
        self.assertTrue(properties["disableLocalAccounts"])
        self.assertTrue(properties["aadProfile"]["enableAzureRBAC"])
        self.assertTrue(properties["oidcIssuerProfile"]["enabled"])
        self.assertTrue(properties["securityProfile"]["workloadIdentity"]["enabled"])
        self.assertFalse(properties["workloadAutoScalerProfile"]["keda"]["enabled"])

    def test_builder_has_no_cloud_identity_or_public_ip(self):
        vm = self.resource("Microsoft.Compute/virtualMachines")
        self.assertNotIn("identity", vm)
        self.assertNotIn("customData", vm["properties"]["osProfile"])
        self.assertNotIn("adminPassword", vm["properties"]["osProfile"])
        self.assertFalse(vm["properties"]["osProfile"]["allowExtensionOperations"])
        nic = self.resource("Microsoft.Network/networkInterfaces")
        self.assertNotIn("publicIPAddress", nic["properties"]["ipConfigurations"][0]["properties"])
        self.assertEqual(self.template["parameters"]["operatorSshPublicKey"]["type"], "securestring")
        self.assertNotIn("operatorSshPublicKey", json.dumps(self.template["outputs"]))

    def test_no_existing_scope_or_wildcard_roles(self):
        role = self.resource("Microsoft.Authorization/roleDefinitions")
        actions = role["properties"]["permissions"][0]["actions"]
        self.assertTrue(actions)
        self.assertTrue(all("*" not in action for action in actions))
        self.assertEqual(role["properties"]["assignableScopes"], ["[resourceGroup().id]"])
        assignment = self.resource("Microsoft.Authorization/roleAssignments")
        self.assertNotIn("scope", assignment)
        self.assertEqual([r["type"] for r in self.template["resources"]],
                         ["Microsoft.Resources/resourceGroups", "Microsoft.Resources/deployments"])
        for resource in self.resources:
            self.assertNotIn("virtualNetworkPeerings", resource["type"])
            self.assertNotIn("virtualNetworkLinks", resource["type"])
            self.assertNotIn("Microsoft.Automation", resource["type"])
            self.assertNotIn("Microsoft.Compute/virtualMachines/extensions", resource["type"])

    def test_only_one_isolated_basic_authenticated_registry_is_created(self):
        registry = self.resource("Microsoft.ContainerRegistry/registries")
        self.assertEqual(registry["sku"]["name"], "Basic")
        self.assertFalse(registry["properties"]["adminUserEnabled"])
        self.assertFalse(registry["properties"]["anonymousPullEnabled"])
        self.assertEqual(registry["properties"]["publicNetworkAccess"], "Enabled")
        self.assertEqual(registry["properties"]["roleAssignmentMode"], "LegacyRegistryPermissions")
        self.assertFalse(any(r["type"].startswith("Microsoft.ContainerRegistry/registries/") for r in self.resources))

    def test_builder_network_does_not_open_ssh_or_block_host_metadata(self):
        groups = [r for r in self.resources if r["type"] == "Microsoft.Network/networkSecurityGroups"]
        rules = next(r["properties"]["securityRules"] for r in groups
                     if any(rule["name"] == "trusted-build-client-mtls"
                            for rule in r["properties"]["securityRules"]))
        rules = {r["name"]: r["properties"] for r in rules}
        ingress = [r for r in rules.values() if r["direction"] == "Inbound" and r["access"] == "Allow"]
        self.assertEqual(len(ingress), 1)
        self.assertEqual(ingress[0]["destinationPortRange"], "1234")
        self.assertEqual(ingress[0]["sourceAddressPrefix"], "[parameters('trustedBuildClientCidr')]")
        self.assertFalse(any(r["access"] == "Deny" and r["direction"] == "Outbound" and
                             r["destinationAddressPrefix"] == "AzurePlatformIMDS" for r in rules.values()))
        self.assertEqual(rules["deny-lateral-connections"]["destinationAddressPrefix"], "VirtualNetwork")
        self.assertLess(rules["platform-dns"]["priority"], rules["deny-lateral-connections"]["priority"])
        nat = self.resource("Microsoft.Network/natGateways")
        self.assertEqual(len(nat["properties"]["publicIpAddresses"]), 1)
        subnets = self.resource("Microsoft.Network/virtualNetworks")["properties"]["subnets"]
        self.assertEqual(len(subnets), 2)
        self.assertTrue(all(s["properties"]["defaultOutboundAccess"] is False for s in subnets))
        nodes = next(s for s in subnets if s["name"] == "nodes")
        self.assertEqual(nodes["properties"]["privateEndpointNetworkPolicies"], "NetworkSecurityGroupEnabled")

    def test_staged_daemon_requires_mtls_and_independent_state(self):
        config = tomllib.loads((SOURCE / "buildkitd.toml").read_text())
        self.assertEqual(config["root"], "/var/lib/orka-buildkit")
        self.assertEqual(config["insecure-entitlements"], [])
        self.assertEqual(config["grpc"]["address"], ["tcp://0.0.0.0:1234"])
        tls = config["grpc"]["tls"]
        self.assertEqual(set(tls), {"cert", "key", "ca"})
        self.assertTrue(all(v.startswith("/etc/orka-buildkit/tls/") for v in tls.values()))
        self.assertEqual(config["worker"]["oci"]["max-parallelism"], 1)
        self.assertFalse(config["worker"]["oci"]["noProcessSandbox"])
        self.assertEqual(config["worker"]["oci"]["networkMode"], "cni")
        self.assertEqual(config["worker"]["oci"]["defaultCgroupParent"], "/workloads")
        self.assertFalse(config["worker"]["containerd"]["enabled"])
        unit = (SOURCE / "orka-buildkit.service").read_text()
        self.assertIn("ExecStartPre=/usr/bin/mountpoint -q /var/lib/orka-buildkit", unit)
        for limit in ("CPUQuota=400%", "MemoryMax=12G", "TasksMax=512"):
            self.assertIn(limit, unit)
        self.assertIn("DelegateSubgroup=supervisor", unit)
        self.assertIn("KillMode=control-group", unit)
        wrapper = (SOURCE / "start-bounded-buildkit.sh").read_text()
        self.assertIn("unshare --mount --cgroup --propagation private", wrapper)
        self.assertIn("mount -t cgroup2", wrapper)
        self.assertNotIn("docker.sock", unit)
        self.assertNotIn("docker.sock", json.dumps(config))

    def test_new_node_nsg_restricts_cross_control_connections(self):
        groups = [r for r in self.resources if r["type"] == "Microsoft.Network/networkSecurityGroups"]
        rules = next(r["properties"]["securityRules"] for r in groups
                     if any(rule["name"] == "trusted-control-api" for rule in r["properties"]["securityRules"]))
        rules = {r["name"]: r["properties"] for r in rules}
        allow = rules["trusted-control-api"]
        deny = rules["deny-other-control-ingress"]
        self.assertEqual(allow["sourceAddressPrefix"], "[parameters('trustedBuildClientCidr')]")
        self.assertEqual(allow["destinationPortRange"], "443")
        self.assertEqual(deny["sourceAddressPrefix"], "[parameters('trustedControlVnetCidr')]")
        self.assertEqual(deny["access"], "Deny")
        self.assertLess(allow["priority"], deny["priority"])
        self.assertEqual(rules["deny-connections-to-control"]["destinationAddressPrefix"],
                         "[parameters('trustedControlVnetCidr')]")
        self.assertEqual(rules["deny-connections-to-control"]["access"], "Deny")


if __name__ == "__main__":
    unittest.main()
