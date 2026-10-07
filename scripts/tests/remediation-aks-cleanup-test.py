#!/usr/bin/env python3
"""Offline review of fixed-scope cleanup, armed apply and guest guard contracts."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock
import uuid
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "config/development/remediation-aks"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


apply = module("apply_foundation", ROOT / "scripts/remediation_aks_apply.py")
guest = module("guest_preflight", SOURCE / "buildkit-preflight.py")


class ArmedPlanTests(unittest.TestCase):
    def setUp(self):
        self.directory = ROOT / "bin/remediation-aks-tests" / uuid.uuid4().hex
        self.directory.mkdir(parents=True)
        self.addCleanup(lambda: shutil.rmtree(self.directory))
        sub = "11111111-1111-1111-1111-111111111111"
        base = f"/subscriptions/{sub}/resourceGroups/control/providers/"
        scope = apply.plan.targets(sub, "sample01",
                                   base + "Microsoft.Network/virtualNetworks/control",
                                   base + "Microsoft.ContainerService/managedClusters/control")
        self.bundle = {"subscriptionId": sub, "scope": scope, "owner": "fixture-owner",
                       "cleanupReceipt": "22222222-2222-2222-2222-222222222222", "sourceDigest": "a" * 64}
        self.receipt = {"T0": "2026-01-01T00:00:00Z", "deadline": "2026-01-02T00:00:00Z"}
        self.tags = {"orka-purpose": "isolated-remediation-verification", "orka-owner": "fixture-owner",
                     "orka-deployment": "orka-verify-sample01", "orka-cleanup-receipt": self.bundle["cleanupReceipt"],
                     "orka-source-digest": "a" * 64, "orka-budget-start-utc": "pending",
                     "orka-expires-at-utc": "pending"}
        self.prepared = {"id": scope["verificationResourceGroupId"], "location": "eastus2", "tags": self.tags}
        after = copy.deepcopy(self.prepared)
        after["tags"].update({"orka-budget-start-utc": self.receipt["T0"],
                              "orka-expires-at-utc": self.receipt["deadline"]})
        self.preview = {"status": "Succeeded", "changes": [
            {"resourceId": scope["verificationResourceGroupId"], "changeType": "Modify",
             "before": copy.deepcopy(self.prepared), "after": after,
             "delta": [{"path": "tags.orka-budget-start-utc", "propertyChangeType": "Modify"}]},
            {"resourceId": scope["verificationClusterId"], "changeType": "Create"},
            {"resourceId": scope["builderVirtualMachineId"], "changeType": "Create"},
            {"resourceId": scope["verificationRegistryId"], "changeType": "Create"},
        ]}

    def validate(self):
        apply.validate_armed_preview(self.preview, self.bundle, self.receipt, self.prepared)

    def test_owned_prepared_group_tag_transition_is_accepted(self):
        self.validate()

    def test_foreign_receipt_and_id_fail_before_apply(self):
        self.prepared["tags"]["orka-cleanup-receipt"] = "foreign"
        with self.assertRaisesRegex(apply.Failure, "ownership"):
            self.validate()
        self.prepared["tags"]["orka-cleanup-receipt"] = self.bundle["cleanupReceipt"]
        self.prepared["id"] = "/foreign"
        with self.assertRaisesRegex(apply.Failure, "id-mismatch"):
            self.validate()

    def test_child_nochange_and_existing_network_edits_are_rejected(self):
        for change in ("NoChange", "Modify", "Delete", "Ignore"):
            self.preview["changes"][1]["changeType"] = change
            with self.subTest(change=change), self.assertRaises(apply.Failure):
                self.validate()
        self.preview["changes"][1]["changeType"] = "Create"
        self.preview["changes"][1]["resourceId"] = self.bundle["scope"]["controlVnetId"]
        with self.assertRaisesRegex(apply.Failure, "outside-owned-group"):
            self.validate()

    def test_arming_digest_and_nontag_changes_fail(self):
        self.preview["changes"][0]["after"]["tags"].pop("orka-source-digest")
        with self.assertRaisesRegex(apply.Failure, "unexpected-prepared-group-change"):
            self.validate()
        self.preview["changes"][0]["after"]["tags"]["orka-source-digest"] = "a" * 64
        self.preview["changes"][0]["delta"] = [{"path": "location"}]
        with self.assertRaisesRegex(apply.Failure, "nontag-change"):
            self.validate()

    def test_parameter_or_template_drift_is_rejected_before_any_cli_call(self):
        runner = mock.Mock()
        azure = apply.Azure(self.bundle["subscriptionId"], self.directory, runner=runner)
        template = self.directory / "arm.json"
        template.write_text("{}")
        for arguments, error in (
                ({"expected_parameters": "wrong"}, "parameters"),
                ({"expected_template": "wrong"}, "template")):
            with self.subTest(error=error), self.assertRaisesRegex(apply.Failure, error):
                azure.deploy("fixture", template, {"budgetStartUtc": self.receipt["T0"]}, **arguments)
        runner.assert_not_called()

    def test_provider_validation_precedes_cleanup_and_access_create(self):
        runner = mock.Mock(side_effect=[
            subprocess.CompletedProcess([], 0, '{"error":null,"properties":{"provisioningState":"Succeeded"}}', ""),
            subprocess.CompletedProcess([], 0, '{"properties":{"provisioningState":"Succeeded"}}', ""),
        ])
        azure = apply.Azure(self.bundle["subscriptionId"], self.directory, runner=runner)
        template = self.directory / "template.json"
        template.write_text("{}")
        azure.deploy("cleanup", template, {"owner": "fixture"}, provider_validate=True)
        commands = [call.args[0] for call in runner.call_args_list]
        self.assertEqual(commands[0][1:4], ["deployment", "sub", "validate"])
        self.assertEqual(commands[0][commands[0].index("--validation-level") + 1], "Provider")
        self.assertEqual(commands[1][1:4], ["deployment", "sub", "create"])
        for flag in ("--template-file", "--parameters", "--subscription"):
            self.assertEqual(commands[0][commands[0].index(flag) + 1],
                             commands[1][commands[1].index(flag) + 1])

    def test_failed_provider_validation_never_creates_resource(self):
        runner = mock.Mock(return_value=subprocess.CompletedProcess(
            [], 0, '{"error":{"code":"BadRequest"},"properties":{"provisioningState":"Failed"}}', ""))
        azure = apply.Azure(self.bundle["subscriptionId"], self.directory, runner=runner)
        template = self.directory / "template.json"
        template.write_text("{}")
        with self.assertRaisesRegex(apply.Failure, "validation-required-before-create"):
            azure.deploy("cleanup", template, {"owner": "fixture"}, provider_validate=True)
        self.assertEqual(runner.call_count, 1)

    def test_matching_parameter_digest_is_used_for_the_exact_cli_input(self):
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, '{"properties":{}}', ""))
        azure = apply.Azure(self.bundle["subscriptionId"], self.directory, runner=runner)
        template = self.directory / "arm.json"
        template.write_text("{}")
        values = {"budgetStartUtc": self.receipt["T0"], "sourceDigest": self.bundle["sourceDigest"]}
        reviewed = self.directory / "reviewed.json"
        apply.write_json(reviewed, apply.arm_parameters(values))
        azure.deploy("fixture", template, values, expected_parameters=apply.sha(reviewed.read_bytes()),
                     expected_template=apply.sha(template.read_bytes()))
        command = runner.call_args.args[0]
        self.assertEqual(command[command.index("--subscription") + 1], self.bundle["subscriptionId"])
        actual = Path(command[command.index("--parameters") + 1][1:])
        self.assertEqual(actual.read_bytes(), reviewed.read_bytes())

    def test_az_rest_404_transport_requires_exact_status_and_expected_code(self):
        errors = [
            ('ERROR: Not Found({"error":{"code":"ResourceGroupNotFound","message":"fixture"}})\n', True),
            ('ERROR: Not Found({"error":{"code":"ResourceNotFound","message":"fixture"}})\n', True),
            ('ERROR: Not Found({"error":{"code":"RoleAssignmentNotFound","message":"fixture"}})\n', True),
            ('ERROR: Not Found({"error":{"code":"ParentResourceNotFound","message":"fixture"}})\n', True),
            ('ERROR: Not Found({"code":"NotFound","message":"Automation fixture"})\n', True),
            ('ERROR: Forbidden({"error":{"code":"ResourceNotFound"}})\n', False),
            ('ERROR: Forbidden({"code":"NotFound"})\n', False),
            ('ERROR: Not Found({"error":{"code":"AuthorizationFailed"}})\n', False),
            ('ERROR: Not Found({"code":"AuthorizationFailed"})\n', False),
            ('ERROR: Not Found({"error":null,"code":"NotFound"})\n', False),
            ('ERROR: Not Found(not-json)\n', False),
            ('ERROR: (ResourceGroupNotFound) fixture\n', False),
        ]
        for text, missing in errors:
            runner = mock.Mock(return_value=subprocess.CompletedProcess([], 1, "", text))
            azure = apply.Azure(self.bundle["subscriptionId"], self.directory, runner=runner)
            with self.subTest(error=text):
                if missing:
                    self.assertIsNone(azure.get(self.bundle["scope"]["verificationResourceGroupId"],
                                               "2024-03-01", absent=True))
                else:
                    with self.assertRaises(apply.Failure):
                        azure.get(self.bundle["scope"]["verificationResourceGroupId"], "2024-03-01", absent=True)

    def test_peer_binding_is_direct_and_scoped_to_exact_new_child(self):
        self.bundle["roleGuids"] = apply.role_guids(self.bundle["scope"])
        principal = "33333333-3333-3333-3333-333333333333"
        identity, body = apply.peer_assignment(self.bundle, {"principalId": principal})
        self.assertTrue(identity.startswith(self.bundle["scope"]["controlSidePeeringId"] +
                                           "/providers/Microsoft.Authorization/roleAssignments/"))
        self.assertEqual(body["properties"]["principalId"], principal)
        self.assertEqual(body["properties"]["principalType"], "ServicePrincipal")

    def test_schedule_put_has_name_and_exact_immutable_binding(self):
        bundle = {**self.bundle, "tenantId": "44444444-4444-4444-4444-444444444444", "suffix": "sample01"}
        receipt = {**self.receipt, "principalId": "33333333-3333-3333-3333-333333333333"}
        stored, writes = {}, []

        class FakeAzure:
            def get(self, identity, version, absent=False):
                return stored.get(identity)

            def rest(self, method, identity, version, body):
                self_outer.assertEqual(method, "PUT")
                writes.append((identity, copy.deepcopy(body)))
                stored[identity] = copy.deepcopy(body)
                if "/schedules/" in identity:
                    self_outer.assertEqual(body["name"], identity.rsplit("/", 1)[-1])
                    stored[identity]["properties"]["isEnabled"] = True

        self_outer = self
        apply.schedules(FakeAzure(), bundle, receipt, create=True)
        self.assertEqual(len(writes), 4)
        self.assertEqual({body["name"] for identity, body in writes if "/schedules/" in identity},
                         {"PrimaryCleanup", "CatchupCleanup"})
        apply.schedules(FakeAzure(), bundle, receipt)
        self.assertEqual(len(writes), 4, "readback must not rewrite an existing one-time binding")

    def test_metadata_reader_binding_is_one_action_on_exact_control_vnet(self):
        self.bundle["roleGuids"] = apply.role_guids(self.bundle["scope"])
        identity, body = apply.scoped_assignment(
            self.bundle, {"principalId": "33333333-3333-3333-3333-333333333333"},
            self.bundle["scope"]["controlVnetId"], "peering-metadata-read")
        self.assertTrue(identity.startswith(self.bundle["scope"]["controlVnetId"] +
                                           "/providers/Microsoft.Authorization/roleAssignments/"))
        self.assertTrue(body["properties"]["roleDefinitionId"].endswith(
            self.bundle["roleGuids"]["peering-metadata-read"]))
        self.assertEqual(apply.READ_ONLY_ACTIONS["peering-metadata-read"],
                         {"Microsoft.Network/virtualNetworks/virtualNetworkPeerings/read"})

    def test_retirement_requires_authoritative_physical_absence_before_any_delete(self):
        azure = mock.Mock()
        azure.get.return_value = {"id": self.bundle["scope"]["verificationResourceGroupId"]}
        with self.assertRaisesRegex(apply.Failure, "absence-required"):
            apply.retire(azure, self.bundle, {"principalId": "33333333-3333-3333-3333-333333333333"})
        azure.rest.assert_not_called()
        azure.cli.assert_not_called()

    def test_kubelet_object_id_is_not_substituted_with_client_id(self):
        scope = self.bundle["scope"]
        value = {"id": scope["controlClusterId"], "properties": {"identityProfile": {"kubeletidentity": {
            "objectId": "33333333-3333-3333-3333-333333333333",
            "clientId": "44444444-4444-4444-4444-444444444444",
            "resourceId": f"/subscriptions/{self.bundle['subscriptionId']}/resourceGroups/control/providers/Microsoft.ManagedIdentity/userAssignedIdentities/kubelet",
        }}}}
        identity = apply.kubelet_identity(value, self.bundle["subscriptionId"])
        self.assertEqual(identity["objectId"], "33333333-3333-3333-3333-333333333333")
        self.assertNotEqual(identity["objectId"], identity["clientId"])

    def test_preflight_wait_covers_queue_plus_full_ten_minute_execution(self):
        elapsed = [0]
        bundle = {**self.bundle, "tenantId": "44444444-4444-4444-4444-444444444444", "suffix": "sample01"}
        receipt = {"principalId": "33333333-3333-3333-3333-333333333333"}
        proof = {"outcome": "preflight-succeeded", "principalMatched": True, "coreDeleteAuthority": True,
                 "postDeleteGroupRead": True, "postDeletePeeringRead": True}

        class FakeAzure:
            work = self.directory
            complete_after = 1040

            def rest(self, method, identity, version, body=None, raw=False):
                return json.dumps(proof) if method == "GET" else {}

            def get(self, identity, version):
                state = "Queued" if elapsed[0] < 450 else (
                    "Running" if elapsed[0] < self.complete_after else "Completed")
                return {"properties": {"status": state}}

        def sleep(seconds):
            elapsed[0] += seconds

        with mock.patch.object(apply.time, "monotonic", side_effect=lambda: elapsed[0]), \
                mock.patch.object(apply.time, "sleep", side_effect=sleep):
            apply.preflight_job(FakeAzure(), bundle, receipt)
        self.assertIn("preflightCompleted", receipt)
        self.assertGreater(elapsed[0], 660)
        self.assertLessEqual(elapsed[0], 1200)
        elapsed[0] = 0
        FakeAzure.complete_after = 99999
        with mock.patch.object(apply.time, "monotonic", side_effect=lambda: elapsed[0]), \
                mock.patch.object(apply.time, "sleep", side_effect=sleep), \
                self.assertRaisesRegex(apply.Failure, "preflight-timed-out"):
            apply.preflight_job(FakeAzure(), bundle, {"principalId": receipt["principalId"]})
        self.assertEqual(elapsed[0], 1200)

class RecoveryPlanTests(unittest.TestCase):
    def setUp(self):
        self.directory = ROOT / "bin/remediation-aks-tests" / uuid.uuid4().hex
        self.directory.mkdir(parents=True)
        self.addCleanup(lambda: shutil.rmtree(self.directory))
        subscription = "11111111-1111-1111-1111-111111111111"
        base = f"/subscriptions/{subscription}/resourceGroups/control/providers/"
        scope = apply.plan.targets(subscription, "sample01",
                                   base + "Microsoft.Network/virtualNetworks/control",
                                   base + "Microsoft.ContainerService/managedClusters/control")
        self.previous = {"subscriptionId": subscription, "scope": scope, "suffix": "sample01",
                         "owner": "fixture-owner", "cleanupReceipt": "22222222-2222-2222-2222-222222222222",
                         "sourceDigest": "a" * 64}
        self.current = {**self.previous, "sourceDigest": "b" * 64}
        self.tags = {"orka-purpose": "isolated-remediation-verification", "orka-owner": "fixture-owner",
                     "orka-deployment": "orka-verify-sample01", "orka-cleanup-receipt": self.previous["cleanupReceipt"],
                     "orka-source-digest": self.previous["sourceDigest"],
                     "orka-budget-start-utc": "pending", "orka-expires-at-utc": "pending"}
        changes = []
        for child in ("runtimeEnvironments/PowerShell74", "runbooks/ExactFoundationCleanup"):
            changes.append({"resourceId": scope["automationAccountId"] + "/" + child, "changeType": "Create",
                            "after": {"tags": {k: self.tags[k] for k in
                                              ("orka-owner", "orka-deployment", "orka-cleanup-receipt")}}})
        self.preview = {"status": "Succeeded", "changes": changes}

    def test_only_two_missing_owned_children_are_allowed_in_recovery_deployment(self):
        apply.validate_recovery_preview(self.preview, self.previous, self.current)
        self.preview["changes"].append({"resourceId": self.previous["scope"]["automationAccountId"],
                                        "changeType": "Ignore"})
        apply.validate_recovery_preview(self.preview, self.previous, self.current)

    def test_recovery_may_not_drop_owner_recreate_account_or_touch_unrelated_scope(self):
        for mutation in ("owner", "recreate", "foreign", "identity"):
            preview = copy.deepcopy(self.preview)
            if mutation == "owner":
                preview["changes"][0]["after"]["tags"].pop("orka-owner")
            elif mutation == "recreate":
                preview["changes"][0]["resourceId"] = self.previous["scope"]["automationAccountId"]
            elif mutation == "foreign":
                preview["changes"][0]["resourceId"] = self.previous["scope"]["controlVnetId"]
            else:
                preview["changes"][0]["changeType"] = "Modify"
            with self.subTest(mutation=mutation), self.assertRaises(apply.Failure):
                apply.validate_recovery_preview(preview, self.previous, self.current)

    def test_previous_failed_receipt_is_linked_read_only_and_not_generically_adopted(self):
        previous = self.directory / "previous"
        previous.mkdir()
        (previous / "compute-inputs.json").write_text("{}")
        self.previous.update({"computeInputsSha256": apply.sha(b"{}"), "compiledHashes": {}})
        receipt = {"phase": "bootstrap-intent", "subscriptionId": self.previous["subscriptionId"],
                   "cleanupReceipt": self.previous["cleanupReceipt"], "sourceDigest": self.previous["sourceDigest"]}
        apply.write_json(previous / "bundle.json", self.previous)
        apply.write_json(previous / "receipt.json", receipt)
        receipt_bytes = (previous / "receipt.json").read_bytes()
        args = SimpleNamespace(work_dir=str(self.directory / "next"), subscription=self.previous["subscriptionId"],
                               control_vnet_id=self.previous["scope"]["controlVnetId"],
                               control_aks_id=self.previous["scope"]["controlClusterId"])
        with mock.patch.object(apply.plan, "private_path", side_effect=Path):
            path, bundle = apply.previous_recovery_inputs(str(previous), args)
            self.assertEqual(path, previous)
            self.assertEqual(bundle["sourceDigest"], "a" * 64)
            self.assertEqual((previous / "receipt.json").read_bytes(), receipt_bytes)
            receipt["phase"] = "armed"
            apply.write_json(previous / "receipt.json", receipt)
            with self.assertRaisesRegex(apply.Failure, "unsupported-prior-receipt"):
                apply.previous_recovery_inputs(str(previous), args)

    def test_mutating_recovery_requires_separate_explicit_approval_before_calls(self):
        azure = mock.Mock()
        with self.assertRaisesRegex(apply.Failure, "explicit-new-recovery-receipt"):
            apply.recover_bootstrap(azure, self.current, {}, SimpleNamespace(approved_recovery_sha256=None))
        self.assertFalse(azure.mock_calls)

    def test_recovery_tag_merges_only_two_groups_and_leaves_account_untouched(self):
        previous_dir = self.directory / "previous"
        next_dir = self.directory / "next"
        previous_dir.mkdir()
        next_dir.mkdir()
        self.previous.update({"tenantId": "44444444-4444-4444-4444-444444444444", "roleGuids": {},
                              "controlKubeletIdentity": {}, "publicKeyReady": True})
        self.current = {**self.previous, "sourceDigest": "b" * 64}
        apply.write_json(previous_dir / "bundle.json", self.previous)
        apply.write_json(previous_dir / "receipt.json", {"phase": "bootstrap-intent"})
        apply.write_json(previous_dir / "compute-inputs.json", {"sourceDigest": "a" * 64})
        apply.write_json(next_dir / "compute-inputs.json", {"sourceDigest": "b" * 64})
        proof = {"principalId": "33333333-3333-3333-3333-333333333333", "expectedTags": self.tags}
        link = {"kind": "automation-runtime-three-tag-recovery", "previousWorkDir": str(previous_dir),
                "previousBundleSha256": apply.sha((previous_dir / "bundle.json").read_bytes()),
                "previousReceiptSha256": apply.sha((previous_dir / "receipt.json").read_bytes()),
                "previousSourceDigest": "a" * 64, "nextSourceDigest": "b" * 64, "partialProof": proof}
        digest = apply.sha(apply.wire(link))
        apply.write_json(next_dir / "recovery-link.json", {"plan": link, "sha256": digest})
        azure = mock.Mock(work=next_dir)
        azure.get.side_effect = lambda identity, version: {
            "id": identity, "tags": {**self.tags, "orka-source-digest": "b" * 64}}
        with mock.patch.object(apply, "previous_recovery_inputs", return_value=(previous_dir, self.previous)), \
                mock.patch.object(apply, "partial_bootstrap_proof", return_value=proof), \
                mock.patch.object(apply, "validate_recovery_preview"), \
                mock.patch.object(apply, "finish_bootstrap"):
            apply.recover_bootstrap(azure, self.current, {}, SimpleNamespace(approved_recovery_sha256=digest))
        ids = [c.args[c.args.index("--resource-id") + 1] for c in azure.cli.call_args_list]
        self.assertEqual(ids, [self.previous["scope"]["verificationResourceGroupId"],
                               self.previous["scope"]["cleanupResourceGroupId"]])
        self.assertNotIn(self.previous["scope"]["automationAccountId"], ids)
        self.assertEqual(self.tags["orka-source-digest"], "a" * 64)


class NewTemplateTests(unittest.TestCase):
    def compile(self, name):
        result = subprocess.run(["az", "bicep", "build", "--file", str(SOURCE / (name + ".bicep")), "--stdout"],
                                capture_output=True, text=True, check=True, timeout=120)
        self.assertFalse(result.stderr.strip(), result.stderr)
        return json.loads(result.stdout)

    def test_cleanup_service_has_one_identity_no_hybrid_or_webhook(self):
        template = self.compile("cleanup")
        groups = [r for r in template["resources"] if r["type"] == "Microsoft.Resources/resourceGroups"]
        self.assertEqual(len(groups), 2)
        nested = next(r for r in template["resources"] if r["type"] == "Microsoft.Resources/deployments")
        resources = nested["properties"]["template"]["resources"]
        self.assertEqual(len(resources), 3)
        account = next(r for r in resources if r["type"] == "Microsoft.Automation/automationAccounts")
        self.assertEqual(account["identity"]["type"], "SystemAssigned")
        self.assertTrue(account["properties"]["disableLocalAuth"])
        self.assertFalse(account["properties"]["publicNetworkAccess"])
        self.assertFalse(any("schedules" in r["type"].lower() for r in resources))
        child_tags = nested["properties"]["template"]["variables"]["childOwnershipTags"]
        self.assertEqual(len(child_tags), 3)
        self.assertEqual(set(child_tags), {"orka-owner", "orka-deployment", "orka-cleanup-receipt"})
        self.assertEqual(account["tags"], "[parameters('ownershipTags')]")
        for resource in resources:
            if resource["type"] != "Microsoft.Automation/automationAccounts":
                self.assertEqual(resource["tags"], "[variables('childOwnershipTags')]")
        for group in groups:
            self.assertEqual(group["tags"], "[variables('tags')]")
        self.assertEqual(len(template["variables"]["tags"]), 7)

    def test_cleanup_roles_are_exact_delete_only_and_assignments_are_narrow(self):
        template = self.compile("cleanup-access")
        roles = [r for r in template["resources"] if r["type"] == "Microsoft.Authorization/roleDefinitions"]
        self.assertEqual(len(roles), 4)
        actions = [set(r["properties"]["permissions"][0]["actions"]) for r in roles]
        self.assertIn(apply.REQUIRED_ACTIONS, actions)
        self.assertFalse(any("*" in a or a.endswith("/write") for group in actions for a in group))
        for role in roles:
            self.assertEqual(role["properties"]["permissions"][0]["dataActions"], [])
        modules = [r for r in template["resources"] if r["type"] == "Microsoft.Resources/deployments"]
        self.assertEqual(len(modules), 2)
        self.assertTrue(all("control" not in r["resourceGroup"].lower() for r in modules))
        groups_read = next(r for r in roles if r["name"] == "[parameters('groupMetadataRoleGuid')]")
        peers_read = next(r for r in roles if r["name"] == "[parameters('peerMetadataRoleGuid')]")
        self.assertEqual(groups_read["properties"]["permissions"][0]["actions"],
                         ["Microsoft.Resources/subscriptions/resourceGroups/read"])
        self.assertEqual(groups_read["properties"]["assignableScopes"], ["[subscription().id]"])
        self.assertEqual(peers_read["properties"]["permissions"][0]["actions"],
                         ["Microsoft.Network/virtualNetworks/virtualNetworkPeerings/read"])
        self.assertIn("Microsoft.Resources/resourceGroups", peers_read["properties"]["assignableScopes"][0])

    def test_tag_recovery_cannot_put_existing_account_or_change_child_configuration(self):
        recovery = self.compile("cleanup-recovery")
        normal = self.compile("cleanup")
        nested = next(r for r in normal["resources"] if r["type"] == "Microsoft.Resources/deployments")
        original = {r["type"]: r for r in nested["properties"]["template"]["resources"]}
        self.assertEqual(len(recovery["resources"]), 2)
        for resource in recovery["resources"]:
            self.assertIn(resource["type"], ("Microsoft.Automation/automationAccounts/runbooks",
                                             "Microsoft.Automation/automationAccounts/runtimeEnvironments"))
            self.assertEqual(resource["properties"], original[resource["type"]]["properties"])
            self.assertEqual(resource["tags"], "[variables('childOwnershipTags')]")
        self.assertEqual(len(recovery["variables"]["childOwnershipTags"]), 3)

    def test_registry_assignments_are_pull_only_on_the_single_new_registry(self):
        template = self.compile("registry-pull")
        self.assertEqual(len(template["resources"]), 2)
        self.assertIn(apply.ACR_PULL_ROLE, template["variables"]["pullRoleId"])
        for assignment in template["resources"]:
            self.assertEqual(assignment["type"], "Microsoft.Authorization/roleAssignments")
            self.assertIn("Microsoft.ContainerRegistry/registries", assignment["scope"])
            self.assertEqual(assignment["properties"]["principalType"], "ServicePrincipal")
            self.assertEqual(assignment["properties"]["roleDefinitionId"], "[variables('pullRoleId')]")

    def test_private_links_never_enable_gateway_transit_or_dns_registration(self):
        peer = self.compile("peering")["resources"][0]["properties"]
        self.assertTrue(peer["allowVirtualNetworkAccess"])
        self.assertFalse(peer["allowForwardedTraffic"])
        self.assertFalse(peer["allowGatewayTransit"])
        self.assertFalse(peer["useRemoteGateways"])
        link = self.compile("dns-link")["resources"][0]["properties"]
        self.assertFalse(link["registrationEnabled"])

    def test_real_powershell_runbook_contracts_without_azure(self):
        executable = ROOT / "bin/remediation-aks-pwsh/pwsh"
        self.assertTrue(executable.is_file(), "Install the required approved PowerShell validation runtime")
        runtime = ROOT / "bin/remediation-aks-pwsh/runtime"
        runtime.mkdir(parents=True, exist_ok=True)
        environment = {**os.environ, "TMPDIR": str(runtime), "DOTNET_EnableDiagnostics": "0",
                       "POWERSHELL_TELEMETRY_OPTOUT": "1"}
        result = subprocess.run([str(executable), "-NoLogo", "-NoProfile", "-NonInteractive",
                                 "-File", str(ROOT / "scripts/tests/remediation-aks-runbook-test.ps1"),
                                 "-Runbook", str(SOURCE / "cleanup-runbook.ps1")],
                                capture_output=True, text=True, env=environment, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("contracts passed: 21", result.stdout)


class GuestGuardTests(unittest.TestCase):
    def fixture(self):
        def match(left, right):
            return {"match": {"op": "==", "left": left, "right": right}}
        source = match({"meta": {"key": "iifname"}}, "orka-build0")
        def rule(chain, address=None, protocol=None, port=None, verdict="drop"):
            expressions = [copy.deepcopy(source)]
            if address:
                expressions.append(match({"payload": {"protocol": "ip", "field": "daddr"}}, address))
            if protocol:
                expressions.append(match({"payload": {"protocol": protocol, "field": "dport"}}, port))
            expressions += [{"counter": {"packets": 0, "bytes": 0}}, {verdict: None}]
            return {"rule": {"chain": chain, "expr": expressions}}
        return {"nftables": [
            {"chain": {"name": "input", "hook": "input", "prio": -200, "policy": "accept"}},
            {"chain": {"name": "forward", "hook": "forward", "prio": -200, "policy": "accept"}},
            rule("input"),
            rule("forward", "169.254.169.254"),
            rule("forward", "168.63.129.16", "udp", 53, "accept"),
            rule("forward", "168.63.129.16", "tcp", 53, "accept"),
            rule("forward", "168.63.129.16"),
        ]}

    def test_exact_forwarded_boundary_preserves_dns(self):
        guest.validate_rules(self.fixture())

    def test_metadata_accept_and_extra_inbound_rule_fail(self):
        document = self.fixture()
        document["nftables"][3]["rule"]["expr"][-1] = {"accept": None}
        with self.assertRaisesRegex(RuntimeError, "rule-mismatch"):
            guest.validate_rules(document)
        document = self.fixture()
        document["nftables"].append(copy.deepcopy(document["nftables"][2]))
        with self.assertRaisesRegex(RuntimeError, "count-mismatch"):
            guest.validate_rules(document)

    def test_wireserver_http_exception_and_wrong_bridge_fail(self):
        document = self.fixture()
        document["nftables"][4]["rule"]["expr"][2]["match"]["right"] = 80
        with self.assertRaises(RuntimeError):
            guest.validate_rules(document)
        document = self.fixture()
        document["nftables"][3]["rule"]["expr"][0]["match"]["right"] = "eth0"
        with self.assertRaisesRegex(RuntimeError, "unbounded-firewall-source"):
            guest.validate_rules(document)

    def test_default_and_override_paths_stay_below_the_service(self):
        for leaf in ("workloads", "requested-override"):
            guest.validate_run_cgroup("0::" + guest.CGROUP + "/supervisor/" + leaf + "/buildkit/fixture")
        for escaped in ("0::/buildkit/fixture", "0::/other.slice/buildkit/fixture",
                        "0::" + guest.CGROUP + "/supervisor/daemon"):
            with self.subTest(cgroup=escaped), self.assertRaisesRegex(RuntimeError, "outside-bounded"):
                guest.validate_run_cgroup(escaped)


if __name__ == "__main__":
    unittest.main()
