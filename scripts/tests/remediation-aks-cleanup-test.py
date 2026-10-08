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
from urllib.parse import parse_qs, urlsplit

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
        self.bundle["roleGuids"] = apply.builtin_role_guids()
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
        for identity, body in writes:
            if "/jobSchedules/" not in identity:
                continue
            values = {key: json.loads(value) for key, value in body["properties"]["parameters"].items()}
            self.assertEqual(values["Mode"], "Cleanup")
            self.assertIsInstance(values["ManifestJson"], str)
            self.assertEqual(json.loads(values["ManifestJson"]), apply.manifest(bundle, receipt, cleanup=True))
            self.assertTrue(json.loads(values["ManifestJson"])["requireNodeScope"])
            self.assertTrue(json.loads(values["ManifestJson"])["requirePeeringScope"])
        apply.schedules(FakeAzure(), bundle, receipt)
        self.assertEqual(len(writes), 4, "readback must not rewrite an existing one-time binding")

    def test_preflight_job_serializes_each_parameter_before_the_outer_request(self):
        bundle = {**self.bundle, "tenantId": "44444444-4444-4444-4444-444444444444", "suffix": "sample01"}
        receipt = {"principalId": "33333333-3333-3333-3333-333333333333"}
        azure = mock.Mock(work=self.directory)
        captured = []

        def request(method, identity, version, body=None, raw=False):
            if method == "PUT":
                captured.append(copy.deepcopy(body))
                return None
            self.assertEqual(method, "GET")
            self.assertTrue(identity.endswith("/output"))
            return json.dumps({"outcome": "preflight-succeeded", "principalMatched": True,
                               "coreDeleteAuthority": True, "postDeleteGroupRead": True,
                               "postDeletePeeringRead": True})

        azure.rest.side_effect = request
        azure.get.return_value = {"properties": {"status": "Completed"}}
        apply.preflight_job(azure, bundle, receipt)
        self.assertEqual(len(captured), 1)
        parameters = captured[0]["properties"]["parameters"]
        self.assertEqual(set(parameters), {"ManifestJson", "Mode"})
        values = {key: json.loads(value) for key, value in parameters.items()}
        self.assertEqual(values["Mode"], "Preflight")
        self.assertIsInstance(values["ManifestJson"], str)
        self.assertEqual(values["ManifestJson"], apply.wire(apply.manifest(bundle, receipt)).decode())
        self.assertEqual(json.loads(values["ManifestJson"]), apply.manifest(bundle, receipt))
        self.assertFalse(json.loads(values["ManifestJson"])["requireNodeScope"])
        self.assertIn("preflightCompleted", receipt)

    def test_parameter_encoding_preserves_quotes_backslashes_and_unicode_after_service_decode(self):
        bundle = {**self.bundle, "tenantId": "44444444-4444-4444-4444-444444444444",
                  "suffix": "sample01", "owner": 'quoted "owner" \\ caf\u00e9'}
        receipt = {**self.receipt, "principalId": "33333333-3333-3333-3333-333333333333"}
        for cleanup in (False, True):
            parameters = apply.runbook_parameters(bundle, receipt, cleanup=cleanup)
            decoded = json.loads(parameters["ManifestJson"])
            self.assertIsInstance(decoded, str)
            self.assertEqual(decoded, apply.wire(apply.manifest(bundle, receipt, cleanup=cleanup)).decode())
            self.assertEqual(json.loads(decoded)["owner"], bundle["owner"])

    def test_reader_is_explicitly_subscription_scoped_without_network_write(self):
        self.bundle["roleGuids"] = apply.builtin_role_guids()
        scope = "/subscriptions/" + self.bundle["subscriptionId"]
        identity, body = apply.scoped_assignment(
            self.bundle, {"principalId": "33333333-3333-3333-3333-333333333333"},
            scope, "group-metadata-read")
        self.assertTrue(identity.startswith(scope +
                                           "/providers/Microsoft.Authorization/roleAssignments/"))
        self.assertTrue(body["properties"]["roleDefinitionId"].endswith(
            "acdd72a7-3385-48ef-bd42-f606fba81ae7"))
        self.assertEqual(apply.BUILTIN_ROLES["group-metadata-read"][2], {"*/read"})

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

class BuiltinAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.directory = ROOT / "bin/remediation-aks-tests" / uuid.uuid4().hex
        self.directory.mkdir(parents=True)
        self.addCleanup(lambda: shutil.rmtree(self.directory))
        self.subscription = "11111111-1111-1111-1111-111111111111"
        base = f"/subscriptions/{self.subscription}/resourceGroups/control/providers/"
        self.scope = apply.plan.targets(self.subscription, "sample01",
            base + "Microsoft.Network/virtualNetworks/control",
            base + "Microsoft.ContainerService/managedClusters/control")
        self.bundle = {"subscriptionId": self.subscription, "scope": self.scope,
                       "authorizationModel": apply.AUTHORIZATION_MODEL,
                       "roleGuids": apply.builtin_role_guids(), "suffix": "sample01",
                       "owner": "fixture", "cleanupReceipt": "22222222-2222-2222-2222-222222222222"}
        self.principal = "33333333-3333-3333-3333-333333333333"
        self.roles = {}
        for guid, name, actions in apply.BUILTIN_ROLES.values():
            identity = f"/subscriptions/{self.subscription}/providers/Microsoft.Authorization/roleDefinitions/{guid}"
            self.roles[identity] = {"id": identity, "properties": {"type": "BuiltInRole", "roleName": name,
                "permissions": [{"actions": sorted(actions), "notActions": [], "dataActions": [],
                                 "notDataActions": []}]}}

    def test_exact_builtin_catalog_is_read_without_mutation(self):
        azure = mock.Mock()
        azure.get.side_effect = lambda identity, version: self.roles[identity]
        apply.validate_builtin_roles(azure, self.bundle)
        self.assertEqual(azure.get.call_count, 3)
        azure.rest.assert_not_called()
        azure.deploy.assert_not_called()
        azure.cli.assert_not_called()

    def test_new_permission_model_requires_explicit_pinned_builtin_ids(self):
        for field in ("authorizationModel", "roleGuids"):
            bundle = copy.deepcopy(self.bundle)
            bundle.pop(field)
            azure = mock.Mock()
            with self.subTest(field=field), self.assertRaises(apply.Failure):
                apply.validate_builtin_roles(azure, bundle)
            azure.get.assert_not_called()

    def test_builtin_catalog_changes_and_impostors_fail_before_grants(self):
        for mode in ("custom", "wildcard", "missing", "data", "conditional"):
            roles = copy.deepcopy(self.roles)
            first = next(iter(roles.values()))["properties"]
            permission = first["permissions"][0]
            if mode == "custom":
                first["type"] = "CustomRole"
            elif mode == "wildcard":
                permission["actions"].append("*")
            elif mode == "missing":
                permission["actions"].pop()
            elif mode == "data":
                permission["dataActions"].append("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read")
            else:
                permission["condition"] = "unexpected"
            azure = mock.Mock()
            azure.get.side_effect = lambda identity, version: roles[identity]
            with self.subTest(mode=mode), self.assertRaises(apply.Failure):
                apply.validate_builtin_roles(azure, self.bundle)
            azure.rest.assert_not_called()
            azure.deploy.assert_not_called()

    def assignment_fixture(self):
        expected = apply.cleanup_assignment_scopes(self.bundle, node=True, peer=True)
        receipt = {"principalId": self.principal, "cleanupAssignments": {}}
        assignments = []
        for key, (scope, role) in expected.items():
            identity, body = apply.scoped_assignment(self.bundle, receipt, scope, role)
            assignments.append({"id": identity, "properties": {**body["properties"], "scope": scope}})
            receipt["cleanupAssignments"][key] = identity
        return expected, receipt, assignments

    def test_exact_assignment_inventory_and_scopes_are_required(self):
        expected, receipt, assignments = self.assignment_fixture()
        azure = mock.Mock()
        azure.cli.return_value = {"value": assignments}
        apply.audit_cleanup_assignments(azure, self.bundle, receipt, expected, complete=True)
        for mode in ("extra", "broad-peer", "foreign-principal", "missing", "pagination", "condition", "duplicate"):
            document = {"value": copy.deepcopy(assignments)}
            if mode == "extra":
                extra = copy.deepcopy(assignments[0])
                extra["properties"]["scope"] = "/subscriptions/" + self.subscription
                document["value"].append(extra)
            elif mode == "broad-peer":
                document["value"][-1]["properties"]["scope"] = self.scope["controlVnetId"]
            elif mode == "foreign-principal":
                document["value"][0]["properties"]["principalId"] = "44444444-4444-4444-4444-444444444444"
            elif mode == "missing":
                document["value"].pop()
            elif mode == "pagination":
                document["nextLink"] = "https://management.azure.com/another-page"
            elif mode == "condition":
                document["value"][0]["properties"]["condition"] = "unexpected"
            else:
                document["value"].append(copy.deepcopy(assignments[0]))
            azure.cli.return_value = document
            with self.subTest(mode=mode), self.assertRaises(apply.Failure):
                apply.audit_cleanup_assignments(azure, self.bundle, receipt, expected, complete=True)
        azure.rest.assert_not_called()

    def test_matching_but_unrecorded_assignment_is_not_adopted(self):
        expected, receipt, assignments = self.assignment_fixture()
        receipt["cleanupAssignments"] = {}
        azure = mock.Mock()
        azure.cli.return_value = {"value": assignments}
        with self.assertRaisesRegex(apply.Failure, "unrecorded"):
            apply.audit_cleanup_assignments(azure, self.bundle, receipt, expected, complete=False)

    def test_post_grant_list_visibility_wait_is_bounded_and_subset_only(self):
        expected, receipt, assignments = self.assignment_fixture()
        azure = mock.Mock()
        clock = [0]

        def sleep(seconds):
            clock[0] += seconds

        azure.cli.side_effect = [{"value": assignments[:1]}, {"value": assignments}]
        with mock.patch.object(apply.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(apply.time, "sleep", side_effect=sleep):
            apply.audit_cleanup_assignments(azure, self.bundle, receipt, expected, complete=True, wait_missing=True)
        self.assertEqual(azure.cli.call_count, 2)
        self.assertEqual(clock[0], 2)
        azure.cli.reset_mock(side_effect=True)
        azure.cli.return_value = {"value": assignments[:1]}
        clock[0] = 0
        with mock.patch.object(apply.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(apply.time, "sleep", side_effect=sleep), \
             self.assertRaisesRegex(apply.Failure, "inventory-incomplete"):
            apply.audit_cleanup_assignments(azure, self.bundle, receipt, expected, complete=True, wait_missing=True)
        self.assertGreater(azure.cli.call_count, 1)
        self.assertLess(clock[0], apply.ASSIGNMENT_READBACK_SECONDS)
        azure.rest.assert_not_called()
        azure.deploy.assert_not_called()

    def test_post_grant_wait_never_retries_extra_scope_conditions_or_pagination(self):
        expected, receipt, assignments = self.assignment_fixture()
        for mode in ("scope", "condition", "unrecorded", "pagination"):
            document = {"value": copy.deepcopy(assignments)}
            if mode == "scope":
                document["value"][0]["properties"]["scope"] = self.scope["controlVnetId"]
            elif mode == "condition":
                document["value"][0]["properties"]["condition"] = "unexpected"
            elif mode == "unrecorded":
                document["value"][0]["id"] += "-different"
            else:
                document["nextLink"] = "https://management.azure.com/unknown-page"
            azure = mock.Mock()
            azure.cli.return_value = document
            with self.subTest(mode=mode), mock.patch.object(apply.time, "sleep") as sleep, \
                 self.assertRaises(apply.Failure):
                apply.audit_cleanup_assignments(azure, self.bundle, receipt, expected, complete=True, wait_missing=True)
            sleep.assert_not_called()
            self.assertEqual(azure.cli.call_count, 1)

    def test_custom_role_resource_is_rejected_even_inside_conditional_nested_template(self):
        for condition in (True, False):
            value = {"resources": [{"type": "Microsoft.Resources/deployments", "properties": {"template": {
                "resources": [{"type": "Microsoft.Authorization/roleDefinitions", "condition": condition}]}}}]}
            with self.subTest(condition=condition), self.assertRaisesRegex(apply.Failure, "custom-role-creation"):
                apply.reject_custom_role_definitions(value)

    def test_retirement_never_deletes_builtin_role_definitions(self):
        expected, receipt, assignments = self.assignment_fixture()
        self.bundle.update({"owner": "fixture", "cleanupReceipt": "22222222-2222-2222-2222-222222222222"})
        receipt["cleanupAssignments"] = {"groupsRead": receipt["cleanupAssignments"]["groupsRead"]}
        reader = next(item for item in assignments if item["id"] == receipt["cleanupAssignments"]["groupsRead"])
        group = {"id": self.scope["cleanupResourceGroupId"], "tags": {
            "orka-purpose": "isolated-remediation-verification", "orka-owner": "fixture",
            "orka-deployment": "orka-verify-sample01", "orka-cleanup-receipt": self.bundle["cleanupReceipt"]}}
        deleted = []
        azure = mock.Mock()
        azure.work = Path("/unused-private-test-output")
        azure.get.side_effect = lambda identity, version, **kwargs: (
            {"value": []} if identity.endswith("/jobs") else
            group if identity == self.scope["cleanupResourceGroupId"] else
            reader if identity == reader["id"] and identity not in deleted else None)
        azure.rest.side_effect = lambda method, identity, version: deleted.append(identity)
        azure.cli.return_value = False
        with mock.patch.object(apply, "account_identity", return_value=self.principal), \
             mock.patch.object(apply, "write_json"), mock.patch.object(apply, "save_receipt"):
            apply.retire(azure, self.bundle, receipt)
        self.assertEqual(deleted, [reader["id"]])
        self.assertTrue(all("/roleAssignments/" in identity for identity in deleted))
        self.assertFalse(any("/roleDefinitions/" in call.args[1] for call in azure.rest.call_args_list))
        self.assertEqual(receipt["phase"], "retired")

    def test_unapproved_builtin_resume_has_no_azure_calls(self):
        azure = mock.Mock()
        with self.assertRaisesRegex(apply.Failure, "approved-new-authorization"):
            apply.resume_builtin_bootstrap(azure, self.bundle, {}, SimpleNamespace(approved_authorization_sha256=None))
        self.assertEqual(azure.mock_calls, [])

    def grant_client(self, mode=None):
        outer = self

        class FakeAzure:
            def __init__(self):
                self.work = outer.directory
                self.assignments = {}
                self.deployments = []
                self.puts = []
                self.delayed_reads = 0

            def get(self, identity, _version, absent=False):
                if identity in outer.roles:
                    return copy.deepcopy(outer.roles[identity])
                value = self.assignments.get(identity)
                if value is None and not absent:
                    raise AssertionError("unexpected assignment read")
                return copy.deepcopy(value)

            def cli(self, *arguments):
                outer.assertEqual(arguments[:3], ("rest", "--method", "GET"))
                values = list(self.assignments.values())
                if mode == "delayed-list" and self.deployments and self.delayed_reads < 2:
                    self.delayed_reads += 1
                    values = values[:-1]
                return {"value": copy.deepcopy(values)}

            def rest(self, method, identity, _version, body):
                outer.assertEqual(method, "PUT")
                outer.assertIn("/roleAssignments/", identity)
                self.puts.append(identity)
                scope = identity.rsplit("/providers/Microsoft.Authorization/roleAssignments/", 1)[0]
                self.assignments[identity] = {"id": identity, "properties": {**body["properties"], "scope": scope}}

            def deploy(self, name, _template, values, **options):
                outer.assertEqual(name, "bounded-cleanup-builtin-access")
                outer.assertTrue(options["provider_validate"])
                self.deployments.append(copy.deepcopy(values))
                expected = apply.cleanup_assignment_scopes(outer.bundle, node=values["includeNodeGroup"])
                outputs = {"nodeAssignmentId": {"value": ""}}
                keys = {"verification": "verificationAssignmentId", "groupsRead": "groupMetadataAssignmentId",
                        "nodes": "nodeAssignmentId"}
                for key, (scope, role_name) in expected.items():
                    role = f"/subscriptions/{outer.subscription}/providers/Microsoft.Authorization/roleDefinitions/" + \
                        outer.bundle["roleGuids"][role_name]
                    identity = scope + "/providers/Microsoft.Authorization/roleAssignments/" + \
                        apply.arm_guid(scope, role, values["principalId"])
                    target = outer.scope["cleanupResourceGroupId"] if mode == "wrong-scope" and key == "verification" else scope
                    self.assignments[identity] = {"id": identity, "properties": {
                        "scope": target, "principalId": values["principalId"], "roleDefinitionId": role,
                        "principalType": "ServicePrincipal"}}
                    outputs[keys[key]] = {"value": identity}
                if mode == "extra-after-deploy":
                    extra = copy.deepcopy(next(iter(self.assignments.values())))
                    extra["id"] += "-unexpected"
                    extra["properties"]["scope"] = outer.scope["controlVnetId"]
                    self.assignments[extra["id"]] = extra
                return {"properties": {"outputs": outputs}}

        return FakeAzure()

    def test_access_executes_each_approved_stage_with_exact_readbacks_and_audits(self):
        azure = self.grant_client()
        receipt = {"principalId": self.principal}
        for node, peer, count in ((False, False, 2), (True, False, 3), (True, True, 4)):
            apply.access(azure, self.bundle, receipt, node=node, peer=peer)
            self.assertEqual(len(azure.assignments), count)
            self.assertEqual(len(receipt["cleanupAssignments"]), count)
            self.assertIs(receipt["nodeScopeReady"], node)
            self.assertIs(receipt["peeringScopeReady"], peer)
            saved = json.loads((self.directory / "receipt.json").read_text())
            self.assertEqual(saved, receipt)
        self.assertEqual(len(azure.deployments), 3)
        self.assertEqual(len(azure.puts), 1)
        self.assertTrue(azure.puts[0].startswith(self.scope["controlSidePeeringId"] + "/"))

    def test_access_rejects_wrong_scope_outputs_and_extra_grants_after_deploy(self):
        for mode, expected in (("wrong-scope", "readback-mismatch"),
                               ("extra-after-deploy", "unexpected-cleanup-assignment")):
            azure = self.grant_client(mode)
            receipt = {"principalId": self.principal}
            with self.subTest(mode=mode), mock.patch.object(apply.time, "sleep") as sleep, \
                 self.assertRaisesRegex(apply.Failure, expected):
                apply.access(azure, self.bundle, receipt)
            sleep.assert_not_called()
            self.assertEqual(len(azure.deployments), 1)
            self.assertNotIn("nodeScopeReady", receipt)
            self.assertEqual(azure.puts, [])

    def test_access_waits_for_new_bindings_at_its_actual_post_deploy_audit(self):
        azure = self.grant_client("delayed-list")
        receipt = {"principalId": self.principal}
        clock = [0]

        def sleep(seconds):
            clock[0] += seconds

        with mock.patch.object(apply.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(apply.time, "sleep", side_effect=sleep):
            apply.access(azure, self.bundle, receipt)
        self.assertEqual(len(azure.deployments), 1)
        self.assertEqual(azure.delayed_reads, 2)
        self.assertEqual(clock[0], 4)
        self.assertEqual(set(receipt["cleanupAssignments"]), {"verification", "groupsRead"})
        self.assertEqual(len(azure.assignments), 2)
        self.assertEqual(azure.puts, [])

    def test_access_does_not_deploy_when_an_unrecorded_grant_already_exists(self):
        azure = self.grant_client()
        _, _, assignments = self.assignment_fixture()
        azure.assignments[assignments[0]["id"]] = assignments[0]
        with self.assertRaisesRegex(apply.Failure, "unrecorded"):
            apply.access(azure, self.bundle, {"principalId": self.principal})
        self.assertEqual(azure.deployments, [])
        self.assertEqual(azure.puts, [])

    def test_network_readbacks_match_actual_identity_instance_and_exact_scopes(self):
        identity_id = self.scope["verificationResourceGroupId"] + \
            "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/orka-verify-sample01-aks-control-plane"
        client = "55555555-5555-5555-5555-555555555555"
        identity = {"id": identity_id, "properties": {"principalId": self.principal, "clientId": client}, "tags": {
            "orka-owner": self.bundle["owner"], "orka-cleanup-receipt": self.bundle["cleanupReceipt"],
            "orka-purpose": "isolated-remediation-verification", "orka-deployment": "orka-verify-sample01"}}
        aks = {"identity": {"type": "UserAssigned", "userAssignedIdentities": {
            identity_id: {"principalId": self.principal, "clientId": client}}}}
        role = f"/subscriptions/{self.subscription}/providers/Microsoft.Authorization/roleDefinitions/" + \
            apply.BUILTIN_ROLES["peering-cleanup"][0]
        # Independently evaluated by Bicep console for these exact public inputs.
        self.assertEqual(apply.arm_guid(self.scope["verificationVnetId"], identity_id, role),
                         "a02ca53c-384d-5d0d-811b-e6351d4301bd")
        objects = {identity_id: identity}
        for scope in apply.network_assignment_scopes(self.bundle).values():
            assignment = scope + "/providers/Microsoft.Authorization/roleAssignments/" + \
                apply.arm_guid(scope, identity_id, role)
            objects[assignment] = {"properties": {
                "principalId": self.principal, "roleDefinitionId": role, "scope": scope}}
        azure = mock.Mock(work=self.directory)
        azure.get.side_effect = lambda key, *_args: copy.deepcopy(objects[key])
        receipt = {}
        apply.verify_network_assignments(azure, self.bundle, receipt, aks)
        self.assertEqual(set(receipt["networkAssignments"]), {"vnet", "nodes", "nat"})
        self.assertEqual(receipt["aksControlPrincipalId"], self.principal)
        first = next(key for key in objects if key != identity_id)
        for property_name, value in (("scope", self.scope["controlVnetId"]),
                                     ("principalId", "66666666-6666-6666-6666-666666666666")):
            original = objects[first]["properties"][property_name]
            objects[first]["properties"][property_name] = value
            with self.subTest(property=property_name), self.assertRaisesRegex(apply.Failure, "readback-mismatch"):
                apply.verify_network_assignments(azure, self.bundle, {}, aks)
            objects[first]["properties"][property_name] = original
        aks["identity"]["userAssignedIdentities"][identity_id]["clientId"] = "different"
        with self.assertRaisesRegex(apply.Failure, "identity-instance-drift"):
            apply.verify_network_assignments(azure, self.bundle, {}, aks)
        azure.rest.assert_not_called()
        azure.deploy.assert_not_called()

    def transition_fixture(self):
        directories = [self.directory / name for name in ("original", "middle", "stopped", "next")]
        for directory in directories:
            directory.mkdir()
        original_dir, middle_dir, stopped_dir, next_dir = directories
        base = {**self.bundle, "version": 1, "suffix": "sample01", "owner": "fixture",
                "tenantId": "44444444-4444-4444-4444-444444444444",
                "cleanupReceipt": "22222222-2222-2222-2222-222222222222",
                "roleGuids": apply.role_guids(self.scope), "controlKubeletIdentity": {}, "publicKeyReady": True}
        base.pop("authorizationModel")
        previous = None
        for index, directory in enumerate(directories[:3]):
            hashes = {"fixture-source": str(index) * 64}
            digest = apply.sha(apply.wire(hashes))
            apply.write_json(directory / "compute-inputs.json", {"sourceDigest": digest})
            value = {**base, "sourceHashes": hashes, "sourceDigest": digest, "compiledHashes": {},
                     "computeInputsSha256": apply.sha((directory / "compute-inputs.json").read_bytes())}
            apply.write_json(directory / "bundle.json", value)
            if index == 0:
                original = value
                apply.write_json(directory / "receipt.json", {
                    "phase": "bootstrap-intent", "subscriptionId": self.subscription,
                    "sourceDigest": digest, "cleanupReceipt": base["cleanupReceipt"]})
            elif index == 1:
                apply.write_json(directory / "receipt.json", {"phase": "recovery-intent"})
                apply.write_json(directory / "recovery-link.json", {"plan": {"fixture": True}})
            else:
                previous = value
        failed = {"workDir": str(middle_dir), "bundleSha256": apply.sha((middle_dir / "bundle.json").read_bytes()),
                  "receiptSha256": apply.sha((middle_dir / "receipt.json").read_bytes()),
                  "linkFileSha256": apply.sha((middle_dir / "recovery-link.json").read_bytes())}
        tags = {"orka-purpose": "isolated-remediation-verification", "orka-owner": base["owner"],
                "orka-deployment": "orka-verify-sample01", "orka-cleanup-receipt": base["cleanupReceipt"],
                "orka-source-digest": original["sourceDigest"], "orka-budget-start-utc": "pending",
                "orka-expires-at-utc": "pending"}
        link = {"kind": "automation-child-zero-tag-recovery", "previousWorkDir": str(original_dir),
                "previousBundleSha256": apply.sha((original_dir / "bundle.json").read_bytes()),
                "previousReceiptSha256": apply.sha((original_dir / "receipt.json").read_bytes()),
                "previousSourceDigest": original["sourceDigest"], "nextSourceDigest": previous["sourceDigest"],
                "partialProof": {"principalId": self.principal, "expectedTags": tags}, "failedRecovery": failed}
        link_digest = apply.sha(apply.wire(link))
        apply.write_json(stopped_dir / "recovery-link.json", {"plan": link, "sha256": link_digest})
        receipt = {"phase": "recovery-intent", "subscriptionId": self.subscription,
                   "cleanupReceipt": base["cleanupReceipt"], "sourceDigest": previous["sourceDigest"],
                   "principalId": self.principal, "recoveryOf": {
                       "sourceDigest": original["sourceDigest"], "receiptSha256": link["previousReceiptSha256"],
                       "recoveryLinkSha256": link_digest, "failedRecovery": failed}}
        apply.write_json(stopped_dir / "receipt.json", receipt)
        args = SimpleNamespace(subscription=self.subscription, work_dir=str(next_dir),
                               control_vnet_id=self.scope["controlVnetId"],
                               control_aks_id=self.scope["controlClusterId"])
        return stopped_dir, previous, receipt, tags, args

    @mock.patch.object(apply.plan, "private_path", side_effect=Path)
    def test_transition_reads_and_pins_all_three_historical_receipts_without_edits(self, _private_path):
        stopped, previous, receipt, tags, args = self.transition_fixture()
        originals = {path: path.read_bytes() for path in self.directory.rglob("*.json")}
        result = apply.quota_blocked_inputs(args, str(stopped))
        self.assertEqual(result, (stopped, previous, receipt, tags))
        self.assertTrue(all(path.read_bytes() == raw for path, raw in originals.items()))
        for path in (self.directory / "original/receipt.json", self.directory / "middle/recovery-link.json",
                     stopped / "compute-inputs.json", stopped / "receipt.json"):
            raw = path.read_bytes()
            path.write_bytes(raw + b" ")
            if path == stopped / "receipt.json":
                modified = json.loads(raw)
                modified["T0"] = "2026-01-01T00:00:00Z"
                apply.write_json(path, modified)
            with self.subTest(path=path.name), self.assertRaises(apply.Failure):
                apply.quota_blocked_inputs(args, str(stopped))
            path.write_bytes(raw)

    def test_transition_live_proof_refuses_publication_grants_and_changed_ownership(self):
        stopped, previous, receipt, tags, args = self.transition_fixture()
        account = self.scope["automationAccountId"]
        objects = {}
        for key in ("verificationResourceGroupId", "cleanupResourceGroupId", "automationAccountId"):
            objects[self.scope[key]] = {"id": self.scope[key],
                "tags": dict(tags if key == "automationAccountId" else
                             {**tags, "orka-source-digest": previous["sourceDigest"]})}
        objects[account].update({"identity": {"type": "SystemAssigned", "tenantId": previous["tenantId"],
            "principalId": self.principal}, "properties": {"state": "Ok", "disableLocalAuth": True,
                                                          "publicNetworkAccess": False}})
        runtime = account + "/runtimeEnvironments/PowerShell74"
        book = account + "/runbooks/ExactFoundationCleanup"
        objects[runtime] = {"id": runtime, "tags": {}, "properties": {
            "runtime": {"language": "PowerShell", "version": "7.4"}, "defaultPackages": {}}}
        objects[book] = {"id": book, "tags": {}, "properties": {
            "state": "New", "runbookType": "PowerShell", "runtimeEnvironment": "PowerShell74"}}
        for name in ("jobs", "schedules", "jobSchedules"):
            objects[account + "/" + name] = {"value": []}
        failed = f"/subscriptions/{self.subscription}/providers/Microsoft.Resources/deployments/bounded-cleanup-access"
        objects[failed] = {"id": failed, "properties": {
            "provisioningState": "Failed", "error": {"code": "RoleDefinitionLimitExceeded"}}}
        azure = mock.Mock()
        azure.get.side_effect = lambda identity, *unused, **kwargs: objects.get(identity)
        state = {"assignments": [], "nodeExists": False, "verificationResources": []}
        azure.cli.side_effect = lambda *arguments: (
            {"value": state["assignments"]} if arguments[0] == "rest" else
            state["nodeExists"] if arguments[:2] == ("group", "exists") else
            [{"id": account}] if arguments[-1] == self.scope["cleanupResourceGroupId"].split("/")[-1] else
            state["verificationResources"])
        proof = apply.quota_blocked_proof(azure, previous, receipt, tags)
        self.assertEqual(proof["principalId"], self.principal)
        self.assertEqual(proof["existingAssignments"], 0)
        for identity, key, wrong in (
                (book, "state", "Published"), (account, "publicNetworkAccess", True),
                (failed, "error", {"code": "AuthorizationFailed"})):
            old = objects[identity]["properties"][key]
            objects[identity]["properties"][key] = wrong
            with self.subTest(key=key), self.assertRaises(apply.Failure):
                apply.quota_blocked_proof(azure, previous, receipt, tags)
            objects[identity]["properties"][key] = old
        objects[account + "/schedules"]["value"] = [{"name": "unexpected"}]
        with self.assertRaisesRegex(apply.Failure, "jobs-or-schedules"):
            apply.quota_blocked_proof(azure, previous, receipt, tags)
        objects[account + "/schedules"]["value"] = []
        for key, value, error in (
                ("assignments", [{"properties": {"principalId": self.principal}}], "existing-authority"),
                ("nodeExists", True, "node-group-already-exists"),
                ("verificationResources", [{"id": "unexpected"}], "verification-group-not-empty")):
            original = state[key]
            state[key] = value
            with self.subTest(guard=key), self.assertRaisesRegex(apply.Failure, error):
                apply.quota_blocked_proof(azure, previous, receipt, tags)
            state[key] = original
        legacy = f"/subscriptions/{self.subscription}/providers/Microsoft.Authorization/roleDefinitions/" + \
            next(iter(previous["roleGuids"].values()))
        objects[legacy] = {"id": legacy}
        with self.assertRaisesRegex(apply.Failure, "legacy-custom-role-already-exists"):
            apply.quota_blocked_proof(azure, previous, receipt, tags)
        objects.pop(legacy)
        objects[self.scope["verificationResourceGroupId"]]["tags"]["orka-owner"] = "someone-else"
        with self.assertRaisesRegex(apply.Failure, "ownership"):
            apply.quota_blocked_proof(azure, previous, receipt, tags)
        objects[self.scope["verificationResourceGroupId"]]["tags"]["orka-owner"] = previous["owner"]
        builtin = {**previous, "authorizationModel": apply.AUTHORIZATION_MODEL,
                   "roleGuids": apply.builtin_role_guids()}
        _, recorded, assignments = self.assignment_fixture()
        grant_receipt = {**receipt, "cleanupAssignments": {
            key: recorded["cleanupAssignments"][key] for key in ("verification", "groupsRead")}}
        objects.update(copy.deepcopy(self.roles))
        for assignment in assignments[:2]:
            objects[assignment["id"]] = assignment
        state["assignments"] = assignments[:2]
        deployment = f"/subscriptions/{self.subscription}/providers/Microsoft.Resources/deployments/bounded-cleanup-builtin-access"
        objects[deployment] = {"id": deployment, "properties": {"provisioningState": "Succeeded"}}
        result = apply.quota_blocked_proof(azure, builtin, grant_receipt, tags, granted=True)
        self.assertEqual(result["existingAssignments"], 2)
        for state_name in ("Failed", "Running"):
            objects[deployment]["properties"]["provisioningState"] = state_name
            with self.subTest(deployment=state_name), self.assertRaisesRegex(apply.Failure, "capacity-stop-required"):
                apply.quota_blocked_proof(azure, builtin, grant_receipt, tags, granted=True)
        objects[deployment]["properties"]["provisioningState"] = "Succeeded"
        for key in ("verification", "groupsRead"):
            identity = grant_receipt["cleanupAssignments"][key]
            original_scope = objects[identity]["properties"]["scope"]
            objects[identity]["properties"]["scope"] = self.scope["controlVnetId"]
            with self.subTest(grant=key), self.assertRaisesRegex(apply.Failure, "readback-mismatch"):
                apply.quota_blocked_proof(azure, builtin, grant_receipt, tags, granted=True)
            objects[identity]["properties"]["scope"] = original_scope
        state["assignments"] = assignments[:1]
        with self.assertRaisesRegex(apply.Failure, "inventory-incomplete"):
            apply.quota_blocked_proof(azure, builtin, grant_receipt, tags, granted=True)
        azure.rest.assert_not_called()
        azure.deploy.assert_not_called()

    @mock.patch.object(apply.plan, "private_path", side_effect=Path)
    def test_readonly_preparation_builds_the_exact_explicit_transition_without_mutations(self, _private_path):
        stopped, previous, old_receipt, tags, args = self.transition_fixture()
        args.previous_work_dir = str(stopped)
        work = Path(args.work_dir)
        azure = self.grant_client()
        proof = {"principalId": self.principal, "groupTags": {
            **tags, "orka-source-digest": previous["sourceDigest"]}}
        hashes = {"fixture-source": "d" * 64}
        with mock.patch.object(apply, "quota_blocked_proof", return_value=proof) as checked, \
             mock.patch.object(apply, "source_hashes", return_value=hashes), \
             mock.patch.object(apply, "compile_templates", return_value={}):
            apply.prepare_builtin_resume(args, work, azure)
        checked.assert_called_once_with(azure, previous, old_receipt, tags)
        bundle = json.loads((work / "bundle.json").read_text())
        record = json.loads((work / "authorization-link.json").read_text())
        self.assertEqual(bundle["authorizationModel"], apply.AUTHORIZATION_MODEL)
        self.assertEqual(bundle["roleGuids"], apply.builtin_role_guids())
        self.assertEqual(bundle["sourceDigest"], apply.sha(apply.wire(hashes)))
        self.assertEqual(record["sha256"], apply.sha(apply.wire(record["plan"])))
        self.assertEqual(record["plan"]["previousReceiptSha256"], apply.sha((stopped / "receipt.json").read_bytes()))
        self.assertEqual(record["plan"]["proof"], proof)
        self.assertEqual(record["plan"]["networkAssignmentScopes"], apply.network_assignment_scopes(bundle))
        self.assertEqual(azure.deployments, [])
        self.assertEqual(azure.puts, [])
        self.assertFalse((work / "receipt.json").exists())

    @mock.patch.object(apply.plan, "private_path", side_effect=Path)
    def test_approved_resume_checks_every_bound_field_and_only_merges_two_group_tags(self, _private_path):
        stopped, previous, old_receipt, tags, args = self.transition_fixture()
        args.previous_work_dir = str(stopped)
        work = Path(args.work_dir)
        proof = {"principalId": self.principal,
                 "groupTags": {**tags, "orka-source-digest": previous["sourceDigest"]}}
        with mock.patch.object(apply, "quota_blocked_proof", return_value=proof), \
             mock.patch.object(apply, "source_hashes", return_value={"fixture-source": "d" * 64}), \
             mock.patch.object(apply, "compile_templates", return_value={}):
            apply.prepare_builtin_resume(args, work, self.grant_client())
        bundle = json.loads((work / "bundle.json").read_text())
        record = json.loads((work / "authorization-link.json").read_text())
        original_records = {path: path.read_bytes() for path in self.directory.rglob("*.json")
                            if path.parent != work}
        azure = mock.Mock(work=work)
        azure.get.side_effect = lambda identity, *_args: {
            "id": identity, "tags": {**proof["groupTags"], "orka-source-digest": bundle["sourceDigest"]}}
        for field in ("kind", "authorizationModel", "nextSourceDigest", "previousSourceDigest",
                      "previousBundleSha256", "previousReceiptSha256", "previousLinkSha256",
                      "assignments", "networkAssignmentScopes", "builtinRoles", "kubernetesAuthorization", "proof"):
            changed = copy.deepcopy(record)
            changed["plan"][field] = {} if isinstance(changed["plan"][field], dict) else "tampered"
            changed["sha256"] = apply.sha(apply.wire(changed["plan"]))
            apply.write_json(work / "authorization-link.json", changed)
            args.approved_authorization_sha256 = changed["sha256"]
            azure.reset_mock()
            with mock.patch.object(apply, "quota_blocked_proof", return_value=proof), \
                 mock.patch.object(apply, "validate_builtin_roles"), \
                 mock.patch.object(apply, "finish_bootstrap") as finished, \
                 self.subTest(field=field), self.assertRaises(apply.Failure):
                apply.resume_builtin_bootstrap(azure, bundle, {}, args)
            azure.cli.assert_not_called()
            azure.rest.assert_not_called()
            azure.deploy.assert_not_called()
            finished.assert_not_called()
            self.assertFalse((work / "receipt.json").exists())
        apply.write_json(work / "authorization-link.json", record)
        args.approved_authorization_sha256 = record["sha256"]
        receipt = {}
        with mock.patch.object(apply, "quota_blocked_proof", return_value=proof), \
             mock.patch.object(apply, "validate_builtin_roles"), \
             mock.patch.object(apply, "finish_bootstrap") as finished:
            apply.resume_builtin_bootstrap(azure, bundle, receipt, args)
        finished.assert_called_once_with(azure, bundle, receipt)
        self.assertEqual(receipt["phase"], "authorization-transition-intent")
        self.assertEqual(receipt["principalId"], self.principal)
        targets = [call.args[call.args.index("--resource-id") + 1] for call in azure.cli.call_args_list]
        self.assertEqual(targets, [self.scope["verificationResourceGroupId"], self.scope["cleanupResourceGroupId"]])
        self.assertNotIn(self.scope["automationAccountId"], targets)
        self.assertTrue(all(path.read_bytes() == raw for path, raw in original_records.items()))
        azure.rest.assert_not_called()
        azure.deploy.assert_not_called()

    @mock.patch.object(apply.plan, "private_path", side_effect=Path)
    def test_prepublication_continuation_preserves_verified_grants_and_all_old_records(self, _private_path):
        stopped, previous, _, tags, args = self.transition_fixture()
        args.previous_work_dir = str(stopped)
        granted_dir = Path(args.work_dir)
        proof = {"principalId": self.principal, "accountTags": tags,
                 "groupTags": {**tags, "orka-source-digest": previous["sourceDigest"]}}
        with mock.patch.object(apply, "quota_blocked_proof", return_value=proof), \
             mock.patch.object(apply, "source_hashes", return_value={"fixture-source": "d" * 64}), \
             mock.patch.object(apply, "compile_templates", return_value={}):
            apply.prepare_builtin_resume(args, granted_dir, self.grant_client())
        granted_bundle = json.loads((granted_dir / "bundle.json").read_text())
        grant_link = json.loads((granted_dir / "authorization-link.json").read_text())
        args.approved_authorization_sha256 = grant_link["sha256"]
        azure = mock.Mock(work=granted_dir)
        azure.get.return_value = {"tags": {**proof["groupTags"], "orka-source-digest": granted_bundle["sourceDigest"]}}
        granted_receipt = {}
        with mock.patch.object(apply, "quota_blocked_proof", return_value=proof), \
             mock.patch.object(apply, "validate_builtin_roles"), mock.patch.object(apply, "finish_bootstrap"):
            apply.resume_builtin_bootstrap(azure, granted_bundle, granted_receipt, args)
        _, fixture_receipt, _ = self.assignment_fixture()
        grants = {key: fixture_receipt["cleanupAssignments"][key] for key in ("verification", "groupsRead")}
        granted_receipt["cleanupAssignments"] = grants
        apply.write_json(granted_dir / "receipt.json", granted_receipt)
        before = {path: path.read_bytes() for path in self.directory.rglob("*.json")}
        next_dir = self.directory / "continuation"
        next_dir.mkdir()
        args.work_dir = str(next_dir)
        args.previous_work_dir = str(granted_dir)
        args.continue_granted_bootstrap = True
        observed = apply.granted_bootstrap_inputs(args, str(granted_dir))
        self.assertEqual(observed, (granted_dir, granted_bundle, granted_receipt, tags))
        for change in ("clock", "phase", "missing-grant", "extra-grant"):
            mutated = copy.deepcopy(granted_receipt)
            if change == "clock":
                mutated["T0"] = "2026-01-01T00:00:00Z"
            elif change == "phase":
                mutated["phase"] = "bootstrap-ready"
            elif change == "missing-grant":
                mutated["cleanupAssignments"].pop("groupsRead")
            else:
                mutated["cleanupAssignments"]["nodes"] = fixture_receipt["cleanupAssignments"]["nodes"]
            apply.write_json(granted_dir / "receipt.json", mutated)
            with self.subTest(change=change), self.assertRaises(apply.Failure):
                apply.granted_bootstrap_inputs(args, str(granted_dir))
        (granted_dir / "receipt.json").write_bytes(before[granted_dir / "receipt.json"])
        continuation_proof = {**proof, "groupTags": {
            **tags, "orka-source-digest": granted_bundle["sourceDigest"]}, "existingAssignments": 2}
        planning_azure = self.grant_client()
        with mock.patch.object(apply, "quota_blocked_proof", return_value=continuation_proof) as checked, \
             mock.patch.object(apply, "source_hashes", return_value={"fixture-source": "e" * 64}), \
             mock.patch.object(apply, "compile_templates", return_value={}):
            apply.prepare_builtin_resume(args, next_dir, planning_azure)
        checked.assert_called_once_with(planning_azure, granted_bundle, granted_receipt, tags, granted=True)
        next_bundle = json.loads((next_dir / "bundle.json").read_text())
        link = json.loads((next_dir / "authorization-link.json").read_text())
        self.assertEqual(link["plan"]["kind"], "builtin-prepublication-continuation")
        args.approved_authorization_sha256 = link["sha256"]
        azure = mock.Mock(work=next_dir)
        azure.get.return_value = {"tags": {**continuation_proof["groupTags"],
                                          "orka-source-digest": next_bundle["sourceDigest"]}}
        receipt = {}
        with mock.patch.object(apply, "quota_blocked_proof", return_value=continuation_proof), \
             mock.patch.object(apply, "validate_builtin_roles"), \
             mock.patch.object(apply, "finish_bootstrap") as finish:
            apply.resume_builtin_bootstrap(azure, next_bundle, receipt, args)
        finish.assert_called_once_with(azure, next_bundle, receipt)
        self.assertEqual(receipt["cleanupAssignments"], grants)
        self.assertEqual(receipt["phase"], "authorization-transition-intent")
        self.assertTrue(all(path.read_bytes() == raw for path, raw in before.items()))
        self.assertEqual(azure.cli.call_count, 2)
        azure.rest.assert_not_called()
        azure.deploy.assert_not_called()


class QualifiedBootstrapTests(unittest.TestCase):
    def setUp(self):
        fixture = BuiltinAuthorizationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.directory = fixture.directory
        self.private = mock.patch.object(apply.plan, "private_path", side_effect=Path)
        self.private.start()
        self.addCleanup(self.private.stop)
        self.diagnostic_text = "# reviewed offline diagnostic"
        pinned = mock.patch.object(apply, "QUALIFIED_DIAGNOSTIC_SHA256",
                                   apply.sha(self.diagnostic_text.encode()))
        pinned.start()
        self.addCleanup(pinned.stop)
        stopped, _, _, tags, args = fixture.transition_fixture()
        self.args = args
        self.tags = tags
        self.subscription = fixture.subscription
        self.scope = fixture.scope
        self.account = self.scope["automationAccountId"]
        source_hashes = apply.source_hashes()
        source_hashes["scripts/remediation_aks_apply.py"] = "b" * 64
        proof = {"principalId": fixture.principal, "accountTags": tags,
                 "groupTags": {**tags, "orka-source-digest": "a" * 64}}
        args.previous_work_dir = str(stopped)
        granted_dir = Path(args.work_dir)
        with mock.patch.object(apply, "quota_blocked_proof", return_value=proof), \
             mock.patch.object(apply, "source_hashes", return_value=source_hashes), \
             mock.patch.object(apply, "compile_templates", side_effect=self.compile_fixture):
            apply.prepare_builtin_resume(args, granted_dir, fixture.grant_client())
        granted_bundle = json.loads((granted_dir / "bundle.json").read_text())
        record = json.loads((granted_dir / "authorization-link.json").read_text())
        args.approved_authorization_sha256 = record["sha256"]
        legacy = mock.Mock(work=granted_dir)
        legacy.get.return_value = {"tags": {**proof["groupTags"], "orka-source-digest": granted_bundle["sourceDigest"]}}
        granted_receipt = {}
        with mock.patch.object(apply, "quota_blocked_proof", return_value=proof), \
             mock.patch.object(apply, "validate_builtin_roles"), mock.patch.object(apply, "finish_bootstrap"):
            apply.resume_builtin_bootstrap(legacy, granted_bundle, granted_receipt, args)
        _, assignments, role_objects = fixture.assignment_fixture()
        granted_receipt["cleanupAssignments"] = {key: assignments["cleanupAssignments"][key]
                                                for key in ("verification", "groupsRead")}
        apply.write_json(granted_dir / "receipt.json", granted_receipt)
        self.previous_dir = self.directory / "failed-original-preflight"
        self.previous_dir.mkdir()
        args.work_dir = str(self.previous_dir)
        args.previous_work_dir = str(granted_dir)
        args.continue_granted_bootstrap = True
        source_hashes["scripts/remediation_aks_apply.py"] = "c" * 64
        with mock.patch.object(apply, "quota_blocked_proof", return_value=proof), \
             mock.patch.object(apply, "source_hashes", return_value=source_hashes), \
             mock.patch.object(apply, "compile_templates", side_effect=self.compile_fixture):
            apply.prepare_builtin_resume(args, self.previous_dir, fixture.grant_client())
        self.previous = json.loads((self.previous_dir / "bundle.json").read_text())
        record = json.loads((self.previous_dir / "authorization-link.json").read_text())
        args.approved_authorization_sha256 = record["sha256"]
        legacy = mock.Mock(work=self.previous_dir)
        legacy.get.return_value = {"tags": {**proof["groupTags"], "orka-source-digest": self.previous["sourceDigest"]}}
        self.old = {}
        with mock.patch.object(apply, "quota_blocked_proof", return_value=proof), \
             mock.patch.object(apply, "validate_builtin_roles"), mock.patch.object(apply, "finish_bootstrap"):
            apply.resume_builtin_bootstrap(legacy, self.previous, self.old, args)
        self.failed_job = self.account + "/jobs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        self.diag_job = self.account + "/jobs/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        self.passed_job = self.account + "/jobs/cccccccc-cccc-cccc-cccc-cccccccccccc"
        self.old.update({"nodeScopeReady": False, "peeringScopeReady": False, "preflightJobId": self.failed_job})
        apply.write_json(self.previous_dir / "receipt.json", self.old)
        self.work = self.directory / "qualified"
        self.work.mkdir()
        self.preflight = self.directory / "corrected-preflight"
        self.diagnostic = self.directory / "diagnostic"
        self.preflight.mkdir()
        self.diagnostic.mkdir()
        args.work_dir = str(self.work)
        args.previous_work_dir = str(self.previous_dir)
        args.qualified_preflight_work_dir = str(self.preflight)
        args.diagnostic_work_dir = str(self.diagnostic)
        source_hashes["scripts/remediation_aks_apply.py"] = "d" * 64
        original_hash = apply.sha((SOURCE / "cleanup-runbook.ps1").read_bytes())
        old_hashes = {name: apply.sha((self.previous_dir / name).read_bytes())
                      for name in ("bundle.json", "receipt.json", "authorization-link.json")}
        self.request = {"properties": {"runbook": {"name": "ExactFoundationCleanup"},
                                       "parameters": apply.runbook_parameters(self.previous, self.old)}}
        apply.write_json(self.preflight / "job-request.json", self.request)
        apply.write_json(self.preflight / "safe-output.json", apply.PREFLIGHT_PROOF)
        self.passed = {
            "phase": "corrected-preflight-passed", "jobId": self.passed_job, "jobStatus": "Completed",
            "jobPutAttempts": 1, "sourceReviewClosed": True, "foundationInputs": old_hashes,
            "foundationReceiptsUnchanged": True, "noPermissionScheduleComputeChanges": True,
            "originalRunbookUnchanged": True, "originalRunbookSha256": original_hash,
            "requestSha256": apply.sha((self.preflight / "job-request.json").read_bytes()),
            "safeOutputSha256": apply.sha((self.preflight / "safe-output.json").read_bytes()),
            "sourceDigest": apply.sha(apply.wire(source_hashes)),
            "startTime": "2026-10-08T20:43:14.8073784+00:00", "endTime": "2026-10-08T20:43:19.3712445+00:00",
        }
        apply.write_json(self.preflight / "receipt.json", self.passed)
        apply.write_json(self.preflight / "plan.json", {
            "kind": "corrected-original-preflight-once", "subscriptionId": self.subscription,
            "jobId": self.passed_job, "runbookId": self.account + "/runbooks/ExactFoundationCleanup",
            "allowedJobPuts": 1, "preflightRuntimeLimitSeconds": apply.PREFLIGHT_EXECUTION_SECONDS,
            "noGrantsOrSchedulesOrCompute": True, "foundationInputs": old_hashes,
            "jobRequestSha256": self.passed["requestSha256"], "currentSourceHashes": source_hashes,
            "currentSourceDigest": self.passed["sourceDigest"], "originalPublishedRunbookSha256": original_hash,
            "expectedManifestDigest": apply.sha(apply.wire(apply.manifest(self.previous, self.old))),
        })
        self.diag_output = {"outcome": "diagnostic-succeeded"}
        apply.write_json(self.diagnostic / "safe-output.json", self.diag_output)
        apply.write_json(self.diagnostic / "receipt.json", {
            "jobId": self.diag_job, "jobStatus": "Completed", "jobPutAttempts": 1, "sourceReviewClosed": True,
            "runbookId": self.account + "/runbooks/" + apply.QUALIFIED_DIAGNOSTIC,
            "runbookSHA256": apply.QUALIFIED_DIAGNOSTIC_SHA256,
            "safeOutputSHA256": apply.sha((self.diagnostic / "safe-output.json").read_bytes()),
            "originalRunbookUnchanged": True, "foundationRecordsUnchanged": True,
        })
        self.objects = copy.deepcopy(fixture.roles)
        group_tags = {**tags, "orka-source-digest": self.previous["sourceDigest"]}
        for key in ("verificationResourceGroupId", "cleanupResourceGroupId", "automationAccountId"):
            identity = self.scope[key]
            self.objects[identity] = {"id": identity, "tags": copy.deepcopy(tags if identity == self.account else group_tags)}
        self.objects[self.account].update({
            "properties": {"state": "Ok", "disableLocalAuth": True, "publicNetworkAccess": False},
            "identity": {"type": "SystemAssigned", "tenantId": self.previous["tenantId"],
                         "principalId": self.old["principalId"]}})
        self.assignments = role_objects[:2]
        self.objects.update({item["id"]: item for item in self.assignments})
        self.text = {}
        books = []
        for name, content in (("ExactFoundationCleanup", (SOURCE / "cleanup-runbook.ps1").read_text()),
                              (apply.QUALIFIED_DIAGNOSTIC, self.diagnostic_text + "\n")):
            identity = self.account + "/runbooks/" + name
            books.append({"id": identity})
            self.objects[identity] = {"id": identity, "tags": {}, "properties": {
                "state": "Published", "runbookType": "PowerShell", "runtimeEnvironment": "PowerShell74",
                "logVerbose": False, "logProgress": False}}
            self.text[identity + "/content"] = content
        self.objects[self.account + "/runbooks"] = {"value": books}
        self.objects[self.scope["cleanupResourceGroupId"] + "/resources"] = {"value": [{"id": self.account}, *books]}
        self.objects[self.scope["verificationResourceGroupId"] + "/resources"] = {"value": []}
        runtimes = {**apply.SYSTEM_RUNTIMES, "PowerShell74": ("PowerShell", "7.4")}
        self.objects[self.account + "/runtimeEnvironments"] = {"value": [
            {"id": self.account + "/runtimeEnvironments/" + name, "tags": {}, "properties": {
                "runtime": {"language": language, "version": version}, "defaultPackages": {}}}
            for name, (language, version) in runtimes.items()]}
        for collection in ("schedules", "jobSchedules", "webhooks", "credentials", "connections", "variables",
                           "certificates", "sourceControls", "watchers", "hybridRunbookWorkerGroups",
                           "runtimeEnvironments/PowerShell74/packages"):
            self.objects[self.account + "/" + collection] = {"value": []}
        old_parameters = {"ManifestJson": apply.wire(apply.manifest(self.previous, self.old)).decode(), "Mode": "Preflight"}
        for identity, book, state in ((self.failed_job, "ExactFoundationCleanup", "Failed"),
                                       (self.diag_job, apply.QUALIFIED_DIAGNOSTIC, "Completed"),
                                       (self.passed_job, "ExactFoundationCleanup", "Completed")):
            self.objects[identity] = {"id": identity, "name": identity.rsplit("/", 1)[-1], "properties": {
                "jobId": str(uuid.uuid4()), "runbook": {"name": book}, "status": state, "runOn": "",
                "parameters": copy.deepcopy(self.request["properties"]["parameters"] if identity == self.passed_job else old_parameters),
                "startTime": self.passed["startTime"], "endTime": self.passed["endTime"]}}
        self.objects[self.account + "/jobs"] = {"value": [{"id": identity} for identity in
                                                         (self.failed_job, self.diag_job, self.passed_job)]}
        self.text[self.passed_job + "/output"] = json.dumps(apply.PREFLIGHT_PROOF)
        self.text[self.diag_job + "/output"] = json.dumps(self.diag_output)
        self.calls = []
        self.writes = []
        self.azure = apply.Azure(self.subscription, self.work, runner=self.runner)
        self.before = {path: path.read_bytes() for path in self.directory.rglob("*.json")}

    def compile_fixture(self, work):
        result = {}
        for name in (*apply.NEW_TEMPLATES, "main"):
            apply.write_json(work / (name + ".arm.json"), {"resources": [], "fixture": name})
            result[name] = apply.sha((work / (name + ".arm.json")).read_bytes())
        return result

    def runner(self, command, **_kwargs):
        self.assertEqual(command[0], "az")
        self.assertEqual(command[command.index("--subscription") + 1], self.subscription)
        arguments = command[1:command.index("--subscription")]
        self.calls.append(arguments)
        result = None
        if arguments[:2] == ["account", "show"]:
            result = {"subscription": self.subscription, "tenant": self.previous["tenantId"], "environment": "AzureCloud"}
        elif arguments[:2] == ["tag", "update"]:
            identity = arguments[arguments.index("--resource-id") + 1]
            self.assertIn(identity, (self.scope["verificationResourceGroupId"], self.scope["cleanupResourceGroupId"]))
            self.assertEqual(arguments[arguments.index("--operation") + 1], "Merge")
            tag = arguments[arguments.index("--tags") + 1]
            self.assertTrue(tag.startswith("orka-source-digest="))
            self.assertEqual(len(arguments) - arguments.index("--tags"), 2)
            self.objects[identity]["tags"]["orka-source-digest"] = tag.split("=", 1)[1]
            self.writes.append((identity, tag))
            result = self.objects[identity]
        else:
            self.assertEqual(arguments[:3], ["rest", "--method", "GET"], "only-tag-merges-may-mutate")
            uri = urlsplit(arguments[arguments.index("--url") + 1])
            self.assertEqual(uri.scheme + "://" + uri.netloc, apply.ARM)
            identity = uri.path
            if identity.endswith("/roleAssignments") and "$filter" in parse_qs(uri.query):
                result = {"value": self.assignments}
            elif identity in self.text:
                return SimpleNamespace(returncode=0, stdout=self.text[identity], stderr="")
            elif identity in self.objects:
                result = self.objects[identity]
            else:
                return SimpleNamespace(returncode=1, stdout="",
                    stderr='ERROR: Not Found({"error":{"code":"ResourceNotFound"}})')
        return SimpleNamespace(returncode=0, stdout=json.dumps(result), stderr="")

    def prepare(self):
        with mock.patch.object(apply, "compile_templates", side_effect=self.compile_fixture):
            apply.prepare_qualified_bootstrap(self.args, self.work, self.azure)
        self.bundle = json.loads((self.work / "bundle.json").read_text())
        self.link = json.loads((self.work / "authorization-link.json").read_text())
        self.calls.clear()

    def adopt(self, approved=None, reviewed=None):
        arguments = ["apply", "adopt-qualified-bootstrap", "--subscription", self.subscription,
            "--control-vnet-id", self.scope["controlVnetId"], "--control-aks-id", self.scope["controlClusterId"],
            "--work-dir", str(self.work), "--reviewed-source-sha256", reviewed or self.bundle["sourceDigest"],
            "--approved-authorization-sha256", approved or self.link["sha256"]]
        with mock.patch.object(sys, "argv", arguments), mock.patch.object(apply, "Azure", return_value=self.azure):
            apply.main()

    def fail_get_once_after_merges(self, count, suffix=None):
        fault = {"fired": False}

        def transient_get(command, **kwargs):
            if command[1:4] == ["rest", "--method", "GET"]:
                identity = urlsplit(command[command.index("--url") + 1]).path
                if ((self.work / "receipt.json").exists() and len(self.writes) == count and not fault["fired"] and
                        (suffix is None or identity.endswith(suffix))):
                    fault["fired"] = True
                    return SimpleNamespace(returncode=1, stdout="", stderr="ERROR: transient read unavailable")
            return self.runner(command, **kwargs)

        self.azure.runner = transient_get
        return fault

    def test_read_only_plan_and_real_adopt_path_only_merge_two_current_digest_tags(self):
        self.prepare()
        self.assertFalse(self.writes)
        self.assertFalse((self.work / "receipt.json").exists())
        before_account = copy.deepcopy(self.objects[self.account])
        self.adopt()
        receipt = json.loads((self.work / "receipt.json").read_text())
        self.assertEqual(receipt["phase"], "bootstrap-ready")
        self.assertEqual(receipt["preflightJobId"], self.passed_job)
        self.assertEqual(receipt["preflightCompleted"], self.passed["endTime"])
        self.assertEqual(receipt["cleanupAssignments"], self.old["cleanupAssignments"])
        self.assertNotIn("T0", receipt)
        self.assertNotIn("deadline", receipt)
        self.assertEqual(self.objects[self.account], before_account)
        self.assertEqual(self.writes, [(self.scope[key], "orka-source-digest=" + self.bundle["sourceDigest"])
                                      for key in ("verificationResourceGroupId", "cleanupResourceGroupId")])
        self.assertTrue(all(path.read_bytes() == data for path, data in self.before.items()))
        self.assertNotEqual(self.bundle["sourceDigest"], self.previous["sourceDigest"])
        self.assertEqual(self.bundle["compiledHashes"], self.previous["compiledHashes"])
        with self.assertRaisesRegex(apply.Failure, "qualified-receipt-reentry-mismatch"):
            self.adopt()
        self.assertEqual(len(self.writes), 2)

    def test_adopt_rejects_unapproved_or_changed_source_before_mutation(self):
        self.prepare()
        for kind in ("approval", "source"):
            with self.subTest(kind=kind), self.assertRaises(apply.Failure):
                self.adopt(approved="f" * 64 if kind == "approval" else None,
                           reviewed="f" * 64 if kind == "source" else None)
            self.assertFalse(self.writes)
            self.assertFalse((self.work / "receipt.json").exists())

    def test_job_identity_status_encoded_parameters_and_exact_original_output_are_required(self):
        self.prepare()
        baseline = copy.deepcopy(self.objects[self.passed_job])
        output = self.text[self.passed_job + "/output"]
        for change in ("failed", "foreign-id", "foreign-name", "diagnostic-book", "decoded-instead-of-encoded",
                       "other-manifest", "other-mode", "extra-parameter", "other-time", "hybrid-target",
                       "diagnostic-proof", "partial-proof", "numeric-booleans", "extra-proof-field"):
            with self.subTest(change=change):
                job = self.objects[self.passed_job]
                properties = job["properties"]
                if change == "failed":
                    properties["status"] = "Failed"
                elif change == "foreign-id":
                    job["id"] = self.diag_job
                elif change == "foreign-name":
                    job["name"] = self.diag_job.rsplit("/", 1)[-1]
                elif change == "diagnostic-book":
                    properties["runbook"]["name"] = apply.QUALIFIED_DIAGNOSTIC
                elif change == "decoded-instead-of-encoded":
                    properties["parameters"] = {key: json.loads(value) for key, value in properties["parameters"].items()}
                elif change == "other-manifest":
                    properties["parameters"]["ManifestJson"] = apply.wire("{}").decode()
                elif change == "other-mode":
                    properties["parameters"]["Mode"] = apply.wire("Cleanup").decode()
                elif change == "extra-parameter":
                    properties["parameters"]["LibraryOnly"] = "true"
                elif change == "other-time":
                    properties["endTime"] = "2026-10-08T20:44:19Z"
                elif change == "hybrid-target":
                    properties["runOn"] = "foreign"
                else:
                    value = dict(apply.PREFLIGHT_PROOF)
                    if change == "diagnostic-proof":
                        value = self.diag_output
                    elif change == "partial-proof":
                        value.pop("principalMatched")
                    elif change == "numeric-booleans":
                        value["principalMatched"] = 1
                    else:
                        value["extra"] = True
                    self.text[self.passed_job + "/output"] = json.dumps(value)
                with self.assertRaises(apply.Failure):
                    self.adopt()
                self.assertFalse(self.writes)
                self.assertFalse((self.work / "receipt.json").exists())
                self.objects[self.passed_job] = copy.deepcopy(baseline)
                self.text[self.passed_job + "/output"] = output

    def test_all_live_inventories_and_unarmed_ownership_are_fail_closed(self):
        self.prepare()
        for collection in ("jobs", "runbooks", "runtimeEnvironments", "schedules", "jobSchedules", "webhooks",
                           "credentials", "connections", "variables", "certificates", "sourceControls", "watchers",
                           "hybridRunbookWorkerGroups", "runtimeEnvironments/PowerShell74/packages"):
            for kind in ("extra", "pagination"):
                identity = self.account + "/" + collection
                baseline = copy.deepcopy(self.objects[identity])
                with self.subTest(collection=collection, kind=kind):
                    if kind == "extra":
                        self.objects[identity]["value"].append({"id": identity + "/unapproved"})
                    else:
                        self.objects[identity]["nextLink"] = apply.ARM + identity + "?next=true"
                    with self.assertRaises(apply.Failure):
                        self.adopt()
                    self.assertFalse(self.writes)
                    self.assertFalse((self.work / "receipt.json").exists())
                    self.objects[identity] = baseline
        for key in ("verificationResourceGroupId", "cleanupResourceGroupId"):
            identity = self.scope[key] + "/resources"
            self.objects[identity]["value"].append({"id": self.scope[key] + "/providers/Microsoft.Compute/virtualMachines/foreign"})
            with self.subTest(group=key), self.assertRaises(apply.Failure):
                self.adopt()
            self.objects[identity]["value"].pop()
        self.objects[self.scope["managedNodeResourceGroupId"]] = {"id": self.scope["managedNodeResourceGroupId"]}
        with self.assertRaises(apply.Failure):
            self.adopt()
        del self.objects[self.scope["managedNodeResourceGroupId"]]
        for field, value in (("orka-budget-start-utc", "active"), ("orka-expires-at-utc", "active"),
                             ("orka-owner", "foreign"), ("orka-source-digest", "f" * 64)):
            tags = self.objects[self.scope["verificationResourceGroupId"]]["tags"]
            before = tags[field]
            tags[field] = value
            with self.subTest(field=field), self.assertRaises(apply.Failure):
                self.adopt()
            tags[field] = before
        self.assertFalse(self.writes)

    def test_role_and_principal_changes_are_rejected_at_the_real_adopt_path(self):
        self.prepare()
        before = copy.deepcopy(self.assignments)
        for change in ("extra", "missing", "scope", "principal", "condition", "builtin-wildcard", "identity"):
            with self.subTest(change=change):
                objects = copy.deepcopy(self.objects)
                if change == "extra":
                    self.assignments.append(copy.deepcopy(self.assignments[0]))
                elif change == "missing":
                    self.assignments.pop()
                elif change in ("scope", "principal", "condition"):
                    field = {"scope": "scope", "principal": "principalId", "condition": "condition"}[change]
                    self.assignments[0]["properties"][field] = "unapproved"
                elif change == "identity":
                    self.objects[self.account]["identity"]["principalId"] = "99999999-9999-9999-9999-999999999999"
                else:
                    role = self.assignments[0]["properties"]["roleDefinitionId"]
                    self.objects[role]["properties"]["permissions"][0]["actions"].append("*")
                with self.assertRaises(apply.Failure):
                    self.adopt()
                self.assertFalse(self.writes)
                self.objects = objects
                self.assignments = copy.deepcopy(before)

    def test_published_source_and_pinned_private_evidence_cannot_be_substituted(self):
        self.prepare()
        for name in ("ExactFoundationCleanup", apply.QUALIFIED_DIAGNOSTIC):
            key = self.account + "/runbooks/" + name + "/content"
            before = self.text[key]
            self.text[key] = before + "# changed\n"
            with self.subTest(book=name), self.assertRaises(apply.Failure):
                self.adopt()
            self.text[key] = before
        for path in (self.previous_dir / "bundle.json", self.previous_dir / "receipt.json",
                     self.previous_dir / "authorization-link.json", self.previous_dir / "compute-inputs.json",
                     self.previous_dir / "main.arm.json",
                     self.preflight / "plan.json", self.preflight / "job-request.json",
                     self.preflight / "receipt.json", self.preflight / "safe-output.json",
                     self.diagnostic / "receipt.json", self.diagnostic / "safe-output.json"):
            before = path.read_bytes()
            path.write_bytes(before + b" ")
            with self.subTest(file=path.name), self.assertRaises(apply.Failure):
                self.adopt()
            path.write_bytes(before)
        self.assertFalse(self.writes)
        self.assertFalse((self.work / "receipt.json").exists())

    def test_partial_tag_merges_retry_same_exact_intent_without_remerging(self):
        self.prepare()
        baseline = copy.deepcopy(self.objects)
        link_bytes = (self.work / "authorization-link.json").read_bytes()
        bundle_bytes = (self.work / "bundle.json").read_bytes()
        for completed in (0, 1, 2):
            with self.subTest(completed=completed):
                self.objects = copy.deepcopy(baseline)
                self.writes.clear()
                (self.work / "receipt.json").unlink(missing_ok=True)
                fault = self.fail_get_once_after_merges(completed)
                with self.assertRaisesRegex(apply.Failure, "azure-command-failed"):
                    self.adopt()
                self.assertTrue(fault["fired"])
                intent = json.loads((self.work / "receipt.json").read_text())
                self.assertEqual(intent["phase"], "qualified-bootstrap-intent")
                self.assertNotIn("preflightCompleted", intent)
                self.assertNotIn("T0", intent)
                self.assertEqual(len(self.writes), completed)
                self.adopt()
                receipt = json.loads((self.work / "receipt.json").read_text())
                self.assertEqual(receipt["phase"], "bootstrap-ready")
                self.assertEqual(receipt["preflightJobId"], self.passed_job)
                self.assertEqual(receipt["preflightCompleted"], self.passed["endTime"])
                self.assertEqual(self.writes, [
                    (self.scope[key], "orka-source-digest=" + self.bundle["sourceDigest"])
                    for key in ("verificationResourceGroupId", "cleanupResourceGroupId")])
                self.assertEqual((self.work / "authorization-link.json").read_bytes(), link_bytes)
                self.assertEqual((self.work / "bundle.json").read_bytes(), bundle_bytes)
                self.assertTrue(all(path.read_bytes() == data for path, data in self.before.items()))

    def test_transient_final_recheck_retries_without_any_new_merge(self):
        self.prepare()
        fault = self.fail_get_once_after_merges(2, suffix="/runtimeEnvironments")
        with self.assertRaisesRegex(apply.Failure, "azure-command-failed"):
            self.adopt()
        self.assertTrue(fault["fired"])
        receipt = json.loads((self.work / "receipt.json").read_text())
        self.assertEqual(receipt["phase"], "qualified-bootstrap-intent")
        self.assertNotIn("preflightCompleted", receipt)
        self.assertNotIn("T0", receipt)
        writes = list(self.writes)
        self.assertEqual(len(writes), 2)
        self.adopt()
        self.assertEqual(self.writes, writes)
        self.assertEqual(json.loads((self.work / "receipt.json").read_text())["phase"], "bootstrap-ready")

    def test_retry_checks_each_group_independently_and_skips_new_second_group(self):
        self.prepare()
        self.fail_get_once_after_merges(0)
        with self.assertRaisesRegex(apply.Failure, "azure-command-failed"):
            self.adopt()
        cleanup = self.scope["cleanupResourceGroupId"]
        self.objects[cleanup]["tags"]["orka-source-digest"] = self.bundle["sourceDigest"]
        self.adopt()
        self.assertEqual(self.writes, [
            (self.scope["verificationResourceGroupId"], "orka-source-digest=" + self.bundle["sourceDigest"])])
        self.assertEqual(json.loads((self.work / "receipt.json").read_text())["phase"], "bootstrap-ready")

    def test_retry_requires_byte_exact_intent_and_only_old_or_approved_group_tags(self):
        self.prepare()
        self.fail_get_once_after_merges(1)
        with self.assertRaisesRegex(apply.Failure, "azure-command-failed"):
            self.adopt()
        original = (self.work / "receipt.json").read_bytes()
        intent = json.loads(original)
        variants = [original + b"\n", (json.dumps(intent, sort_keys=True, indent=2) + "\n").encode(), b"{}\n"]
        for change in ("approval", "input-hash", "source", "phase", "completion", "clock", "extra"):
            changed = copy.deepcopy(intent)
            if change == "approval":
                changed["qualificationOf"]["approvalLinkSha256"] = "f" * 64
            elif change == "input-hash":
                changed["qualificationOf"]["inputHashes"]["preflight"]["safe-output.json"] = "f" * 64
            elif change == "source":
                changed["sourceDigest"] = "f" * 64
            elif change == "phase":
                changed["phase"] = "bootstrap-ready"
            elif change == "completion":
                changed["preflightCompleted"] = self.passed["endTime"]
            elif change == "clock":
                changed["T0"] = self.passed["endTime"]
            else:
                changed["unapproved"] = True
            variants.append((json.dumps(changed, indent=2) + "\n").encode())
        for index, raw in enumerate(variants):
            with self.subTest(receipt_variant=index):
                (self.work / "receipt.json").write_bytes(raw)
                with self.assertRaises(apply.Failure):
                    self.adopt()
                self.assertEqual(len(self.writes), 1)
                self.assertEqual((self.work / "receipt.json").read_bytes(), raw)
        (self.work / "receipt.json").write_bytes(original)
        for key in ("verificationResourceGroupId", "cleanupResourceGroupId"):
            for tag, value in (("orka-source-digest", "e" * 64), ("orka-owner", "unapproved"),
                               ("orka-expires-at-utc", "active"), ("extra-tag", "unapproved")):
                tags = self.objects[self.scope[key]]["tags"]
                previous = copy.deepcopy(tags)
                tags[tag] = value
                with self.subTest(group=key, tag=tag), self.assertRaises(apply.Failure):
                    self.adopt()
                self.objects[self.scope[key]]["tags"] = previous
                self.assertEqual(len(self.writes), 1)
                self.assertEqual((self.work / "receipt.json").read_bytes(), original)
        with self.assertRaises(apply.Failure):
            self.adopt(approved="f" * 64)
        self.assertEqual(len(self.writes), 1)
        self.adopt()
        self.assertEqual(len(self.writes), 2)

    def test_promoted_group_without_exact_intent_is_not_fresh_adoption(self):
        self.prepare()
        self.objects[self.scope["verificationResourceGroupId"]]["tags"]["orka-source-digest"] = self.bundle["sourceDigest"]
        with self.assertRaisesRegex(apply.Failure, "qualified-ownership-or-clock-drift"):
            self.adopt()
        self.assertFalse(self.writes)
        self.assertFalse((self.work / "receipt.json").exists())

    def test_late_child_or_runtime_change_after_second_merge_prevents_finalization(self):
        self.prepare()
        baseline = copy.deepcopy(self.objects)
        for collection in ("schedules", "jobs", "runtime-properties"):
            with self.subTest(collection=collection):
                self.objects = copy.deepcopy(baseline)
                self.writes.clear()
                (self.work / "receipt.json").unlink(missing_ok=True)

                def create_after_merge(command, **kwargs):
                    result = self.runner(command, **kwargs)
                    if command[1:3] == ["tag", "update"] and len(self.writes) == 2:
                        if collection == "runtime-properties":
                            runtime = self.objects[self.account + "/runtimeEnvironments"]["value"][0]
                            runtime["properties"]["description"] = "changed-between-runtime-reads"
                        else:
                            self.objects[self.account + "/" + collection]["value"].append({
                                "id": self.account + "/" + collection + "/unapproved-late-child"})
                    return result

                self.azure.runner = create_after_merge
                with self.assertRaises(apply.Failure):
                    self.adopt()
                receipt = json.loads((self.work / "receipt.json").read_text())
                self.assertEqual(receipt["phase"], "qualified-bootstrap-intent")
                self.assertNotIn("preflightCompleted", receipt)
                self.assertNotIn("T0", receipt)
                self.assertEqual(len(self.writes), 2)

    def test_same_id_system_runtime_projection_properties_change_rejects_adoption(self):
        self.prepare()
        catalogue = self.objects[self.account + "/runtimeEnvironments"]["value"]
        runtime = next(item for item in catalogue if item["id"].endswith("/PowerShell-5.1"))
        identity = runtime["id"]
        runtime["properties"]["description"] = "changed-system-projection"
        with self.assertRaisesRegex(apply.Failure, "qualified-approved-proof-drift"):
            self.adopt()
        self.assertEqual(runtime["id"], identity)
        self.assertFalse(self.writes)
        self.assertFalse((self.work / "receipt.json").exists())

    def test_live_diagnostic_output_change_rejects_adoption(self):
        self.prepare()
        self.text[self.diag_job + "/output"] = json.dumps({"outcome": "diagnostic-failed"})
        with self.assertRaisesRegex(apply.Failure, "qualified-diagnostic-output-drift"):
            self.adopt()
        self.assertFalse(self.writes)
        self.assertFalse((self.work / "receipt.json").exists())

    def test_templates_and_compute_inputs_may_not_change_with_the_handoff(self):
        original = self.compile_fixture
        def different(work):
            result = original(work)
            result["main"] = "f" * 64
            return result
        with mock.patch.object(apply, "compile_templates", side_effect=different), \
             self.assertRaisesRegex(apply.Failure, "compiled-footprint"):
            apply.prepare_qualified_bootstrap(self.args, self.work, self.azure)
        self.assertFalse((self.work / "bundle.json").exists())
        self.prepare()
        values = json.loads((self.work / "compute-inputs.json").read_text())
        values["newUnapprovedCompute"] = True
        apply.write_json(self.work / "compute-inputs.json", values)
        with self.assertRaises(apply.Failure):
            self.adopt()
        self.assertFalse(self.writes)


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
            properties = ({"runtime": {"language": "PowerShell", "version": "7.4"}, "defaultPackages": {}}
                          if child.startswith("runtime") else {
                              "runbookType": "PowerShell", "runtimeEnvironment": "PowerShell74",
                              "logVerbose": False, "logProgress": False, "logActivityTrace": 0, "draft": {}})
            changes.append({"resourceId": scope["automationAccountId"] + "/" + child, "changeType": "Create",
                            "after": {"properties": properties}})
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
                preview["changes"][0]["after"]["tags"] = {"orka-owner": "unexpected-child-tag"}
            elif mutation == "recreate":
                preview["changes"][0]["resourceId"] = self.previous["scope"]["automationAccountId"]
            elif mutation == "foreign":
                preview["changes"][0]["resourceId"] = self.previous["scope"]["controlVnetId"]
            else:
                preview["changes"][0]["changeType"] = "Modify"
            with self.subTest(mutation=mutation), self.assertRaises(apply.Failure):
                apply.validate_recovery_preview(preview, self.previous, self.current)

    def test_zero_tag_preview_rejects_any_count_key_or_value_instead_of_guessing_limits(self):
        for tags in ({}, {"r": "x"}, {"k" * 16: "v"}, {"k" * 17: "v"}, {"r": "v" * 1024},
                     {str(i): "v" for i in range(3)}, {str(i): "v" for i in range(4)}, None):
            preview = copy.deepcopy(self.preview)
            preview["changes"][0]["after"]["tags"] = tags
            with self.subTest(tags=tags):
                if tags == {}:
                    apply.validate_recovery_preview(preview, self.previous, self.current)
                else:
                    with self.assertRaisesRegex(apply.Failure, "child-tags-forbidden"):
                        apply.validate_recovery_preview(preview, self.previous, self.current)

    def test_recovery_preview_rejects_unexpected_child_properties(self):
        for index, key, value in ((0, "description", "not in reviewed template"),
                                  (0, "defaultPackages", {"Az": "1.0"}),
                                  (1, "publishContentLink", {"uri": "https://example.invalid/"}),
                                  (1, "logVerbose", True), (1, "runtimeEnvironment", "other")):
            preview = copy.deepcopy(self.preview)
            preview["changes"][index]["after"]["properties"][key] = value
            with self.subTest(key=key), self.assertRaises(apply.Failure):
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
        failed = {"workDir": str(self.directory / "failed-recovery"), "receiptSha256": "e" * 64}
        link = {"kind": "automation-child-zero-tag-recovery", "previousWorkDir": str(previous_dir),
                "previousBundleSha256": apply.sha((previous_dir / "bundle.json").read_bytes()),
                "previousReceiptSha256": apply.sha((previous_dir / "receipt.json").read_bytes()),
                "previousSourceDigest": "a" * 64, "nextSourceDigest": "b" * 64, "partialProof": proof,
                "failedRecovery": failed}
        digest = apply.sha(apply.wire(link))
        apply.write_json(next_dir / "recovery-link.json", {"plan": link, "sha256": digest})
        azure = mock.Mock(work=next_dir)
        azure.get.side_effect = lambda identity, version: {
            "id": identity, "tags": {**self.tags, "orka-source-digest": "b" * 64}}
        with mock.patch.object(apply, "previous_recovery_inputs", return_value=(previous_dir, self.previous)), \
                mock.patch.object(apply, "partial_bootstrap_proof", return_value=proof), \
                mock.patch.object(apply, "failed_recovery_proof", return_value=failed), \
                mock.patch.object(apply, "validate_recovery_preview"), \
                mock.patch.object(apply, "finish_bootstrap"):
            apply.recover_bootstrap(azure, self.current, {}, SimpleNamespace(approved_recovery_sha256=digest))
        ids = [c.args[c.args.index("--resource-id") + 1] for c in azure.cli.call_args_list]
        self.assertEqual(ids, [self.previous["scope"]["verificationResourceGroupId"],
                               self.previous["scope"]["cleanupResourceGroupId"]])
        self.assertNotIn(self.previous["scope"]["automationAccountId"], ids)
        self.assertEqual(self.tags["orka-source-digest"], "a" * 64)
        self.assertEqual(azure.deploy.call_args_list[-1].args[0], "bounded-cleanup-zero-tags")

    def failed_chain_fixture(self):
        previous_dir = self.directory / "original"
        failed_dir = self.directory / "failed"
        previous_dir.mkdir()
        failed_dir.mkdir()
        self.previous.update({"tenantId": "44444444-4444-4444-4444-444444444444", "roleGuids": {},
                              "controlKubeletIdentity": {}, "publicKeyReady": True,
                              "computeInputsSha256": apply.sha(b"{}"), "compiledHashes": {}})
        apply.write_json(previous_dir / "bundle.json", self.previous)
        apply.write_json(previous_dir / "receipt.json", {
            "phase": "bootstrap-intent", "subscriptionId": self.previous["subscriptionId"],
            "cleanupReceipt": self.previous["cleanupReceipt"], "sourceDigest": self.previous["sourceDigest"]})
        (failed_dir / "compute-inputs.json").write_text("{}")
        failed = {**self.previous, "sourceDigest": "b" * 64}
        apply.write_json(failed_dir / "bundle.json", failed)
        partial = {"principalId": "33333333-3333-3333-3333-333333333333", "expectedTags": self.tags}
        link = {"kind": "automation-runtime-three-tag-recovery", "previousSourceDigest": "a" * 64,
                "nextSourceDigest": "b" * 64, "partialProof": partial,
                "previousBundleSha256": apply.sha((previous_dir / "bundle.json").read_bytes()),
                "previousReceiptSha256": apply.sha((previous_dir / "receipt.json").read_bytes())}
        apply.write_json(failed_dir / "recovery-link.json", {"plan": link, "sha256": apply.sha(apply.wire(link))})
        receipt = {"phase": "recovery-intent", "subscriptionId": self.previous["subscriptionId"],
                   "cleanupReceipt": self.previous["cleanupReceipt"], "sourceDigest": "b" * 64,
                   "principalId": partial["principalId"], "recoveryOf": {
                       "sourceDigest": "a" * 64, "receiptSha256": link["previousReceiptSha256"],
                       "recoveryLinkSha256": apply.sha(apply.wire(link))}}
        apply.write_json(failed_dir / "receipt.json", receipt)
        deployment_id = self.previous["scope"]["cleanupResourceGroupId"] + \
            "/providers/Microsoft.Resources/deployments/bounded-cleanup-recovery"
        operation = {"provisioningState": "Failed", "targetResource": {
            "id": self.previous["scope"]["automationAccountId"] + "/runtimeEnvironments/PowerShell74"},
            "statusMessage": {"error": {"code": "BadRequest", "message":
                "Argument RuntimeEnvironmentTags.Key.Length with value 20 cannot be greater than 16."}}}
        azure = mock.Mock()
        azure.get.return_value = {"id": deployment_id, "properties": {"provisioningState": "Failed"}}
        azure.cli.return_value = [operation]
        azure.cli.side_effect = lambda *args: [] if args[:3] == ("deployment", "group", "list") else azure.cli.return_value
        args = SimpleNamespace(work_dir=str(self.directory / "next"))
        return previous_dir, failed_dir, partial, args, azure

    def test_failed_recovery_link_pins_both_receipts_and_exact_live_failure(self):
        original, failed, partial, args, azure = self.failed_chain_fixture()
        before = {(p, name): (p / name).read_bytes() for p in (original, failed)
                  for name in ("bundle.json", "receipt.json")}
        with mock.patch.object(apply.plan, "private_path", side_effect=Path):
            proof = apply.failed_recovery_proof(str(failed), args, original, self.previous, partial, azure)
            self.assertEqual(proof["receiptSha256"], apply.sha((failed / "receipt.json").read_bytes()))
            self.assertEqual(proof["sourceDigest"], "b" * 64)
            for (path, name), contents in before.items():
                self.assertEqual((path / name).read_bytes(), contents)
            receipt = json.loads((failed / "receipt.json").read_text())
            receipt["principalId"] = "55555555-5555-5555-5555-555555555555"
            apply.write_json(failed / "receipt.json", receipt)
            with self.assertRaisesRegex(apply.Failure, "unsupported-failed-recovery-receipt"):
                apply.failed_recovery_proof(str(failed), args, original, self.previous, partial, azure)
        azure.rest.assert_not_called()

    def test_failed_recovery_link_rejects_any_different_platform_failure_or_deployment(self):
        original, failed, partial, args, azure = self.failed_chain_fixture()
        with mock.patch.object(apply.plan, "private_path", side_effect=Path):
            azure.cli.return_value[0]["statusMessage"]["error"]["message"] = "some other failure"
            with self.assertRaisesRegex(apply.Failure, "exact-tag-key-limit-failure"):
                apply.failed_recovery_proof(str(failed), args, original, self.previous, partial, azure)
            azure.get.return_value["id"] += "-different"
            with self.assertRaisesRegex(apply.Failure, "deployment-mismatch"):
                apply.failed_recovery_proof(str(failed), args, original, self.previous, partial, azure)

    def test_zero_tag_recovery_is_not_a_generic_recursive_adoption_path(self):
        original, failed, partial, args, azure = self.failed_chain_fixture()
        record = json.loads((failed / "recovery-link.json").read_text())
        record["plan"]["kind"] = "automation-child-zero-tag-recovery"
        record["sha256"] = apply.sha(apply.wire(record["plan"]))
        apply.write_json(failed / "recovery-link.json", record)
        with mock.patch.object(apply.plan, "private_path", side_effect=Path), \
                self.assertRaisesRegex(apply.Failure, "only-known-three-tag-recovery"):
            apply.failed_recovery_proof(str(failed), args, original, self.previous, partial, azure)
        self.assertFalse(azure.mock_calls)

    def test_zero_tag_recovery_cannot_replay_an_existing_zero_tag_attempt(self):
        original, failed, partial, args, azure = self.failed_chain_fixture()
        azure.cli.side_effect = None
        with mock.patch.object(apply.plan, "private_path", side_effect=Path), \
                self.assertRaisesRegex(apply.Failure, "zero-tag-recovery-already-attempted"):
            apply.failed_recovery_proof(str(failed), args, original, self.previous, partial, azure)


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
        self.assertEqual(account["tags"], "[parameters('ownershipTags')]")
        for resource in resources:
            if resource["type"] != "Microsoft.Automation/automationAccounts":
                self.assertNotIn("tags", resource)
                self.assertNotIn("description", resource["properties"])
                encoded = json.dumps(resource, sort_keys=True).encode()
                self.assertNotIn(b'"tags"', encoded)
                self.assertEqual(len(resource.get("tags", {})), 0)
                self.assertEqual(json.dumps(resource.get("tags", {}), separators=(",", ":")).encode(), b"{}")
        for group in groups:
            self.assertEqual(group["tags"], "[variables('tags')]")
        self.assertEqual(len(template["variables"]["tags"]), 7)

    def test_cleanup_creates_only_scoped_builtin_assignments_not_role_definitions(self):
        template = self.compile("cleanup-access")
        apply.reject_custom_role_definitions(template)
        self.assertIn("94877a25-7520-40c5-9c42-68e02e4758bd", template["variables"]["resourceRoleId"])
        self.assertIn("acdd72a7-3385-48ef-bd42-f606fba81ae7", template["variables"]["readerRoleId"])
        modules = [r for r in template["resources"] if r["type"] == "Microsoft.Resources/deployments"]
        self.assertEqual(len(modules), 2)
        self.assertEqual(template["variables"]["prefix"], "[format('orka-verify-{0}', parameters('suffix'))]")
        self.assertEqual({module["name"]: module["resourceGroup"] for module in modules}, {
            "verification-cleanup-access": "[format('rg-{0}', variables('prefix'))]",
            "node-cleanup-access": "[format('rg-{0}-nodes', variables('prefix'))]",
        })
        node = next(module for module in modules if module["name"] == "node-cleanup-access")
        self.assertEqual(node["condition"], "[parameters('includeNodeGroup')]")
        readers = [r for r in template["resources"] if r["type"] == "Microsoft.Authorization/roleAssignments"]
        self.assertEqual(len(readers), 1)
        self.assertNotIn("scope", readers[0])
        self.assertEqual(readers[0]["properties"]["roleDefinitionId"], "[variables('readerRoleId')]")
        for module in modules:
            self.assertEqual(module["properties"]["parameters"]["roleDefinitionId"]["value"],
                             "[variables('resourceRoleId')]")
        self.assertEqual(apply.BUILTIN_ROLES["resource-cleanup"][2], {
            "Microsoft.Resources/subscriptions/resourceGroups/read",
            "Microsoft.Resources/subscriptions/resourceGroups/write",
            "Microsoft.Resources/subscriptions/resourceGroups/delete",
        })

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
            self.assertNotIn("tags", resource)
            self.assertNotIn("description", resource["properties"])
            self.assertNotIn(b'"tags"', json.dumps(resource, sort_keys=True).encode())
            self.assertEqual(json.dumps(resource.get("tags", {}), separators=(",", ":")).encode(), b"{}")
        self.assertNotIn("ownershipTags", recovery["parameters"])

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
        self.assertIn("contracts passed: 29", result.stdout)


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
