#!/usr/bin/env python3
"""Exercise the real validation REST API, controller, Jobs and evidence store."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = "orka-validation"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--profile", choices=["offline", "local-services"], default="offline")
    args = parser.parse_args()
    token = (args.artifacts / "caller-token").read_text().strip()
    tool = (args.artifacts / "tool-image").read_text().strip()
    environment = dict(os.environ)
    environment["KUBECONFIG"] = (args.artifacts / "kubeconfig-path").read_text().strip()
    records = []
    api_url = args.url.rstrip("/")
    forwarding = None

    def kube(*arguments, input_bytes=None):
        return subprocess.run(
            ["kubectl", "-n", NAMESPACE, *arguments],
            env=environment, input=input_bytes, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=True,
        ).stdout

    def api(method, suffix="", body=None, expected=200, binary=False):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            api_url + "/api/v1/validations" + suffix + "?namespace=" + NAMESPACE,
            data=data, method=method,
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                status, raw = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read()
        if status != expected:
            raise RuntimeError(f"{method} validation API returned {status}, expected {expected}: {raw[:512]!r}")
        if binary:
            return raw
        return json.loads(raw) if raw else None

    def wait(request_id, conclusion, recorded=None):
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            progress = api("GET", "/" + request_id)
            if progress["state"] == "terminal":
                evidence = api("GET", "/" + request_id + "/evidence")
                actual = evidence["assessment"]["conclusion"]
                assert actual == conclusion, (actual, conclusion, progress, evidence["assessment"])
                observations = [] if evidence["evidence"] is None else evidence["evidence"]
                assert isinstance(observations, list), "invalid evidence collection shape"
                if recorded is not None:
                    assert len(observations) == recorded, evidence["assessment"]
                assert evidence["binding"]["runID"] == progress["runID"]
                for entry in observations:
                    observation = entry["observation"]
                    assert observation["origin"] == "runner"
                    assert observation["taskID"] in (progress["originalTaskUID"], progress.get("patchedTaskUID"))
                    assert observation["jobUID"] and observation["podUID"] and observation["containerID"]
                    assert observation["manifestDigest"] == evidence["binding"]["manifestDigest"]
                    for kind in ("stdout", "stderr"):
                        digest = observation[kind + "Digest"]
                        content = api("GET", "/" + request_id + "/evidence/" + digest, binary=True)
                        assert "sha256:" + hashlib.sha256(content).hexdigest() == digest
                        assert len(content) == observation[kind + "Bytes"]
                request_label = "patchverification.orka.ai/request=" + request_id
                jobs = json.loads(kube("get", "jobs", "-l", request_label, "-o", "json"))
                pods = json.loads(kube("get", "pods", "-l", request_label, "-o", "json"))
                assert not jobs["items"] and not pods["items"], "runtime resources survived terminal cleanup"
                records.append({"requestID": request_id, "runID": progress["runID"],
                                "conclusion": actual, "observations": len(observations)})
                (args.artifacts / (request_id + ".json")).write_text(json.dumps(evidence, indent=2))
                print(f"PASS {actual}: {len(observations)} observations; runtime cleanup confirmed")
                return progress, evidence
            time.sleep(1)
        raise TimeoutError("validation did not reach terminal state: " + request_id)

    provisioner_name = "validation-input-upload-" + str(os.getpid())
    provisioner = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": provisioner_name, "namespace": NAMESPACE},
        "spec": {
            "automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {"runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532,
                                "runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "upload", "image": tool, "imagePullPolicy": "IfNotPresent",
                "command": ["/bin/sh", "-c", "sleep 1800"],
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "inputs", "mountPath": "/validation"}],
            }],
            "volumes": [{"name": "inputs", "persistentVolumeClaim": {"claimName": "validation-inputs"}}],
        },
    }
    kube("create", "-f", "-", input_bytes=json.dumps(provisioner).encode())
    try:
        kube("wait", "--for=condition=Ready", "pod/" + provisioner_name, "--timeout=120s")

        def fixture(project, variant="fixed", action="verify-patch", mode="patch"):
            created = subprocess.run(
                ["bash", "examples/patch-verification/demo.sh", project, variant, mode, action],
                cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            filename = Path(created.stdout.decode().strip())
            request = json.loads(filename.read_text())
            identifier = project + "-" + variant + "-" + action + "-" + str(time.time_ns())
            destination = "/validation/" + NAMESPACE + "/" + identifier
            with tempfile.TemporaryFile() as stream:
                with tarfile.open(fileobj=stream, mode="w") as archive:
                    archive.add(filename.parent / "repo", arcname="repo")
                    archive.add(filename.parent / "checks", arcname="checks")
                    if "patchFile" in request:
                        archive.add(request["patchFile"], arcname="supplied.patch")
                stream.seek(0)
                kube("exec", provisioner_name, "--", "mkdir", "-p", destination)
                kube("exec", "-i", provisioner_name, "--", "tar", "xf", "-", "--no-same-owner", "-C", destination,
                     input_bytes=stream.read())
            request["repository"], request["checksDir"] = identifier + "/repo", identifier + "/checks"
            request["image"] = tool
            request["gaps"] = [gap for gap in request["gaps"] if "not wired" not in gap]
            if "patchFile" in request:
                request["patchFile"] = identifier + "/supplied.patch"
            if filename.parent.parent != Path("/tmp") or not filename.parent.name.startswith("patchverify-demo."):
                raise RuntimeError("unexpected fixture directory; refusing cleanup")
            shutil.rmtree(filename.parent)
            return request

        project = "go" if args.profile == "offline" else "http"
        report_request = fixture(project, action="validate-report")
        report = api("POST", body=report_request, expected=202)
        original, original_evidence = wait(report["requestID"], "Reproduced", 3)
        repeat = api("POST", body=report_request, expected=202)
        wait(repeat["requestID"], "Reproduced", 3)
        assert repeat["requestID"] != report["requestID"]
        verification = fixture(project)
        linked = {
            "action": "verify-patch", "earlierValidation": original["runID"],
            "patchFile": verification["patchFile"], "declaredChanges": verification["declaredChanges"],
        }
        started = api("POST", body=linked, expected=202)
        _, linked_evidence = wait(started["requestID"], "Verified for these checks", 6)
        assert linked_evidence["manifest"]["earlierValidation"]["runID"] == original["runID"]
        assert api("GET", "/" + report["requestID"] + "/evidence") == original_evidence
        api("POST", "/" + report["requestID"] + "/cancel", body={}, expected=202)
        assert api("GET", "/" + report["requestID"] + "/evidence") == original_evidence

        for variant, conclusion in (
            ("fixed", "Verified for these checks"), ("notfixed", "Not fixed"),
            ("partial", "Partially fixed"), ("regression", "Introduces a regression"),
        ):
            request = fixture("c" if args.profile == "offline" else "config", variant)
            started = api("POST", body=request, expected=202)
            wait(started["requestID"], conclusion, 6 if args.profile == "offline" else 10)

        def running_job(request_id):
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                pods = json.loads(kube("get", "pods", "-l",
                                      "patchverification.orka.ai/request=" + request_id, "-o", "json"))
                for pod in pods["items"]:
                    statuses = pod.get("status", {}).get("containerStatuses", [])
                    if any(status["name"] == "validation" and "running" in status["state"] for status in statuses):
                        return pod["metadata"]["ownerReferences"][0]["uid"]
                time.sleep(0.2)
            raise TimeoutError("check did not enter actual execution before lifecycle test")

        if args.profile == "offline":
            commit_request = fixture("c", mode="commit")
            started = api("POST", body=commit_request, expected=202)
            wait(started["requestID"], "Verified for these checks", 6)
            clean_report = copy.deepcopy(commit_request)
            clean_report["action"] = "validate-report"
            clean_report["originalCommit"] = clean_report.pop("patchedCommit")
            del clean_report["declaredChanges"]
            started = api("POST", body=clean_report, expected=202)
            wait(started["requestID"], "Not reproduced under these conditions", 3)

            restarted = api("POST", body=report_request, expected=202)
            preserved_job_uid = running_job(restarted["requestID"])
            kube("rollout", "restart", "deployment/validation-controller")
            kube("rollout", "status", "deployment/validation-controller", "--timeout=120s")
            forwarding = subprocess.Popen(
                ["kubectl", "-n", NAMESPACE, "port-forward", "--address", "127.0.0.1",
                 "service/validation-api", ":8080"],
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            ready, _, _ = select.select([forwarding.stdout], [], [], 30)
            if not ready:
                raise TimeoutError("restarted controller API port-forward did not become ready")
            match = re.search(r"Forwarding from 127\.0\.0\.1:(\d+)", forwarding.stdout.readline())
            if match is None:
                raise RuntimeError("restarted controller API port-forward failed")
            api_url = "http://127.0.0.1:" + match.group(1)
            _, restarted_evidence = wait(restarted["requestID"], "Reproduced", 3)
            assert preserved_job_uid in {
                entry["observation"]["jobUID"] for entry in restarted_evidence["evidence"]
            }, "controller restart replayed the active check instead of observing its Job"
            assert api("GET", "/" + report["requestID"] + "/evidence") == original_evidence
            print("PASS controller restart: existing Job UID preserved and earlier evidence unchanged")

            active_cancel = api("POST", body=report_request, expected=202)
            running_job(active_cancel["requestID"])
            api("POST", "/" + active_cancel["requestID"] + "/cancel", body={}, expected=202)
            _, cancelled_evidence = wait(active_cancel["requestID"], "Unable to validate")
            assert cancelled_evidence["state"] == "cancelled"
            print("PASS cancellation while a check is running")

        unsupported = copy.deepcopy(report_request)
        unsupported["requiredEnvironment"].append({"kind": "cluster", "name": "unsupported-real-cluster"})
        started = api("POST", body=unsupported, expected=202)
        wait(started["requestID"], "Unable to validate", 0)
        cancelled = api("POST", body=report_request, expected=202)
        api("POST", "/" + cancelled["requestID"] + "/cancel", body={}, expected=202)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            progress = api("GET", "/" + cancelled["requestID"])
            if progress["state"] == "terminal":
                assert progress.get("assessment", {}).get("conclusion", "Unable to validate") == "Unable to validate"
                break
            time.sleep(1)
        else:
            raise TimeoutError("cancelled preparation did not settle")
        print("PASS cancellation and unsupported-environment handling")
        if args.profile == "local-services":
            temporary = api("POST", body=fixture("config", "temporary"), expected=202)
            wait(temporary["requestID"], "Partially fixed", 10)
        report_path = args.artifacts / ("conformance-" + args.profile + ".json")
        report_path.write_text(json.dumps(records, indent=2))
        print(f"Saved {len(records)} completed-run summaries to {report_path}")
    finally:
        if forwarding is not None:
            forwarding.terminate()
            try:
                forwarding.wait(timeout=10)
            except subprocess.TimeoutExpired:
                forwarding.kill()
                forwarding.wait()
        kube("delete", "pod", provisioner_name, "--wait=true", "--timeout=60s", "--ignore-not-found")


if __name__ == "__main__":
    main()
