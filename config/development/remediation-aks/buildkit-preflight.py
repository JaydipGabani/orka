#!/usr/bin/env python3
"""Guest-only network/cgroup checks; never install tools or print metadata bodies."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib

CONFIG = Path("/etc/orka-buildkit")
CGROUP = "/orka-buildkit.slice/orka-buildkit.service"
CGROOT = Path("/sys/fs/cgroup" + CGROUP)
PROOF = CONFIG / "qualification.json"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def call(arguments):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=30, check=False)
    require(result.returncode == 0, "preflight-command-failed")
    return result.stdout


def fingerprint():
    files = [CONFIG / "buildkitd.toml", CONFIG / "qualification.toml", CONFIG / "cni.json", CONFIG / "buildkit-network.nft",
             Path("/etc/systemd/system/orka-buildkit.service"),
             Path("/etc/systemd/system/orka-buildkit.slice"),
             Path("/opt/orka-buildkit/bin/start-bounded-buildkit.sh")]
    values = {}
    for path in files:
        info = path.stat()
        require(info.st_uid == 0 and info.st_mode & 0o022 == 0, "untrusted-configuration-owner")
        values[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def validate_rules(document):
    chains, rules = {}, {"input": [], "forward": []}
    for entry in document["nftables"]:
        if "chain" in entry:
            chain = entry["chain"]
            chains[chain["name"]] = chain
        if "rule" in entry:
            rule = entry["rule"]
            require(rule["chain"] in rules, "unexpected-firewall-chain")
            matches, verdict = [], None
            for expression in rule["expr"]:
                if "counter" in expression:
                    continue
                if "match" in expression:
                    item = expression["match"]
                    require(item["op"] == "==", "unexpected-firewall-operator")
                    left = item["left"]
                    if "meta" in left:
                        matches.append((left["meta"]["key"], item["right"]))
                    elif "payload" in left:
                        payload = left["payload"]
                        matches.append((payload["protocol"] + "." + payload["field"], item["right"]))
                    else:
                        raise RuntimeError("unexpected-firewall-expression")
                elif "drop" in expression:
                    verdict = "drop"
                elif "accept" in expression:
                    verdict = "accept"
                else:
                    raise RuntimeError("unexpected-firewall-expression")
            require(("iifname", "orka-build0") in matches, "unbounded-firewall-source")
            rules[rule["chain"]].append((set(matches), verdict))
    for name in rules:
        require(name in chains and chains[name]["hook"] == name and chains[name]["prio"] == -200 and
                chains[name]["policy"] == "accept", "firewall-hook-mismatch")
    source = {("iifname", "orka-build0")}
    expected = {
        "input": [(source, "drop")],
        "forward": [
            (source | {("ip.daddr", "169.254.169.254")}, "drop"),
            (source | {("ip.daddr", "168.63.129.16"), ("udp.dport", 53)}, "accept"),
            (source | {("ip.daddr", "168.63.129.16"), ("tcp.dport", 53)}, "accept"),
            (source | {("ip.daddr", "168.63.129.16")}, "drop"),
        ],
    }
    for name, wanted in expected.items():
        require(len(rules[name]) == len(wanted), "firewall-rule-count-mismatch")
        for (actual, verdict), (match, decision) in zip(rules[name], wanted):
            actual = {item for item in actual if item not in (("l4proto", "tcp"), ("l4proto", "udp"))}
            require(actual == match and verdict == decision, "firewall-rule-mismatch")


def host():
    require(os.geteuid() == 0, "trusted-host-root-required")
    require(Path("/sys/fs/cgroup/cgroup.controllers").is_file(), "cgroup-v2-required")
    config = tomllib.loads((CONFIG / "buildkitd.toml").read_text())
    qualification = tomllib.loads((CONFIG / "qualification.toml").read_text())
    worker = config["worker"]["oci"]
    require(config["insecure-entitlements"] == [] and worker["networkMode"] == "cni" and
            worker["defaultCgroupParent"] == "/workloads" and not worker["noProcessSandbox"],
            "unsafe-buildkit-worker")
    require(qualification["worker"] == config["worker"] and
            qualification["insecure-entitlements"] == [] and
            qualification["grpc"]["address"] == ["unix:///run/orka-buildkit-qualification.sock"] and
            qualification["grpc"]["uid"] == 0 and qualification["grpc"]["gid"] == 0,
            "unsafe-qualification-listener")
    cni = json.loads((CONFIG / "cni.json").read_text())
    bridge = next(p for p in cni["plugins"] if p["type"] == "bridge")
    require(bridge["bridge"] == "orka-build0" and bridge["isGateway"] is True and
            bridge["ipam"]["ranges"] == [[{"subnet": "10.89.0.0/24"}]], "unexpected-build-network")
    validate_rules(json.loads(call(["nft", "-j", "list", "table", "inet", "orka_buildkit"])))
    quota, period = (CGROOT / "cpu.max").read_text().split()
    require(quota != "max" and 0 < int(quota) <= 4 * int(period), "cpu-limit-missing")
    require(0 < int((CGROOT / "memory.max").read_text()) <= 12 * 1024**3, "memory-limit-missing")
    require(0 < int((CGROOT / "pids.max").read_text()) <= 512, "pid-limit-missing")
    require({"cpu", "memory", "pids"}.issubset(set((CGROOT / "cgroup.subtree_control").read_text().split())),
            "cgroup-delegation-missing")
    require(call(["systemctl", "show", "orka-buildkit.service", "--property=KillMode", "--value"]).strip() ==
            "control-group", "descendant-stop-policy-missing")
    return fingerprint()


def start_ticks(process):
    return int(process.joinpath("stat").read_text().rsplit(")", 1)[1].split()[19])


def validate_run_cgroup(cgroup):
    require(cgroup.startswith("0::" + CGROUP + "/supervisor/") and
            "/buildkit/" in cgroup, "run-outside-bounded-service")


def run_probe(pid, case):
    require(pid > 1, "actual-run-pid-required")
    process = Path("/proc") / str(pid)
    cgroup = process.joinpath("cgroup").read_text().strip()
    validate_run_cgroup(cgroup)
    require(process.joinpath("ns/net").stat().st_ino != Path("/proc/1/ns/net").stat().st_ino,
            "host-network-fallback")
    # Connect-only probes: never request or output instance metadata or tokens.
    probe = (
        "import socket,sys\n"
        "for host,port in [('169.254.169.254',80),('168.63.129.16',80),('168.63.129.16',32526)]:\n"
        " try:\n"
        "  s=socket.create_connection((host,port),2);s.close();sys.exit(1)\n"
        " except OSError:pass\n"
    )
    call(["nsenter", "--net=" + str(process / "ns/net"), "--", "python3", "-c", probe])
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    hashes = host()
    values = json.loads(PROOF.read_text()) if PROOF.exists() else {}
    if values.get("bootId") != boot or values.get("configHashes") != hashes:
        values = {"version": 1, "bootId": boot, "configHashes": hashes, "runs": {}}
    values["runs"][case] = {"pid": pid, "startTicks": start_ticks(process), "cgroup": cgroup,
                            "networkDenied": True}
    values["descendantsStopped"] = False
    PROOF.write_text(json.dumps(values, indent=2) + "\n")
    PROOF.chmod(0o600)


def stopped():
    proof = json.loads(PROOF.read_text())
    require(proof["configHashes"] == fingerprint() and set(proof["runs"]) == {"default", "override"} and
            all(run["networkDenied"] is True for run in proof["runs"].values()), "qualification-drift")
    require(not CGROOT.exists() or "populated 0" in (CGROOT / "cgroup.events").read_text(),
            "build-descendants-still-present")
    for run in proof["runs"].values():
        process = Path("/proc") / str(run["pid"])
        require(not process.exists() or start_ticks(process) != run["startTicks"], "run-process-still-present")
    proof["descendantsStopped"] = True
    PROOF.write_text(json.dumps(proof, indent=2) + "\n")
    PROOF.chmod(0o600)


def certified():
    proof = json.loads(PROOF.read_text())
    require(PROOF.stat().st_uid == 0 and PROOF.stat().st_mode & 0o077 == 0, "unsafe-proof-owner")
    require(proof["configHashes"] == host() and set(proof["runs"]) == {"default", "override"} and
            all(run["networkDenied"] is True for run in proof["runs"].values()) and
            proof["descendantsStopped"] is True and
            proof["bootId"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "current-boot-qualification-required")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("host", "run-pid", "stopped", "certified"))
    parser.add_argument("--pid", type=int)
    parser.add_argument("--case", choices=("default", "override"))
    args = parser.parse_args()
    os.umask(0o077)
    if args.operation == "run-pid":
        require(args.pid is not None and args.case is not None, "actual-run-pid-and-case-required")
        run_probe(args.pid, args.case)
    else:
        {"host": host, "stopped": stopped, "certified": certified}[args.operation]()
    print("BuildKit preflight passed; no credential or metadata content captured.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, StopIteration):
        print("BuildKit qualification failed; daemon must remain unavailable.", file=sys.stderr)
        sys.exit(1)
