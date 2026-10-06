import json
import os
import pathlib
import subprocess
import sys


scenario = sys.argv[1]
state_file = pathlib.Path(os.environ.get("TMPDIR", "/tmp")) / "effective-state.json"


def manage(operation, policy="/src/policy.json", identity=None):
    command = ["/usr/bin/python3", "/src/manager.py", policy, str(state_file), operation]
    if identity is not None:
        command.append(identity)
    return subprocess.check_output(command, timeout=5).decode("utf-8").strip()


if scenario == "upgrade":
    manage("install", "/checks/affected-policy.json")
    before = json.loads(state_file.read_text())
    assert before["allowAnonymous"] and before["retained"] == "fixture-order"
    manage("upgrade")
else:
    manage("install")
    if scenario in ("reconcile", "restart"):
        manage(scenario)
    elif scenario == "normal":
        manage("reconcile")
        manage("restart")
        manage("upgrade")
    elif scenario != "install":
        raise ValueError("unknown lifecycle scenario")

effective = json.loads(state_file.read_text())
assert effective["retained"] == "fixture-order"
if scenario == "normal":
    response = manage("request", identity="authenticated")
    print("authenticated=" + response)
    print("retained=" + effective["retained"])
else:
    response = manage("request", identity="anonymous")
    print("step=" + scenario)
    print("effective.allowAnonymous=" + str(effective["allowAnonymous"]).lower())
    print("request=" + response)
    print("retained=" + effective["retained"])
