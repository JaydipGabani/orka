import json
import pathlib
import sys
import urllib.request


policy_path, state_path, operation = sys.argv[1:4]
policy = json.loads(pathlib.Path(policy_path).read_text())
state_file = pathlib.Path(state_path)
state = json.loads(state_file.read_text()) if state_file.exists() else {"retained": "fixture-order"}

if operation in ("install", "reconcile", "restart") or (
    operation == "upgrade" and policy["migrateExisting"]
):
    state.update(
        allowAnonymous=policy["allowAnonymous"],
        allowAuthenticated=policy["allowAuthenticated"],
        installedRevision=policy["revision"],
    )
    if operation == "install" and policy["postInstallOverride"]:
        state["allowAnonymous"] = False
    state_file.write_text(json.dumps(state, sort_keys=True))
elif operation == "upgrade":
    pass
elif operation == "request":
    identity = sys.argv[4]
    field = "allowAnonymous" if identity == "anonymous" else "allowAuthenticated"
    if state[field]:
        with urllib.request.urlopen("http://127.0.0.1:18080/reserve", timeout=2) as response:
            if response.read() != b"reserved\n":
                raise RuntimeError("fake inventory response does not match")
        print("accepted")
    else:
        print("rejected")
else:
    raise ValueError("unsupported model operation")
