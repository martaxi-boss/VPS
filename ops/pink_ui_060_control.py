"""Canonical exact-scope audit; no host effects or private inputs."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

BASE = "a8af395df2c2b83b627f5a71337b67d209daf5f3"
SOURCE = "46362b11667fb604edd61bf8c5a2eac61a0f15ac"
TASK = "PINK-IPTV-ACTUAL-UI-PROOF-060"
AUTH_COMMIT = "046d95ca0311401d744d5917f1e523c03304976a"


def api(repo, path):
    req = urllib.request.Request("https://api.github.com/repos/" + repo + "/" + path,
                                 headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                                          "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


def main():
    own = f".project-leader/tasks/{TASK}.json"
    assert Path(own).read_text() == git("show", AUTH_COMMIT + ":" + own) + "\n"
    subprocess.run([sys.executable, "_canonical/control/validate_records.py", "task", own], check=True)
    files = git("diff", "--name-only", BASE, "HEAD").splitlines()
    subprocess.run([sys.executable, "_canonical/control/validate_records.py", "scope", own, *files], check=True)
    task = json.loads(Path(own).read_text())
    policy = Path("_canonical/control/generic-project-policy.json").read_bytes()
    assert hashlib.sha256(policy).hexdigest() == task["policy"]["sha256"]
    assert api("martaxi-boss/Project-leader", "commits/main")["sha"] == task["policy"]["revision"]
    assert not git("diff", "--name-only", BASE, "HEAD", "--", "ops/pink_vpn_056_runtime.py",
                   "ops/pink_vpn_054_manifest.json", "ops/pink_vpn_054_observe.py")
    events = sorted(Path(f".project-leader/recovery-events/{TASK}").glob("*.json"))
    assert events
    subprocess.run([sys.executable, "_canonical/control/validate_records.py", "recovery-journal", *map(str, events)], check=True)
    for result in sorted(Path(".project-leader/transitions").glob(f"{TASK}-*.result.json")):
        subprocess.run([sys.executable, "_canonical/control/validate_records.py", "transition-result", str(result)], check=True)
    print("CANONICAL_060_IMMUTABLE_TASK_SCOPE_POLICY_AND_REUSED_PROTECTION=PASS")
    if os.environ.get("PINK060_MESSAGE") != "Authorize exact actual UI proof060":
        return
    added = git("diff", "--name-only", "--diff-filter=A", "HEAD^", "HEAD").splitlines()
    assert len(added) == 1 and added[0].startswith(f".project-leader/transitions/{TASK}-EXECUTE")
    auth = json.loads(Path(added[0]).read_text())
    subprocess.run([sys.executable, "_canonical/control/validate_records.py", "transition-auth", added[0]], check=True)
    assert auth["repository"] == "martaxi-boss/VPS" and auth["task_id"] == TASK
    assert auth["action"] == "staging_operational_proof"
    assert auth["authority"]["source"] == "STANDING_OWNER_GRANT"
    assert auth["target"]["environment"] == "staging-disposable-emulator"
    assert git("rev-parse", "HEAD^") == auth["target"]["revision"]
    assert auth["target"]["base_revision"] == BASE
    prefix = f"OVH:vps-32bea5b6;PINK:{SOURCE};artifact-run:"
    assert auth["target"]["identifier"].startswith(prefix)
    run_id = auth["target"]["identifier"][len(prefix):]
    assert run_id.isdigit()
    prep = api("martaxi-boss/VPS", "actions/runs/" + run_id)
    assert prep["head_sha"] == auth["target"]["revision"]
    assert prep["name"] == "PINK actual UI proof 060" and prep["conclusion"] == "success"
    assert api("martaxi-boss/VPS", "git/ref/heads/builder/pink-actual-ui-proof-060")["object"]["sha"] == os.environ["GITHUB_SHA"]
    assert api("martaxi-boss/pink-iptv", "git/ref/heads/builder/physical-ui-recovery-059")["object"]["sha"] == SOURCE
    runs = api("martaxi-boss/pink-iptv", f"actions/runs?head_sha={SOURCE}&per_page=100")["workflow_runs"]
    for name in ("PINK Extreme Android 042", "Backend CI"):
        relevant = [run for run in runs if run["name"] == name]
        assert relevant and all(run["head_sha"] == SOURCE and run["status"] == "completed"
                                and run["conclusion"] == "success" for run in relevant)
    with open(os.environ["GITHUB_ENV"], "a") as env:
        env.write("PINK060_ARTIFACT_RUN=" + run_id + "\n")
    print("EXACT_PRIVILEGED_AUTHORIZATION_SOURCE_CI_AND_PREPARED_ARTIFACT=PASS")


if __name__ == "__main__":
    main()
