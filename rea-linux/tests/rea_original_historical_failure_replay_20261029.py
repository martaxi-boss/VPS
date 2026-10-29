#!/usr/bin/env python3
"""Real historical-cleanup regression replay on untouched upstream REA CLI.

No changes to production services, no MCP, no installs, no provider downloads.
Triggered only via existing GitHub Actions -> pinned SSH -> this Python runner.
"""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import time

os.umask(0o077)
SOURCE_COMMIT = "160d821ac9a0310afcb8d1fc427862dd6508add5"
ROOT = Path("/home/ubuntu/rea-original-upstream-680")
OUT = Path("/home/ubuntu/rea-original-upstream-680-evidence/historical-replay-20261029")
NODE = Path("/opt/rea-reversa/providers/node-v24.22.1/bin/node")
SHARED_DEP_ROOT = Path("/opt/rea-reversa/rea")
EXPECTED_DIGESTS = {
    "dist/process/ProcessOwnership.js":
        "2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852",
    "dist/process/ProcessOwnershipObservation.js":
        "81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655",
}


def invoke(cmd, **kwargs):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, check=False, **kwargs)


def check(condition, label):
    if not condition:
        raise RuntimeError(label)


def preflight():
    check(pwd.getpwuid(os.geteuid()).pw_name == "ubuntu",
          "REFUSE_NON_UBUNTU_USER")
    check(ROOT.is_dir() and not ROOT.is_symlink(), "ORIGINAL_SOURCE_ABSENT")
    check(NODE.is_file(), "EXISTING_NODE_UNAVAILABLE")
    check(OUT.parent.is_dir(), "ORIGINAL_EVIDENCE_ROOT_ABSENT")
    check((OUT.parent / ("build-pass-for-" + SOURCE_COMMIT)).is_file(),
          "ORIGINAL_BUILD_NOT_VERIFIED")
    result = invoke(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    check(result.returncode == 0 and result.stdout.strip() == SOURCE_COMMIT,
          "ORIGINAL_TAG_MISMATCH")
    result = invoke([str(NODE), str(ROOT / "scripts/rea.mjs"), "--version"],
                    cwd=ROOT)
    check(result.returncode == 0 and result.stdout.strip() == "6.8.0",
          "ORIGINAL_ENGINE_VERSION_MISMATCH")
    check((ROOT / "node_modules").is_symlink() and
          (ROOT / "node_modules").resolve() == (SHARED_DEP_ROOT / "node_modules").resolve(),
          "REUSE_ONLY_VERIFIED_DEPENDENCIES")
    original_lock = (ROOT / "package-lock.json").read_bytes()
    shared_lock = (SHARED_DEP_ROOT / "package-lock.json").read_bytes()
    check(original_lock == shared_lock, "DEPENDENCY_LOCK_MISMATCH")
    deps = invoke([str(NODE), "scripts/check-dependency-install.mjs"], cwd=ROOT)
    check(deps.returncode == 0, "EXISTING_DEPENDENCIES_FAIL_VERIFICATION")
    for name, wanted in EXPECTED_DIGESTS.items():
        path = ROOT / name
        check(path.is_file() and not path.is_symlink(),
              "ORIGINAL_COMPILED_MODULE_MISSING_OR_LINKED:" + name)
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        check(actual == wanted, "ORIGINAL_COMPILED_MODULE_DRIFT:" + name)
    OUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    OUT.chmod(0o700)
    print("REA_REPLAY_SOURCE=OFFICIAL_ORIGINAL_PINNED;commit=" + SOURCE_COMMIT,
          flush=True)
    print("REA_REPLAY_METHOD=GITHUB_ACTIONS_SSH_DIRECT_CLI_NO_MCP",
          flush=True)
    print("REA_REPLAY_PROVIDER_INSTALLS=ZERO", flush=True)
    print("REA_REPLAY_DEPENDENCIES=EXISTING_EXACT_LOCK_VERIFIED", flush=True)
    print("REA_REPLAY_COMPILED_HASHES=OFFICIAL_ORIGINAL_VERIFIED", flush=True)


def make_case(name, executable, args=(), **parameters):
    data = {"executable": executable}
    if args:
        data["arguments"] = list(args)
    data.update(parameters)
    return name, data


def python_children(count):
    # Reconstructed historical 8/30 fast-child profile; exact original
    # Python source text was not retained in the older MCP evidence.
    return (
        "import subprocess; "
        "p=[subprocess.Popen(['/usr/bin/true']) for _ in range(" +
        str(count) + ")]; "
        "r=[x.wait() for x in p]; "
        "print('REPLAY_CHILDREN=" + str(count) + " FAILS='+str(sum(bool(x) for x in r)))"
    )


def nested_children():
    return (
        "import subprocess; "
        "p=subprocess.Popen(['/usr/bin/python3','-c',"
        "'import subprocess; x=[subprocess.Popen([\"/usr/bin/true\"]) "
        "for _ in range(12)]; [p.wait() for p in x]']); "
        "print('NESTED_EXIT='+str(p.wait()))"
    )


def scenarios():
    cases = []
    cases.extend(make_case("bin-true-%02d" % i, "/bin/true")
                 for i in range(1, 7))
    cases.extend(make_case("usr-true-%02d" % i, "/usr/bin/true")
                 for i in range(1, 7))
    cases.extend(make_case("false-%02d" % i, "/usr/bin/false")
                 for i in range(1, 4))
    cases.extend(make_case("printf-%02d" % i, "/usr/bin/printf", ["REA_OK"])
                 for i in range(1, 4))
    cases.extend(make_case("children-8-%02d" % i, "/usr/bin/python3",
                           ["-c", python_children(8)])
                 for i in range(1, 17))
    cases.extend(make_case("children-30-%02d" % i, "/usr/bin/python3",
                           ["-c", python_children(30)])
                 for i in range(1, 21))
    cases.extend(make_case("children-12-%02d" % i, "/usr/bin/python3",
                           ["-c", python_children(12)])
                 for i in range(1, 5))
    cases.extend(make_case("nested-%02d" % i, "/usr/bin/python3",
                           ["-c", nested_children()])
                 for i in range(1, 3))
    cases.extend(make_case("child-python-%02d" % i, "/usr/bin/python3",
                           ["-c", "import subprocess; x=subprocess.run(['/usr/bin/true']); print('CHILD_EXIT='+str(x.returncode))"])
                 for i in range(1, 3))
    cases.extend(make_case("stderr-%02d" % i, "/usr/bin/python3",
                           ["-c", "import sys;print('REA_STDOUT');print('REA_STDERR',file=sys.stderr)"])
                 for i in range(1, 3))
    cases.extend(make_case("environment-%02d" % i, "/usr/bin/python3",
                           ["-c", "import os;print('REA_ENV='+str(os.getenv('REA_TEST_FLAG')))"],
                           environment={"REA_TEST_FLAG": "standalone"})
                 for i in range(1, 3))
    cases.extend(make_case("nonzero7-%02d" % i, "/usr/bin/python3",
                           ["-c", "import sys;print('INTENTIONAL_EXIT_7');sys.exit(7)"])
                 for i in range(1, 3))
    cases.extend(make_case("timeout-%02d" % i, "/usr/bin/sleep", ["5"],
                           timeout_ms=1000)
                 for i in range(1, 3))
    cases.extend(make_case("idle-timeout-%02d" % i, "/usr/bin/python3",
                           ["-c", "import time;print('START',flush=True);time.sleep(5)"],
                           timeout_ms=9000, idle_timeout_ms=900)
                 for i in range(1, 3))
    cases.extend(make_case("signal-term-%02d" % i, "/usr/bin/sleep", ["5"],
                           timeout_ms=9000,
                           events=[{"type": "signal", "at_ms": 400, "signal": "SIGTERM"}])
                 for i in range(1, 3))
    cases.extend(make_case("signal-kill-%02d" % i, "/usr/bin/sleep", ["5"],
                           timeout_ms=9000,
                           events=[{"type": "signal", "at_ms": 400, "signal": "SIGKILL"}])
                 for i in range(1, 3))
    cases.extend(make_case("resize-%02d" % i, "/usr/bin/python3",
                           ["-c", "import time;print('RESIZE',flush=True);time.sleep(.8)"],
                           terminal={"columns": 80, "rows": 24, "scrollback": 120},
                           timeout_ms=8000,
                           events=[{"type": "resize", "at_ms": 80, "columns": 100, "rows": 30}])
                 for i in range(1, 3))
    # A controlled comparison with extended settlement, not substituted for
    # default-window tests. The earlier system's default was left untouched.
    cases.extend(make_case("children-8-settle800-%02d" % i,
                           "/usr/bin/python3", ["-c", python_children(8)],
                           settle_ms=800) for i in range(1, 3))
    cases.extend(make_case("children-30-settle800-%02d" % i,
                           "/usr/bin/python3", ["-c", python_children(30)],
                           settle_ms=800) for i in range(1, 3))
    return cases


def save(name, suffix, data):
    (OUT / (name + "." + suffix)).write_text(
        data, encoding="utf-8", errors="replace")


def capture(name, scenario):
    save(name, "scenario.json", json.dumps(scenario, indent=2, sort_keys=True))
    env = dict(os.environ)
    env["HOME"] = str(OUT / "isolated-home")
    env["XDG_CACHE_HOME"] = str(OUT / "isolated-home" / ".cache")
    env["XDG_CONFIG_HOME"] = str(OUT / "isolated-home" / ".config")
    env["XDG_DATA_HOME"] = str(OUT / "isolated-home" / ".local" / "share")
    env["CI"] = "1"
    for key in ("REA_MCP_URL", "REA_MCP_CONFIG", "REA_ANALYSIS_PROVIDER"):
        env.pop(key, None)
    case_path = OUT / (name + ".scenario.json")
    try:
        p = subprocess.run(
            [str(NODE), "scripts/rea.mjs", "capture-process",
             str(case_path), "--json"],
            cwd=ROOT, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=55, check=False)
        stdout = p.stdout
        stderr = p.stderr
        rc = p.returncode
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        rc = 124
    save(name, "evidence.json", stdout)
    save(name, "stderr", stderr)
    try:
        evidence = json.loads(stdout)
        if isinstance(evidence, dict) and isinstance(evidence.get("result"), dict):
            evidence = evidence["result"]
        if not isinstance(evidence, dict):
            evidence = {}
    except (ValueError, TypeError):
        evidence = {}
    norm = evidence.get("normalized_result", {})
    if not isinstance(norm, dict):
        norm = {}
    cleanup = norm.get("cleanup", {})
    if not isinstance(cleanup, dict):
        cleanup = {}
    observed_exit = norm.get("exit", {})
    if not isinstance(observed_exit, dict):
        observed_exit = {}
    settlement = norm.get("settlement", {})
    if not isinstance(settlement, dict):
        settlement = {}
    cleanup_incomplete = "cleanup_incomplete" in (stdout + stderr).lower()
    group_ok = cleanup.get("owned_process_group") in ("verified", "cleaned")
    root_ok = cleanup.get("temporary_root") in ("removed", "cleaned")
    expected = 0
    if name.startswith("false"):
        expected = 1
    elif name.startswith("nonzero7"):
        expected = 7
    if name.startswith("timeout-"):
        exit_ok = observed_exit.get("reason") == "timeout"
    elif name.startswith("idle-timeout"):
        exit_ok = observed_exit.get("reason") == "idle_timeout"
    elif name.startswith("signal-"):
        sig = "SIGTERM" if name.startswith("signal-term") else "SIGKILL"
        observed_signal = observed_exit.get("signal")
        exit_ok = observed_signal in (sig, 15 if sig=="SIGTERM" else 9)
    else:
        exit_ok = observed_exit.get("code") == expected
    complete = (
        rc == 0 and bool(evidence) and group_ok and root_ok
        and exit_ok and not cleanup_incomplete
    )
    return {
        "case": name, "result": "PASS" if complete else "FAIL",
        "cli_exit": rc, "expected_exit": expected,
        "exit_observed": observed_exit,
        "cleanup": cleanup,
        "settlement": settlement.get("state"),
        "cleanup_incomplete": cleanup_incomplete,
        "evidence_sha256": hashlib.sha256(stdout.encode()).hexdigest()
    }


def main():
    preflight()
    (OUT / "isolated-home").mkdir(mode=0o700, parents=True, exist_ok=True)
    cases = scenarios()
    results = []
    started = time.monotonic()
    for name, scenario in cases:
        obj = capture(name,scenario)
        results.append(obj)
        print("REA_REPLAY_CASE=" + name + ";result=" + obj["result"] +
              ";cleanup_incomplete=" + str(obj["cleanup_incomplete"]).lower() +
              ";settlement=" + str(obj["settlement"]), flush=True)
    # Tests of concurrent separate CLI captures follow serial reproductions.
    for batch in range(1, 4):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(capture, "parallel-%02d-%s" % (batch, postfix),
                            make_case("", "/usr/bin/python3",
                                      ["-c", python_children(30)])[1])
                for postfix in ("a","b")
            ]
            for future in concurrent.futures.as_completed(futures):
                obj = future.result()
                results.append(obj)
                print("REA_REPLAY_CASE=" + obj["case"] +
                      ";result=" + obj["result"] +
                      ";cleanup_incomplete=" + str(obj["cleanup_incomplete"]).lower(),
                      flush=True)
    failures = [r for r in results if r["result"]!="PASS"]
    cleanup_failures = [r for r in results if r["cleanup_incomplete"]]
    summary = {
        "target": "original-repo-only",
        "git_commit": SOURCE_COMMIT,
        "mechanism": "GitHub Actions SSH original CLI; no MCP or external vendor install",
        "historical_replay": "equivalent known profiles; exact old Python source and all MCP call fields not fully retained",
        "test_count": len(results),
        "passed": len(results)-len(failures),
        "failed": len(failures),
        "cleanup_incomplete": len(cleanup_failures),
        "duration_seconds": round(time.monotonic()-started,2),
        "failed_cases": failures,
        "cases": results
    }
    save("summary", "json", json.dumps(summary,sort_keys=True,indent=2))
    print("REA_REPLAY_TOTAL=" + str(summary["test_count"]), flush=True)
    print("REA_REPLAY_PASS=" + str(summary["passed"]), flush=True)
    print("REA_REPLAY_FAIL=" + str(summary["failed"]), flush=True)
    print("REA_REPLAY_CLEANUP_INCOMPLETE=" + str(summary["cleanup_incomplete"]), flush=True)
    print("REA_REPLAY_EVIDENCE_DIR=" + str(OUT), flush=True)
    print("REA_REPLAY_ACCEPTANCE=" + ("PASS" if not failures else "FAIL"), flush=True)
    if failures:
        sys.exit(31)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("REA_REPLAY_PRECONDITION_OR_RUN_FAIL=" + type(error).__name__ +
              ":" + str(error)[:220], flush=True)
        sys.exit(32)
