#!/usr/bin/env python3
"""Read-only canonical Project Leader loader for each isolated Codex task.

Only the pinned git object database is used. This does not grant Codex new
permissions, run Project Leader code, or mutate either repository.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

SOURCE = "martaxi-boss/Project-leader"
TARGETS = {"martaxi-boss/VPS", SOURCE}
REQUIRED_CONTROLS = {
    "exact_target_and_revision_revalidated_before_consequential_transition",
    "required_ci_validation_and_evidence_must_pass",
    "supervisor_audits_before_and_after_consequential_transition",
    "transition_authorization_and_result_are_durable",
}


class BootstrapError(ValueError):
    pass


def git(repo, *args):
    p = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, check=False, text=True, timeout=15,
    )
    if p.returncode != 0:
        raise BootstrapError("Unable to read pinned canonical git object")
    return p.stdout


def read_at_revision(repo, sha, path):
    if path.startswith("/") or ".." in Path(path).parts:
        raise BootstrapError("Invalid canonical path")
    return git(repo, "show", sha + ":" + path)


def load_runtime(repo, target, target_sha):
    if target not in TARGETS:
        raise BootstrapError("Unsupported target repository")
    if not re.fullmatch(r"[0-9a-f]{40}", target_sha):
        raise BootstrapError("Malformed target SHA")
    if git(repo, "symbolic-ref", "--short", "HEAD").strip() != "main":
        raise BootstrapError("Canonical repository is not on main")
    sha = git(repo, "rev-parse", "HEAD").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise BootstrapError("Malformed canonical revision")
    if target == SOURCE and sha != target_sha:
        raise BootstrapError("Target Project Leader checkout and canonical revision differ")

    try:
        manifest = json.loads(read_at_revision(
            repo, sha, "plugins/project-leader/plugin.json"))
        authority = json.loads(read_at_revision(
            repo, sha, "projects/standing-authority.json"))
        skill = read_at_revision(
            repo, sha, "plugins/project-leader/skills/project-leader/SKILL.md")
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise BootstrapError("Invalid canonical runtime payload") from exc

    version = manifest.get("version")
    if manifest.get("name") != "project-leader" or not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise BootstrapError("Incompatible Project Leader plugin manifest")
    if not skill.startswith("---\n") or "\nname: project-leader\n" not in skill[:500]:
        raise BootstrapError("Incorrect canonical Project Leader Skill")
    for anchor in ("CANONICAL_RUNTIME_BOOTSTRAP", "CAPABILITY_AND_RESULT_TRUTH",
                   "MINIMAL_COORDINATION_BUDGET", "Supervisor", "Human Gate"):
        if anchor not in skill:
            raise BootstrapError("Incomplete Project Leader Skill: " + anchor)

    if authority.get("source") != "STANDING_OWNER_GRANT" or authority.get("runtime_scope") != "PROJECT_LEADER_SKILL_RUNTIME" or authority.get("project_isolation") != "ONE_MUTABLE_TARGET_REPOSITORY_PER_TASK":
        raise BootstrapError("Unexpected standing-authority binding")
    controls = authority.get("required_controls")
    if not isinstance(controls, list) or not REQUIRED_CONTROLS.issubset(set(controls)):
        raise BootstrapError("Canonical standing-authority controls are missing")

    metadata = {
        "loader_version": 1,
        "source_repository": SOURCE,
        "canonical_revision": sha,
        "plugin_version": version,
        "target_repository": target,
        "target_revision": target_sha,
        "mode": "PINNED_CANONICAL_SKILL",
    }
    instructions = (
        "PROJECT LEADER CANONICAL CONTROL: PINNED AND VERIFIED\n"
        + "RUNTIME_CANONICAL_REVISION=" + sha + "\n"
        + "PROJECT_LEADER_VERSION=" + version + "\n"
        + "TARGET_REPOSITORY=" + target + "\n"
        + "TARGET_REVISION=" + target_sha + "\n\n"
        + "Apply the following canonical Project Leader Skill throughout this "
          "bounded Codex implementation. Treat Supervisor, Builder, and Recovery "
          "Guardian as internal decision capabilities, not fictitious external "
          "agents. Report what actually ran. Do not assume that having the Skill "
          "or standing-authority file grants GitHub/VPS production permissions.\n"
        + "The trusted publisher independently enforces scope, protected paths, "
          "CI and consequential merge controls. A protected/material action "
          "not executable through this route must remain pending; do not bypass "
          "the gate, fake approval, or claim completion.\n\n"
        + "BEGIN PINNED CANONICAL PROJECT LEADER SKILL\n"
        + skill.rstrip() + "\n"
        + "END PINNED CANONICAL PROJECT LEADER SKILL\n"
    )
    return instructions, metadata


def main():
    if len(sys.argv) != 6:
        raise BootstrapError(
            "Usage: bootstrap.py CANONICAL_CHECKOUT TARGET_REPO TARGET_SHA PROMPT_PATH METADATA_PATH")
    repo, target, target_sha, prompt_path, metadata_path = sys.argv[1:]
    prompt, metadata = load_runtime(Path(repo), target, target_sha)
    # Outputs are the current job's private workspace, never the repo checkout.
    Path(prompt_path).write_text(prompt, encoding="utf-8")
    Path(metadata_path).write_text(
        json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8")
    print("PROJECT_LEADER_RUNTIME_PIN=" + metadata["canonical_revision"])
    print("PROJECT_LEADER_RUNTIME_VERSION=" + metadata["plugin_version"])
    print("PROJECT_LEADER_RUNTIME_LOADED=PASS")


if __name__ == "__main__":
    try:
        main()
    except (BootstrapError, OSError, subprocess.TimeoutExpired) as exc:
        print("PROJECT_LEADER_RUNTIME_BOOTSTRAP=FAIL: " + str(exc), file=sys.stderr)
        sys.exit(13)
