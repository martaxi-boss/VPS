"""Offline acceptance of bounded owner-authorized later phases; no models."""
import base64
import json
import unittest

from ops import coordinator_phase_continuation as phases

ORIGINAL = "a" * 40
UPDATED = "b" * 40


def fixture():
    return {
        "target_repository": phases.TARGET,
        "audit": {
            "revision": ORIGINAL,
            "findings": [
                {"id": "one", "severity": "low", "paths": ["docs/one.md"],
                 "observation": "First inspected guide contains an obsolete example"},
                {"id": "two", "severity": "low", "paths": ["docs/two.md"],
                 "observation": "Second inspected guide uses a stale instruction"},
                {"id": "three", "severity": "medium", "paths": ["docs/three.md"],
                 "observation": "Third inspected guide depends on both earlier changes"},
            ],
            "work_items": [
                {"id": "correct-one", "paths": ["docs/one.md"],
                 "finding_ids": ["one"],
                 "task": "Correct the verified first guide documentation"},
                {"id": "correct-two", "paths": ["docs/two.md"],
                 "finding_ids": ["two"],
                 "task": "Correct the verified second guide documentation"},
                {"id": "correct-three", "paths": ["docs/three.md"],
                 "finding_ids": ["three"], "depends_on": ["correct-one", "correct-two"],
                 "task": "Update the third guide after both predecessor guides are merged"},
            ],
        },
    }


def enc(value):
    return base64.b64encode(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).decode()


class PhaseContinuationTests(unittest.TestCase):
    def setUp(self):
        self.original = enc(fixture())

    def test_dispatch_next_phase_without_any_coordinator_reaudit(self):
        scope = phases.scope_for_phase(self.original, 2)
        self.assertEqual(scope["phase_count"], 2)
        self.assertEqual(scope["task_ids"], ["correct-three"])
        self.assertEqual(scope["paths"], ["docs/three.md"])
        self.assertEqual(scope["reasoning_by_task"]["correct-three"], "medium")
        next_phase = phases.prepared_phase(self.original, 2, UPDATED)
        self.assertEqual(next_phase["audited_sha"], UPDATED)
        self.assertEqual(next_phase["phase"], 2)
        self.assertEqual(next_phase["remaining_phases"], 1)
        self.assertEqual(next_phase["task_ids"], ["correct-three"])
        self.assertEqual(next_phase["workers"], 1)
        self.assertEqual(next_phase["mode"], "serial")
        clean = json.loads(base64.b64decode(next_phase["coordinator_plan_b64"]))
        self.assertEqual(clean["audit"]["revision"], UPDATED)
        self.assertEqual(clean["audit"]["work_items"][0]["id"], "correct-three")
        self.assertEqual(clean["audit"]["findings"][0]["id"], "three")
        self.assertNotIn("depends_on", clean["audit"]["work_items"][0])
        self.assertNotIn("docs/one.md", next_phase["paths"])

    def test_prepared_phase_is_deterministic_and_scoped(self):
        first = phases.prepared_phase(self.original, 2, UPDATED)
        second = phases.prepared_phase(self.original, 2, UPDATED)
        self.assertEqual(first, second)
        value = json.loads(base64.b64decode(first["coordinator_plan_b64"]))
        self.assertEqual(len(value["audit"]["work_items"]), 1)
        self.assertEqual(len(value["audit"]["findings"]), 1)
        self.assertNotIn("correct-two", str(value))

    def test_cannot_repeat_first_or_invent_later_phase(self):
        for n in (0, 1, 3, -1, True, "2", 1000):
            with self.subTest(phase=n), self.assertRaises(phases.PhaseContinuationError):
                phases.scope_for_phase(self.original, n)

    def test_invalid_current_sha_refused_before_worker(self):
        for invalid in ("", "bad", "c" * 39, "G" * 40, None):
            with self.subTest(invalid=invalid), self.assertRaises(phases.PhaseContinuationError):
                phases.prepared_phase(self.original, 2, invalid)

    def test_cannot_expand_original_task_paths_or_ids(self):
        original = fixture()
        original["audit"]["work_items"][2]["paths"] = ["docs/three.md", "../.env"]
        with self.assertRaises(phases.PhaseContinuationError):
            phases.prepared_phase(enc(original), 2, UPDATED)
        original = fixture()
        original["audit"]["work_items"][2]["id"] = "correct-one"
        with self.assertRaises(phases.PhaseContinuationError):
            phases.prepared_phase(enc(original), 2, UPDATED)

    def test_corrupt_owner_audit_refused(self):
        with self.assertRaises(phases.PhaseContinuationError):
            phases.prepared_phase("not-encoded", 2, UPDATED)
        p = fixture()
        p["target_repository"] = "untrusted-owner/VPS"
        with self.assertRaises(phases.PhaseContinuationError):
            phases.prepared_phase(enc(p), 2, UPDATED)
        p = fixture()
        p["audit"]["work_items"][2]["depends_on"] = ["unknown"]
        with self.assertRaises(phases.PhaseContinuationError):
            phases.prepared_phase(enc(p), 2, UPDATED)


class PhaseWorkflowGuards(unittest.TestCase):
    def test_held_phases_use_original_owner_plan_without_coordinator(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[2]
        owner = (root / ".github/workflows/coordinator-owner-order.yml").read_text()
        child = (root / ".github/workflows/coordinator-phase-cycle.yml").read_text()
        self.assertIn("github.event.issue.user.login == github.repository_owner", child)
        self.assertIn("uses: ./.github/workflows/agent-switch.yml", child)
        self.assertNotIn("ops/coordinator-smoke-remote.sh", child)
        self.assertIn("ops.coordinator_phase_continuation import prepared_phase", child)
        self.assertNotIn("sshpass", child)
        self.assertIn("OWNER_DAG_NEXT_PHASE_VERIFIED_WITHOUT_COORDINATOR_AI", child)
        self.assertIn("ops/coordinator_pr_integrator.py", child)
        self.assertNotIn("codex exec", child)
        self.assertNotIn("project-leader-rules.md", child)
        self.assertIn("VERIFIED_PREVIOUS_MERGE_HEAD_CHANGED", child)
        self.assertIn("OWNER_ISSUE_UNAUTHORIZED", child)
        self.assertNotIn("StrictHostKeyChecking=yes", child)
        self.assertNotIn("StrictHostKeyChecking=no", child)
        dollar = chr(36)
        for phase in range(2, 9):
            prior = "integrate" if phase == 2 else "phase_" + str(phase-1)
            self.assertIn("  phase_" + str(phase) + ":", owner)
            self.assertIn("    needs: [plan, " + prior + "]", owner)
            self.assertIn("      phase_number: " + str(phase), owner)
            expected = ("      previous_merged_sha: " + dollar +
                        "{{ needs." + prior + ".outputs.merged_sha }}")
            self.assertIn(expected, owner)
        self.assertIn("phase_status: " + dollar +
                      "{{ steps.terminal.outputs.phase_status }}", owner)

    def test_phase_worker_ids_cannot_repeat_or_expand_owner_authority(self):
        from pathlib import Path
        from ops import coordinator_pr_integrator, codex_resource_policy
        root = Path(__file__).resolve().parents[2]
        router = (root / ".github/workflows/agent-switch.yml").read_text()
        executor = (root / ".github/workflows/codex-autonomous.yml").read_text()
        remote = (root / "ops/codex-autonomous-remote.sh").read_text()
        self.assertEqual(router.count("inputs.phase_number > 1"), 5)
        for phase in range(2, 9):
            self.assertTrue(codex_resource_policy.JOB_PATTERN.fullmatch(
                "38398020440-1-p" + str(phase) + "-1"))
            self.assertTrue(coordinator_pr_integrator._expected_branch(
                "codex/issue-181-38398020440-1-p" + str(phase) + "-1",
                181, 38398020440, phase))
            self.assertFalse(coordinator_pr_integrator._expected_branch(
                "codex/issue-181-38398020440-1-p" + str(phase) + "-1",
                181, 38398020440, 1))
        for suffix in ("p1-1", "p9-1", "p2-3", "p2-x", "p2-1/../../x"):
            self.assertFalse(codex_resource_policy.JOB_PATTERN.fullmatch(
                "38398020440-1-" + suffix))
        self.assertIn("p[2-8]-[12]", executor)
        self.assertIn("p[2-8]-[12]", remote)

    def test_inline_python_contract_compiles_without_secrets_on_prs(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/coordinator-phase-cycle.yml").read_text()
        self.assertIn("on:\n  workflow_call:", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("repository_dispatch:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn(chr(92) + chr(36) + "{{", workflow)
        lines = workflow.splitlines()
        count = 0
        for i, row in enumerate(lines):
            tag = next((x for x in ("PY_PREPARE",)
                        if "<<'" + x + "'" in row), None)
            if tag is None:
                continue
            code = []
            for row2 in lines[i+1:]:
                if row2.strip() == tag:
                    break
                code.append(row2)
            else:
                self.fail("Missing Python heredoc terminator")
            indents = [len(line) - len(line.lstrip()) for line in code if line.strip()]
            self.assertTrue(indents)
            indent = min(indents)
            compile("\n".join(line[indent:] for line in code), "<phase-cycle>", "exec")
            count += 1
        self.assertEqual(count, 1)


class PrivateCoordinatorPlanArchiveTests(unittest.TestCase):
    """A staged Android PR must not make the original Owner DAG disappear."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        from ops import coordinator_plan_archive as archive
        self.archive = archive
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name) / "archive"
        self.job = "5857350401-1"
        self.original = enc(fixture())
        self.target = phases.TARGET

    def tearDown(self):
        self.directory.cleanup()

    def _save(self):
        return self.archive.archive_verified_plan(
            self.original, self.root,
            job=self.job, target=self.target, audited_sha=ORIGINAL,
        )

    def _load(self):
        return self.archive.load_original_plan(
            self.root, job=self.job, target=self.target, audited_sha=ORIGINAL,
        )

    def test_private_original_survives_disposable_coordinator_workspace(self):
        import os
        import stat
        from pathlib import Path
        result = self._save()
        self.assertEqual(result["phase_count"], 2)
        self.assertEqual(result["audited_sha"], ORIGINAL)
        self.assertEqual(self._load(), self.original)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        archive_file = self.root / (self.job + ".json")
        self.assertEqual(stat.S_IMODE(archive_file.stat().st_mode), 0o600)
        self.assertFalse(any(p.name.endswith(".tmp") for p in self.root.iterdir()))
        with self.assertRaises(self.archive.PrivatePlanError):
            self._save()  # even an identical replay cannot overwrite
        self.assertEqual(self._load(), self.original)

    def test_tampered_archive_and_stale_scope_fail_closed(self):
        import json
        self._save()
        path = self.root / (self.job + ".json")
        record = json.loads(path.read_text())
        record["phase_count"] += 1
        path.write_text(json.dumps(record))
        with self.assertRaises(self.archive.PrivatePlanError):
            self._load()
        with self.assertRaises(self.archive.PrivatePlanError):
            self.archive.load_original_plan(
                self.root, job=self.job, target=self.target,
                audited_sha=UPDATED,
            )
        with self.assertRaises(self.archive.PrivatePlanError):
            self.archive.load_original_plan(
                self.root, job=self.job, target="martaxi-boss/VPS",
                audited_sha=ORIGINAL,
            )

    def test_public_archive_symlink_and_bad_provenance_refused(self):
        import os
        from pathlib import Path
        with self.assertRaises(self.archive.PrivatePlanError):
            self.archive.archive_verified_plan(
                self.original, self.root,
                job="../evil", target=self.target, audited_sha=ORIGINAL,
            )
        with self.assertRaises(self.archive.PrivatePlanError):
            self.archive.archive_verified_plan(
                self.original, self.root,
                job=self.job, target=self.target, audited_sha=UPDATED,
            )
        self.root.mkdir(mode=0o700)
        self.root.chmod(0o755)
        with self.assertRaises(self.archive.PrivatePlanError):
            self._save()
        self.root.chmod(0o700)
        link = Path(self.directory.name) / "link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(self.archive.PrivatePlanError):
            self.archive.archive_verified_plan(
                self.original, link,
                job=self.job, target=self.target, audited_sha=ORIGINAL,
            )
        self.assertFalse(list(self.root.glob("*.json")))

    def test_existing_workflow_persists_only_audited_original_without_dispatch(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[2]
        shell = (root / "ops/coordinator-smoke-remote.sh").read_text()
        self.assertIn('"$root/.verified-plans" "$job"', shell)
        self.assertIn("from ops.coordinator_plan_archive import archive_verified_plan", shell)
        self.assertIn('base64.b64encode(raw_audit).decode("ascii")', shell)
        self.assertIn('trap cleanup_private_workspace EXIT', shell)
        start = shell.index("<<'PY' || refuse PLAN_RECHECK")
        source = shell[start + len("<<'PY' || refuse PLAN_RECHECK"):].split("\nPY\n")[0]
        compile(source, "<private-coordinator-proof>", "exec")

if __name__ == "__main__":
    unittest.main()
