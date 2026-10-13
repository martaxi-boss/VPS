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


def fresh():
    result = fixture()
    result["audit"]["revision"] = UPDATED
    result["audit"]["findings"] = result["audit"]["findings"][-1:]
    result["audit"]["work_items"] = result["audit"]["work_items"][-1:]
    del result["audit"]["work_items"][0]["depends_on"]
    return result


class PhaseContinuationTests(unittest.TestCase):
    def setUp(self):
        self.original = enc(fixture())
        self.updated = enc(fresh())

    def test_owner_dag_holds_second_phase_until_revision_changes(self):
        scope = phases.scope_for_phase(self.original, 2)
        self.assertEqual(scope["phase_count"], 2)
        self.assertEqual(scope["task_ids"], ["correct-three"])
        self.assertEqual(scope["paths"], ["docs/three.md"])
        self.assertNotIn("docs/one.md", scope["paths"])
        request = phases.new_order(self.original, 2, UPDATED)
        self.assertIn("TARGET_REPOSITORY=" + phases.TARGET, request)
        self.assertIn(UPDATED, request)
        self.assertIn("correct-three", request)
        self.assertNotIn("Project Leader canonical", request)

    def test_current_reaudit_may_dispatch_exact_held_phase_only(self):
        result = phases.validate_new_plan(self.updated, self.original, 2, UPDATED)
        self.assertEqual(result["audited_sha"], UPDATED)
        self.assertEqual(result["phase"], 2)
        self.assertEqual(result["original_phase_count"], 2)
        self.assertEqual(result["remaining_phases"], 1)
        self.assertEqual(result["task_ids"], ["correct-three"])
        self.assertEqual(result["workers"], 1)
        self.assertEqual(result["mode"], "serial")

    def test_cannot_repeat_first_phase_or_invent_later_number(self):
        for n in (0, 1, 3, -1, True, "2", 1000):
            with self.subTest(phase=n), self.assertRaises(phases.PhaseContinuationError):
                phases.scope_for_phase(self.original, n)

    def test_wrong_current_git_head_is_rejected_before_worker(self):
        with self.assertRaisesRegex(phases.PhaseContinuationError, "revision"):
            phases.validate_new_plan(self.updated, self.original, 2, ORIGINAL)
        with self.assertRaises(phases.PhaseContinuationError):
            phases.new_order(self.original, 2, "c"*39)

    def test_model_cannot_expand_scope_or_change_ids(self):
        cases = []
        p = fresh()
        p["audit"]["work_items"][0]["paths"] = ["docs/one.md"]
        cases.append(p)
        p = fresh()
        p["audit"]["work_items"][0]["id"] = "new-task"
        cases.append(p)
        p = fresh()
        p["audit"]["findings"][0]["paths"] = ["docs/one.md"]
        cases.append(p)
        p = fresh()
        p["audit"]["work_items"][0]["depends_on"] = ["correct-one"]
        cases.append(p)
        for item in cases:
            with self.subTest(kind=item["audit"]["work_items"][0]), \
                 self.assertRaises(phases.PhaseContinuationError):
                phases.validate_new_plan(enc(item), self.original, 2, UPDATED)

    def test_corrupt_owner_audit_is_rejected(self):
        with self.assertRaises(phases.PhaseContinuationError):
            phases.scope_for_phase("not-encoded", 2)
        p = fixture()
        p["target_repository"] = "martaxi-boss/VPS"
        with self.assertRaises(phases.PhaseContinuationError):
            phases.scope_for_phase(enc(p), 2)
        p = fixture()
        p["audit"]["work_items"][2]["depends_on"] = ["unknown"]
        with self.assertRaises(phases.PhaseContinuationError):
            phases.scope_for_phase(enc(p), 2)



class PhaseWorkflowGuards(unittest.TestCase):
    def test_held_phases_use_existing_coordinator_and_owner_route(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[2]
        owner = (root / ".github/workflows/coordinator-owner-order.yml").read_text()
        child = (root / ".github/workflows/coordinator-phase-cycle.yml").read_text()
        self.assertIn("github.event.issue.user.login == github.repository_owner", child)
        self.assertIn("uses: ./.github/workflows/agent-switch.yml", child)
        self.assertIn("ops/coordinator-smoke-remote.sh", child)
        self.assertIn("ops/coordinator_supervisor.py", child)
        self.assertNotIn("codex exec", child)
        self.assertNotIn("project-leader-rules.md", child)
        self.assertIn("TARGET_HEAD_CHANGED_REAUDIT_REQUIRED", child)
        self.assertIn("OWNER_ISSUE_NO_LONGER_AUTHORIZED", child)
        self.assertIn("StrictHostKeyChecking=yes", child)
        self.assertNotIn("StrictHostKeyChecking=no", child)
        dollar = chr(36)
        for phase in range(2, 9):
            prior = "supervise" if phase == 2 else "phase_" + str(phase-1)
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
        from ops import coordinator_supervisor, codex_resource_policy
        root = Path(__file__).resolve().parents[2]
        router = (root / ".github/workflows/agent-switch.yml").read_text()
        executor = (root / ".github/workflows/codex-autonomous.yml").read_text()
        remote = (root / "ops/codex-autonomous-remote.sh").read_text()
        self.assertEqual(router.count("inputs.phase_number > 1"), 5)
        for phase in range(2, 9):
            self.assertTrue(codex_resource_policy.JOB_PATTERN.fullmatch(
                "38398020440-1-p" + str(phase) + "-1"))
            self.assertTrue(coordinator_supervisor._expected_branch(
                "codex/issue-181-38398020440-1-p" + str(phase) + "-1",
                181, 38398020440, phase))
            self.assertFalse(coordinator_supervisor._expected_branch(
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
            tag = next((x for x in ("PY_SCOPE", "PY_VALIDATE")
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
        self.assertEqual(count, 2)

if __name__ == "__main__":
    unittest.main()
