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


if __name__ == "__main__":
    unittest.main()
