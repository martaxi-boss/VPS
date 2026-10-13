"""No-model Project Leader Human Gate wire-format and injection regressions."""
import json
import tempfile
import unittest
from pathlib import Path

from ops import human_gate_protocol as gate


def report(reason="EXCLUSIVE_HUMAN_INTERVENTION",
           summary="Confirmação de identidade pendente na plataforma.",
           action="Confirma a identidade na própria plataforma e responde a este pedido."):
    payload = json.dumps({"reason": reason, "summary": summary,
                          "owner_action": action}, ensure_ascii=False)
    return ("Trabalho suspenso apenas nesta tarefa.\n" + gate.START +
            "\n" + payload + "\n" + gate.END + "\n").encode("utf-8")


class HumanGateWireTests(unittest.TestCase):
    def test_true_human_gate_is_strict_and_unchanged(self):
        p = gate.parse_report(report())
        self.assertEqual(p["reason"], "EXCLUSIVE_HUMAN_INTERVENTION")
        self.assertIn("própria plataforma", p["owner_action"])

    def test_material_decision_is_existing_canonical_reason(self):
        self.assertEqual(gate.parse_report(report(
            reason="NEW_UNCOVERED_MATERIAL_DECISION"))["reason"],
            "NEW_UNCOVERED_MATERIAL_DECISION")

    def test_normal_errors_and_recovery_are_not_human_gates(self):
        for ordinary in (b"FAILED: CI missing", b"Found a bug; I fixed it.",
                         b"Human Gate is NOT required here.",
                         b"Git conflict corrected; re-running tests"):
            self.assertIsNone(gate.parse_report(ordinary))

    def test_malformed_marker_fails_closed(self):
        for malformed in (
            b"PROJECT_LEADER_HUMAN_GATE_V1_BEGIN\nbroken\n" +
            gate.END.encode(),
            report() + b"another message",
            report() + report(),
            report().replace(b"PROJECT_LEADER_HUMAN_GATE_V1_END", b"bad"),
        ):
            with self.subTest(malformed=malformed[:40]), self.assertRaises(
                gate.GateProtocolError
            ):
                gate.parse_report(malformed)

    def test_rejects_secret_injection_and_noncanonical_categories(self):
        for value in ("password=abcdefghijk", "ghp_abcdefghijklmnopqr",
                      "-----BEGIN PRIVATE KEY-----"):
            with self.subTest(value=value), self.assertRaises(
                gate.GateProtocolError
            ):
                gate.parse_report(report(summary=value))
        with self.assertRaises(gate.GateProtocolError):
            gate.parse_report(report(reason="TECHNICAL_ERROR"))

    def test_long_value_invalid(self):
        with self.assertRaises(gate.GateProtocolError):
            gate.parse_report(report(action="A" * 560))

    def test_private_file_and_no_gate_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plain = root / "plain.md"
            plain.write_text("CI succeeded")
            target = root / "gate.json"
            self.assertEqual(gate.run_cli(["detect", str(plain), str(target)]), 10)
            self.assertFalse(target.exists())
            plain.write_bytes(report())
            self.assertEqual(gate.run_cli(["detect", str(plain), str(target)]), 0)
            self.assertEqual(json.loads(target.read_text())["reason"],
                             "EXCLUSIVE_HUMAN_INTERVENTION")
            with self.assertRaises(gate.GateProtocolError):
                gate.run_cli(["detect", str(plain), str(target)])


if __name__ == "__main__":
    unittest.main()
