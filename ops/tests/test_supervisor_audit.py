#!/usr/bin/env python3
"""Pure offline Supervisor audit and passivity tests; no bot/model/secrets."""
import hashlib
import unittest

from ops import supervisor_audit as audit


class SupervisorAuditTests(unittest.TestCase):
    def test_report_integrity_and_no_interpretation_of_model_human_gate(self):
        report = "HUMAN_GATE: conta do Owner necessária\nPasso do trabalhador."
        result = audit.worker_report(
            issue="181",
            run_url="https://github.com/martaxi-boss/VPS/actions/runs/1234",
            worker="p2-1", status="WORKER_REPORT_RECEIVED", report=report)
        self.assertIn("Project Leader", result)
        self.assertIn("fase 2, trabalhador 1", result)
        self.assertIn("ainda sem certificação final", result)
        checksum = hashlib.sha256(report.encode()).hexdigest()[:16]
        self.assertIn(checksum, result)
        # The model's instruction text is NOT promoted to authority.
        self.assertNotIn("HUMAN_GATE: conta do Owner", result)
        self.assertIn("não os altera nem os valida", result)

    def test_worker_report_rejected_when_missing_or_too_large(self):
        for report in ("", " " * 200, "X" * 70000):
            with self.subTest(report_size=len(report)):
                with self.assertRaises(RuntimeError):
                    audit.worker_report(issue="181", run_url="", worker="1",
                                        status="WORKER_REPORT_RECEIVED",
                                        report=report)

    def test_run_is_only_claimed_verified_on_expected_repo_and_sha_like_id(self):
        valid = audit.worker_report(
            issue="181", run_url="https://github.com/martaxi-boss/VPS/actions/runs/123",
            worker="2", status="WORKER_REPORT_RECEIVED", report="received")
        self.assertIn("Tarefa #181; execução GitHub", valid)
        other = audit.worker_report(
            issue="181", run_url="https://github.com/attacker/VPS/actions/runs/123",
            worker="2", status="WORKER_REPORT_RECEIVED", report="received")
        self.assertIn("Proveniência não verificada", other)
        with self.assertRaises(RuntimeError):
            audit.worker_report(issue="181", run_url="", worker="evil\nthing",
                                status="WORKER_REPORT_RECEIVED", report="received")

    def test_final_failed_audit_is_not_an_owner_gate_or_secret_replay(self):
        result = audit.pipeline(
            issue="181", run_url="https://github.com/martaxi-boss/VPS/actions/runs/123",
            worker="1", status="FAILED", steps={
                "CODEX_OUTCOME": "failure",
                "STAGE_OUTCOME": "success",
                "PUBLISH_OUTCOME": "skipped",
                "ARTIFACTS_OUTCOME": "failure\nINJECTED_RUN_AGAIN"})
        self.assertIn("ATENÇÃO", result)
        self.assertIn("Etapas autenticadas: 3", result)
        self.assertNotIn("INJECTED_RUN_AGAIN", result)
        self.assertNotIn("HUMAN_GATE:", result)
        self.assertNotIn("POST", result)

    def test_final_claim_of_success_with_failed_step_is_mismatch_not_pass(self):
        result = audit.pipeline(issue="181", run_url="", worker="p2-2",
                                status="MERGED", steps={"CODEX_OUTCOME": "failure"})
        self.assertIn("INCONSISTÊNCIA", result)
        self.assertIn("não certificar sucesso", result)

    def test_staged_pr_is_not_certified_as_merged(self):
        result = audit.pipeline(issue="181", run_url="", worker="1",
                                status="PR_STAGED", steps={"CODEX_OUTCOME": "success"})
        self.assertIn("ainda não integrada", result)

    def test_observer_audits_authenticated_events_without_inventing_commands(self):
        event = ("👁️ Supervisor: Coordenador — falhou.\n"
                 "https://github.com/martaxi-boss/VPS/actions/runs/123\n"
                 "Observação de estado; sem ordens aos trabalhadores.")
        result = audit.observation(event, source="event")
        self.assertIn("AUDITORIA OPERACIONAL", result)
        self.assertIn("Atenção", result)
        self.assertIn("Coordenador — falhou", result)
        self.assertIn("nenhuma ordem", result)

    def test_observer_requires_expected_source_and_repository(self):
        for source, message in (
            ("event", "PRIVATE SECRET NO LINK"),
            ("unknown", "https://github.com/martaxi-boss/VPS/issues/181"),
        ):
            with self.subTest(source=source):
                with self.assertRaises(RuntimeError):
                    audit.observation(message, source=source)

    def test_private_owner_query_can_be_audited_without_any_worker(self):
        result = audit.observation("Execuções ativas: 2", source="owner_query")
        self.assertIn("Consulta privada autorizada", result)
        self.assertIn("Execuções ativas: 2", result)

    def test_transport_rejects_oversize_or_control_characters(self):
        for value in ("", " " * 4, "abc\n\u0000def", "A" * 4001):
            with self.assertRaises(RuntimeError):
                audit.check_delivery(value)
        self.assertEqual(audit.check_delivery("ok\ntexto"), "ok\ntexto")

    def test_auditor_has_no_dispatch_or_human_gate_classifier(self):
        import inspect
        source = inspect.getsource(audit)
        self.assertNotIn('github("POST"', source)
        self.assertNotIn('create_audit(', source)
        self.assertNotIn('dispatch(', source)
        self.assertNotIn('resume(', source)


if __name__ == "__main__":
    unittest.main()
