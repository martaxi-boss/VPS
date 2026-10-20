#!/usr/bin/env python3
"""Read-only live Supervisor contracts; all GitHub and Telegram I/O mocked."""
import os
from io import StringIO
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ops import supervisor_live as live


class SupervisorLiveTests(unittest.TestCase):
    def test_quota_observer_has_one_canonical_workflow_identity(self):
        root = Path(__file__).resolve().parents[2]
        quota = (root / ".github/workflows/codex-quota-watch.yml").read_text()
        gateway = (root / ".github/workflows/telegram-codex-gateway.yml").read_text()
        name = "Supervisor - Real ChatGPT quota watch (Owner notifications only)"
        self.assertEqual(quota.splitlines()[0], "name: " + name)
        self.assertIn('      - "' + name + '"', gateway)
        self.assertEqual(live.WORKFLOWS[name], "Vigilância da quota real")
        self.assertNotIn("Codex quota continuation (Owner checkpoints only)", gateway)
        self.assertNotIn("Codex quota continuation (Owner checkpoints only)", live.WORKFLOWS)

    def test_no_status_fanout_per_workflow_start(self):
        root = Path(__file__).resolve().parents[2]
        gateway = (root / ".github/workflows/telegram-codex-gateway.yml").read_text()
        listener = gateway.split("  workflow_run:", 1)[1].split("  pull_request:", 1)[0]
        self.assertIn("types: [completed]", listener)
        self.assertNotIn("types: [requested, in_progress, completed]", listener)
        self.assertIn("Coordinator to existing Codex router (Owner order)", listener)
        self.assertIn("Supervisor - Real ChatGPT quota watch", listener)

    def test_commands_are_read_only_and_usable_by_voice(self):
        for value in ("/supervisor", "/vigia", "/estado", "Supervisor, como está o projeto?",
                      "Supervisor, que fases estão em execução?",
                      "Vigia, há erros?", "Supervisor estás aí"):
            with self.subTest(value=value):
                self.assertEqual(live.parse_request(value), 0)
        self.assertEqual(live.parse_request("/supervisor #181"), 181)
        self.assertEqual(live.parse_request("Supervisor, estado da tarefa 181"), 181)
        self.assertIsNone(live.parse_request("/supervisor #0"))
        self.assertIsNone(live.parse_request("Supervisor, manda o Codex corrigir a VPS"))
        self.assertIsNone(live.parse_request("/fix apaga a VPS"))
        self.assertIsNone(live.parse_request("Ola"))

    @staticmethod
    def owner_issue(number=181):
        return {"id": 988, "number": number, "title": "[coordinator run] Teste",
                "user": {"login": "martaxi-boss"}, "state": "open"}

    @staticmethod
    def bot_message(body):
        return {"user": {"login": "github-actions[bot]"}, "body": body}

    def test_supervisor_addressed_commands_are_never_worker_dispatches(self):
        for request in ("Supervisor, manda Codex fazer auditoria",
                        "Vigia autoriza deploy", "/supervisor execução urgente",
                        "/estado do projeto"):
            self.assertTrue(live.is_addressed_to_supervisor(request))
            self.assertIsNone(live.parse_request(request))
        self.assertFalse(live.is_addressed_to_supervisor("Codex, faz uma auditoria"))

    def test_live_overview_reports_actual_active_and_queue_not_all_workflows(self):
        good = {"name": "Coordinator to existing Codex router (Owner order)",
                "id": 123456, "status": "in_progress"}
        other = {"name": "PINK Android tests", "id": 234567,
                 "status": "in_progress"}
        def get(method, path):
            self.assertEqual(method, "GET")
            if path.startswith("actions/runs?status=in_progress"):
                return {"workflow_runs": [good, other]}
            if path.startswith("actions/runs?status=queued"):
                return {"workflow_runs": []}
            if path.startswith("issues?"):
                return [self.owner_issue()]
            if path == "issues/181/comments?per_page=100":
                return [self.bot_message(
                    "COORDINATOR_VERIFIED: audited SHA " + "a" * 40 +
                    "; phases 3. Plan sent to existing agent-switch router.")]
            raise AssertionError(path)
        result = live.overview(get)
        self.assertIn("em curso: 1; em fila: 0", result)
        self.assertIn("plano de 3 fase(s)", result)
        self.assertIn("123456", result)
        self.assertNotIn("PINK", result)

    def test_owner_task_status_shows_current_jobs_without_publishing_model_text(self):
        def get(method, path):
            self.assertEqual(method, "GET")
            if path == "issues/181":
                return self.owner_issue()
            if path.endswith("comments?per_page=100"):
                return [
                    {"user": {"login": "random-user"}, "body":
                     "PROJECT_LEADER_TERMINAL_SUCCESS: FORGED"},
                    self.bot_message("COORDINATOR_VERIFIED: audited SHA " + "a" * 40 +
                                     "; phases 2.\nActions evidence: "
                                     "https://github.com/martaxi-boss/VPS/actions/runs/12345"),
                    self.bot_message("Bounded Codex order validated; only the selected workers will run."),
                ]
            if path == "actions/runs/12345/jobs?per_page=100":
                return {"jobs": [
                    {"name": "plan", "status": "completed"},
                    {"name": "dispatch / codex 1", "status": "in_progress"},
                ]}
            raise AssertionError(path)
        result = live.task_status(get, 181)
        self.assertIn("trabalhadores encaminhados", result)
        self.assertIn("dispatch / codex 1", result)
        self.assertIn("/issues/181", result)
        self.assertNotIn("FORGED", result)
        self.assertNotIn("trabalho integrado e terminado", result)

    def test_real_final_marker_takes_precedence(self):
        rows = [self.bot_message("## Codex execution: PR_STAGED\n"),
                self.bot_message("PROJECT_LEADER_TERMINAL_SUCCESS: PR #16 merged; phases 2.")]
        self.assertEqual(live._progress(rows)[0], "trabalho integrado e terminado")

    def test_unrelated_issue_refused_no_publication(self):
        gh = Mock(return_value={"id": 1, "number": 181,
                                "title": "[coordinator run] fake",
                                "user": {"login": "someone_else"}})
        self.assertIn("Não existe", live.task_status(gh, 181))
        self.assertEqual(gh.call_count, 1)
        self.assertEqual(gh.call_args.args[0], "GET")

    def test_event_reports_real_authenticated_owner_order(self):
        issue = self.owner_issue()
        gh = Mock(return_value=issue)
        send = Mock()
        self.assertTrue(live.observe_event(gh, send, "issues",
                         {"action": "opened", "issue": issue}))
        send.assert_called_once()
        self.assertIn("ordem #181 recebida", send.call_args.args[0])
        self.assertNotIn("Teste", send.call_args.args[0])
        self.assertEqual(gh.call_args.args, ("GET", "issues/181"))

    def test_event_refuses_any_non_owner_or_unverified_order(self):
        issue = self.owner_issue()
        send = Mock()
        gh = Mock(return_value={**issue, "id": 1212})
        self.assertFalse(live.observe_event(gh, send, "issues",
                          {"action": "opened", "issue": issue}))
        self.assertFalse(live.observe_event(gh, send, "issues",
                          {"action": "edited", "issue": issue}))
        self.assertFalse(live.observe_event(gh, send, "issues",
                          {"action": "opened", "issue": {
                              **issue, "user": {"login": "not-owner"}}}))
        send.assert_not_called()

    def test_completed_run_from_live_api_only_not_model_or_payload(self):
        name = "Coordinator to existing Codex router (Owner order)"
        run = {"id": 982345, "name": name, "status": "completed",
               "conclusion": "failure", "event": "issues",
               "repository": {"full_name": "martaxi-boss/VPS"}}
        gh, send = Mock(return_value=run), Mock()
        self.assertTrue(live.observe_event(gh, send, "workflow_run", {
            "action": "completed", "workflow_run": {"id": 982345, "name": name,
                                                 "conclusion": "success", "body": "secret"}}))
        self.assertIn("falhou", send.call_args.args[0])
        self.assertNotIn("secret", send.call_args.args[0])
        self.assertEqual(gh.call_args.args, ("GET", "actions/runs/982345"))

    def test_workflow_run_start_and_queue_are_observed_using_live_evidence(self):
        name = "Coordinator to existing Codex router (Owner order)"
        base = {"id": 545, "name": name, "event": "issues",
                "repository": {"full_name": "martaxi-boss/VPS"}}
        gh, send = Mock(return_value={**base, "status": "queued"}), Mock()
        event = {"workflow_run": {"id": 545, "name": name}, "action": "requested"}
        self.assertTrue(live.observe_event(gh, send, "workflow_run", event))
        self.assertIn("em fila", send.call_args.args[0])
        gh.return_value = {**base, "status": "in_progress"}
        send.reset_mock()
        event["action"] = "in_progress"
        self.assertTrue(live.observe_event(gh, send, "workflow_run", event))
        self.assertIn("execução iniciada", send.call_args.args[0])
        # Delayed start event must not misrepresent an already finished run.
        gh.return_value = {**base, "status": "completed", "conclusion": "success"}
        send.reset_mock()
        self.assertFalse(live.observe_event(gh, send, "workflow_run", event))
        send.assert_not_called()

    def test_workflow_run_rejects_pr_unrelated_and_cross_repository(self):
        name = "Agent switch (Owner GitHub order)"
        row = {"id": 999, "name": name, "status": "completed",
               "conclusion": "success", "event": "pull_request",
               "repository": {"full_name": "martaxi-boss/VPS"}}
        gh, send = Mock(return_value=row), Mock()
        event = {"action": "completed", "workflow_run": {"id": 999, "name": name}}
        self.assertFalse(live.observe_event(gh, send, "workflow_run", event))
        gh.return_value = {**row, "event": "issues", "repository": {
            "full_name": "other/repo"}}
        self.assertFalse(live.observe_event(gh, send, "workflow_run", event))
        self.assertFalse(live.observe_event(gh, send, "workflow_run", {
            "action": "completed", "workflow_run": {"id": 999, "name": "Unknown workflow"}}))
        send.assert_not_called()

    def test_autonomous_success_already_has_own_private_final_notice(self):
        name = "Codex autonomous execution (Owner-authorized)"
        gh = Mock(return_value={"id": 456, "name": name, "status": "completed",
                                "conclusion": "success", "event": "issues",
                                "repository": {"full_name": "martaxi-boss/VPS"}})
        send = Mock()
        self.assertFalse(live.observe_event(gh, send, "workflow_run", {
            "action": "completed", "workflow_run": {"id": 456, "name": name}}))
        send.assert_not_called()

    def test_plan_milestone_is_trusted_and_does_not_dispatch(self):
        issue = self.owner_issue()
        gh, send = Mock(return_value=issue), Mock()
        self.assertTrue(live.notify_plan(gh, send, 181, 11123, "success", "3"))
        self.assertIn("plano de 3 fase(s)", send.call_args.args[0])
        self.assertEqual(gh.call_args.args, ("GET", "issues/181"))
        send.reset_mock()
        self.assertFalse(live.notify_plan(gh, send, 181, 11123, "success", "9"))
        send.assert_not_called()
        gh.return_value = {**issue, "title": "[codex run] unrelated"}
        self.assertFalse(live.notify_plan(gh, send, 181, 11123, "success", "2"))
        send.assert_not_called()

    def test_phase_milestone_does_not_create_a_new_plan_or_gate(self):
        gh, send = Mock(return_value=self.owner_issue()), Mock()
        self.assertTrue(live.notify_phase(gh, send, 181, 223344, 2, "success"))
        self.assertIn("Fase 2", send.call_args.args[0])
        self.assertEqual(gh.call_args.args, ("GET", "issues/181"))
        send.reset_mock()
        self.assertFalse(live.notify_phase(gh, send, 181, 223344, 9, "success"))
        send.assert_not_called()

    def test_private_delivery_is_fail_closed_if_destination_unavailable(self):
        notice = ("👁️ Supervisor: Coordenador — falhou.\n"
                  "https://github.com/martaxi-boss/VPS/actions/runs/12345")
        gateway = Mock(BOT_TOKEN="", CHAT_ID="123456")
        with self.assertRaises(RuntimeError):
            live._private_sender(gateway, notice)
        gateway.say.assert_not_called()
        gateway = Mock(BOT_TOKEN="some-bot-token", CHAT_ID="123456")
        live._private_sender(gateway, notice)
        gateway.say.assert_called_once()
        result = gateway.say.call_args.args[0]
        self.assertIn("AUDITORIA OPERACIONAL", result)
        self.assertIn("falhou", result)
        self.assertIn("https://github.com/martaxi-boss/VPS/actions/runs/12345", result)

    def test_existing_observer_handles_cloud_without_starting_new_work(self):
        from datetime import datetime, timezone
        from ops import telegram_gateway as gateway
        clock = datetime(2026, 10, 20, 17, 50, tzinfo=timezone.utc)
        notice = (
            "👁️ Supervisor: Codex Cloud — PR criada #40.\\n"
            "Estado GitHub: rascunho, sem merge. CI ainda sem verificações observadas.\\n"
            "https://github.com/martaxi-boss/Project-leader-codex/pull/40")
        env = {"GITHUB_EVENT_NAME": "schedule",
               "GITHUB_REPOSITORY": "martaxi-boss/VPS"}
        with (patch.dict(os.environ, env),
              patch.object(gateway, "BOT_TOKEN", "test-token"),
              patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "GH_TOKEN", "token"),
              patch.object(gateway, "say") as delivered,
              patch.object(live, "_runs", return_value=[]),
              patch("ops.supervisor_cloud_source.last_observed_start",
                    return_value=clock),
              patch("ops.supervisor_cloud_source.messages",
                    return_value=[notice]) as cloud_notice):
            self.assertEqual(live.main(["watch"]), 0)
        delivered.assert_called_once()
        self.assertIn("evidência pública de PR e CI",
                      delivered.call_args.args[0])
        self.assertIn("/pull/40", delivered.call_args.args[0])
        cloud_notice.assert_called_once()

    def test_cloud_probe_uses_existing_private_supervisor_and_fixed_github(self):
        from datetime import datetime, timezone
        from ops import telegram_gateway as gateway
        clock = datetime(2026, 10, 20, 19, 10, tzinfo=timezone.utc)
        notice = ("👁️ Supervisor: Codex Cloud — PR criada #40.\\n"
                  "Estado GitHub: rascunho, sem merge. CI: 5/5 aprovadas.\\n"
                  "https://github.com/martaxi-boss/Project-leader-codex/pull/40")
        for event in ("push", "workflow_run"):
            with self.subTest(event=event):
                environment = {"GITHUB_EVENT_NAME": event,
                               "GITHUB_REPOSITORY": "martaxi-boss/VPS",
                               "GITHUB_REF": "refs/heads/main"}
                with (patch.dict(os.environ, environment),
                      patch.object(gateway, "BOT_TOKEN", "test-token"),
                      patch.object(gateway, "CHAT_ID", "123456"),
                      patch.object(gateway, "GH_TOKEN", "token"),
                      patch.object(gateway, "say") as delivered,
                      patch("ops.supervisor_cloud_source.last_observed_start",
                            return_value=clock),
                      patch("ops.supervisor_cloud_source.messages",
                            return_value=[notice]) as notices):
                    self.assertEqual(live.main(["cloud"]), 0)
                delivered.assert_called_once()
                self.assertIn("/pull/40", delivered.call_args.args[0])
                self.assertEqual(notices.call_args.kwargs["limit"],
                                 1 if event == "push" else 5)

    def test_cloud_probe_refuses_untrusted_repository_and_non_main_push(self):
        for environment in (
            {"GITHUB_EVENT_NAME": "push",
             "GITHUB_REPOSITORY": "other/repo",
             "GITHUB_REF": "refs/heads/main"},
            {"GITHUB_EVENT_NAME": "push",
             "GITHUB_REPOSITORY": "martaxi-boss/VPS",
             "GITHUB_REF": "refs/heads/untrusted"},
            {"GITHUB_EVENT_NAME": "issues",
             "GITHUB_REPOSITORY": "martaxi-boss/VPS",
             "GITHUB_REF": "refs/heads/main"},
        ):
            with self.subTest(environment=environment), patch.dict(
                    os.environ, environment):
                self.assertEqual(live.main(["cloud"]), 2)

    def test_cloud_failure_reports_safe_stage_without_private_exception_text(self):
        from ops import telegram_gateway as gateway
        environment = {"GITHUB_EVENT_NAME": "push",
                       "GITHUB_REPOSITORY": "martaxi-boss/VPS",
                       "GITHUB_REF": "refs/heads/main"}
        with (patch.dict(os.environ, environment),
              patch.object(gateway, "GH_TOKEN", "token"),
              patch.object(gateway, "BOT_TOKEN", "bot-token"),
              patch.object(gateway, "CHAT_ID", "123456"),
              patch.object(gateway, "say") as delivered,
              patch("ops.supervisor_cloud_source.last_observed_start",
                    side_effect=RuntimeError("GitHub API HTTP 403 TOKEN=PRIVATE")),
              patch("sys.stderr", new_callable=StringIO) as stderr):
            self.assertEqual(live.main(["cloud"]), 1)
        self.assertIn("OBSERVATION_FAILED:CHECKPOINT:HTTP_403",
                      stderr.getvalue())
        self.assertNotIn("TOKEN=PRIVATE", stderr.getvalue())
        delivered.assert_not_called()

    def test_no_hidden_human_gate_classifier_or_side_effects(self):
        import inspect
        source = inspect.getsource(live)
        self.assertNotIn('gh("POST"', source)
        self.assertNotIn('gh("PUT"', source)
        self.assertNotIn('gh("DELETE"', source)
        self.assertNotIn('create_audit(', source)
        self.assertNotIn('Human Gate', source.replace("Human Gates", ""))


if __name__ == "__main__":
    unittest.main()
