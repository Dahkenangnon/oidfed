"""Regression tests for orchestration failures that must never turn CI green."""
import asyncio
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch
import zipfile

from driver import ApplicationOutcomeError, BASELINE, ENCRYPTED, ModuleFailure, check_export, diagnostics, execute, grade, instances, inventory, module_variant, rp_outcome, run
from run import environment, main


class ResultPolicy(unittest.TestCase):
    def test_full_profile_includes_each_plan_once(self):
        full = BASELINE["profiles"]["full"]
        self.assertEqual(set(full), set(BASELINE["plans"]))
        self.assertEqual(len(full), len(set(full)))
        for role in BASELINE["plans"]:
            self.assertEqual(BASELINE["profiles"][role], [role])

    def test_only_finished_pass_is_success(self):
        for status in ["CONFIGURED", "WAITING", "RUNNING", "INTERRUPTED", "FINISHED"]:
            for result in ["PASSED", "FAILED", "WARNING", "REVIEW", "UNKNOWN", "SKIPPED", None]:
                with self.subTest(status=status, result=result):
                    self.assertEqual(grade("ordinary", "op", {"status": status, "result": result},
                                           [{"result": "SUCCESS"}]),
                                     status == "FINISHED" and result == "PASSED")

    def test_missing_logs_and_browser_failures_fail(self):
        info = {"status": "FINISHED", "result": "PASSED"}
        for logs in [[], [{"src": "BROWSER", "result": "FAILURE"}], [{"result": "WARNING"}], [{"result": "REVIEW"}]]:
            self.assertFalse(grade("ordinary", "op", info, logs))

    def test_optional_skip_is_narrow(self):
        info = {"status": "FINISHED", "result": "SKIPPED"}
        logs = [{"result": "SKIPPED", "msg": "The test was skipped: The server does not support encrypted request objects"}]
        self.assertTrue(grade(ENCRYPTED, "op", info, logs))
        self.assertFalse(grade("another-module", "op", info, logs))
        self.assertFalse(grade(ENCRYPTED, "op", info, [{"msg": "Other failure"}]))
        fetch = "openid-federation-ensure-fetch-with-invalid-sub-fails"
        logs = [{"result": "SKIPPED", "msg": "The test was skipped: Entity metadata does not contain a federation_fetch_endpoint."}]
        self.assertTrue(grade(fetch, "leaf", info, logs))
        self.assertFalse(grade(fetch, "ia", info, logs))

    def test_inventory_rejects_missing_added_and_duplicate_modules(self):
        baseline = BASELINE["plans"]["deployed"]
        names = [x["name"] for x in baseline["modules"]]
        inventory({"modules": [{"testModule": x, "variant": None} for x in names]}, baseline)
        for changed in [names[:-1], names + ["unexpected"], names + names[:1], []]:
            with self.assertRaises(ValueError):
                inventory({"modules": [{"testModule": x} for x in changed]}, baseline)

    def test_variant_drift_and_hidden_reruns_fail(self):
        baseline = BASELINE["plans"]["deployed"]
        with self.assertRaises(ValueError):
            inventory({"modules": [{"testModule": x["name"], "variant": {"server_metadata": "static"}}
                                    for x in baseline["modules"]]}, baseline)
        module_variant({"variant": BASELINE["variants"]})
        with self.assertRaises(ValueError):
            module_variant({"variant": {"server_metadata": "static", "client_registration": "automatic"}})
        instances({"modules": [{"testModule": "module", "instances": ["one"]}]}, {"module": "one"})
        for ids in [[], ["one", "two"], ["other"]]:
            with self.assertRaises(ValueError):
                instances({"modules": [{"testModule": "module", "instances": ids}]}, {"module": "one"})

    def test_rp_acceptance_is_checked_independently(self):
        happy = "openid-federation-client-test"
        invalid = "openid-federation-client-invalid-aud-in-id-token"
        rp_outcome(happy, 200, {"accepted": True, "stage": "protocol"})
        rp_outcome(invalid, 400, {"accepted": False, "stage": "protocol"})
        for name, status, body in [(invalid, 200, {"accepted": True, "stage": "protocol"}),
                                  (happy, 400, {"accepted": False, "stage": "federation"}),
                                  (invalid, 400, {"accepted": False, "stage": "federation"})]:
            with self.assertRaises(ValueError):
                rp_outcome(name, status, body)

    def test_raw_secrets_do_not_reach_diagnostics(self):
        logs = [{"src": "ValidateSignature", "result": "FAILURE", "msg": "secret", "private_key": "secret"},
                {"src": "key: secret", "result": "WARNING"}]
        exported = json.dumps(diagnostics(logs))
        self.assertNotIn("secret", exported)
        self.assertIn("ValidateSignature", exported)

    def test_export_must_match_all_instances_and_results(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "export.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("test-log.json", json.dumps({"testInfo": {"id": "abc", "status": "FINISHED", "result": "PASSED"}}))
            check_export(archive, {"abc": ("FINISHED", "PASSED")})
            for expected in [{}, {"abc": ("FINISHED", "FAILED")}, {"abc": ("FINISHED", "PASSED"), "missing": ("FINISHED", "PASSED")}]:
                with self.assertRaises(ValueError):
                    check_export(archive, expected)

    def test_compose_and_private_state_are_removed_on_failure(self):
        with tempfile.TemporaryDirectory() as temp, patch("run.subprocess.run") as docker:
            state = Path(temp) / "private"
            state.mkdir()
            docker.return_value.returncode = 0
            with self.assertRaisesRegex(RuntimeError, "fixture failed"):
                with environment(["docker", "compose", "-p", "disposable"], {}, state):
                    raise RuntimeError("fixture failed")
            self.assertFalse(state.exists())
            self.assertIn("down", docker.call_args.args[0])
            self.assertIn("--volumes", docker.call_args.args[0])

    def test_private_state_is_removed_when_docker_cleanup_raises(self):
        with tempfile.TemporaryDirectory() as temp, patch("run.subprocess.run", side_effect=OSError("Docker unavailable")):
            state = Path(temp) / "private"
            state.mkdir()
            with self.assertRaises(OSError):
                with environment(["docker", "compose"], {}, state):
                    (state / "disposable-key").write_text("private")
            self.assertFalse(state.exists())

    def test_private_diagnostics_are_opt_in_and_prohibited_in_ci(self):
        with tempfile.TemporaryDirectory() as temp, patch("run.subprocess.run") as docker:
            docker.return_value.returncode = 0
            state = Path(temp) / "private"
            state.mkdir()
            with environment(["docker", "compose"], {}, state, keep_private=True):
                (state / "diagnostic").write_text("private")
            self.assertTrue((state / "diagnostic").exists())
        with patch.dict("os.environ", {"CI": "true"}), self.assertRaisesRegex(ValueError, "cannot be retained"):
            main("full", None, keep_private=True)


class Lifecycle(unittest.IsolatedAsyncioTestCase):
    async def test_application_failure_survives_foundation_failure_logs(self):
        name = "openid-federation-client-test"
        for expected_error in [ApplicationOutcomeError, ModuleFailure]:
            with self.subTest(expected_error=expected_error), tempfile.TemporaryDirectory() as temp:
                state = Path(temp) / "private"
                state.mkdir()
                (state / "settings.json").write_text(json.dumps({"runId": "disposable"}))
                (state / "suite-keys.json").write_text(json.dumps({
                    key: {} for key in ["authority", "entity", "protocol", "encryption"]}))
                output = Path(temp) / "results"
                api = AsyncMock()
                api.create_test_plan.return_value = {"id": "plan", "modules": [{"testModule": name}]}
                api.create_test_from_plan_with_variant.return_value = {"id": "instance"}
                api.get_module_info.side_effect = [{"status": "CONFIGURED"},
                    {"status": "FINISHED", "result": "FAILED"}]
                api.get_test_log.return_value = [{"src": "ValidateToken", "result": "FAILURE"}]
                response = Mock(status_code=400, url="https://rp.ofed.test:8443/callback", text="private")
                if expected_error is ApplicationOutcomeError:
                    response.json.return_value = {"accepted": False, "stage": "protocol"}
                else:
                    response.json.side_effect = ValueError("untrusted response body")
                client = AsyncMock()
                client.get.return_value = response
                client.__aenter__.return_value = client
                with patch.dict("sys.modules", {
                        "conformance": SimpleNamespace(Conformance=Mock(return_value=api)),
                        "httpx": SimpleNamespace(AsyncClient=Mock(return_value=client), HTTPError=OSError)}), \
                        patch("driver.ssl.create_default_context"), \
                        patch.dict(BASELINE["plans"]["rp"], {"modules": [{"name": name}]}), \
                        redirect_stderr(io.StringIO()), \
                        self.assertRaises(expected_error):
                    await run("rp", output, state)
                report = json.loads((output / "summary.json").read_text())
                self.assertFalse(report["passed"])
                self.assertEqual(report["failureKind"],
                    "application" if expected_error is ApplicationOutcomeError else "module")
                self.assertNotIn("untrusted response body", json.dumps(report))
                api.httpclient.delete.assert_awaited_once()
                api.close_client.assert_awaited_once()

    async def test_timeout_cancels_module(self):
        api = AsyncMock()
        async def wait(*_):
            await asyncio.sleep(1)
        api.wait_for_state.side_effect = wait
        with self.assertRaises(TimeoutError):
            await execute(api, "abc", "op", AsyncMock(), timeout=0.01)
        api.httpclient.delete.assert_awaited_once()

    async def test_trigger_failure_cancels_module(self):
        api = AsyncMock()
        api.get_module_info.return_value = {"status": "CONFIGURED"}
        with self.assertRaises(RuntimeError):
            await execute(api, "abc", "rp", AsyncMock(side_effect=RuntimeError("browser failed")))
        api.httpclient.delete.assert_awaited_once()

    async def test_external_cancellation_cancels_module(self):
        api = AsyncMock()
        api.wait_for_state.side_effect = asyncio.CancelledError
        with self.assertRaises(asyncio.CancelledError):
            await execute(api, "abc", "op", AsyncMock())
        api.httpclient.delete.assert_awaited_once()

    async def test_finished_failed_module_is_returned_for_grading(self):
        api = AsyncMock()
        api.get_module_info.return_value = {"status": "FINISHED", "result": "FAILED"}
        api.get_test_log.return_value = [{"result": "FAILURE"}]
        trigger = AsyncMock()
        info, logs = await execute(api, "abc", "rp", trigger)
        self.assertFalse(grade("ordinary", "rp", info, logs))
        trigger.assert_not_awaited()
        api.httpclient.delete.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
