"""Drive unmodified OIDF modules; never infer success from a finished lifecycle."""
import argparse
import asyncio
from contextlib import redirect_stderr, redirect_stdout
import json
from pathlib import Path
import re
import ssl
import tempfile
import zipfile

BASELINE = json.loads(Path(__file__).with_name("baseline.json").read_text())
SUITE = "https://suite.ofed.test:8443"
ENCRYPTED = "openid-federation-automatic-client-registration-with-jar-and-encrypted-request-object"
FETCH_MODULES = {
    "openid-federation-ensure-fetch-with-invalid-sub-fails",
    "openid-federation-ensure-fetch-with-iss-as-sub-fails",
}


class ApplicationOutcomeError(ValueError):
    """The test application accepted or rejected a flow incorrectly."""


def grade(name, target, info, logs):
    """Only documented optional capabilities may produce an accepted skip."""
    if info.get("status") != "FINISHED":
        return False
    if not logs or any(x.get("result") in {"FAILURE", "WARNING", "REVIEW"} for x in logs):
        return False
    if info.get("result") == "PASSED":
        return True
    if info.get("result") != "SKIPPED":
        return False
    reasons = [str(x.get("msg", "")) for x in logs]
    if name == ENCRYPTED:
        return "The server does not support encrypted request objects" in reasons
    if name in FETCH_MODULES and target == "leaf":
        return any("does not contain a federation_fetch_endpoint" in x for x in reasons)
    return False


def inventory(plan, expected):
    """Reject added, removed, duplicated, or variant-mismatched plan modules."""
    modules = plan.get("modules", [])
    names = [x.get("testModule") for x in modules]
    wanted = [x["name"] for x in expected["modules"]]
    if len(names) != len(set(names)) or set(names) != set(wanted):
        raise ValueError("Official plan inventory differs from the pinned baseline")
    if any(x.get("variant") != BASELINE["variants"] for x in modules):
        raise ValueError("Official module variants differ from the pinned baseline")


def instances(plan, executed):
    if {x["testModule"]: x.get("instances") for x in plan["modules"]} != {
            name: [ident] for name, ident in executed.items()}:
        raise ValueError("Missing or repeated module executions")


def rp_outcome(name, status, body):
    """The suite cannot observe whether an RP accepted its invalid ID Token."""
    positive = name in {"openid-federation-client-test",
        "openid-federation-client-valid-unknown-client-registration-types-supported"}
    expected_stage = {"protocol"} if positive or name.endswith("-in-id-token") else {"federation", "registration"}
    if (status != (200 if positive else 400) or body.get("accepted") is not positive
            or body.get("stage") not in expected_stage):
        raise ApplicationOutcomeError("RP application outcome contradicts the module's expected behavior")


def diagnostics(logs):
    # Export only bounded identifiers. Raw logs contain private JWKs, assertions,
    # authorization codes and cookies even though all participants are disposable.
    result = []
    for entry in logs:
        if entry.get("result") not in {"FAILURE", "WARNING", "REVIEW"}:
            continue
        src = str(entry.get("src", ""))
        result.append({"source": src if re.fullmatch(r"[\w.$-]{1,180}", src) else "unknown",
                       "result": entry["result"]})
    return result


def check_export(path, expected):
    """The export must contain every executed instance and agree with its result."""
    found = {}
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            if not entry.filename.endswith(".json"):
                continue
            if entry.file_size > 50_000_000:
                raise ValueError("Oversized suite export")
            data = json.loads(archive.read(entry))
            info = data.get("testInfo", {})
            # The upstream export wraps Mongo TestInfo in its public JSON shape.
            ident = info.get("id", info.get("_id"))
            if ident in found:
                raise ValueError("Duplicate test in suite export")
            found[ident] = (info.get("status"), info.get("result"))
    if found != expected:
        raise ValueError("Missing or inconsistent suite export results")


async def execute(api, ident, role, trigger, timeout=180):
    """Bound a module and cancel it on timeout, browser failure, or interruption."""
    completed = False
    try:
        async with asyncio.timeout(timeout):
            await api.wait_for_state(ident, ["CONFIGURED", "FINISHED"])
            info = await api.get_module_info(ident)
            if info.get("status") != "FINISHED":
                await api.start_test(ident)
                if role == "rp":
                    await trigger()
                await api.wait_for_state(ident, ["FINISHED"])
            info = await api.get_module_info(ident)
            logs = await api.get_test_log(ident)
            completed = info.get("status") == "FINISHED"
            return info, logs
    finally:
        if not completed:
            # This is an API transport operation absent from the upstream wrapper.
            # Shield cleanup from the timeout/cancellation that interrupted the test.
            await asyncio.shield(api.httpclient.delete(f"{SUITE}/api/runner/{ident}"))


def configuration(role, target, settings, keys):
    alias = f"{settings['runId']}-{role}-{target}" if role == "deployed" else f"{settings['runId']}-{role}"
    fed = {"entity_identifier": f"https://{target}.ofed.test:8443"}
    config = {"alias": alias, "description": "Disposable oidfed conformance fixture",
              "publish": "no", "federation": fed}
    if role == "deployed":
        fed.update(de_trust_anchor="https://ta.ofed.test:8443",
                   de_trust_anchor_jwks={"keys": [keys["anchorPublic"]]})
    else:
        config["federation_trust_anchor"] = {"trust_anchor_jwks": {"keys": [keys["authority"]]}}
        if role == "op":
            fed.update(rp_ec_jwks={"keys": [keys["entity"]]}, rp_client_jwks={"keys": [keys["protocol"]]})
            config["client"] = {"scope": "openid"}
            config["browser"] = [{"match": "https://op.ofed.test:8443/auth*", "tasks": [
                {"task": "Verify Complete", "match": f"{SUITE}/test/a/{alias}/callback*"}
            ]}]
        else:
            fed.update(op_ec_jwks={"keys": [keys["entity"]]}, op_server_jwks={"keys": [keys["protocol"]]})
    return config


async def run(profile, output):
    # Imported only during integration execution; unit tests need no network/deps.
    import httpx
    from conformance import Conformance

    state = Path("/run/oidfed")
    settings = json.loads((state / "settings.json").read_text())
    context = ssl.create_default_context(cafile=str(state / "ca.pem"))
    api = Conformance(SUITE, None, context)
    report = {"revision": BASELINE["revision"], "profile": profile, "modules": [], "passed": False}
    output.mkdir(parents=True, exist_ok=True)
    try:
        async with asyncio.timeout(360):
            await api.wait_for_server_ready(timeout=330)
            async with httpx.AsyncClient(verify=context) as client:
                while True:
                    try:
                        response = await client.get("https://rp.ofed.test:8443/health")
                        response.raise_for_status()
                        if (state / "suite-keys.json").exists():
                            break
                    except httpx.HTTPError:
                        pass
                    await asyncio.sleep(1)
        keys = json.loads((state / "suite-keys.json").read_text())
        roles = ["deployed"] if profile == "deployed" else ["deployed", "op", "rp"]
        for role in roles:
            for target in (["ta", "ia", "leaf"] if role == "deployed" else [role]):
                baseline = BASELINE["plans"][role]
                variant = BASELINE["variants"]
                plan = await api.create_test_plan(baseline["name"], json.dumps(configuration(role, target, settings, keys)), variant)
                inventory(plan, baseline)
                expected = {}
                executed = {}
                for module in baseline["modules"]:
                    record = {"name": module["name"], "target": target, "status": "INCOMPLETE",
                              "result": "UNKNOWN", "accepted": False, "diagnostics": []}
                    report["modules"].append(record)
                    created = await api.create_test_from_plan_with_variant(plan["id"], module["name"], variant)
                    ident = created["id"]
                    executed[module["name"]] = ident

                    async def trigger():
                        async with httpx.AsyncClient(verify=context, follow_redirects=True, timeout=30) as client:
                            response = await client.get("https://rp.ofed.test:8443/login")
                            # Check the application's observed outcome as well as the
                            # Foundation result, especially for invalid ID Tokens.
                            rp_outcome(module["name"], response.status_code, response.json())

                    info, logs = await execute(api, ident, role, trigger)
                    passed = grade(module["name"], target, info, logs)
                    expected[ident] = (info.get("status"), info.get("result"))
                    record.update(status=info.get("status"), result=info.get("result"),
                                  accepted=passed, diagnostics=diagnostics(logs))
                    print(f"{target}: {module['name']}: {info.get('result')}", flush=True)
                response = await api.httpclient.get(f"{SUITE}/api/plan/{plan['id']}")
                response.raise_for_status()
                final_plan = response.json()
                inventory(final_plan, baseline)
                instances(final_plan, executed)
                # Keep raw exports out of the upload directory, then delete them.
                with tempfile.TemporaryDirectory(dir=state) as private:
                    exported = await api.exportjson(plan["id"], private)
                    check_export(exported, expected)
        report["passed"] = bool(report["modules"]) and all(x["accepted"] for x in report["modules"])
    except BaseException as error:
        # Exception text from the upstream client can embed request/configuration data.
        report["infrastructureError"] = type(error).__name__
        report["failureKind"] = "application" if isinstance(error, ApplicationOutcomeError) else "orchestration"
        raise
    finally:
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
        await api.close_client()
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=["deployed", "full"], default="deployed")
    args = parser.parse_args()
    try:
        with Path("/run/oidfed/driver-private.log").open("w") as log, redirect_stdout(log), redirect_stderr(log):
            asyncio.run(run(args.profile, Path("/results")))
        print("Conformance run passed. See the sanitized summary.json report.")
    except Exception as error:
        print(f"Conformance infrastructure failed: {type(error).__name__}", flush=True)
        raise SystemExit(1) from None
