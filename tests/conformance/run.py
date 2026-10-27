"""Build the pinned upstream suite and run it on a disposable Docker network."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
BASELINE = json.loads(Path(__file__).with_name("baseline.json").read_text())
MAVEN = "maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237"


def command(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def checkout(source):
    if not (source / ".git").exists():
        source.mkdir(parents=True, exist_ok=True)
        command("git", "init", str(source))
        command("git", "-C", str(source), "remote", "add", "origin", BASELINE["repository"])
        command("git", "-C", str(source), "fetch", "--depth=1", "origin", BASELINE["revision"])
        command("git", "-C", str(source), "checkout", "--detach", "FETCH_HEAD")
    actual = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if actual != BASELINE["revision"]:
        raise ValueError("Suite checkout does not match baseline.json")
    if subprocess.check_output(["git", "-C", str(source), "status", "--porcelain", "--untracked-files=all"], text=True):
        raise ValueError("Suite checkout contains local changes")
    # The checked-in inventory must still describe the source we will build.
    import re
    for plan in BASELINE["plans"].values():
        text = (source / plan["source"]).read_text()
        active = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))
        names = re.findall(r"\b(OpenIDFederation\w+)\.class", active)
        classes = [Path(module["source"]).stem for module in plan["modules"]]
        if names != classes:
            raise ValueError("Pinned plan source differs from baseline.json")


def certificates(state):
    command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", "/CN=oidfed disposable conformance CA", "-keyout", str(state / "ca-key.pem"),
            "-out", str(state / "ca.pem"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    command("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=suite.ofed.test",
            "-keyout", str(state / "tls-key.pem"), "-out", str(state / "tls.csr"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    extensions = state / "tls.ext"
    extensions.write_text("subjectAltName=DNS:suite.ofed.test,DNS:ta.ofed.test,DNS:ia.ofed.test,DNS:leaf.ofed.test,DNS:op.ofed.test,DNS:rp.ofed.test\nextendedKeyUsage=serverAuth\n")
    command("openssl", "x509", "-req", "-days", "2", "-in", str(state / "tls.csr"),
            "-CA", str(state / "ca.pem"), "-CAkey", str(state / "ca-key.pem"), "-CAcreateserial",
            "-extfile", str(extensions), "-out", str(state / "tls.pem"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@contextmanager
def environment(compose, env, state):
    try:
        yield
    finally:
        # No raw container output: fixture and suite logs may include test secrets.
        try:
            result = subprocess.run([*compose, "down", "--volumes", "--remove-orphans", "--timeout", "10"],
                                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
        finally:
            shutil.rmtree(state)
        if result.returncode:
            raise RuntimeError("Docker cleanup failed; remove the reported Compose project manually")


def main(profile, source_override):
    cache = ROOT / ".conformance"
    source = Path(source_override).resolve() if source_override else cache / "suite" / BASELINE["revision"]
    checkout(source)
    maven = cache / "maven"
    maven.mkdir(parents=True, exist_ok=True)
    command("docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
            "-v", f"{source}:/src", "-v", f"{maven}:/tmp/maven", "-w", "/src", MAVEN,
            "mvn", "-B", "-Dmaven.repo.local=/tmp/maven", "-Dmaven.test.skip=true", "-Dpmd.skip=true", "package")
    jar = source / "target/fapi-test-suite.jar"
    if not jar.is_file():
        raise ValueError("Official suite build did not produce its JAR")
    definition = ROOT / "tests/conformance"
    digest = hashlib.sha256((definition / "Dockerfile").read_bytes() + (definition / "requirements.txt").read_bytes()).hexdigest()
    runner = f"oidfed-conformance-runner:{digest[:16]}"
    command("docker", "build", "-t", runner, str(definition))
    run_id = "oidfed-" + uuid.uuid4().hex[:16]
    run = cache / "runs" / run_id
    state = run / "private"
    state.mkdir(parents=True, mode=0o700)
    results = run / "results"
    results.mkdir()
    # Container processes use the caller's ownership for report and fixture files.
    # Java/nginx need only read access; the parent private directory is host-only.
    env = {**os.environ, "OIDF_ROOT": str(ROOT), "OIDF_SOURCE": str(source), "OIDF_STATE": str(state),
           "OIDF_RESULTS": str(results), "OIDF_PROFILE": profile,
           "OIDF_UID": str(os.getuid()), "OIDF_GID": str(os.getgid()), "OIDF_RUNNER": runner}
    compose = ["docker", "compose", "-p", run_id, "-f", str(ROOT / "tests/conformance/compose.yml")]
    with environment(compose, env, state):
        certificates(state)
        (state / "settings.json").write_text(json.dumps({"runId": run_id}))
        fixture_hash = hashlib.sha256()
        for path in sorted(definition.iterdir()):
            if path.is_file():
                fixture_hash.update(path.name.encode() + b"\0" + path.read_bytes())
        (results / "build.json").write_text(json.dumps({"revision": BASELINE["revision"],
            "jarSha256": hashlib.sha256(jar.read_bytes()).hexdigest(), "profile": profile,
            "oidfedCommit": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
            "dirty": bool(subprocess.check_output(["git", "-C", str(ROOT), "status", "--porcelain"], text=True)),
            "fixtureSha256": fixture_hash.hexdigest(), "runnerImage": runner}, indent=2) + "\n")
        print(f"Compose project: {run_id}\nReports: {results}", flush=True)
        command(*compose, "up", "-d", "mongo", "suite", "proxy", "fixtures", env=env)
        command(*compose, "run", "--rm", "driver", env=env)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=["deployed", "full"], default="deployed")
    parser.add_argument("--source", help="Existing clean checkout at the pinned suite revision")
    args = parser.parse_args()
    # Convert CI termination into stack unwinding so Compose cleanup still runs.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    main(args.profile, args.source)
