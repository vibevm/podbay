#!/usr/bin/env python3
"""One disposable privileged run, followed by a separate unprivileged verifier.

No fixture path or arbitrary program is passed to the privileged bootstrap.
Use --verify LOG for an independent repeat of only the cleanup verification.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

OUT = Path("/fast/git/v/research/2026-10-06-podbay-linux-broker-build")
BROKER = OUT / "broker"
PREFIX = re.compile(r"/var/tmp/codex-podbay-broker-probe-[0-9a-f]{32}\Z")


def read_log(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line]


def verify(path):
    if os.geteuid() == 0:
        raise RuntimeError("cleanup verification must be unprivileged")
    events = read_log(path)
    fixtures = [e for e in events if e.get("event") == "fixture"]
    assert len(fixtures) == 1, "exactly one nonce fixture manifest required"
    f = fixtures[0]
    assert PREFIX.fullmatch(f["vault"]), "unexpected fixture path"
    assert f["alias"] == f["vault"] + ".alias"
    assert f["mount_target"] == f["vault"] + ".mount-target"
    checks = []
    for path in [f["vault"], f["alias"], f["mount_target"]]:
        try:
            os.lstat(path)
        except FileNotFoundError:
            checks.append({"path": path, "absent": True})
        else:
            raise AssertionError(f"residual fixture: {path}")
    reaped = [e for e in events if e.get("event") == "child_reaped"]
    assert reaped, "no child reaping evidence"
    for e in reaped:
        assert not Path(f'/proc/{e["pid"]}').exists(), f'PID still present: {e["pid"]}'
    assert f["vault"] not in Path("/proc/self/mountinfo").read_text()
    cleanup = [e for e in events if e.get("event") == "cleanup"]
    assert len(cleanup) == 1 and cleanup[0]["ok"] is True, "root cleanup not verified"
    assert any(e.get("event") == "host_namespace_mounts_unchanged" and e.get("ok") is True for e in events)
    result = {"event": "unprivileged_cleanup_verification", "ok": True,
              "uid": os.geteuid(), "paths": checks, "reaped_pids": [e["pid"] for e in reaped]}
    print(json.dumps(result, sort_keys=True))
    return 0


def main():
    if sys.argv[1:2] == ["--verify"] and len(sys.argv) == 3:
        return verify(sys.argv[2])
    if sys.argv[1:] != ["--run"]:
        print("usage: test.py --run | --verify LOG", file=sys.stderr)
        return 2
    if os.geteuid() == 0:
        raise RuntimeError("run from the ordinary owner account")
    OUT.mkdir(parents=True, exist_ok=True)
    run_id = f"{time.time_ns()}-{os.getpid()}"
    log = OUT / f"probe-{run_id}.jsonl"
    err = OUT / f"probe-{run_id}.stderr"
    receipt = OUT / f"probe-{run_id}.receipt.json"
    verifier_log = OUT / f"probe-{run_id}.cleanup.jsonl"
    source = Path(__file__).with_name("broker.c")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    binary_hash = hashlib.sha256(BROKER.read_bytes()).hexdigest()
    before_ns = os.readlink("/proc/self/ns/mnt")
    before_mounts = Path("/proc/self/mountinfo").read_bytes()
    # Sudo executes exactly this fixed program. There is no shell, input path,
    # worker command, DB name, or runtime configuration supplied by the caller.
    command = ["sudo", "-n", str(BROKER), "--test-only"]
    with log.open("xb") as stdout, err.open("xb") as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                   stdin=subprocess.DEVNULL, close_fds=True)
        try:
            rc = process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            # Do not kill the root supervisor, because that could skip cleanup.
            # Its own pipe/pidfd phase timers are 15s. Stop and report this PID.
            receipt.write_text(json.dumps({"command": command, "running_sudo_pid": process.pid,
                                          "status": "TIMEOUT_NO_FORCED_KILL", "log": str(log)}) + "\n")
            print(f"Root supervisor timeout; preserve inaccessible fixture, inspect {receipt}", file=sys.stderr)
            return 1
    verified = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--verify", str(log)],
                              capture_output=True, text=True, check=False)
    verifier_log.write_text(verified.stdout + verified.stderr)
    caller_same = before_ns == os.readlink("/proc/self/ns/mnt") and before_mounts == Path("/proc/self/mountinfo").read_bytes()
    result = {"command": command, "exit": rc, "cleanup_verifier_exit": verified.returncode,
              "caller_namespace_mounts_unchanged": caller_same, "log": str(log), "stderr": str(err),
              "cleanup_log": str(verifier_log), "source_sha256": source_hash, "binary_sha256": binary_hash}
    receipt.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if verified.stdout:
        print(verified.stdout, end="")
    if verified.stderr:
        print(verified.stderr, end="", file=sys.stderr)
    events = read_log(log)
    final = [e for e in events if e.get("event") == "probe_result"]
    failed = [e for e in events if e.get("ok") is False]
    return 0 if rc == 0 and verified.returncode == 0 and caller_same and len(final) == 1 and final[0]["ok"] and not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
