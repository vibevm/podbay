#!/usr/bin/env python3
"""Ordinary-UID disposable filesystem controls; no service or enforcer execution."""
import copy
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import plan_install as plan

ISSUER = "r1-issuer.service"
ISSUER_BYTES = b"[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nUser=1000\nGroup=1000\nExecStart=/bin/busybox touch /tmp/r1-issuer-ran\nRestart=no\n"


class InstallPlanTest(unittest.TestCase):
    def setUp(self):
        self.assertEqual(sys.platform, "linux")
        self.assertNotEqual(os.geteuid(), 0, "these disposable tests must use an ordinary UID")
        # /tmp is writable ancestry and is intentionally not a positive fixture.
        self.base = Path(tempfile.mkdtemp(prefix="podbay-r1-plan-test-", dir=Path.home()))
        self.addCleanup(shutil.rmtree, self.base)
        self.binary = self.write("podbay-r1-linux", b"\x7fELFoffline-test-bytes-never-executed")
        self.unit = self.write(ISSUER, ISSUER_BYTES)
        self.request_path = self.base / "request.json"
        self.output = self.base / "stage"
        self.request = {
            "schema": plan.REQUEST_SCHEMA, "generation": "fixture-1",
            "binary": self.spec(self.binary),
            "subject": {"vault_path": "/fixture/vault", "source_relative_path": "state/db.sqlite",
                        "source_sha256": "1" * 64, "source_bytes": 397312,
                        "source_lineage": "00000000000000000000000000000024", "schema_sha256": "2" * 64},
            "issuer_inventory": {"scope": "DISPOSABLE_SYSTEMD_IMAGE_ONLY", "image_id": "fixed-disposable-image",
                                 "complete_declared": True, "unresolved": [], "expected_units": [ISSUER],
                                 "excluded_routes": list(plan.ROUTES),
                                 "issuers": [{"unit": ISSUER, "uid": 1000, "unit_file": self.spec(self.unit)}]},
            "prior_state": {p: {"state": "absent"} for p in self.destinations()},
        }

    def write(self, name, data):
        path = self.base / name
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def spec(self, path):
        return {"path": str(path), "sha256": plan.sha(path.read_bytes())}

    def destinations(self):
        return ["/usr/local/libexec/podbay-r1-linux", "/etc/podbay/r1-install-manifest.json",
                "/etc/systemd/system/podbay-r1-closed-bootstrap.service",
                "/etc/systemd/system/podbay-r1-custodian.service",
                "/etc/systemd/system/r1-issuer.service.d/50-podbay-r1-closed.conf"]

    def generate(self, request=None, output=None):
        raw = plan.encoded(self.request if request is None else request)
        self.write("request.json", raw)
        return plan.generate(str(self.request_path), plan.sha(raw), str(output or self.output))

    def refused(self, request, code):
        with self.assertRaisesRegex(plan.Refusal, "^" + code + "$", msg=code):
            self.generate(request)
        self.assertFalse(self.output.exists())

    def changed_unit(self, raw):
        self.unit.write_bytes(raw)
        request = copy.deepcopy(self.request)
        request["issuer_inventory"]["issuers"][0]["unit_file"] = self.spec(self.unit)
        return request

    def test_complete_plan_is_blocked_and_all_installed_bytes_have_exact_root_intent(self):
        response = self.generate()
        self.assertEqual(response["status"], "OFFLINE_STAGED_PLAN_ONLY")
        self.assertTrue(response["deployment_blocked"])
        document = json.loads((self.output / "plan.json").read_bytes())
        self.assertEqual(document["schema"], "podbay.r1.install-plan/1")
        self.assertEqual(document["subject"]["observation"], "CALLER_DECLARED_NOT_OPENED")
        self.assertFalse(document["issuer_inventory"]["independently_verified"])
        self.assertFalse(document["activation_links_created"])
        self.assertEqual(set(row["destination"] for row in document["files"]), set(self.destinations()))
        for row in document["files"]:
            path = self.output / row["staged"]
            self.assertEqual(plan.sha(path.read_bytes()), row["sha256"])
            self.assertEqual(path.stat().st_size, row["bytes"])
            self.assertEqual(row["install_intent"]["uid"], 0)
            self.assertEqual(row["install_intent"]["gid"], 0)
            self.assertEqual(row["prior"], {"state": "absent", "observation": "CALLER_DECLARED_UNVERIFIED"})
        binary = next(row for row in document["files"] if row["destination"] == plan.BINARY)
        self.assertEqual(binary["install_intent"]["mode"], 0o755)
        self.assertEqual(binary["staged_mode"], 0o600)
        marker = json.loads((self.output / ("rootfs" + plan.RUNTIME_MANIFEST)).read_bytes())
        self.assertEqual(marker, {"schema": "podbay.r1.install-manifest/1", "availability": "UNAVAILABLE",
                                  "deployment_blocked": True, "reason": "COLD_BOOT_PROVENANCE_UNAVAILABLE"})
        gate = self.output / "rootfs/etc/systemd/system/r1-issuer.service.d/50-podbay-r1-closed.conf"
        self.assertEqual(gate.read_bytes(), b"[Unit]\nRequires=podbay-r1-closed-bootstrap.service\nAfter=podbay-r1-closed-bootstrap.service\n")
        self.assertIn(plan.BOOTSTRAP, document["graph"]["requires"][ISSUER])
        self.assertIn([plan.BOOTSTRAP, ISSUER], document["graph"]["ordering_edges"])
        for path in [self.output, *self.output.rglob("*")]:
            info = path.lstat()
            self.assertFalse(stat.S_ISLNK(info.st_mode))
            self.assertEqual(info.st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o700 if path.is_dir() else 0o600)
            if path.is_file():
                self.assertEqual(info.st_nlink, 1)
        completion = json.loads((self.output / "COMPLETE.json").read_bytes())
        for entry in completion["files"]:
            self.assertEqual(plan.sha((self.output / entry["path"]).read_bytes()), entry["sha256"])

    def test_outputs_are_deterministic_and_templates_match_review_copies(self):
        self.generate(output=self.base / "a")
        self.generate(output=self.base / "b")
        a = {str(p.relative_to(self.base / "a")): p.read_bytes() for p in (self.base / "a").rglob("*") if p.is_file()}
        b = {str(p.relative_to(self.base / "b")): p.read_bytes() for p in (self.base / "b").rglob("*") if p.is_file()}
        self.assertEqual(a, b)
        folder = Path(__file__).parent / "systemd"
        for name, text in [("podbay-r1-closed-bootstrap.service.in", plan.BOOTSTRAP_TEMPLATE),
                           ("podbay-r1-custodian.service.in", plan.CUSTODIAN_TEMPLATE),
                           ("issuer-gate.conf.in", plan.DROPIN_TEMPLATE)]:
            self.assertEqual((folder / name).read_text(), text)

    def test_incomplete_and_foreign_issuer_declarations_refuse(self):
        changes = [
            ("complete_declared", False), ("complete_declared", 1), ("unresolved", ["ssh"]),
            ("scope", "OWNER_MACHINE"), ("expected_units", []), ("expected_units", [ISSUER, "other.service"]),
            ("issuers", []), ("excluded_routes", list(plan.ROUTES[:-1])),
            ("excluded_routes", list(plan.ROUTES) + [plan.ROUTES[0]]),
        ]
        for field, value in changes:
            request = copy.deepcopy(self.request)
            request["issuer_inventory"][field] = value
            self.refused(request, "INCOMPLETE_ISSUER_INVENTORY")
        request = copy.deepcopy(self.request)
        request["issuer_inventory"]["issuers"][0]["uid"] = 1001
        self.refused(request, "ISSUER_UID_MISMATCH")
        request = copy.deepcopy(self.request)
        request["issuer_inventory"]["expected_units"] = [plan.BOOTSTRAP]
        self.refused(request, "ISSUER_COLLISION")

    def test_closed_request_json_and_duplicate_fields_refuse(self):
        request = copy.deepcopy(self.request)
        request["force"] = True
        self.refused(request, "INVALID_FIELDS")
        raw = plan.encoded(self.request)
        bads = [b'{"schema":"a","schema":"b"}', b'{"x":NaN}', b'{"x":1.0}', b'\xff',
                b'[' * 1000 + b'0' + b']' * 1000, b' ' * (plan.MAX_REQUEST + 1)]
        for bad in bads:
            self.write("request.json", bad)
            with self.assertRaises((plan.Refusal, UnicodeError)):
                plan.generate(str(self.request_path), plan.sha(bad), str(self.output))
            self.assertFalse(self.output.exists())
        self.write("request.json", raw)
        with self.assertRaisesRegex(plan.Refusal, "DIGEST_MISMATCH"):
            plan.generate(str(self.request_path), "0" * 64, str(self.output))

    def test_declared_subject_is_bounded_closed_data_and_never_a_grant(self):
        for field, value in [("source_relative_path", "../outside"), ("source_relative_path", "/absolute"),
                             ("source_relative_path", "a//db"), ("source_relative_path", "a/b/c/d/e"),
                             ("source_bytes", 0), ("source_bytes", True), ("source_bytes", 268435457),
                             ("source_sha256", "x" * 64), ("schema_sha256", "0" * 63),
                             ("source_lineage", "lineage\n"), ("vault_path", "/fixture/../vault")]:
            request = copy.deepcopy(self.request)
            request["subject"][field] = value
            with self.assertRaises(plan.Refusal):
                self.generate(request)
            self.assertFalse(self.output.exists())
        request = copy.deepcopy(self.request)
        request["subject"]["closed"] = True
        self.refused(request, "INVALID_FIELDS")

    def test_unsafe_unit_directives_and_commands_refuse(self):
        for directive in [b"ConditionPathExists=/fixture/vault", b"OnFailure=unseal.service",
                          b"ExecCondition=/bin/true", b"ExecStop=/bin/chmod 777 /fixture/vault",
                          b"ExecStartPre=/bin/true", b"EnvironmentFile=/private/credentials",
                          b"FailureAction=reboot", b"SuccessAction=reboot"]:
            raw = ISSUER_BYTES.replace(b"Restart=no", directive + b"\nRestart=no")
            self.refused(self.changed_unit(raw), "UNSAFE_UNIT_DIRECTIVE")
        for command in [b"/bin/sh -c true", b"/usr/bin/env /bin/true", b"/bin/busybox sh -c true",
                        b"-/bin/true", b"+/bin/true", b"/bin/true;reboot", b"/bin/true $SECRET", b"/bin/true %i"]:
            raw = ISSUER_BYTES.replace(b"/bin/busybox touch /tmp/r1-issuer-ran", command)
            with self.assertRaises(plan.Refusal):
                self.generate(self.changed_unit(raw))
            self.assertFalse(self.output.exists())
        raw = ISSUER_BYTES.replace(b"Restart=no", b"Restart=always")
        self.refused(self.changed_unit(raw), "UNSAFE_SERVICE")
        for command in [b"/tmp/renamed-helper", b"/usr/bin/python3 /tmp/script.py"]:
            raw = ISSUER_BYTES.replace(b"/bin/busybox touch /tmp/r1-issuer-ran", command)
            self.refused(self.changed_unit(raw), "UNSUPPORTED_ISSUER_COMMAND")

    def test_actual_staged_order_cycle_and_unknown_dependency_refuse(self):
        raw = ISSUER_BYTES.replace(b"DefaultDependencies=no", b"DefaultDependencies=no\nBefore=local-fs.target")
        self.refused(self.changed_unit(raw), "CYCLIC_STAGED_GRAPH")
        raw = ISSUER_BYTES.replace(b"DefaultDependencies=no", b"DefaultDependencies=yes\nBefore=sysinit.target")
        self.refused(self.changed_unit(raw), "CYCLIC_STAGED_GRAPH")
        raw = ISSUER_BYTES.replace(b"DefaultDependencies=no", b"DefaultDependencies=no\nAfter=missing.service")
        self.refused(self.changed_unit(raw), "UNRESOLVED_DEPENDENCY")

    def test_symlink_writable_and_hardlinked_inputs_refuse(self):
        self.binary.chmod(0o660)
        with self.assertRaisesRegex(plan.Refusal, "UNTRUSTED_FILE"):
            self.generate()
        self.binary.chmod(0o600)
        os.link(self.binary, self.base / "hardlink")
        with self.assertRaisesRegex(plan.Refusal, "UNTRUSTED_FILE"):
            self.generate()
        (self.base / "hardlink").unlink()
        link = self.base / "link"
        link.symlink_to(self.binary)
        request = copy.deepcopy(self.request)
        request["binary"]["path"] = str(link)
        with self.assertRaises(OSError):
            self.generate(request)
        self.base.chmod(0o770)
        try:
            with self.assertRaisesRegex(plan.Refusal, "UNTRUSTED_DIRECTORY"):
                self.generate()
        finally:
            self.base.chmod(0o700)
        self.assertFalse(self.output.exists())

    def test_staging_existing_symlink_parent_repo_and_system_paths_refuse(self):
        self.output.mkdir(mode=0o700)
        (self.output / "sentinel").write_bytes(b"unchanged")
        with self.assertRaises(FileExistsError):
            self.generate()
        self.assertEqual((self.output / "sentinel").read_bytes(), b"unchanged")
        shutil.rmtree(self.output)
        self.output.symlink_to(self.base)
        with self.assertRaises(FileExistsError):
            self.generate()
        self.output.unlink()
        alias = self.base / "parent-alias"
        alias.symlink_to(self.base)
        with self.assertRaises(OSError):
            self.generate(output=alias / "child")
        with self.assertRaisesRegex(plan.Refusal, "SYSTEM_STAGING_PATH"):
            self.generate(output=Path("/etc/podbay-plan-must-not-exist"))
        with self.assertRaisesRegex(plan.Refusal, "REPOSITORY_PATH"):
            self.generate(output=Path(__file__).absolute().parents[2] / "must-not-create")
        with self.assertRaisesRegex(plan.Refusal, "UNTRUSTED_DIRECTORY"):
            self.generate(output=Path("/tmp/r1-plan-must-not-create"))

    def test_real_input_replacement_during_read_refuses(self):
        raw_request = plan.encoded(self.request)
        self.write("request.json", raw_request)
        original = os.read
        changed = False

        def read(fd, count):
            nonlocal changed
            data = original(fd, count)
            if not changed:
                changed = True
                self.request_path.rename(self.base / "request-old")
                self.write("request.json", raw_request)
            return data

        with patch.object(os, "read", read):
            with self.assertRaisesRegex(plan.Refusal, "FILE_CHANGED|FILE_REPLACED"):
                plan.generate(str(self.request_path), plan.sha(raw_request), str(self.output))
        self.assertFalse(self.output.exists())

    def test_write_failure_retains_partial_without_completion_or_cleanup(self):
        real_write = os.write
        count = 0

        def write(fd, data):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("injected write failure")
            return real_write(fd, data)

        with patch.object(os, "write", write):
            with self.assertRaises(OSError):
                self.generate()
        self.assertTrue(self.output.exists())
        self.assertFalse((self.output / "COMPLETE.json").exists())
        self.assertTrue(any(self.output.rglob("*")))
        with self.assertRaises(FileExistsError):
            self.generate()

    def test_output_directory_swap_is_detected_with_no_completion(self):
        real_write = os.write
        replaced = False

        def write(fd, data):
            nonlocal replaced
            result = real_write(fd, data)
            if not replaced:
                replaced = True
                self.output.rename(self.base / "original-stage")
                self.output.mkdir(mode=0o700)
                (self.output / "sentinel").write_bytes(b"replacement")
            return result

        with patch.object(os, "write", write):
            with self.assertRaisesRegex(plan.Refusal, "STAGE_REPLACED"):
                self.generate()
        self.assertEqual((self.output / "sentinel").read_bytes(), b"replacement")
        self.assertFalse((self.base / "original-stage/COMPLETE.json").exists())

    def test_completed_earlier_file_swap_is_detected(self):
        real_write = os.write
        count = 0

        def write(fd, data):
            nonlocal count
            result = real_write(fd, data)
            count += 1
            if count == 2:
                first = self.output / ("graph-input/" + ISSUER)
                first.rename(first.with_name("old-unit"))
                first.write_bytes(b"unexpected replacement")
                first.chmod(0o600)
            return result

        with patch.object(os, "write", write):
            with self.assertRaisesRegex(plan.Refusal, "OUTPUT_REPLACED"):
                self.generate()
        self.assertFalse((self.output / "COMPLETE.json").exists())

    def test_prior_state_is_exact_pinned_inert_backup_and_must_be_complete(self):
        request = copy.deepcopy(self.request)
        request["prior_state"].pop(plan.BINARY)
        self.refused(request, "INCOMPLETE_PRIOR_STATE")
        request = copy.deepcopy(self.request)
        request["prior_state"][plan.BINARY] = {"state": "unknown"}
        self.refused(request, "INVALID_FIELDS")
        old = self.write("prior-binary.bin", b"prior exact bytes")
        request = copy.deepcopy(self.request)
        request["prior_state"][plan.BINARY] = {"state": "file", "file": self.spec(old), "uid": 0, "gid": 0, "mode": 0o755}
        self.generate(request)
        document = json.loads((self.output / "plan.json").read_bytes())
        row = next(row for row in document["files"] if row["destination"] == plan.BINARY)
        self.assertEqual((self.output / row["prior"]["backup"]).read_bytes(), old.read_bytes())
        self.assertEqual(row["prior"]["sha256"], plan.sha(old.read_bytes()))
        self.assertEqual(row["prior"]["observation"], "CALLER_DECLARED_UNVERIFIED")
        recovery = json.loads((self.output / "rollback-checklist.json").read_bytes())
        self.assertEqual(recovery["automated_actions"], [])
        self.assertEqual(recovery["default"], "VAULT_DENIED_SOURCE_RETAINED_ISSUERS_BLOCKED")

    def test_no_external_process_or_subject_read_and_root_invocation_refuses(self):
        subject = self.write("live-looking.sqlite", b"SQLite format 3\0must not be read")
        request = copy.deepcopy(self.request)
        request["subject"]["vault_path"] = str(self.base)
        request["subject"]["source_relative_path"] = subject.name
        request["subject"]["source_sha256"] = plan.sha(subject.read_bytes())
        original = plan.captured_file
        observed = []

        def capture(path, expected, cap):
            self.assertNotEqual(path, str(subject))
            observed.append(path)
            return original(path, expected, cap)

        with patch.object(subprocess, "run", side_effect=AssertionError("process launch")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process launch")), \
             patch.object(os, "system", side_effect=AssertionError("shell launch")), \
             patch.object(plan, "captured_file", capture):
            self.generate(request)
        self.assertEqual(set(observed), {str(self.request_path), str(self.binary), str(self.unit)})
        with patch.object(os, "geteuid", return_value=0), \
             patch.object(plan, "captured_file", side_effect=AssertionError("root read")):
            with self.assertRaisesRegex(plan.Refusal, "ROOT_PLAN_EXECUTION_REFUSED"):
                plan.generate("/unused", "0" * 64, str(self.base / "root-refused"))

    def test_cli_emits_only_plan_status_and_has_no_activation_option(self):
        raw = plan.encoded(self.request)
        self.write("request.json", raw)
        result = subprocess.run([sys.executable, "-B", str(Path(plan.__file__)), "--request", str(self.request_path),
                                 "--request-sha256", plan.sha(raw), "--output", str(self.output)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertTrue(json.loads(result.stdout)["deployment_blocked"])
        refused = subprocess.run([sys.executable, "-B", str(Path(plan.__file__)), "--install"],
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(refused.returncode, 2)


if __name__ == "__main__":
    unittest.main()
