#!/usr/bin/env python3
"""Offline staging only. No installer, service command or origin authority."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

BINARY = "/usr/local/libexec/podbay-r1-linux"
RUNTIME_MANIFEST = "/etc/podbay/r1-install-manifest.json"
BOOTSTRAP = "podbay-r1-closed-bootstrap.service"
CUSTODIAN = "podbay-r1-custodian.service"
DROPIN = "50-podbay-r1-closed.conf"
FIXTURE_ISSUER_COMMAND = "/bin/busybox touch /tmp/r1-issuer-ran"
REQUEST_SCHEMA = "podbay.r1.install-plan-request/1"
PLAN_SCHEMA = "podbay.r1.install-plan/1"
MAX_REQUEST = 262_144
MAX_BINARY = 67_108_864
MAX_UNIT = 32_768
MAX_ISSUERS = 32
ROUTES = (
    "user-manager", "login", "cron-at", "ssh", "containers", "initramfs-owner-code",
    "root-helper-fd-pass", "manual-owner-code", "alternate-source-aliases",
    "inherited-fd-mmap-scm-rights",
)
ANCHORS = ("local-fs.target", "sysinit.target", "basic.target", "multi-user.target")
BOOTSTRAP_TEMPLATE = """[Unit]
Description=PodBay R1 unavailable early bootstrap (staged plan only)
DefaultDependencies=no
RequiresMountsFor={vault_path}
After=local-fs.target
Before=sysinit.target basic.target {issuer_units}

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart=/usr/local/libexec/podbay-r1-linux bootstrap --manifest /etc/podbay/r1-install-manifest.json
RemainAfterExit=yes
Restart=no
TimeoutStartSec=30s
TimeoutStopSec=30s
KillMode=control-group

[Install]
WantedBy=sysinit.target
"""
CUSTODIAN_TEMPLATE = """[Unit]
Description=PodBay R1 unavailable custodian (staged plan only)
Requires=podbay-r1-closed-bootstrap.service
After=podbay-r1-closed-bootstrap.service

[Service]
Type=notify
User=root
Group=root
UMask=0077
ExecStart=/usr/local/libexec/podbay-r1-linux custodian --manifest /etc/podbay/r1-install-manifest.json
Restart=no
TimeoutStartSec=30s
TimeoutStopSec=30s
KillMode=control-group

[Install]
WantedBy=multi-user.target
"""
DROPIN_TEMPLATE = """[Unit]
Requires=podbay-r1-closed-bootstrap.service
After=podbay-r1-closed-bootstrap.service
"""
BLOCKERS = (
    "EXECUTABLE_HAS_NO_POSITIVE_COLD_BOOT_PROVENANCE",
    "DECLARED_ISSUER_INVENTORY_IS_NOT_INDEPENDENTLY_PROVED",
    "SOURCE_PROVISIONING_AND_ALIAS_EXCLUSION_UNVERIFIED",
    "PRIOR_DESTINATION_STATE_IS_CALLER_DECLARED_NOT_HOST_READBACK",
    "SYSTEMD_NATIVE_ORDER_FAILURE_AND_LATE_ENTRY_GATES_UNRUN",
    "ROOT_INSTALL_ACTIVATION_AND_REBOOT_NOT_AUTHORIZED",
)


class Refusal(Exception):
    """Static codes only; never echo input files or command text."""


def require(value, code):
    if not value:
        raise Refusal(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def keys(value, names):
    require(type(value) is dict and set(value) == set(names), "INVALID_FIELDS")
    return value


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, "INVALID_INTEGER")
    return value


def digest(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
            "INVALID_DIGEST")
    return value


def literal(value, maximum=128):
    require(type(value) is str and 1 <= len(value) <= maximum
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value) is not None,
            "INVALID_LITERAL")
    return value


def absolute(value):
    require(type(value) is str and 1 < len(value.encode("utf-8")) <= 4096
            and value.startswith("/") and "\\" not in value
            and all(ord(c) >= 32 and ord(c) != 127 for c in value)
            and all(p not in ("", ".", "..") for p in value[1:].split("/")),
            "INVALID_PATH")
    return value


def unit_name(value):
    require(type(value) is str and len(value) <= 128
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]*\.(?:service|target|mount)", value)
            and "@." not in value, "INVALID_UNIT_NAME")
    return value


def parse_json(data):
    require(0 < len(data) <= MAX_REQUEST, "REQUEST_BOUNDS")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def number(token):
        require(len(token) <= 20, "JSON_NUMBER_BOUNDS")
        return int(token)

    def no_float(_):
        raise Refusal("JSON_NUMBER_TYPE")

    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=pairs, parse_int=number,
                           parse_float=no_float, parse_constant=no_float)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise Refusal("INVALID_JSON") from error
    pending = [(value, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        require(depth <= 16 and count <= 8192, "JSON_BOUNDS")
        if type(node) is str:
            require(len(node.encode("utf-8")) <= 8192, "JSON_BOUNDS")
        elif type(node) is dict:
            require(len(node) <= 256, "JSON_BOUNDS")
            pending.extend((v, depth + 1) for pair in node.items() for v in pair)
        elif type(node) is list:
            require(len(node) <= 256, "JSON_BOUNDS")
            pending.extend((v, depth + 1) for v in node)
    return value


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def trusted_directory(info):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid())
            and not info.st_mode & 0o022, "UNTRUSTED_DIRECTORY")


class DirectoryChain:
    """Retain and recheck each nofollow component; no path-based writes."""
    def __init__(self, path):
        self.path = absolute(path) if path != "/" else path
        self.fds = []
        self.links = []
        try:
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.fds.append(fd)
            trusted_directory(os.fstat(fd))
            for component in path[1:].split("/") if path != "/" else []:
                parent = fd
                fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=parent)
                self.fds.append(fd)
                info = os.fstat(fd)
                trusted_directory(info)
                self.links.append((parent, component, fd, info.st_dev, info.st_ino))
            self.verify()
        except BaseException:
            self.close()
            raise

    @property
    def fd(self):
        return self.fds[-1]

    def verify(self):
        for fd in self.fds:
            trusted_directory(os.fstat(fd))
            try:
                os.stat(".git", dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Refusal("REPOSITORY_PATH")
        for parent, name, fd, dev, ino in self.links:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(fd)
            require(stat.S_ISDIR(current.st_mode)
                    and (current.st_dev, current.st_ino) == (dev, ino)
                    and (held.st_dev, held.st_ino) == (dev, ino), "DIRECTORY_REPLACED")

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def captured_file(path, expected, cap):
    path = absolute(path)
    expected = digest(expected)
    parent, name = path.rsplit("/", 1)
    with DirectoryChain(parent or "/") as chain:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=chain.fd)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_uid in (0, os.geteuid()) and not before.st_mode & 0o6022,
                    "UNTRUSTED_FILE")
            require(1 <= before.st_size <= cap, "FILE_BOUNDS")
            data = bytearray()
            while len(data) < before.st_size:
                chunk = os.read(fd, min(65536, before.st_size - len(data)))
                require(bool(chunk), "FILE_CHANGED")
                data.extend(chunk)
            require(os.read(fd, 1) == b"", "FILE_CHANGED")
            require(identity(before) == identity(os.fstat(fd)), "FILE_CHANGED")
            named = os.stat(name, dir_fd=chain.fd, follow_symlinks=False)
            require(identity(before) == identity(named), "FILE_REPLACED")
            chain.verify()
            raw = bytes(data)
            require(sha(raw) == expected, "DIGEST_MISMATCH")
            return raw
        finally:
            os.close(fd)


def file_spec(value, cap):
    keys(value, ("path", "sha256"))
    return captured_file(value["path"], value["sha256"], cap)


UNIT_FIELDS = {
    "Unit": {"Description", "After", "Before", "Requires", "Wants", "DefaultDependencies"},
    "Service": {"Type", "User", "Group", "UMask", "ExecStart", "RemainAfterExit", "Restart",
                "TimeoutStartSec", "TimeoutStopSec", "KillMode"},
    "Install": {"WantedBy", "RequiredBy"},
}


def parse_unit(raw):
    require(0 < len(raw) <= MAX_UNIT, "UNIT_BOUNDS")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise Refusal("INVALID_UNIT") from error
    sections = {}
    section = None
    for line in text.splitlines():
        require(not any(ord(c) < 32 for c in line) and "\\" not in line and "%" not in line,
                "UNSAFE_UNIT_SYNTAX")
        if not line or line.startswith("#"):
            continue
        require(line == line.strip(), "UNSAFE_UNIT_SYNTAX")
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            require(section in UNIT_FIELDS and section not in sections, "UNSAFE_UNIT_SECTION")
            sections[section] = {}
            continue
        require(section is not None and "=" in line, "INVALID_UNIT")
        key, value = line.split("=", 1)
        require(key in UNIT_FIELDS[section] and key not in sections[section] and value,
                "UNSAFE_UNIT_DIRECTIVE")
        require("$" not in value and not value.startswith(("-", "+", "!", "@", ":")),
                "UNSAFE_UNIT_SYNTAX")
        sections[section][key] = value
    require("Unit" in sections and "Service" in sections, "INVALID_UNIT")
    service = sections["Service"]
    require(service.get("Type") in ("oneshot", "simple", "exec", "notify")
            and service.get("Restart", "no") == "no"
            and service.get("ExecStart", "").startswith("/"), "UNSAFE_SERVICE")
    require(sections["Unit"].get("DefaultDependencies", "yes") in ("yes", "no"),
            "UNSAFE_UNIT_DIRECTIVE")
    # Issuer commands are pinned declarations, never executed by this generator.
    # Restrict this first fixture profile to a literal executable and arguments.
    command = service["ExecStart"].split(" ")
    require(all(command) and all(re.fullmatch(r"[A-Za-z0-9_./:@=-]+", v) for v in command),
            "UNSAFE_EXEC")
    absolute(command[0])
    require(Path(command[0]).name not in {"sh", "bash", "dash", "env", "sudo", "systemctl",
                                        "mount", "umount", "chmod", "chown", "rm", "reboot"},
            "UNSAFE_EXEC")
    if Path(command[0]).name == "busybox":
        require(command == ["/bin/busybox", "touch", "/tmp/r1-issuer-ran"], "UNSAFE_EXEC")
    for key in ("After", "Before", "Requires", "Wants"):
        values = sections["Unit"].get(key, "").split()
        require(len(values) == len(set(values)), "DUPLICATE_DEPENDENCY")
        for value in values:
            unit_name(value)
    return sections


def graph(issuer_units, bootstrap_raw, custodian_raw):
    all_units = {**issuer_units, BOOTSTRAP: bootstrap_raw, CUSTODIAN: custodian_raw}
    nodes = set(all_units) | set(ANCHORS)
    edges = set(zip(ANCHORS, ANCHORS[1:]))
    requirements = {}
    for name, raw in all_units.items():
        # RequiresMountsFor is fixed by our template, not accepted in issuer text.
        if name == BOOTSTRAP:
            raw = b"\n".join(line for line in raw.split(b"\n")
                             if not line.startswith(b"RequiresMountsFor="))
        parsed = parse_unit(raw)
        unit = parsed["Unit"]
        if unit.get("DefaultDependencies", "yes") == "yes":
            edges.add(("basic.target", name))
        for dependency in unit.get("After", "").split():
            require(dependency in nodes, "UNRESOLVED_DEPENDENCY")
            edges.add((dependency, name))
        for dependency in unit.get("Before", "").split():
            require(dependency in nodes, "UNRESOLVED_DEPENDENCY")
            edges.add((name, dependency))
        requirements[name] = unit.get("Requires", "").split()
        for key in ("Requires", "Wants"):
            require(all(v in nodes for v in unit.get(key, "").split()), "UNRESOLVED_DEPENDENCY")
        for key in ("WantedBy", "RequiredBy"):
            require(all(v in nodes for v in parsed.get("Install", {}).get(key, "").split()),
                    "UNRESOLVED_DEPENDENCY")
    for issuer in issuer_units:
        edges.add((BOOTSTRAP, issuer))
        requirements[issuer] = sorted(set(requirements[issuer]) | {BOOTSTRAP})
    remaining = set(nodes)
    ordered = []
    while remaining:
        ready = sorted(n for n in remaining if not any(b == n and a in remaining for a, b in edges))
        require(bool(ready), "CYCLIC_STAGED_GRAPH")
        ordered.extend(ready)
        remaining.difference_update(ready)
    return {"nodes": sorted(nodes), "ordering_edges": sorted([list(e) for e in edges]),
            "requires": requirements, "topological_order": ordered,
            "scope": "DECLARED_STAGED_STARTUP_GRAPH_ONLY",
            "implicit_mount_and_full_image_dependencies_verified": False}


def unavailable_manifest():
    return encoded({"schema": "podbay.r1.install-manifest/1", "deployment_blocked": True,
                    "availability": "UNAVAILABLE", "reason": "COLD_BOOT_PROVENANCE_UNAVAILABLE"})


def prepare(request):
    keys(request, ("schema", "generation", "binary", "subject", "issuer_inventory", "prior_state"))
    require(request["schema"] == REQUEST_SCHEMA, "REQUEST_SCHEMA")
    literal(request["generation"])
    subject = keys(request["subject"], ("vault_path", "source_relative_path", "source_sha256",
                                      "source_bytes", "source_lineage", "schema_sha256"))
    vault = absolute(subject["vault_path"])
    require(re.fullmatch(r"/[A-Za-z0-9_./-]+", vault) is not None, "UNSAFE_UNIT_PATH")
    relative = subject["source_relative_path"]
    require(type(relative) is str and 1 <= len(relative) <= 256
            and len(relative.split("/")) <= 4, "INVALID_SUBJECT_PATH")
    for component in relative.split("/"):
        literal(component)
        require(component not in (".", ".."), "INVALID_SUBJECT_PATH")
    digest(subject["source_sha256"])
    digest(subject["schema_sha256"])
    integer(subject["source_bytes"], 1, 268_435_456)
    literal(subject["source_lineage"], 256)
    inventory = keys(request["issuer_inventory"], ("scope", "image_id", "complete_declared",
                                                   "unresolved", "expected_units", "excluded_routes", "issuers"))
    require(inventory["scope"] == "DISPOSABLE_SYSTEMD_IMAGE_ONLY"
            and inventory["complete_declared"] is True
            and inventory["unresolved"] == [], "INCOMPLETE_ISSUER_INVENTORY")
    literal(inventory["image_id"])
    require(type(inventory["excluded_routes"]) is list
            and sorted(inventory["excluded_routes"]) == sorted(ROUTES), "INCOMPLETE_ISSUER_INVENTORY")
    expected = inventory["expected_units"]
    issuers = inventory["issuers"]
    require(type(expected) is list and 1 <= len(expected) <= MAX_ISSUERS
            and type(issuers) is list and len(issuers) == len(expected), "INCOMPLETE_ISSUER_INVENTORY")
    for name in expected:
        unit_name(name)
        require(name.endswith(".service") and name not in (BOOTSTRAP, CUSTODIAN), "ISSUER_COLLISION")
    require(len(set(expected)) == len(expected), "ISSUER_COLLISION")
    unit_inputs = {}
    issuer_records = []
    for item in issuers:
        keys(item, ("unit", "uid", "unit_file"))
        name = unit_name(item["unit"])
        require(name in expected and name not in unit_inputs, "INCOMPLETE_ISSUER_INVENTORY")
        uid = integer(item["uid"], 1, 2**32 - 2)
        raw = file_spec(item["unit_file"], MAX_UNIT)
        parsed = parse_unit(raw)
        require(parsed["Service"].get("User") == str(uid), "ISSUER_UID_MISMATCH")
        require(parsed["Service"].get("Group") == str(uid), "ISSUER_UID_MISMATCH")
        # This first package profile supports the reviewed diagnostic issuer
        # only. An arbitrary executable/interpreter is not made safe by syntax.
        require(parsed["Service"]["ExecStart"] == FIXTURE_ISSUER_COMMAND,
                "UNSUPPORTED_ISSUER_COMMAND")
        unit_inputs[name] = raw
        issuer_records.append({"unit": name, "uid": uid, "declared_unit_sha256": sha(raw),
                               "manager": "system", "inventory_verified": False})
    require(set(unit_inputs) == set(expected), "INCOMPLETE_ISSUER_INVENTORY")
    binary = file_spec(request["binary"], MAX_BINARY)
    require(binary.startswith(b"\x7fELF"), "BINARY_FORMAT")
    bootstrap = BOOTSTRAP_TEMPLATE.format(vault_path=vault, issuer_units=" ".join(sorted(expected))).encode()
    custodian = CUSTODIAN_TEMPLATE.encode()
    staged_graph = graph(unit_inputs, bootstrap, custodian)
    files = {
        BINARY: (binary, 0o755), RUNTIME_MANIFEST: (unavailable_manifest(), 0o600),
        f"/etc/systemd/system/{BOOTSTRAP}": (bootstrap, 0o644),
        f"/etc/systemd/system/{CUSTODIAN}": (custodian, 0o644),
    }
    for name in sorted(expected):
        files[f"/etc/systemd/system/{name}.d/{DROPIN}"] = (DROPIN_TEMPLATE.encode(), 0o644)
    prior = request["prior_state"]
    require(type(prior) is dict and set(prior) == set(files), "INCOMPLETE_PRIOR_STATE")
    backups = {}
    records = []
    for index, (destination, (raw, mode)) in enumerate(sorted(files.items())):
        before = prior[destination]
        require(type(before) is dict, "INVALID_PRIOR_STATE")
        if before.get("state") == "absent":
            keys(before, ("state",))
            prior_record = {"state": "absent", "observation": "CALLER_DECLARED_UNVERIFIED"}
        else:
            keys(before, ("state", "file", "uid", "gid", "mode"))
            require(before["state"] == "file" and type(before["uid"]) is int and before["uid"] == 0
                    and type(before["gid"]) is int and before["gid"] == 0, "INVALID_PRIOR_STATE")
            prior_mode = integer(before["mode"], 0, 0o777)
            require(prior_mode in (0o600, 0o644, 0o700, 0o755), "UNSAFE_PRIOR_MODE")
            old = file_spec(before["file"], MAX_BINARY if destination == BINARY else MAX_UNIT)
            backup = f"prior/{index:03d}.bin"
            backups[backup] = old
            prior_record = {"state": "file", "sha256": sha(old), "bytes": len(old),
                            "uid": 0, "gid": 0, "mode": prior_mode, "backup": backup,
                            "observation": "CALLER_DECLARED_UNVERIFIED"}
        records.append({"destination": destination, "staged": "rootfs" + destination,
                        "sha256": sha(raw), "bytes": len(raw),
                        "install_intent": {"uid": 0, "gid": 0, "mode": mode},
                        "staged_owner_uid": os.geteuid(), "staged_mode": 0o600, "prior": prior_record})
    plan = {"schema": PLAN_SCHEMA, "status": "OFFLINE_STAGED_PLAN_ONLY", "deployment_blocked": True,
            "generation": request["generation"], "blockers": list(BLOCKERS),
            "binary_contract": {"path": BINARY, "manifest": RUNTIME_MANIFEST,
                                "commands": ["bootstrap", "custodian"], "positive_acquisition": False},
            "policy": {"origin": "UNESTABLISHED", "admission": "UNAVAILABLE", "unseal": False,
                       "automatic_retry": False, "root_ownership_is_install_intent": True},
            "subject": {**subject, "observation": "CALLER_DECLARED_NOT_OPENED",
                        "vault_install_intent": {"uid": 0, "gid": 0, "mode": 0o700}},
            "issuer_inventory": {"scope": inventory["scope"], "image_id": inventory["image_id"],
                                 "complete_declared": True, "independently_verified": False,
                                 "excluded_routes_declared": list(ROUTES),
                                 "issuers": sorted(issuer_records, key=lambda row: row["unit"])},
            "files": records, "graph": staged_graph,
            "activation_links_created": False, "systemd_analyze_run": False}
    rollback = {"schema": "podbay.r1.manual-recovery-checklist/1", "automated_actions": [],
                "deployment_blocked": True,
                "default": "VAULT_DENIED_SOURCE_RETAINED_ISSUERS_BLOCKED",
                "steps": [
                    "Do not install, reload, enable, start, provision, adopt data or reboot from this plan.",
                    "Independently verify every destination prior byte/hash/owner/mode and the complete image issuer graph.",
                    "Obtain separate authorization for exact root installation and protected specimen provisioning.",
                    "After a failure retain vault/source/checkpoints/latch and block relevant issuers; do not unseal or retry.",
                    "Before any separately approved rollback prove exact custodian/broker/descendant/IPC teardown; unknown teardown stops.",
                    "Prior unit restoration or drop-in removal can reopen issuers; perform only the independently approved recovery sequence.",
                    "Use exact retained prior bytes and ownership/modes; never delete a latch/checkpoint to manufacture success.",
                    "A fresh kernel still begins denied; historical records never grant release."],
                "prior_files": [{"destination": row["destination"], "prior": row["prior"]} for row in records]}
    outputs = {"rootfs" + name: raw for name, (raw, _) in files.items()}
    outputs.update(backups)
    outputs.update({"graph-input/" + name: raw for name, raw in unit_inputs.items()})
    outputs["plan.json"] = encoded(plan)
    outputs["rollback-checklist.json"] = encoded(rollback)
    return outputs, plan


def stage(output, outputs):
    output = absolute(output)
    require(os.geteuid() != 0, "ROOT_PLAN_EXECUTION_REFUSED")
    require(output.split("/")[1] not in {"etc", "usr", "var", "run", "proc", "sys", "dev",
                                         "boot", "root", "bin", "sbin", "lib", "lib64"},
            "SYSTEM_STAGING_PATH")
    repository = str(Path(__file__).absolute().parents[2])
    require(output != repository and not output.startswith(repository + "/"), "REPOSITORY_PATH")
    parent, name = output.rsplit("/", 1)
    with DirectoryChain(parent or "/") as chain:
        chain.verify()
        os.mkdir(name, 0o700, dir_fd=chain.fd)  # Exclusive; even an empty existing path refuses.
        root_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=chain.fd)
        with ExitStack() as stack:
            stack.callback(os.close, root_fd)
            root_info = os.fstat(root_fd)
            require(root_info.st_uid == os.geteuid() and stat.S_IMODE(root_info.st_mode) == 0o700,
                    "STAGE_IDENTITY")
            dirs = {"": root_fd}
            links = []
            written_files = []

            def verify():
                chain.verify()
                current = os.stat(name, dir_fd=chain.fd, follow_symlinks=False)
                require(stat.S_ISDIR(current.st_mode) and (current.st_dev, current.st_ino)
                        == (root_info.st_dev, root_info.st_ino)
                        and stat.S_IMODE(current.st_mode) == 0o700
                        and current.st_uid == os.geteuid(), "STAGE_REPLACED")
                for parent_fd, part, fd, info in links:
                    named = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
                    held = os.fstat(fd)
                    require((named.st_dev, named.st_ino) == (info.st_dev, info.st_ino)
                            and stat.S_ISDIR(named.st_mode) and named.st_uid == os.geteuid()
                            and stat.S_IMODE(named.st_mode) == 0o700
                            and (held.st_dev, held.st_ino) == (info.st_dev, info.st_ino), "STAGE_REPLACED")
                for parent_fd, filename, expected_info in written_files:
                    named = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
                    require(identity(named) == identity(expected_info), "OUTPUT_REPLACED")

            def write(relative, raw):
                require(not relative.startswith("/") and all(p not in ("", ".", "..") for p in relative.split("/")),
                        "OUTPUT_COLLISION")
                parts = relative.split("/")
                prefix = ""
                fd = root_fd
                verify()
                for part in parts[:-1]:
                    child = prefix + "/" + part
                    if child not in dirs:
                        os.mkdir(part, 0o700, dir_fd=fd)
                        child_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                        stack.callback(os.close, child_fd)
                        info = os.fstat(child_fd)
                        links.append((fd, part, child_fd, info))
                        dirs[child] = child_fd
                    fd = dirs[child]
                    prefix = child
                verify()
                target = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=fd)
                try:
                    offset = 0
                    while offset < len(raw):
                        written = os.write(target, raw[offset:])
                        require(written > 0, "SHORT_WRITE")
                        offset += written
                    os.fsync(target)
                    info = os.fstat(target)
                    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                            and info.st_uid == os.geteuid() and info.st_nlink == 1 and info.st_size == len(raw),
                            "OUTPUT_IDENTITY")
                    named = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
                    require(identity(named) == identity(info), "OUTPUT_REPLACED")
                    written_files.append((fd, parts[-1], info))
                finally:
                    os.close(target)
                os.fsync(fd)
                verify()

            for relative, raw in sorted(outputs.items()):
                write(relative, raw)
            receipt = {"schema": "podbay.r1.staged-plan-completion/1", "deployment_blocked": True,
                       "files": [{"path": p, "sha256": sha(raw), "bytes": len(raw)} for p, raw in sorted(outputs.items())]}
            # Completion is last. Failures retain partial output; no recursive rollback.
            write("COMPLETE.json", encoded(receipt))
            for fd in reversed(list(dirs.values())):
                os.fsync(fd)
            os.fsync(chain.fd)
            verify()
    return receipt


def generate(request_path, request_sha256, output):
    require(sys.platform == "linux", "UNSUPPORTED_PLATFORM")
    require(os.geteuid() != 0, "ROOT_PLAN_EXECUTION_REFUSED")
    request_raw = captured_file(request_path, request_sha256, MAX_REQUEST)
    request = parse_json(request_raw)
    outputs, plan = prepare(request)
    stage(output, outputs)
    return {"status": "OFFLINE_STAGED_PLAN_ONLY", "deployment_blocked": True,
            "output": output, "plan_sha256": sha(encoded(plan)), "file_count": len(outputs)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True)
    parser.add_argument("--request-sha256", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = generate(args.request, args.request_sha256, args.output)
    except (Refusal, OSError, UnicodeError, TypeError, ValueError) as error:
        code = str(error) if type(error) is Refusal else "IO_OR_INPUT_REFUSED"
        print(json.dumps({"status": "REFUSED", "deployment_blocked": True,
                          "code": code, "partial_stage_may_be_retained": True}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
