#!/usr/bin/env python3
"""Read-only local inputs for a proposed fixture; never starts or builds a VM."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import sys


TOOLS = ("qemu-system-x86_64", "qemu-img", "cpio", "gcc", "busybox",
         "mke2fs", "debugfs", "unsquashfs", "vmrun", "vmware-vdiskmanager")
SECTOR = 2048


def inspect_iso(path):
    """Validate bounded ISO9660 records; hash kernel bytes without extracting."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        size = os.fstat(stream.fileno()).st_size
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("ISO input must be a regular file")

        def read(offset, count):
            if offset < 0 or count < 0 or offset + count > size:
                raise ValueError("ISO extent outside file")
            stream.seek(offset)
            data = stream.read(count)
            if len(data) != count:
                raise ValueError("short ISO read")
            return data

        def record(data):
            if len(data) < 34 or data[0] != len(data):
                raise ValueError("malformed ISO directory record")
            extent, length = struct.unpack_from("<I", data, 2)[0], struct.unpack_from("<I", data, 10)[0]
            if extent != struct.unpack_from(">I", data, 6)[0] or length != struct.unpack_from(">I", data, 14)[0]:
                raise ValueError("ISO endian fields disagree")
            name_length = data[32]
            if 33 + name_length > len(data):
                raise ValueError("truncated ISO name")
            name = data[33:33 + name_length]
            if extent * SECTOR + length > size:
                raise ValueError("ISO record outside file")
            return extent, length, data[25], name

        def listing(entry):
            extent, length, flags, _ = entry
            if not flags & 2 or length > 1024 * 1024:
                raise ValueError("expected bounded ISO directory")
            data = read(extent * SECTOR, length)
            offset = 0
            entries = []
            while offset < length:
                count = data[offset]
                if not count:
                    offset = (offset // SECTOR + 1) * SECTOR
                    continue
                if offset % SECTOR + count > SECTOR:
                    raise ValueError("ISO record crosses sector")
                item = record(data[offset:offset + count])
                offset += count
                if item[3] not in (b"\0", b"\1"):
                    entries.append(item)
            return entries

        def pick(entries, expected):
            hits = [e for e in entries if e[3].decode("ascii").split(";")[0].rstrip(".").upper() == expected]
            if len(hits) != 1:
                raise ValueError("expected exactly one ISO entry: " + expected)
            return hits[0]

        pvd = read(16 * SECTOR, SECTOR)
        if pvd[:7] != b"\x01CD001\x01" or struct.unpack_from("<H", pvd, 128)[0] != SECTOR:
            raise ValueError("unsupported ISO9660 primary descriptor")
        root = record(pvd[156:156 + pvd[156]])
        casper = listing(pick(listing(root), "CASPER"))
        result = {"path": str(Path(path).absolute()), "bytes": size, "entries": {}}
        for name in ("VMLINUZ", "INITRD"):
            extent, length, flags, _ = pick(casper, name)
            if flags & (2 | 128) or not 1024 <= length <= 256 * 1024 * 1024:
                raise ValueError("invalid kernel/initrd entry")
            data = read(extent * SECTOR, length)
            entry = {"offset": extent * SECTOR, "bytes": length,
                     "sha256": hashlib.sha256(data).hexdigest()}
            if name == "VMLINUZ":
                if data[0x202:0x206] != b"HdrS" or data[0x1fe:0x200] != b"\x55\xaa":
                    raise ValueError("kernel lacks Linux x86 boot header")
                entry["linux_x86_boot_header"] = True
            result["entries"][name.lower()] = entry
        result["compatibility_verified"] = False
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", required=True, help="explicit local Ubuntu ISO; no extraction or downloads")
    args = parser.parse_args()
    tools = {name: shutil.which(name) for name in TOOLS}
    result = {"schema": 1, "scope": "TEST_ONLY_INPUT_INVENTORY", "boot_executed": False,
              "tools": tools, "missing": [], "iso": None}
    try:
        result["iso"] = inspect_iso(args.iso)
    except (OSError, ValueError, UnicodeError, struct.error) as error:
        result["missing"].append("validated readable local ISO kernel/initrd: " + str(error))
    try:
        metadata = os.stat("/dev/kvm")
        result["kvm"] = {"character_device": stat.S_ISCHR(metadata.st_mode),
                         "read_write_access": os.access("/dev/kvm", os.R_OK | os.W_OK),
                         "acceleration_verified": False}
    except OSError as error:
        result["kvm"] = {"error": str(error), "acceleration_verified": False}
    for name in ("qemu-system-x86_64", "cpio", "gcc", "mke2fs"):
        if not tools[name]:
            result["missing"].append("executable: " + name)
    # ISO bytes establish availability, never reviewed boot-policy completeness.
    result["missing"].extend([
        "reviewed kernel config and matching module closure for ext4/virtio and namespaces/seccomp",
        "reviewed fixture PID1, persistent broker/rebind and clean exec worker implementation",
        "reviewed raw-disk/initramfs builder and outside-guest lifecycle verifier",
    ])
    result["status"] = "BLOCKED_NOT_BOOTED"
    print(json.dumps(result, indent=2, sort_keys=True))
    return 3


if __name__ == "__main__":
    sys.exit(main())
