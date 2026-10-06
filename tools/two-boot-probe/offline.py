#!/usr/bin/env python3
"""Pinned local assembler only. Never launches a VM, mounts, or opens admission."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import struct
import subprocess
import sys

BASE = Path('/home/olegchir/podbay-two-boot-offline-build')
ISO = Path('/home/olegchir/Downloads/ubuntu-26.04.1-desktop-amd64.iso')
EPOCH = 1700000000
UUID = '10cc005e-0000-4000-8000-000000000001'
SIZE = 32 * 1024 * 1024
PINS = {
    'busybox': ('/usr/bin/busybox', 'df12634c17fcdca839ae5dc47d7627b7558511f7645de7c99ccf097a0f28ed5b'),
    'mke2fs': ('/usr/sbin/mke2fs', 'e42e49656dfc308efeed86f9bfad7746fc22ad1d4a3b0d508b5dba7a4b9a904f'),
    'debugfs': ('/usr/sbin/debugfs', '864e1d7b445e7b5bfc831da78330dbcafc590fa82b89ea9de60b7527f989954f'),
    'unsquashfs': ('/usr/bin/unsquashfs', '003a7e9d70fbdcd05dfe132101c4b7bbb19a217976777f5393573eff21ddc202'),
}
KERNEL = (5166469120, 17295752, '0ad39b13e289e1a5cf806d14541ac8f221eefe849017f5915e0846917ed67785')
ISO_SIZE = 6482409472
ISO_HASH = '601e30fbf5d97759367c632e2c33630665039b7e2158fd068403da3ccf1bda1f'
CONFIG_HASH = 'b07d3cb0d53236b021d73038e315018801fa6b843529d53129ad94a2a5233bf6'
BUILTIN_HASH = 'ef55d7bc5528d2c01f38fc0d8f6473c75e14ec62349898f6529be9bbac871366'
DB_HASH = 'f0261e453e64e433aa736b5d200a711f089b49771eee6e1bf4981d5a70b62ce8'
CONFIG_PATH = 'boot/config-7.0.0-30-generic'
BUILTIN_PATH = 'usr/lib/modules/7.0.0-30-generic/modules.builtin'
GATE = b'schema=1\npolicy=offline-closed-v1\ngeneration=1\nnonce=OFFLINE-DETERMINISTIC-NOT-A-RUNTIME-NONCE\nstate=CLOSED\nadmission=UNIMPLEMENTED\n'
REQUIRED_CONFIG = ('EXT4_FS', 'VIRTIO', 'VIRTIO_BLK', 'VIRTIO_PCI', 'DEVTMPFS',
                   'BLK_DEV_INITRD', 'RD_GZIP', 'BINFMT_SCRIPT', 'PROC_FS', 'SYSFS',
                   'TMPFS', 'NAMESPACES', 'SECCOMP', 'SECCOMP_FILTER', 'SERIAL_8250_CONSOLE')
REQUIRED_BUILTIN = ('kernel/fs/ext4/ext4.ko', 'kernel/drivers/virtio/virtio.ko',
                    'kernel/drivers/virtio/virtio_ring.ko', 'kernel/drivers/virtio/virtio_pci.ko',
                    'kernel/drivers/block/virtio_blk.ko')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular_fd(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    s = os.fstat(fd)
    if not stat.S_ISREG(s.st_mode):
        os.close(fd)
        raise ValueError('input must be a regular non-symlink file: ' + str(path))
    return fd


def fd_hash(fd):
    h = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        data = os.read(fd, 1024 * 1024)
        if not data:
            return h.hexdigest()
        h.update(data)


def read_pinned(path, expected):
    fd = regular_fd(path)
    try:
        if fd_hash(fd) != expected:
            raise ValueError('SHA-256 mismatch: ' + str(path))
        os.lseek(fd, 0, os.SEEK_SET)
        return os.read(fd, os.fstat(fd).st_size)
    finally:
        os.close(fd)


def static_elf(data):
    if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 62:
        raise ValueError('BusyBox must be little-endian x86_64 ELF64')
    off = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    if size != 56 or off + count * size > len(data):
        raise ValueError('malformed ELF program headers')
    if any(struct.unpack_from('<I', data, off + i * size)[0] in (2, 3) for i in range(count)):
        raise ValueError('BusyBox has dynamic or interpreter program header')


def newc(entries):
    """Exact sorted newc archive with root identity, fixed times and inode numbers."""
    result = bytearray()
    for ino, (name, mode, data, major, minor) in enumerate(entries + [('TRAILER!!!', 0, b'', 0, 0)], 1):
        rawname = name.encode('ascii') + b'\0'
        fields = (ino, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1, EPOCH,
                  len(data), 0, 0, major, minor, len(rawname), 0)
        result.extend(b'070701' + ''.join(f'{x:08x}' for x in fields).encode('ascii'))
        result.extend(rawname)
        result.extend(b'\0' * (-len(result) % 4))
        result.extend(data)
        result.extend(b'\0' * (-len(result) % 4))
    result.extend(b'\0' * (-len(result) % 512))
    return bytes(result)


class TrustedOutput:
    """Retain directory/file descriptors and refuse identity or permission drift."""
    def __init__(self, root, create=False):
        self.root = Path(root)
        self.pins = {}
        self.out = None
        try:
            if not self.root.is_absolute() or '..' in self.root.parts:
                raise ValueError('output root must be absolute without traversal')
            parent = None
            for i, part in enumerate(self.root.parts):
                path = Path(*self.root.parts[:i + 1])
                if i == len(self.root.parts) - 1 and create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=parent)
                    except FileExistsError:
                        pass
                fd = os.open('/' if i == 0 else part,
                             os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                             dir_fd=parent)
                self.pins[path] = fd
                st = os.fstat(fd)
                if st.st_uid not in (0, os.getuid()) or stat.S_IMODE(st.st_mode) & 0o022:
                    raise ValueError('untrusted output ancestor: ' + str(path))
                parent = fd
            st = os.fstat(parent)
            if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
                raise ValueError('output base must be owner mode 0700')
            self.check()
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    def close(self):
        for fd in self.pins.values():
            os.close(fd)
        self.pins.clear()

    def check(self):
        for path, fd in self.pins.items():
            pinned = os.fstat(fd)
            current = os.stat(path, follow_symlinks=False)
            if (current.st_dev, current.st_ino, current.st_mode, current.st_uid) != (
                    pinned.st_dev, pinned.st_ino, pinned.st_mode, pinned.st_uid):
                raise ValueError('output identity drift: ' + str(path))
            mode = stat.S_IMODE(current.st_mode)
            if stat.S_ISDIR(current.st_mode):
                if current.st_uid not in (0, os.getuid()) or mode & 0o022:
                    raise ValueError('untrusted output ancestor: ' + str(path))
                if path == self.root or path == self.out:
                    if current.st_uid != os.getuid() or mode != 0o700:
                        raise ValueError('output directory must be owner mode 0700')
            elif not stat.S_ISREG(current.st_mode) or current.st_uid != os.getuid() or mode != 0o600 or current.st_nlink != 1:
                raise ValueError('output file must remain owned regular mode 0600 with one link')

    def create_dir(self, name):
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', name):
            raise ValueError('invalid build name')
        self.check()
        os.mkdir(name, 0o700, dir_fd=self.pins[self.root])
        self.out = self.root / name
        self.pins[self.out] = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                     dir_fd=self.pins[self.root])
        self.check()
        return self.out

    def write(self, name, data):
        self.check()
        if self.out is None or not re.fullmatch(r'[a-zA-Z0-9_.-]+', name):
            raise ValueError('invalid output filename')
        path = self.out / name
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                     0o600, dir_fd=self.pins[self.out])
        self.pins[path] = fd
        os.fchmod(fd, 0o600)
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(data)
        self.check()

    def read(self, name):
        self.check()
        fd = self.pins[self.out / name]
        return os.pread(fd, os.fstat(fd).st_size, 0)


def trusted_tool(path):
    # Installed root-owned path trust; not execution-inode attestation.
    path = Path(path)
    for item in reversed(path.parents):
        st = item.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError('untrusted installed tool ancestor: ' + str(item))
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise ValueError('untrusted root-owned installed tool: ' + str(path))


def build(name, iso_path=ISO):
    # Validate every input before creating output. No caller-controlled commands.
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', name):
        raise ValueError('invalid build name')
    if Path(iso_path) != ISO:
        raise ValueError('only the fixed local ISO is allowed')
    with TrustedOutput(BASE, create=True) as output:
        for path, _ in PINS.values():
            trusted_tool(path)
        tools = {key: read_pinned(path, digest) for key, (path, digest) in PINS.items()}
        static_elf(tools['busybox'])
        iso_fd = regular_fd(iso_path)
        try:
            if os.fstat(iso_fd).st_size != ISO_SIZE or fd_hash(iso_fd) != ISO_HASH:
                raise ValueError('ISO size/SHA-256 mismatch')
            kernel = os.pread(iso_fd, KERNEL[1], KERNEL[0])
            if sha(kernel) != KERNEL[2] or kernel[0x202:0x206] != b'HdrS' or kernel[0x1fe:0x200] != b'\x55\xaa':
                raise ValueError('kernel extent/hash/header mismatch')
            def squash(path):
                cmd = [PINS['unsquashfs'][0], '-cat', '-o', '105723904', f'/proc/self/fd/{iso_fd}', path]
                output.check()
                trusted_tool(cmd[0])
                result = subprocess.run(cmd, pass_fds=(iso_fd,), check=True, capture_output=True, timeout=60).stdout
                output.check()
                return result
            config, builtin = squash(CONFIG_PATH), squash(BUILTIN_PATH)
            if sha(config) != CONFIG_HASH or sha(builtin) != BUILTIN_HASH:
                raise ValueError('kernel config/modules.builtin mismatch')
            if any(f'CONFIG_{x}=y' not in config.decode().splitlines() for x in REQUIRED_CONFIG):
                raise ValueError('required kernel feature is not built in')
            if any(x not in builtin.decode().splitlines() for x in REQUIRED_BUILTIN):
                raise ValueError('required ext4/virtio builtin absent')
        finally:
            os.close(iso_fd)
        with sqlite3.connect(':memory:') as db:
            db.executescript('PRAGMA page_size=4096; CREATE TABLE specimen(id INTEGER PRIMARY KEY, value INTEGER); INSERT INTO specimen VALUES(1,42);')
            seed = db.serialize()
        if sha(seed) != DB_HASH:
            raise ValueError('SQLite fixture bytes mismatch')
        init = Path(__file__).with_name('init.closed').read_bytes()
        if not init.startswith(b'#!/bin/busybox sh\n'):
            raise ValueError('invalid fixed PID1 interpreter')
        out = output.create_dir(name)
        write = output.write
        write('vmlinuz', kernel)
        write('kernel.config', config)
        write('modules.builtin', builtin)
        write('db.sqlite', seed)
        write('gate', GATE)
        # Force deterministic mke2fs config: don't depend on /etc/mke2fs.conf.
        write('mke2fs.conf', b'[defaults]\nbase_features = sparse_super,large_file,filetype,extent\nblocksize = 4096\ninode_size = 256\ninode_ratio = 16384\n[fs_types]\next4 = {\nfeatures = extent\n}\n')
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC',
               'E2FSPROGS_FAKE_TIME': str(EPOCH), 'SOURCE_DATE_EPOCH': str(EPOCH),
               'MKE2FS_CONFIG': str(out / 'mke2fs.conf')}
        commands = []
        def run(cmd, logfile):
            output.check()
            trusted_tool(cmd[0])
            r = subprocess.run(cmd, env=env, capture_output=True, timeout=60)
            output.check()
            write(logfile, r.stdout + r.stderr)
            commands.append({'argv': cmd, 'exit': r.returncode})
            if r.returncode:
                raise ValueError('offline tool failed: ' + cmd[0])
            return r.stdout.decode() + r.stderr.decode()
        image = out / 'fixture.raw'
        write('fixture.raw', b'')
        os.ftruncate(output.pins[image], SIZE)
        output.check()
        run([PINS['mke2fs'][0], '-q', '-t', 'ext4', '-b', '4096', '-I', '256', '-N', '2048',
             '-m', '0', '-U', UUID, '-L', 'PODBAY-CLOSED', '-O', 'none,extent,filetype,sparse_super,large_file',
             '-E', f'lazy_itable_init=0,hash_seed={UUID}', str(image)], 'mke2fs.log')
        def debug(commands_text, tag, writable=False):
            script = out / (tag + '.debugfs')
            write(script.name, commands_text.encode())
            cmd = [PINS['debugfs'][0]] + (['-w'] if writable else []) + ['-f', str(script), str(image)]
            result = run(cmd, tag + '.log')
            # debugfs can exit zero even when a command fails.
            if re.search(r'File not found|Filesystem not open|Usage:|while |Command not found|Could not|Error|not a directory', result, re.I):
                raise ValueError('debugfs command failed; inspect ' + tag + '.log')
            return result
        debug(f'rmdir /lost+found\nmkdir /vault\nmkdir /vault/state\nwrite {out}/db.sqlite /vault/state/db.sqlite\nwrite {out}/gate /gate\n', 'populate', True)
        identities = {'/': (0, 0, '040700'), '/vault': (0, 0, '040700'),
                      '/vault/state': (1000, 1000, '040700'), '/vault/state/db.sqlite': (1000, 1000, '0100600'), '/gate': (0, 0, '0100600')}
        def inode_settings(paths):
            lines = []
            for path, (uid, gid, mode) in paths.items():
                for key, val in [('uid', uid), ('gid', gid), ('mode', mode), ('atime', EPOCH), ('ctime', EPOCH), ('mtime', EPOCH), ('crtime', EPOCH)]:
                    lines.append(f'set_inode_field {path} {key} {val}')
            return '\n'.join(lines) + '\n'
        debug(inode_settings(identities), 'identity', True)
        stats = debug('stat /vault/state/db.sqlite\n', 'database-stat')
        match = re.search(r'Inode: (\d+)', stats)
        if not match:
            raise ValueError('cannot obtain offline database inode')
        db_inode = int(match[1])
        manifest = {'schema': 1, 'scope': 'TEST_ONLY_OFFLINE_STUB', 'policy': 'offline-closed-v1',
                    'generation': 1, 'nonce': 'OFFLINE-DETERMINISTIC-NOT-A-RUNTIME-NONCE',
                    'gate': 'CLOSED', 'admission': 'UNIMPLEMENTED', 'fs_uuid': UUID,
                    'db': {'path': '/vault/state/db.sqlite', 'inode': db_inode, 'uid': 1000, 'gid': 1000,
                           'mode': '0600', 'bytes': len(seed), 'sha256': sha(seed)},
                    'gate_sha256': sha(GATE)}
        write('disk-manifest.json', (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode())
        debug(f'write {out}/disk-manifest.json /disk-manifest.json\n', 'manifest-write', True)
        identities['/disk-manifest.json'] = (0, 0, '0100600')
        debug(inode_settings(identities), 'final-identity', True)
        checks = (f'{sha(GATE)}  /fixture/gate\n{sha(seed)}  /fixture/vault/state/db.sqlite\n'
                  f'{sha(output.read("disk-manifest.json"))}  /fixture/disk-manifest.json\n').encode()
        # Pin exact DB inode to the stub; no caller-provided authority manifest.
        init = init.replace(b'# No owner execution is implemented.',
            f'[ "$(/bin/busybox stat -c \'%i\' /fixture/vault/state/db.sqlite)" = {db_inode} ] || fail database_inode\n# No owner execution is implemented.'.encode())
        entries = [(x, stat.S_IFDIR | 0o755, b'', 0, 0) for x in ('bin', 'dev', 'etc', 'fixture', 'proc', 'sys')]
        entries += [('bin/busybox', stat.S_IFREG | 0o755, tools['busybox'], 0, 0),
                    ('dev/console', stat.S_IFCHR | 0o600, b'', 5, 1),
                    ('etc/fixture.sha256', stat.S_IFREG | 0o600, checks, 0, 0),
                    ('init', stat.S_IFREG | 0o700, init, 0, 0)]
        entries.sort(key=lambda e: e[0])
        archive = newc(entries)
        write('initramfs.cpio.gz', gzip.compress(archive, compresslevel=9, mtime=0))
        write('initramfs.contents.json', (json.dumps([{'path': n, 'mode': oct(m), 'uid': 0, 'gid': 0,
            'bytes': len(d), 'sha256': sha(d), 'rdev': [a, b]} for n, m, d, a, b in entries], indent=2, sort_keys=True) + '\n').encode())
        report = {'schema': 1, 'status': 'OFFLINE_ASSEMBLED_UNBOOTED_STUB', 'boot_executed': False,
                  'admission': 'UNIMPLEMENTED', 'gate': 'CLOSED', 'epoch': EPOCH,
                  'iso_sha256': ISO_HASH, 'kernel_sha256': KERNEL[2], 'kernel_config_sha256': CONFIG_HASH,
                  'modules_builtin_sha256': BUILTIN_HASH, 'tool_pins': PINS, 'sqlite_version': sqlite3.sqlite_version,
                  'source_sha256': sha(Path(__file__).read_bytes()), 'pid1_source_sha256': sha(Path(__file__).with_name('init.closed').read_bytes()),
                  'kernel_feature_check': 'CONFIG_y_AND_modules.builtin', 'module_files_required': [],
                  'tool_execution_trust': 'root-owned installed paths; no execution-inode attestation',
                  'commands': commands, 'artifacts': {n: sha(output.read(n)) for n in
                      ('vmlinuz', 'initramfs.cpio.gz', 'fixture.raw', 'disk-manifest.json', 'initramfs.contents.json')},
                  'missing_proof': ['actual direct-kernel boot', 'boot-A issued-handle negative controls',
                      'fresh boot-B closed admission and clean exec sealing', 'persistent broker/rebind',
                      'durable crash recovery and dirty late engagement refusals', 'outside hypervisor lifecycle verifier']}
        write('build-report.json', (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
        print(json.dumps({'status': report['status'], 'output': str(out), 'artifacts': report['artifacts']}, sort_keys=True))
        return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--name', required=True, help='new single build directory under the fixed external output root')
    p.add_argument('--iso', default=str(ISO), help='fixed pinned ISO only; other paths refused')
    args = p.parse_args()
    try:
        build(args.name, Path(args.iso))
    except (OSError, ValueError, subprocess.SubprocessError, sqlite3.Error) as error:
        print(json.dumps({'status': 'REFUSED_OR_BUILD_FAILED', 'boot_executed': False, 'error': str(error)}), file=sys.stderr)
        return 2
    return 0  # Assembler success only; never a two-boot pass.


if __name__ == '__main__':
    sys.exit(main())
