#!/usr/bin/env python3
"""Independent bounded offline artifact checks. Never boots or mounts anything."""
from contextlib import contextmanager
import tempfile
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('offline', HERE / 'offline.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
BASE = builder.BASE


def digest(data):
    return hashlib.sha256(data).hexdigest()


def archive(data):
    raw = gzip.decompress(data)
    pos, entries = 0, {}
    while True:
        if raw[pos:pos + 6] != b'070701':
            raise ValueError('invalid newc magic')
        f = [int(raw[pos + 6 + x * 8:pos + 14 + x * 8], 16) for x in range(13)]
        pos += 110
        namebytes = raw[pos:pos + f[11]]
        if not namebytes.endswith(b'\0'):
            raise ValueError('missing archive name terminator')
        name = namebytes[:-1].decode('ascii')
        pos = (pos + f[11] + 3) & ~3
        content = raw[pos:pos + f[6]]
        if len(content) != f[6]:
            raise ValueError('short archive content')
        pos = (pos + f[6] + 3) & ~3
        if name == 'TRAILER!!!':
            if any(raw[pos:]):
                raise ValueError('nonzero archive tail')
            break
        if name in entries or name.startswith('/') or any(x in ('', '.', '..') for x in name.split('/')):
            raise ValueError('unsafe/duplicate archive name')
        entries[name] = (f, content)
    return entries


def debug(image, command):
    r = subprocess.run([builder.PINS['debugfs'][0], '-R', command, str(image)],
                       capture_output=True, check=True, timeout=20)
    if re.search(r'File not found|Filesystem not open|Usage:|while |Command not found|Could not|Error', r.stderr.decode(), re.I):
        raise ValueError(r.stderr.decode())
    return r.stdout


@contextmanager
def private_fixture():
    """Only clean exact inode/owner-checked entries this invocation created."""
    with builder.TrustedOutput(BASE) as guard:
        root = Path(tempfile.mkdtemp(prefix='offline-test-', dir=BASE))
        rootfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        rootst = os.fstat(rootfd)
        created = []
        def record(path):
            created.append((path, path.lstat()))
            return path
        def file(name, data):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=rootfd)
            path = root / name
            record(path)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
            return path
        try:
            guard.check()
            yield root, rootfd, record, file
        finally:
            guard.check()
            now = root.lstat()
            if (now.st_dev, now.st_ino, now.st_uid) != (rootst.st_dev, rootst.st_ino, os.getuid()):
                raise ValueError('refusing cleanup of replaced test directory')
            for path, original in reversed(created):
                current = path.lstat()
                if (current.st_dev, current.st_ino, current.st_uid, stat.S_IFMT(current.st_mode)) != (
                        original.st_dev, original.st_ino, os.getuid(), stat.S_IFMT(original.st_mode)):
                    raise ValueError('refusing cleanup of replaced test entry')
                if stat.S_ISDIR(current.st_mode):
                    path.rmdir()
                else:
                    path.unlink()
            os.close(rootfd)
            os.rmdir(root.name, dir_fd=guard.pins[BASE])


class OfflineArtifacts(unittest.TestCase):
    def test_independent_archive_and_disk(self):
        out = BASE / 'final-a'
        image = out / 'fixture.raw'
        self.assertEqual(image.stat().st_size, builder.SIZE)
        superblock = debug(image, 'stats').decode()
        self.assertIn('Filesystem UUID:          ' + builder.UUID, superblock)
        self.assertIn('Filesystem features:      filetype extent sparse_super large_file', superblock)
        self.assertIn('Filesystem state:         clean', superblock)
        self.assertIn('Mount count:              0', superblock)
        self.assertEqual(stat.S_IMODE(image.stat().st_mode), 0o600)
        report = json.loads((out / 'build-report.json').read_text())
        self.assertFalse(report['boot_executed'])
        self.assertEqual(report['status'], 'OFFLINE_ASSEMBLED_UNBOOTED_STUB')
        self.assertEqual(report['admission'], 'UNIMPLEMENTED')
        self.assertEqual(report['gate'], 'CLOSED')
        for name, expected in report['artifacts'].items():
            self.assertEqual(digest((out / name).read_bytes()), expected, name)
        parsed = archive((out / 'initramfs.cpio.gz').read_bytes())
        expected_modes = {n: stat.S_IFDIR | 0o755 for n in ('bin', 'dev', 'etc', 'fixture', 'proc', 'sys')}
        expected_modes.update({'bin/busybox': stat.S_IFREG | 0o755, 'dev/console': stat.S_IFCHR | 0o600,
                               'etc/fixture.sha256': stat.S_IFREG | 0o600, 'init': stat.S_IFREG | 0o700})
        self.assertEqual(set(parsed), set(expected_modes))
        self.assertEqual(list(parsed), sorted(parsed))
        for name, (fields, data) in parsed.items():
            self.assertEqual(fields[1], expected_modes[name], name)
            self.assertEqual(fields[2:4], [0, 0], name)
            self.assertEqual(fields[5], builder.EPOCH, name)
        self.assertEqual(parsed['dev/console'][0][9:11], [5, 1])
        self.assertEqual(digest(parsed['bin/busybox'][1]), builder.PINS['busybox'][1])
        builder.static_elf(parsed['bin/busybox'][1])
        init = parsed['init'][1]
        self.assertTrue(init.startswith(b'#!/bin/busybox sh\n'))
        self.assertIn(b'ro,noload,nosuid,nodev,noexec', init)
        self.assertIn(b'fail persistent_broker_and_two_boot_protocol_unimplemented', init)
        manifestbytes = debug(image, 'cat /disk-manifest.json')
        manifest = json.loads(manifestbytes)
        self.assertEqual(manifestbytes, (out / 'disk-manifest.json').read_bytes())
        self.assertEqual(manifest['gate'], 'CLOSED')
        self.assertEqual(manifest['admission'], 'UNIMPLEMENTED')
        expected_init = (HERE / 'init.closed').read_bytes().replace(b'# No owner execution is implemented.',
            f'[ \"$(/bin/busybox stat -c \'%i\' /fixture/vault/state/db.sqlite)\" = {manifest["db"]["inode"]} ] || fail database_inode\n# No owner execution is implemented.'.encode())
        self.assertEqual(init, expected_init)
        self.assertEqual(debug(image, 'cat /gate'), builder.GATE)
        seed = debug(image, 'cat /vault/state/db.sqlite')
        self.assertEqual(digest(seed), builder.DB_HASH)
        self.assertEqual(digest(seed), manifest['db']['sha256'])
        self.assertEqual(seed[:16], b'SQLite format 3\0')
        identities = {'/': (0, 0, '0700'), '/vault': (0, 0, '0700'),
                      '/vault/state': (1000, 1000, '0700'), '/vault/state/db.sqlite': (1000, 1000, '0600'),
                      '/gate': (0, 0, '0600'), '/disk-manifest.json': (0, 0, '0600')}
        for path, (uid, gid, mode) in identities.items():
            st = debug(image, 'stat ' + path).decode()
            self.assertIn('Type: directory' if path in ('/', '/vault', '/vault/state') else 'Type: regular', st)
            if path not in ('/', '/vault', '/vault/state'):
                self.assertRegex(st, r'Links: 1\s')
            self.assertRegex(st, rf'Mode:\s+{mode}')
            self.assertRegex(st, rf'User:\s+{uid}\s+Group:\s+{gid}\b')
            for field in ('atime', 'ctime', 'mtime', 'crtime'):
                self.assertRegex(st, rf'{field}:\s+0x{builder.EPOCH:08x}:00000000')
            if path == '/vault/state/db.sqlite':
                self.assertIn('Inode: ' + str(manifest['db']['inode']) + ' ', st)
                self.assertIn(('stat -c \'%i\' /fixture/vault/state/db.sqlite)" = ' + str(manifest['db']['inode'])).encode(), init)
        # Enumerate the entire fixture tree, not only known files.
        wanted = {'/': {'.', '..', 'vault', 'gate', 'disk-manifest.json'},
                  '/vault': {'.', '..', 'state'}, '/vault/state': {'.', '..', 'db.sqlite'}}
        for path, names in wanted.items():
            listing = debug(image, 'ls -p ' + path).decode()
            found = {line.split('/')[5] for line in listing.splitlines() if line.startswith('/')}
            self.assertEqual(found, names)
        for line in parsed['etc/fixture.sha256'][1].decode().splitlines():
            expected, name = line.split('  ')
            self.assertTrue(name.startswith('/fixture/'))
            self.assertEqual(digest(debug(image, 'cat ' + name[len('/fixture'): ])), expected)

    def test_reproducible_artifacts(self):
        for name in ('vmlinuz', 'fixture.raw', 'initramfs.cpio.gz', 'disk-manifest.json', 'initramfs.contents.json'):
            self.assertEqual(digest((BASE / 'final-a' / name).read_bytes()),
                             digest((BASE / 'final-b' / name).read_bytes()), name)

    def test_refusal_before_output_on_bad_inputs(self):
        with self.assertRaisesRegex(ValueError, 'fixed local ISO'):
            builder.build('wrong-iso', Path('/nonexistent.iso'))
        self.assertFalse((BASE / 'wrong-iso').exists())
        with self.assertRaisesRegex(ValueError, 'invalid build name'):
            builder.build('../escape')
        with private_fixture() as (root, rootfd, record, file):
            bad = file('wrong-busybox', b'wrong bytes')
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                builder.read_pinned(bad, builder.PINS['busybox'][1])
            old = builder.PINS['busybox']
            try:
                builder.PINS['busybox'] = (old[0], '0' * 64)
                with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                    builder.build('bad-input-refusal')
            finally:
                builder.PINS['busybox'] = old
            self.assertFalse((BASE / 'bad-input-refusal').exists())
        with self.assertRaisesRegex(ValueError, 'dynamic or interpreter'):
            # Mutated header with PT_INTERP validates the independent static check.
            data = bytearray((BASE / 'final-a' / 'vmlinuz').read_bytes()[:128])
            data[:6] = b'\x7fELF\x02\x01'
            import struct
            struct.pack_into('<H', data, 18, 62)
            struct.pack_into('<Q', data, 32, 64)
            struct.pack_into('<HH', data, 54, 56, 1)
            struct.pack_into('<I', data, 64, 3)
            builder.static_elf(data)


    def test_output_mode_ancestor_symlink_and_replacement_refusals(self):
        with private_fixture() as (root, rootfd, record, file):
            root.chmod(0o755)
            try:
                with self.assertRaisesRegex(ValueError, 'owner mode 0700'):
                    builder.TrustedOutput(root)
            finally:
                root.chmod(0o700)
            ancestor = root / 'writable-ancestor'
            ancestor.mkdir(mode=0o700)
            record(ancestor)
            child = ancestor / 'private'
            child.mkdir(mode=0o700)
            record(child)
            ancestor.chmod(0o775)
            try:
                with self.assertRaisesRegex(ValueError, 'untrusted output ancestor'):
                    builder.TrustedOutput(child)
            finally:
                ancestor.chmod(0o700)
            target = file('sentinel', b'unchanged')
            link = root / 'linked'
            link.symlink_to(target)
            record(link)
            with self.assertRaises(OSError):
                builder.TrustedOutput(link)
            with self.assertRaises(FileExistsError):
                os.open('linked', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600, dir_fd=rootfd)
            self.assertEqual(target.read_bytes(), b'unchanged')
            with builder.TrustedOutput(root) as guarded:
                out = guarded.create_dir('existing')
                record(out)
                with self.assertRaises(FileExistsError):
                    guarded.create_dir('existing')
                guarded.write('image', b'fixture')
                record(out / 'image')
                guarded.write('sentinel', b'unchanged')
                record(out / 'sentinel')
                with self.assertRaises(FileExistsError):
                    guarded.write('sentinel', b'clobber')
                self.assertEqual((out / 'sentinel').read_bytes(), b'unchanged')
                # Replace a tracked image with a symlink; guard must stop before tools.
                (out / 'image').rename(out / 'original-image')
                created_link = out / 'image'
                created_link.symlink_to(out / 'sentinel')
                link_identity = created_link.lstat()
                try:
                    with self.assertRaisesRegex(ValueError, 'identity drift'):
                        guarded.check()
                    self.assertEqual((out / 'sentinel').read_bytes(), b'unchanged')
                finally:
                    current = created_link.lstat()
                    if (current.st_dev, current.st_ino, current.st_uid) != (
                            link_identity.st_dev, link_identity.st_ino, os.getuid()):
                        raise ValueError('refusing cleanup of replaced test symlink')
                    created_link.unlink()
                    (out / 'original-image').rename(out / 'image')


if __name__ == '__main__':
    unittest.main(verbosity=2)
