"""Export an inactive PRoot tree, never its private link2symlink backing files.

Only the explicit host-PRoot build route uses this module. Public guest files
are materialized by tar and then compared byte-for-byte with the visible tree.
No build-host absolute backing links may escape into an Android release image.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile


def private_path(name):
    return any(part.startswith('.l2s.') for part in Path(name).parts)


def visible_inventory(root):
    records, private = {}, []
    for base, directories, files in os.walk(root, followlinks=False):
        for name in sorted(directories + files):
            path = Path(base) / name
            relative = path.relative_to(root).as_posix()
            if private_path(relative):
                private.append(relative)
                continue
            info = path.lstat()
            row = {'mode': stat.S_IMODE(info.st_mode)}
            if stat.S_ISREG(info.st_mode):
                with path.open('rb') as stream:
                    row.update(kind='file', bytes=info.st_size,
                               sha256=hashlib.file_digest(stream, 'sha256').hexdigest())
            elif stat.S_ISDIR(info.st_mode):
                row.update(kind='directory')
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                if private_path(target):
                    raise ValueError('Public guest link exposes PRoot backing storage: ' + relative)
                row.update(kind='symlink', target=target)
            else:
                raise ValueError('Special object in inactive export: ' + relative)
            records[relative] = row
        directories[:] = sorted(name for name in directories if not name.startswith('.l2s.'))
    return records, private


def write_archive(root, archive, evidence):
    root, archive = Path(root), Path(archive)
    expected, private = visible_inventory(root)
    with archive.open('wb') as stream:
        tar = subprocess.Popen(['tar', '--sort=name', '--hard-dereference',
            '--exclude=.l2s.*', '--numeric-owner', '--format=posix',
            '--pax-option=delete=atime,delete=ctime', '-C', str(root), '-cf', '-', '.'],
            stdout=subprocess.PIPE)
        try:
            subprocess.run(['gzip', '-n', '-6'], stdin=tar.stdout, stdout=stream, check=True)
            tar.stdout.close()
            if tar.wait():
                raise RuntimeError('PRoot visible-tree tar failed')
        finally:
            if tar.poll() is None:
                tar.terminate()
                tar.wait()
    actual = {}
    with tarfile.open(archive, 'r:gz') as stream:
        for member in stream:
            name = member.name.removeprefix('./').rstrip('/')
            if name in ('', '.') and member.isdir():
                continue
            if private_path(name) or name in actual or member.islnk():
                raise ValueError('Private, duplicate or non-materialized archive member: ' + name)
            row = {'mode': member.mode}
            if member.isfile():
                with stream.extractfile(member) as payload:
                    row.update(kind='file', bytes=member.size,
                               sha256=hashlib.file_digest(payload, 'sha256').hexdigest())
            elif member.isdir():
                row.update(kind='directory')
            elif member.issym():
                row.update(kind='symlink', target=member.linkname)
            else:
                raise ValueError('Unsupported archive member: ' + name)
            actual[name] = row
    if actual != expected or visible_inventory(root)[0] != expected:
        changed = sorted(k for k in set(actual) | set(expected) if actual.get(k) != expected.get(k))
        raise ValueError('Export differs from the inactive visible guest tree: ' + repr(changed[:20]))
    Path(evidence).write_text(json.dumps({'schema': 'codex.proot-visible-export.v1',
        'publicMembers': len(actual), 'publicBytesLinksModesVerified': True,
        'privateBackingEntriesExcluded': private, 'androidExecuted': False}, indent=2) + '\n')
