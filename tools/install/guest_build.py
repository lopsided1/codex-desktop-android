"""Run package configuration in a disposable guest's private mount namespace.

Only new root-owned /var/tmp/codex-phone-image-* trees are admitted. Temporary
devices/proc never enter an exported rootfs; no host device tree is bind-mounted.
This requires a real Linux build VM, not Android/PRoot or an installed phone.
"""
import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys


def validate(root):
    root = Path(root)
    work = root.parent
    if (root.name != 'rootfs' or work.parent != Path('/var/tmp')
            or not work.name.startswith('codex-phone-image-')):
        raise ValueError('Expected a disposable phone-image build tree')
    for path in (work, root, root / 'dev', root / 'proc'):
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or path.resolve(strict=True) != path
                or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022):
            raise ValueError('Guest build directories must be real private root-owned directories')
    return root


def command(root, argv):
    root = validate(root)
    unshare = shutil.which('unshare')
    if not unshare:
        raise RuntimeError('Native Linux unshare is required for package configuration')
    return [unshare, '--mount', '--propagation', 'private', sys.executable, '-B',
            str(Path(__file__).resolve()), 'namespace', '--root', str(root), '--', *map(str, argv)]


def namespace(root, argv):
    root = validate(root)
    if os.geteuid() != 0 or Path('/system/build.prop').exists():
        raise RuntimeError('Use a disposable native Linux build VM')
    if os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt'):
        raise RuntimeError('Refusing device mounts outside a private mount namespace')
    mount, chroot = shutil.which('mount'), shutil.which('chroot')
    if not mount or not chroot:
        raise RuntimeError('Native mount/chroot tools are required')
    device, proc = root / 'dev', root / 'proc'
    def run(args):
        subprocess.run(list(map(str, args)), check=True, timeout=15)
    # Every mount is private and vanishes even on abrupt namespace termination.
    run([mount, '-t', 'tmpfs', '-o', 'size=1m,mode=0755,nosuid,noexec', 'tmpfs', device])
    for name, major, minor in (('null', 1, 3), ('zero', 1, 5), ('random', 1, 8), ('urandom', 1, 9)):
        os.mknod(device / name, stat.S_IFCHR | 0o666, os.makedev(major, minor))
        (device / name).chmod(0o666)
    (device / 'pts').mkdir()
    run([mount, '-t', 'devpts', '-o', 'newinstance,ptmxmode=0666,mode=0620,nosuid,noexec',
         'devpts', device / 'pts'])
    (device / 'ptmx').symlink_to('pts/ptmx')
    (device / 'fd').symlink_to('/proc/self/fd')
    for name, fd in (('stdin', 0), ('stdout', 1), ('stderr', 2)):
        (device / name).symlink_to('/proc/self/fd/' + str(fd))
    run([mount, '-t', 'proc', '-o', 'nosuid,nodev,noexec', 'proc', proc])
    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root',
                   'LC_ALL': 'C.UTF-8', 'DEBIAN_FRONTEND': 'noninteractive'}
    result = subprocess.run([chroot, str(root), *argv], env=environment)
    return result.returncode


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('namespace',))
    parser.add_argument('--root', type=Path, required=True)
    # Keep the guest argv separate from the helper's named arguments.
    split = sys.argv.index('--') if '--' in sys.argv else len(sys.argv)
    args = parser.parse_args(sys.argv[1:split])
    argv = sys.argv[split + 1:]
    if not argv:
        parser.error('Expected a guest command after --')
    raise SystemExit(namespace(args.root, argv))
