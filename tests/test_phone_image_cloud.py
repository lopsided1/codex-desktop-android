"""Native image admission/transport tests; no VM, mount or download is performed."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/install'))
import guest_build

SPEC = importlib.util.spec_from_file_location('phone_cloud_tests', ROOT / 'tools/ci/phone-image-cloud.py')
CLOUD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLOUD)


class PhoneCloudTests(unittest.TestCase):
    def test_local_session_is_not_a_native_cloud_vm(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(RuntimeError, 'native ARM64'):
            CLOUD.require_vm()

    def test_image_stage_is_not_admitted_as_ordinary_user(self):
        environment = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'GITHUB_WORKSPACE': str(ROOT)}
        with patch.dict(os.environ, environment), patch.object(CLOUD.platform, 'machine', return_value='aarch64'), \
                patch.object(CLOUD.os, 'geteuid', return_value=1001), self.assertRaisesRegex(RuntimeError, 'native ARM64'):
            CLOUD.require_vm(root=True)

    def test_guest_build_refuses_installed_or_host_roots(self):
        for root in (Path('/'), Path('/root'), Path('/data/user/0/com.ai.codex/rootfs')):
            with self.subTest(root=root), self.assertRaisesRegex(ValueError, 'disposable'):
                guest_build.validate(root)

    def test_guest_apt_command_is_always_in_a_private_mount_namespace(self):
        with patch.object(guest_build, 'validate', return_value=Path('/var/tmp/codex-phone-image-test/rootfs')), \
                patch.object(guest_build.shutil, 'which', return_value='/usr/bin/unshare'):
            command = guest_build.command(Path('/not-used'), ['/usr/bin/apt-get', 'update'])
        self.assertEqual(command[:4], ['/usr/bin/unshare', '--mount', '--propagation', 'private'])
        self.assertEqual(command[-3:], ['--', '/usr/bin/apt-get', 'update'])

    def test_missing_namespace_tool_is_not_silently_replaced_by_chroot(self):
        with patch.object(guest_build, 'validate', return_value=Path('/var/tmp/codex-phone-image-test/rootfs')), \
                patch.object(guest_build.shutil, 'which', return_value=None), self.assertRaisesRegex(RuntimeError, 'unshare'):
            guest_build.command(Path('/not-used'), ['/usr/bin/true'])

    def test_chunked_transfer_preserves_exact_bytes_and_checksums(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'rootfs.gz'
            source.write_bytes(b'0123456789' * 7)
            rows = CLOUD.split_archive(source, root / 'parts', part_bytes=13)
            self.assertEqual(b''.join((root / 'parts' / row['name']).read_bytes() for row in rows), source.read_bytes())
            self.assertTrue(all(CLOUD.sha(root / 'parts' / row['name']) == row['sha256'] for row in rows))
            self.assertEqual(sum(row['bytes'] for row in rows), source.stat().st_size)

    def test_empty_transfer_cannot_be_published_as_completed_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'empty').write_bytes(b'')
            with self.assertRaisesRegex(ValueError, 'one and eight'):
                CLOUD.split_archive(root / 'empty', root / 'parts', part_bytes=13)


if __name__ == '__main__':
    unittest.main()
