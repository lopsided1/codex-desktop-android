"""Regression checks for explicit build-host PRoot export and origin admission."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/install'))
import proot_archive


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VisibleExportTests(unittest.TestCase):
    def test_public_hardlinks_are_materialized_and_private_backing_omitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'root'
            root.mkdir()
            (root / 'a').write_bytes(b'guest data')
            os.link(root / 'a', root / 'b')
            (root / '.l2s.synthetic').write_bytes(b'host private')
            (root / 'link').symlink_to('a')
            archive, evidence = Path(temporary) / 'root.tar.gz', Path(temporary) / 'export.json'
            proot_archive.write_archive(root, archive, evidence)
            with tarfile.open(archive) as stream:
                members = {p.name.removeprefix('./'): p for p in stream}
                self.assertTrue(members['a'].isfile())
                self.assertTrue(members['b'].isfile())
                self.assertTrue(members['link'].issym())
                self.assertFalse(any(proot_archive.private_path(p) for p in members))
            self.assertTrue(json.loads(evidence.read_text())['publicBytesLinksModesVerified'])

    def test_public_link_to_host_backing_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / '.l2s.backing').write_bytes(b'data')
            (root / 'public').symlink_to('.l2s.backing')
            # Some PRoot link2symlink hosts reject this reserved target at lstat.
            with self.assertRaises((ValueError, OSError)):
                proot_archive.visible_inventory(root)

    def test_fingerprint_detects_mutation_without_mount_claim(self):
        verifier = load('rootfs_mutation_check', ROOT / 'tools/install/verify_rootfs.py')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file = root / 'file'
            file.write_bytes(b'before')
            before = verifier.tree_fingerprint(root)
            file.write_bytes(b'after')
            self.assertNotEqual(before, verifier.tree_fingerprint(root))


class OriginAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.module = load('local_origin_admission', ROOT / 'tools/install/build-phone-image.py')
        self.descriptor = {'version': '26.1103.31037'}

    def test_wrong_client_version_refused_before_signature_tools(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / 'authenticated-input.json').write_text('{}')
            with patch.object(self.module.client, 'descriptor', return_value={'version': 'wrong'}), patch.object(self.module.subprocess, 'check_output') as command:
                with self.assertRaisesRegex(ValueError, 'client version'):
                    self.module.authenticated_client_origin(source, source)
                command.assert_not_called()

    def test_wrong_origin_key_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / 'authenticated-input.json').write_text('{}')
            with patch.object(self.module.client, 'descriptor', return_value=self.descriptor), patch.object(self.module.subprocess, 'check_output', return_value='fpr:::::::::0000000000000000000000000000000000000000:\n') as command:
                with self.assertRaisesRegex(ValueError, 'fingerprint'):
                    self.module.authenticated_client_origin(source, source)
                self.assertEqual(command.call_count, 1)


class InterruptedGuestTests(unittest.TestCase):
    def test_only_known_empty_device_placeholders_are_cleaned(self):
        module = load('phone_placeholder_cleanup', ROOT / 'tools/install/build-phone-image.py')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'dev').mkdir()
            for name in ('null', 'random', 'urandom'):
                (root / 'dev' / name).write_bytes(b'')
            module.cleanup_proot_devices(root)
            self.assertEqual(list((root / 'dev').iterdir()), [])

    def test_unknown_or_nonempty_device_state_is_preserved(self):
        module = load('phone_placeholder_refusal', ROOT / 'tools/install/build-phone-image.py')
        for name, data in (('null', b'keep'), ('unexpected', b'')):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / 'dev').mkdir()
                path = root / 'dev' / name
                path.write_bytes(data)
                with self.assertRaisesRegex(ValueError, 'Unknown'):
                    module.cleanup_proot_devices(root)
                self.assertEqual(path.read_bytes(), data)


if __name__ == '__main__':
    unittest.main()
